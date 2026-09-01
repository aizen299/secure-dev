package trivy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
)

// maxMisconfigurations bounds how many findings are accepted from one report.
//
// The report describes attacker-controlled content, so it is bounded like any
// other external input (§15.8).
const maxMisconfigurations = 200_000

// redactedMarker replaces source content. It is a fixed string rather than an
// elision of the original, because a partial line can still contain the whole
// secret -- truncation is not redaction.
const redactedMarker = "[redacted]"

// report is the subset of trivy's JSON this adapter reads and rewrites.
//
// Adapter-local by design: nothing outside this package may import it (§7 rule
// 3). Phase 4 adds the mapping into the canonical model.
type report struct {
	SchemaVersion *int              `json:"SchemaVersion"`
	ArtifactName  string            `json:"ArtifactName"`
	ArtifactType  string            `json:"ArtifactType"`
	Results       []json.RawMessage `json:"Results"`
}

// validateReport checks that the output really is a trivy report.
//
// A garbled or truncated report is more dangerous than an obviously broken one:
// stored as-is, it later reads as "this project has no misconfigurations"
// rather than "this scan did not work".
func validateReport(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		// Distinct from a report with no findings, which is the expected
		// outcome for a project with nothing misconfigured.
		return fmt.Errorf("%w: output was empty", ErrMalformedReport)
	}

	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		// The error text quotes the offending bytes, which came from scanning
		// untrusted content, so it is not wrapped into the returned message.
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	// SchemaVersion is trivy's own marker and every report carries it. Its
	// absence means this is valid JSON from something else, which would
	// otherwise be stored as if trivy had produced it.
	if r.SchemaVersion == nil {
		return fmt.Errorf("%w: report is not from trivy", ErrMalformedReport)
	}
	if len(r.Results) > maxMisconfigurations {
		return fmt.Errorf("%w: more than %d results", ErrMalformedReport, maxMisconfigurations)
	}
	return nil
}

// redactSourceContent removes the source lines trivy embeds in every finding.
//
// Trivy reports each misconfiguration with the lines that caused it, in
// CauseMetadata.Code.Lines. For infrastructure-as-code that source is routinely
// a credential: a Terraform resource with a hardcoded password produces a
// misconfiguration whose cause lines contain that password, and §15.3 forbids
// storing it.
//
// There is no trivy flag for this -- --render-cause affects only the table
// report -- so the rewrite happens here. It is structural rather than textual:
// the document is parsed, the three fields that carry source are replaced, and
// it is re-serialised. A regex over the bytes would be guessing.
//
// What survives is everything a person or a later phase needs: the file, the
// line numbers, which lines were the cause, the rule, and its severity. What
// does not survive is the code itself.
func redactSourceContent(data []byte) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	redactLines(doc)

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: could not re-serialise after redaction", ErrMalformedReport)
	}
	return out, nil
}

// sourceBearingFields are the keys on a trivy Line that carry source text.
//
// Content is the line. Highlighted is the same line with ANSI colour, which is
// why redacting only Content leaves the secret in the document -- measured, not
// assumed. Annotation is free text derived from the source and is cleared for
// the same reason.
var sourceBearingFields = []string{"Content", "Highlighted", "Annotation"}

// redactLines walks the decoded document and clears source-bearing fields on
// every object that looks like a trivy Line.
//
// Structural rather than path-based: trivy nests Results differently for
// different artifact types, and a walk cannot be wrong about where the Lines
// are. An object is treated as a Line when it carries a "Number" alongside any
// source-bearing field.
func redactLines(node any) {
	switch v := node.(type) {
	case map[string]any:
		if _, hasNumber := v["Number"]; hasNumber {
			for _, field := range sourceBearingFields {
				if _, present := v[field]; present {
					v[field] = redactedMarker
				}
			}
		}
		for _, child := range v {
			redactLines(child)
		}
	case []any:
		for _, child := range v {
			redactLines(child)
		}
	}
}

// assertNoSourceContent verifies redaction actually happened.
//
// Fail-closed: redactSourceContent walks a decoded document, and a trivy schema
// change that moved or renamed those fields would make the walk silently miss
// them. This checks the result rather than trusting the rewrite, so a miss
// discards the report instead of storing credentials.
func assertNoSourceContent(data []byte) error {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}
	if found := findUnredacted(doc); found != "" {
		// The offending value is not echoed: it may be the credential.
		return fmt.Errorf("%w: %s survived redaction", ErrSourceLeak, found)
	}
	return nil
}

// findUnredacted returns the name of the first source-bearing field still
// holding something other than the marker.
func findUnredacted(node any) string {
	switch v := node.(type) {
	case map[string]any:
		for _, field := range sourceBearingFields {
			if raw, present := v[field]; present {
				if s, ok := raw.(string); ok && s != redactedMarker && s != "" {
					return field
				}
			}
		}
		for _, child := range v {
			if found := findUnredacted(child); found != "" {
				return found
			}
		}
	case []any:
		for _, child := range v {
			if found := findUnredacted(child); found != "" {
				return found
			}
		}
	}
	return ""
}

// assertNoWorkspacePaths verifies the report does not embed the worker's
// filesystem layout.
//
// Same reasoning as T-30 against syft: a workspace directory is ephemeral and
// randomly suffixed, so a report containing it differs between two scans of the
// identical commit and could never be compared.
func assertNoWorkspacePaths(data []byte, workspacePath string) error {
	if workspacePath == "" {
		return nil
	}
	candidates := []string{workspacePath}
	if parent := filepath.Dir(workspacePath); parent != "" && parent != workspacePath && parent != "/" {
		candidates = append(candidates, parent)
	}
	for _, path := range candidates {
		if bytes.Contains(data, []byte(path)) {
			// The path is not echoed: it is an internal detail, and the point
			// is that it should not travel.
			return fmt.Errorf("%w: a finding references the scan workspace", ErrSourceLeak)
		}
	}
	return nil
}

// misconfigurationCount reports how many findings the report holds, across all
// results. Used by tests to confirm output is not merely well-formed but
// populated.
func misconfigurationCount(data []byte) (int, error) {
	var doc struct {
		Results []struct {
			Misconfigurations []json.RawMessage `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}
	total := 0
	for _, r := range doc.Results {
		total += len(r.Misconfigurations)
	}
	return total, nil
}

// parseVersion extracts the version from `trivy version --format json`.
func parseVersion(data []byte) string {
	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return ""
	}
	return v.Version
}
