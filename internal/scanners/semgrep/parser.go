package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v4"
)

// maxResults bounds how many findings are accepted from one report.
//
// The report describes attacker-controlled content, so it is bounded like any
// other external input (§15.8).
const maxResults = 200_000

// maxRulesetBytes bounds one downloaded ruleset. The registry is a remote
// service and its response is external input like any other.
const maxRulesetBytes = 32 << 20

// registryBaseURL is where a named ruleset is fetched from. Rules are code:
// they are fetched once at provisioning, over TLS, and then read from disk.
const registryBaseURL = "https://semgrep.dev/c/"

// report is the subset of semgrep's JSON this adapter validates.
//
// Adapter-local by design: nothing outside this package may import it (§7 rule
// 3). Phase 4 adds the mapping into the canonical model.
type report struct {
	Results []result   `json:"results"`
	Errors  []anyValue `json:"errors"`
	Paths   *anyValue  `json:"paths"`
	Version string     `json:"version"`
}

type result struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   pos    `json:"start"`
	End     pos    `json:"end"`
	Extra   extra  `json:"extra"`
}

type pos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type extra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	// Lines is the matched source. See ErrSourceLeak: for a credential rule
	// this field is the credential.
	Lines string `json:"lines"`
}

type anyValue = json.RawMessage

// redactedMarker is what semgrep writes instead of matched source when it is
// not authenticated against the Semgrep registry.
const redactedMarker = "requires login"

// validateReport checks that the output really is a semgrep report.
//
// A garbled or truncated report is more dangerous than an obviously broken one:
// stored as-is, it later reads as "this project has no static-analysis
// findings" rather than "this scan did not work".
func validateReport(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		// Distinct from a report with no results, which is the expected
		// outcome for a project with nothing to find.
		return fmt.Errorf("%w: output was empty", ErrMalformedReport)
	}

	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		// The error text quotes the offending bytes, which came from scanning
		// untrusted content, so it is not wrapped into the returned message.
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	// A semgrep report always carries these keys, even when empty. Their
	// absence means this is valid JSON from something else -- another tool, or
	// a substituted binary -- which would otherwise be stored as if semgrep
	// had produced it.
	if r.Paths == nil && r.Errors == nil && r.Results == nil {
		return fmt.Errorf("%w: report is not from semgrep", ErrMalformedReport)
	}
	if len(r.Results) > maxResults {
		return fmt.Errorf("%w: more than %d results", ErrMalformedReport, maxResults)
	}
	return nil
}

// assertNoMatchedSource verifies the report carries no matched source code.
//
// Semgrep embeds the matched line in `extra.lines`. For a rule that fires on a
// credential, that line IS the credential, and §15.3 forbids storing it.
// Unauthenticated semgrep writes "requires login" there instead -- verified
// against a local ruleset and a planted key, which appeared nowhere in the
// output -- but that behaviour follows from its login state, not from any flag
// this adapter sets.
//
// So the result is asserted rather than assumed. A future semgrep, or a
// SEMGREP_APP_TOKEN that reaches the subprocess despite the environment
// allow-list, fails the scan instead of quietly writing credentials into
// storage.
func assertNoMatchedSource(data []byte) error {
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}
	for _, res := range r.Results {
		if !isRedactedSource(res.Extra.Lines) {
			// The offending value is not echoed: it may be the credential.
			return fmt.Errorf("%w: a finding carries matched source", ErrSourceLeak)
		}
	}
	return nil
}

// isRedactedSource reports whether a `lines` value is free of source code.
func isRedactedSource(v string) bool {
	trimmed := strings.TrimSpace(v)
	return trimmed == "" || trimmed == redactedMarker
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

// assertIsRulesDocument verifies a downloaded ruleset really carries rules.
func assertIsRulesDocument(body []byte) error {
	// []any rather than json.RawMessage: RawMessage is a []byte, and YAML
	// cannot decode a mapping into one, so the struct that looked right for
	// JSON silently rejected every real ruleset.
	var doc struct {
		Rules []any `yaml:"rules" json:"rules"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("not a parseable rules document")
	}
	if len(doc.Rules) == 0 {
		return fmt.Errorf("contains no rules")
	}
	return nil
}

// resultCount reports how many findings the report holds. Used by tests to
// confirm output is not merely well-formed but populated.
func resultCount(data []byte) (int, error) {
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return 0, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}
	return len(r.Results), nil
}

// fetchRuleset downloads one named ruleset into the rules directory.
//
// Rules are code, and this is the one place they enter the system. The response
// is bounded, written to a validated filename, and checked for being a rules
// document before it is kept -- a truncated or error-page download that landed
// in the rules directory would silently reduce coverage on every later scan.
func (s *Scanner) fetchRuleset(ctx context.Context, ruleset string) error {
	name, err := rulesetFilename(ruleset)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryBaseURL+ruleset, nil)
	if err != nil {
		return fmt.Errorf("semgrep: building the request for %s: %w", ruleset, err)
	}
	// A preference, not a requirement: the registry content-negotiates and the
	// validation below accepts either form.
	req.Header.Set("Accept", "application/x-yaml, application/json")
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("semgrep: fetching ruleset %s: %w", ruleset, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("semgrep: fetching ruleset %s: status %d", ruleset, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRulesetBytes+1))
	if err != nil {
		return fmt.Errorf("semgrep: reading ruleset %s: %w", ruleset, err)
	}
	if int64(len(body)) > maxRulesetBytes {
		return fmt.Errorf("semgrep: ruleset %s exceeds %d bytes", ruleset, maxRulesetBytes)
	}
	// Parsed rather than string-matched, because the registry content-negotiates:
	// it answers a Go client with JSON and curl with YAML, so a check for a
	// literal "rules:" passes with one and fails with the other. Parsing covers
	// both -- JSON is valid YAML -- and actually establishes what the check
	// claims: that this is a rules document with rules in it.
	//
	// It matters because an error page, a redirect body, or a truncated
	// download written into the rules directory would quietly remove a whole
	// ruleset's worth of coverage from every later scan, with nothing failing.
	if err := assertIsRulesDocument(body); err != nil {
		return fmt.Errorf("semgrep: ruleset %s: %w", ruleset, err)
	}

	if err := os.WriteFile(filepath.Join(s.rulesDir(), name), body, 0o600); err != nil {
		return fmt.Errorf("semgrep: writing ruleset %s: %w", ruleset, err)
	}
	return nil
}
