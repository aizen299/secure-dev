package gitleaks

import (
	"encoding/json"
	"fmt"
	"strings"
)

// maxFindings bounds how many findings are parsed from one report.
//
// The report comes from a process that read attacker-controlled content, so it
// is treated as untrusted input like any other (§15.7, §15.8). A repository
// crafted to produce millions of matches must not exhaust the worker.
const maxFindings = 100_000

// finding is one gitleaks result.
//
// This type is adapter-local and stays that way: nothing outside this package
// may import it (§7 rule 3). Phase 4 adds the mapping to the canonical Finding;
// Phase 3 needs the parsed form only to enforce the redaction invariant.
//
// Secret and Match are the two fields that carry the credential. They are
// parsed precisely so they can be checked, and are never stored or logged.
type finding struct {
	RuleID      string  `json:"RuleID"`
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	StartColumn int     `json:"StartColumn"`
	EndColumn   int     `json:"EndColumn"`
	Secret      string  `json:"Secret"`
	Match       string  `json:"Match"`
	Entropy     float64 `json:"Entropy"`
	Fingerprint string  `json:"Fingerprint"`
	Commit      string  `json:"Commit"`
	Author      string  `json:"Author"`
	Email       string  `json:"Email"`
	Date        string  `json:"Date"`
}

// parseReport decodes a gitleaks JSON report.
//
// Malformed or hostile output must produce a structured error, never a panic
// and never a silently dropped finding (§8).
func parseReport(data []byte) ([]finding, error) {
	// gitleaks writes an empty file rather than "[]" when there is nothing to
	// report, so this is a clean scan, not a malformed one.
	if len(trimSpace(data)) == 0 {
		return nil, nil
	}

	var findings []finding
	if err := json.Unmarshal(data, &findings); err != nil {
		// The error text quotes the offending bytes, which came from scanning
		// untrusted content, so it is not wrapped into the returned message.
		return nil, fmt.Errorf("%w: report is not valid JSON", ErrMalformedReport)
	}
	if len(findings) > maxFindings {
		return nil, fmt.Errorf("%w: report contains more than %d findings", ErrMalformedReport, maxFindings)
	}
	return findings, nil
}

// assertRedacted verifies that no finding carries a credential.
//
// This is the fail-closed half of ADR 007. --redact does the redaction; this
// proves it happened. Without it, a gitleaks release that renamed the flag or
// changed its default would silently persist live credentials, and nothing
// downstream would notice.
//
// The error deliberately names only the rule and the index. Reporting "which
// characters were not redacted" would be a way of leaking the secret through
// the error path that was just closed.
func assertRedacted(findings []finding) error {
	for i, f := range findings {
		if !isRedactedSecret(f.Secret) {
			return fmt.Errorf("%w: finding %d (rule %q) has an unredacted Secret", ErrRedactionFailed, i, f.RuleID)
		}
		if !isRedactedMatch(f.Match) {
			return fmt.Errorf("%w: finding %d (rule %q) has an unredacted Match", ErrRedactionFailed, i, f.RuleID)
		}
	}
	return nil
}

// isRedactedSecret reports whether the Secret field is safe to persist.
//
// Secret is the bare credential, so under --redact it is exactly the marker
// and nothing else. The check is exact: a value that merely resembles the
// marker is treated as a live credential.
//
// Empty counts as redacted -- an absent value cannot leak anything.
func isRedactedSecret(v string) bool {
	return v == "" || v == redactedMarker
}

// isRedactedMatch reports whether the Match field is safe to persist.
//
// Match is the matched text *with its surrounding context*, so gitleaks
// substitutes the marker inside it rather than replacing the whole field:
// `api_key = "REDACTED"` is correctly redacted output, not a leak. Requiring
// an exact match here was wrong, and it failed closed on real repositories --
// every finding from the common generic-api-key rule was discarded.
//
// So the assertion is that the marker is present, which is what proves gitleaks
// applied redaction to this finding. The residual risk is a line containing two
// secrets where only one was substituted; each finding's Match corresponds to
// its own secret, so that is not a shape gitleaks produces.
func isRedactedMatch(v string) bool {
	return v == "" || strings.Contains(v, redactedMarker)
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpaceByte(b[start]) {
		start++
	}
	for end > start && isSpaceByte(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
