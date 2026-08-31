package gitleaks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads a captured gitleaks report. Tests run against these rather than
// executing gitleaks, so parsing and the redaction invariant are covered
// without depending on the binary being installed (§19).
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "fixtures", "gitleaks", name)
	data, err := os.ReadFile(path) //nolint:gosec // G304: a fixed test fixture path.
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestParseRedactedReport(t *testing.T) {
	findings, err := parseReport(fixture(t, "redacted.json"))
	if err != nil {
		t.Fatalf("parseReport: unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("parsed %d findings, want 2", len(findings))
	}

	got := findings[0]
	if got.RuleID != "github-pat" {
		t.Errorf("RuleID = %q, want %q", got.RuleID, "github-pat")
	}
	if got.File != "config/settings.py" {
		t.Errorf("File = %q, want %q", got.File, "config/settings.py")
	}
	if got.StartLine != 2 {
		t.Errorf("StartLine = %d, want 2", got.StartLine)
	}
	// Everything an engineer needs to act survives redaction: which rule,
	// which file, which line. Only the value is gone.
	if got.Fingerprint != "config/settings.py:github-pat:2" {
		t.Errorf("Fingerprint = %q, want the location-based fingerprint", got.Fingerprint)
	}
	if got.Entropy == 0 {
		t.Error("Entropy was not parsed")
	}
}

func TestParseEmptyReports(t *testing.T) {
	// A clean scan takes two forms: gitleaks writes "[]" in some paths and a
	// zero-byte file in others. Both mean "no secrets", and neither is an
	// error -- treating the empty file as malformed would fail every clean
	// scan.
	for _, name := range []string{"empty.json", "no-findings.json"} {
		t.Run(name, func(t *testing.T) {
			findings, err := parseReport(fixture(t, name))
			if err != nil {
				t.Fatalf("parseReport: unexpected error: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("parsed %d findings, want 0", len(findings))
			}
		})
	}
}

func TestParseRejectsMalformedReports(t *testing.T) {
	for _, name := range []string{"truncated.json", "malformed.json"} {
		t.Run(name, func(t *testing.T) {
			_, err := parseReport(fixture(t, name))
			if !errors.Is(err, ErrMalformedReport) {
				t.Fatalf("parseReport: error = %v, want ErrMalformedReport", err)
			}
		})
	}
}

// Hostile scanner output is in the threat model (§15.7). A parse failure must
// be a structured error, never a panic.
func TestParseSurvivesHostileInput(t *testing.T) {
	hostile := [][]byte{
		[]byte(`{"not":"an array"}`),
		[]byte(`[[[[[[[[[[`),
		[]byte(`[{"StartLine": "not a number"}]`),
		[]byte(`[null]`),
		[]byte("\x00\x01\x02"),
		[]byte(`[{"RuleID":` + strings.Repeat(`"a",`, 1000) + `}]`),
	}

	for i, data := range hostile {
		// A panic here fails the test rather than taking the worker down,
		// which is the behaviour being asserted.
		_, _ = parseReport(data)
		_ = i
	}
}

// The control from ADR 007. This is the assertion that stops SecureOps
// becoming a store of harvested credentials.
func TestAssertRedactedRejectsALiveSecret(t *testing.T) {
	findings, err := parseReport(fixture(t, "unredacted.json"))
	if err != nil {
		t.Fatalf("parseReport: unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("parsed %d findings, want 1", len(findings))
	}

	err = assertRedacted(findings)
	if !errors.Is(err, ErrRedactionFailed) {
		t.Fatalf("assertRedacted: error = %v, want ErrRedactionFailed", err)
	}
}

func TestAssertRedactedAcceptsRedactedOutput(t *testing.T) {
	findings, err := parseReport(fixture(t, "redacted.json"))
	if err != nil {
		t.Fatalf("parseReport: unexpected error: %v", err)
	}
	if err := assertRedacted(findings); err != nil {
		t.Errorf("assertRedacted rejected properly redacted output: %v", err)
	}
}

// The error raised on a redaction failure must not itself leak the secret it
// just refused to store -- that would reopen the hole through the error path.
func TestRedactionErrorDoesNotLeakTheSecret(t *testing.T) {
	data := fixture(t, "unredacted.json")
	findings, err := parseReport(data)
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}

	err = assertRedacted(findings)
	if err == nil {
		t.Fatal("expected a redaction error")
	}
	if strings.Contains(err.Error(), findings[0].Secret) {
		t.Errorf("the error echoed the secret it refused to store: %q", err)
	}
	// The rule name is safe and useful, so it should be there.
	if !strings.Contains(err.Error(), "github-pat") {
		t.Errorf("the error should name the rule, got %q", err)
	}
}

// Secret is the bare credential, so the check is exact.
func TestIsRedactedSecret(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"REDACTED", true},
		// Some rules produce no value. An absent one cannot leak anything.
		{"", true},
		// Anything else is treated as a live credential, because it might be.
		{"redacted", false},
		{"REDACTED ", false},
		{"partially-REDACTED", false},
		{`api_key = "REDACTED"`, false},
		{"ghp_something", false},
		{"****", false},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			if got := isRedactedSecret(tc.value); got != tc.want {
				t.Errorf("isRedactedSecret(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// Match is the matched text with its surrounding context, so gitleaks
// substitutes the marker inside it rather than replacing the whole field.
// Requiring an exact match here discarded every real generic-api-key finding.
func TestIsRedactedMatch(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"REDACTED", true},
		{"", true},
		{`api_key = "REDACTED"`, true},
		{`MAILCHIMP_API_KEY="REDACTED"`, true},
		{`auth": "REDACTED"`, true},
		// No marker means redaction was not applied to this finding.
		{`api_key = "some-actual-value"`, false},
		{"redacted", false},
		{"ghp_something", false},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			if got := isRedactedMatch(tc.value); got != tc.want {
				t.Errorf("isRedactedMatch(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// The shape that broke the control in production: a real repository produced
// Match values with context, and the exact-match check discarded every finding.
func TestRedactedMatchWithContextIsAccepted(t *testing.T) {
	findings, err := parseReport(fixture(t, "redacted-with-context.json"))
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("parsed %d findings, want 2", len(findings))
	}
	if err := assertRedacted(findings); err != nil {
		t.Fatalf("correctly redacted output with context was rejected: %v\n"+
			"this is the failure that discarded every generic-api-key finding", err)
	}
}

// The narrower case the split check exists to catch: Secret redacted, but
// Match carrying the plaintext.
func TestUnredactedMatchIsStillRejected(t *testing.T) {
	findings, err := parseReport(fixture(t, "unredacted-match.json"))
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if err := assertRedacted(findings); !errors.Is(err, ErrRedactionFailed) {
		t.Fatalf("assertRedacted: error = %v, want ErrRedactionFailed", err)
	}
}

// A repository crafted to produce millions of matches must not exhaust the
// worker: scanner output is untrusted input like any other (§15.8).
func TestParseBoundsTheFindingCount(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := range maxFindings + 1 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"RuleID":"r","Secret":"REDACTED","Match":"REDACTED"}`)
	}
	b.WriteString("]")

	_, err := parseReport([]byte(b.String()))
	if !errors.Is(err, ErrMalformedReport) {
		t.Fatalf("parseReport: error = %v, want ErrMalformedReport for an oversized report", err)
	}
}

// No fixture may contain a live credential (§19). This checks the fixtures
// themselves, since a well-meaning future edit is exactly how one gets in.
func TestFixturesContainNoRealCredentials(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "tests", "fixtures", "gitleaks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixture directory: %v", err)
	}

	// Prefixes that indicate a genuine token format rather than a placeholder.
	realPrefixes := []string{"ghp_", "gho_", "ghs_", "xoxb-", "xoxp-", "AKIA", "ASIA", "sk_live_", "-----BEGIN"}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: fixed test fixture path.
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, prefix := range realPrefixes {
			if strings.Contains(string(data), prefix) {
				t.Errorf("fixture %s contains %q, which is a real credential format; use a placeholder",
					e.Name(), prefix)
			}
		}
	}
}
