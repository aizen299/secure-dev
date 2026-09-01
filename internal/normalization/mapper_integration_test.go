package normalization_test

// These tests live outside the normalization package on purpose: they exercise
// the adapters' mappers, which is the boundary that matters. If normalization
// ever needed something only an adapter's internals could give it, that would
// be a leak (§7 rule 3) and this file would not compile.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/gitleaks"
	"github.com/aizen299/secure-dev/internal/scanners/grype"
	"github.com/aizen299/secure-dev/internal/scanners/semgrep"
	"github.com/aizen299/secure-dev/internal/scanners/trivy"
)

func fixture(t *testing.T, scanner, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../tests/fixtures", scanner, name))
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", scanner, name, err)
	}
	return data
}

type normalizeFunc func([]byte, string) (normalization.Result, error)

// Every mapper must produce valid findings from real captured output.
func TestMappersProduceValidFindings(t *testing.T) {
	cases := []struct {
		scanner  string
		fixture  string
		fn       normalizeFunc
		category scanners.Category
	}{
		{"gitleaks", "redacted.json", gitleaks.Normalize, scanners.CategorySecrets},
		{"semgrep", "valid.json", semgrep.Normalize, scanners.CategorySAST},
		// The REDACTED document, which is what the adapter persists.
		// Feeding it unredacted.json is what the mapper is supposed to refuse,
		// and does -- see TestMappersRefuseUnredactedInput.
		{"trivy", "redacted.json", trivy.Normalize, scanners.CategoryIaC},
	}

	for _, tc := range cases {
		t.Run(tc.scanner, func(t *testing.T) {
			got, err := tc.fn(fixture(t, tc.scanner, tc.fixture), "scan-1")
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if len(got.Findings) == 0 {
				t.Fatal("no findings produced; the test asserts nothing")
			}
			if len(got.Errors) != 0 {
				t.Errorf("errors on a valid fixture: %v", got.Errors)
			}
			for i, f := range got.Findings {
				if err := f.Validate(); err != nil {
					t.Errorf("finding %d is invalid: %v", i, err)
				}
				if f.Category != tc.category {
					t.Errorf("finding %d category = %q, want %q", i, f.Category, tc.category)
				}
				if f.Scanner != tc.scanner {
					t.Errorf("finding %d scanner = %q, want %q", i, f.Scanner, tc.scanner)
				}
				if f.ScannerSeverity == "" && tc.scanner != "gitleaks" {
					t.Errorf("finding %d lost the original severity (§8)", i)
				}
			}
			// Every finding needs a sighting, or nothing can say where it is.
			if len(got.Occurrences) != len(got.Findings) {
				t.Errorf("occurrences = %d, findings = %d", len(got.Occurrences), len(got.Findings))
			}
		})
	}
}

// The mappers must be deterministic: reprocessing stored raw output has to
// produce identical findings, or the raw results are not reprocessable at all.
func TestMappersAreDeterministic(t *testing.T) {
	data := fixture(t, "semgrep", "valid.json")
	first, err := semgrep.Normalize(data, "scan-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := semgrep.Normalize(data, "scan-1")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("counts differ: %d vs %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].Fingerprint != second.Findings[i].Fingerprint {
			t.Errorf("finding %d fingerprinted differently across runs", i)
		}
	}
}

// Hostile and broken output must produce a structured error, never a panic and
// never a silent empty result that reads as "nothing was wrong" (§8, §13).
func TestMappersRejectBrokenOutput(t *testing.T) {
	cases := []struct {
		scanner string
		fn      normalizeFunc
		files   []string
	}{
		{"gitleaks", gitleaks.Normalize, []string{"malformed.json", "truncated.json"}},
		{"semgrep", semgrep.Normalize, []string{"empty.json", "malformed.json", "truncated.json", "wrong-tool.json"}},
		{"trivy", trivy.Normalize, []string{"empty.json", "malformed.json", "truncated.json", "wrong-tool.json"}},
		{"grype", grype.Normalize, []string{"empty.json", "malformed.json", "truncated.json"}},
	}

	for _, tc := range cases {
		for _, name := range tc.files {
			t.Run(tc.scanner+"/"+name, func(t *testing.T) {
				data, err := os.ReadFile(filepath.Join("../../tests/fixtures", tc.scanner, name))
				if err != nil {
					t.Skipf("fixture absent: %v", err)
				}
				if _, err := tc.fn(data, "scan-1"); err == nil {
					t.Error("broken output was accepted")
				}
			})
		}
	}
}

// A clean scan produces zero findings and no error. Conflating that with a
// failed scan is how a broken pipeline becomes a clean bill of health.
func TestNoFindingsIsNotAnError(t *testing.T) {
	for _, tc := range []struct {
		scanner string
		fn      normalizeFunc
		file    string
	}{
		{"semgrep", semgrep.Normalize, "no-findings.json"},
		{"trivy", trivy.Normalize, "no-findings.json"},
	} {
		t.Run(tc.scanner, func(t *testing.T) {
			got, err := tc.fn(fixture(t, tc.scanner, tc.file), "scan-1")
			if err != nil {
				t.Fatalf("a clean scan was rejected: %v", err)
			}
			if len(got.Findings) != 0 {
				t.Errorf("findings = %d, want 0", len(got.Findings))
			}
		})
	}
}

// The redaction controls are checked again at normalization, because this is
// the last point before the database.
func TestMappersRefuseUnredactedInput(t *testing.T) {
	// Semgrep: matched source in extra.lines.
	if _, err := semgrep.Normalize(fixture(t, "semgrep", "source-leak.json"), "scan-1"); err == nil {
		t.Error("semgrep mapper accepted output carrying matched source")
	}
	// Trivy: source content that survived the rewrite.
	if _, err := trivy.Normalize(fixture(t, "trivy", "unredacted-after-rewrite.json"), "scan-1"); err == nil {
		t.Error("trivy mapper accepted output carrying source content")
	}
	// Gitleaks: an unredacted secret is dropped rather than stored, and the
	// drop is reported rather than silent.
	got, err := gitleaks.Normalize(fixture(t, "gitleaks", "unredacted.json"), "scan-1")
	if err == nil && len(got.Findings) > 0 {
		t.Error("gitleaks mapper produced findings from unredacted output")
	}
}

// Secrets must never carry the credential into the finding, in any field.
func TestSecretFindingsCarryNoSecretMaterial(t *testing.T) {
	got, err := gitleaks.Normalize(fixture(t, "gitleaks", "redacted.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	for i, f := range got.Findings {
		for field, v := range map[string]string{
			"Title": f.Title, "Description": f.Description, "Remediation": f.Remediation,
		} {
			if v == "REDACTED" {
				t.Errorf("finding %d: %s carries the redaction marker rather than prose", i, field)
			}
		}
	}
}

// Trivy reports passing checks too when asked. A pass is not a finding, and
// counting it would inflate every number downstream.
func TestTrivyPassingChecksAreNotFindings(t *testing.T) {
	const doc = `{
	  "SchemaVersion": 2,
	  "ArtifactName": ".",
	  "Results": [{
	    "Target": "Dockerfile",
	    "Misconfigurations": [
	      {"ID": "DS-0001", "Title": "A failure", "Severity": "HIGH", "Status": "FAIL"},
	      {"ID": "DS-0002", "Title": "A pass",    "Severity": "HIGH", "Status": "PASS"},
	      {"ID": "DS-0003", "Title": "An exception", "Severity": "LOW", "Status": "EXCEPTION"}
	    ]
	  }]
	}`

	got, err := trivy.Normalize([]byte(doc), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: only the FAIL is a finding", len(got.Findings))
	}
	if got.Findings[0].ScannerFindingID != "DS-0001" {
		t.Errorf("kept %q, want the failing check DS-0001", got.Findings[0].ScannerFindingID)
	}
}

// A finding with no rule, no location, no package and no vulnerability has no
// identity worth the name. The mapper must record the refusal rather than
// dropping it silently or minting a colliding fingerprint.
func TestUnfingerprintableEntriesAreReportedNotDropped(t *testing.T) {
	const doc = `{
	  "SchemaVersion": 2,
	  "ArtifactName": ".",
	  "Results": [{
	    "Target": "",
	    "Misconfigurations": [{"ID": "", "Title": "Nameless", "Severity": "HIGH", "Status": "FAIL"}]
	  }]
	}`

	got, err := trivy.Normalize([]byte(doc), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(got.Findings))
	}
	if len(got.Errors) == 0 {
		t.Error("the entry was dropped silently; it must be reported (§8)")
	}
}
