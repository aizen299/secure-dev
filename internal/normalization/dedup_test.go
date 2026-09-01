package normalization

import (
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func dep(fingerprint, scanner, purl, cve string, sev Severity) Finding {
	return Finding{
		Fingerprint: fingerprint, Scanner: scanner, Title: "t",
		Category: scanners.CategoryDependency, Severity: sev,
		Confidence: ConfidenceHigh, PURL: purl, CVE: cve,
	}
}

// Identical fingerprints are one problem reported twice. This is the only
// relationship that merges.
func TestExactDuplicatesMerge(t *testing.T) {
	got := Deduplicate([]Finding{
		dep("fp1", "grype", "pkg:golang/x@1", "CVE-1", SeverityHigh),
		dep("fp1", "trivy", "pkg:golang/x@1", "CVE-1", SeverityHigh),
	})

	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(got.Findings))
	}
	// Both reporters are kept: independent agreement is information, not noise.
	if len(got.Findings[0].Sources) != 2 {
		t.Errorf("sources = %v, want both scanners", got.Findings[0].Sources)
	}
}

// If two scanners disagree about severity, keeping the lower one is the
// dangerous direction.
func TestMergeKeepsTheHigherSeverity(t *testing.T) {
	got := Deduplicate([]Finding{
		dep("fp1", "grype", "pkg:golang/x@1", "CVE-1", SeverityMedium),
		dep("fp1", "trivy", "pkg:golang/x@1", "CVE-1", SeverityCritical),
	})
	if got.Findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical: under-reporting is the unsafe direction",
			got.Findings[0].Severity)
	}
}

// Only identical fingerprints merge. Similar is not identical (§8), and
// everything weaker than identity is internal/correlation's job now.
func TestSimilarFindingsDoNotMerge(t *testing.T) {
	got := Deduplicate([]Finding{
		dep("fp1", "trivy", "pkg:golang/x@1", "CVE-1", SeverityHigh),
		dep("fp2", "semgrep", "pkg:golang/x@1", "CVE-1", SeverityHigh),
	})
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: same component and CVE is not the same finding", len(got.Findings))
	}
}

// Re-running normalization over one scan must produce the same result, or
// reprocessing stored raw output would produce different findings each time.
func TestDeduplicationIsOrderIndependent(t *testing.T) {
	a := dep("fp1", "grype", "pkg:golang/x@1", "CVE-1", SeverityHigh)
	b := dep("fp1", "trivy", "pkg:golang/x@1", "CVE-1", SeverityHigh)
	c := dep("fp2", "semgrep", "pkg:golang/y@2", "CVE-2", SeverityLow)

	forward := Deduplicate([]Finding{a, b, c})
	reverse := Deduplicate([]Finding{c, b, a})

	if len(forward.Findings) != len(reverse.Findings) {
		t.Fatalf("counts differ: %d vs %d", len(forward.Findings), len(reverse.Findings))
	}
	// Sources are sorted, so the merged record is identical regardless of the
	// order the scanners happened to finish in.
	byFP := map[string][]string{}
	for _, f := range forward.Findings {
		byFP[f.Fingerprint] = f.Sources
	}
	for _, f := range reverse.Findings {
		want := byFP[f.Fingerprint]
		if len(want) != len(f.Sources) {
			t.Errorf("%s sources differ by order: %v vs %v", f.Fingerprint, f.Sources, want)
			continue
		}
		for i := range f.Sources {
			if f.Sources[i] != want[i] {
				t.Errorf("%s sources differ: %v vs %v", f.Fingerprint, f.Sources, want)
				break
			}
		}
	}
}

func TestEmptyInputIsNotAnError(t *testing.T) {
	got := Deduplicate(nil)
	if len(got.Findings) != 0 || len(got.Occurrences) != 0 || len(got.Errors) != 0 {
		t.Error("empty input produced output")
	}
}
