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

// §8 forbids merging things for looking similar. A likely duplicate is a claim
// with a confidence attached, and both findings survive.
func TestLikelyDuplicatesAreLinkedNotMerged(t *testing.T) {
	got := Deduplicate([]Finding{
		dep("fp1", "trivy", "pkg:golang/x@1", "", SeverityHigh),
		dep("fp2", "semgrep", "pkg:golang/x@1", "", SeverityHigh),
	})

	if len(got.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: similar is not identical", len(got.Findings))
	}
	if len(got.Links) != 1 || got.Links[0].Relationship != RelationLikelyDuplicate {
		t.Fatalf("links = %+v, want one likely_duplicate", got.Links)
	}
	if got.Links[0].Confidence == "" {
		t.Error("a likely duplicate must carry a confidence: it is a claim, not a fact")
	}
	if got.Links[0].Evidence == "" {
		t.Error("every link must state its evidence (§9)")
	}
}

// Two findings sharing a CVE are related, not duplicates: both are real and
// both need action.
func TestSharedVulnerabilityIsRelated(t *testing.T) {
	got := Deduplicate([]Finding{
		dep("fp1", "grype", "pkg:golang/a@1", "CVE-1", SeverityHigh),
		dep("fp2", "grype", "pkg:golang/b@2", "CVE-1", SeverityHigh),
	})
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(got.Findings))
	}
	if len(got.Links) != 1 || got.Links[0].Relationship != RelationRelated {
		t.Fatalf("links = %+v, want one related", got.Links)
	}
}

// Findings with nothing in common must not be connected. A wrong link sends
// somebody to investigate a relationship that does not exist.
func TestUnrelatedFindingsAreNotLinked(t *testing.T) {
	got := Deduplicate([]Finding{
		{Fingerprint: "fp1", Scanner: "gitleaks", Title: "t",
			Category: scanners.CategorySecrets, Severity: SeverityCritical, Confidence: ConfidenceHigh},
		{Fingerprint: "fp2", Scanner: "semgrep", Title: "t",
			Category: scanners.CategorySAST, Severity: SeverityHigh, Confidence: ConfidenceHigh},
	})
	if len(got.Links) != 0 {
		t.Errorf("links = %+v, want none: these share nothing", got.Links)
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
	if len(got.Findings) != 0 || len(got.Links) != 0 {
		t.Error("empty input produced output")
	}
}
