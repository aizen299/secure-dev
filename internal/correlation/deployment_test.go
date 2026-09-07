package correlation

import (
	"strings"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func depSubject(fingerprint, purl string, cat scanners.Category) Subject {
	return Subject{Finding: normalization.Finding{
		Fingerprint: fingerprint,
		Scanner:     "grype",
		Category:    cat,
		Severity:    normalization.SeverityHigh,
		PURL:        purl,
		CVE:         "CVE-2026-0001",
	}}
}

const testPURL = "pkg:npm/express@4.17.1"

// mediumSubject is one domain at medium severity: no cross-domain escalation
// applies, so any change in the issue's severity came from what is under test.
func mediumSubject(fingerprint, purl string) Subject {
	return Subject{Finding: normalization.Finding{
		Fingerprint: fingerprint,
		Scanner:     "grype",
		Category:    scanners.CategoryDependency,
		Severity:    normalization.SeverityMedium,
		PURL:        purl,
		CVE:         "CVE-2026-0001",
	}}
}

// issueOfKind finds the issue for one key kind, failing if there is none.
func issueOfKind(t *testing.T, res Result, kind KeyKind) Issue {
	t.Helper()
	for _, i := range res.Issues {
		if i.Key.Kind == kind {
			return i
		}
	}
	t.Fatalf("no %s issue in %d issues", kind, len(res.Issues))
	return Issue{}
}

func artifactWith(purls ...string) Inventory {
	return NewInventory("scan-image-1", time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC), purls, true)
}

// A package in the artifact is reported as deployed.
func TestAPackageInTheArtifactIsDeployed(t *testing.T) {
	res := CorrelateWith([]Subject{
		depSubject("a", testPURL, scanners.CategoryDependency),
		depSubject("b", testPURL, scanners.CategoryContainer),
	}, Options{Artifact: artifactWith(testPURL)})

	got := issueOfKind(t, res, KindComponent)
	if got.Deployment != DeploymentPresent {
		t.Errorf("deployment = %q, want %q", got.Deployment, DeploymentPresent)
	}
	if !strings.Contains(got.DeploymentEvidence, "2026-09-07") {
		t.Errorf("evidence = %q, want it to name the image scan's date: "+
			"'not in the image' is only true of a particular image", got.DeploymentEvidence)
	}
	if got.ArtifactScanID != "scan-image-1" {
		t.Errorf("artifact scan = %q, want the scan compared against", got.ArtifactScanID)
	}
}

// A package missing from a complete artifact is reported as not deployed.
//
// The discriminating signal, and the one nothing else can produce: a finding
// about a package nobody deployed.
func TestAPackageMissingFromTheArtifactIsNotDeployed(t *testing.T) {
	res := CorrelateWith([]Subject{
		depSubject("a", testPURL, scanners.CategoryDependency),
		depSubject("b", testPURL, scanners.CategorySAST),
	}, Options{Artifact: artifactWith("pkg:npm/something-else@1.0.0")})

	got := issueOfKind(t, res, KindComponent)
	if got.Deployment != DeploymentAbsent {
		t.Fatalf("deployment = %q, want %q", got.Deployment, DeploymentAbsent)
	}
	// The evidence must not read as permission to ignore it.
	if !strings.Contains(got.DeploymentEvidence, "verify before dismissing") {
		t.Errorf("evidence = %q, want it to caution the reader: the engine cannot "+
			"tell 'not in the artifact' from 'not in the artifact we looked at'",
			got.DeploymentEvidence)
	}
}

// The whole point of ADR 037: evidence never moves a severity.
//
// Escalating on presence would be redundant with the cross-domain escalation
// that already fires, and de-escalating on absence would quietly reduce a real
// vulnerability's standing on the strength of an inventory being complete.
func TestDeploymentNeverChangesSeverity(t *testing.T) {
	// Deliberately NOT cross-domain, and deliberately not already at the top of
	// the scale. An earlier version of this test used two categories at high
	// severity, so ADR 017's own escalation had already taken the issue to
	// critical -- and an injected deployment escalation changed nothing the
	// assertion could see. The fixture defeated the assertion, which a control
	// run caught and the test alone would not have.
	subjects := []Subject{
		mediumSubject("a", testPURL),
		mediumSubject("b", testPURL),
	}

	for _, tc := range []struct {
		name     string
		artifact Inventory
	}{
		{"no artifact", Inventory{}},
		{"present", artifactWith(testPURL)},
		{"absent", artifactWith("pkg:npm/other@1.0.0")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := issueOfKind(t, CorrelateWith(subjects, Options{}), KindComponent)
			got := issueOfKind(t, CorrelateWith(subjects, Options{Artifact: tc.artifact}), KindComponent)

			if got.Severity != base.Severity {
				t.Errorf("severity = %q with %s, want %q unchanged: deployment is "+
					"evidence, not a judgement", got.Severity, tc.name, base.Severity)
			}
			if got.Escalated != base.Escalated {
				t.Errorf("escalated = %v with %s, want %v unchanged",
					got.Escalated, tc.name, base.Escalated)
			}
		})
	}
}

// A truncated inventory can prove presence but never absence.
//
// A package missing from a prefix may be in the part that was dropped, so an
// incomplete inventory must not produce not_deployed.
func TestATruncatedInventoryCannotProveAbsence(t *testing.T) {
	truncated := NewInventory("scan-image-1", time.Now(),
		[]string{"pkg:npm/other@1.0.0"}, false)

	got := issueOfKind(t, CorrelateWith([]Subject{
		depSubject("a", testPURL, scanners.CategoryDependency),
		depSubject("b", testPURL, scanners.CategorySAST),
	}, Options{Artifact: truncated}), KindComponent)

	if got.Deployment == DeploymentAbsent {
		t.Error("a truncated inventory reported not_deployed; a package missing from " +
			"a prefix may be in the part that was dropped")
	}
	if got.Deployment != DeploymentUnknown {
		t.Errorf("deployment = %q, want %q", got.Deployment, DeploymentUnknown)
	}
}

// No image scan means unknown, and unknown is an answer.
//
// Most projects have no image scan. A state that quietly meant "probably fine"
// would be the same failure as an EPSS probability defaulting to zero.
func TestNoArtifactMeansUnknown(t *testing.T) {
	got := issueOfKind(t, CorrelateWith([]Subject{
		depSubject("a", testPURL, scanners.CategoryDependency),
		depSubject("b", testPURL, scanners.CategoryContainer),
	}, Options{}), KindComponent)

	if got.Deployment != DeploymentUnknown {
		t.Errorf("deployment = %q, want %q", got.Deployment, DeploymentUnknown)
	}
	if got.DeploymentEvidence != "" {
		t.Errorf("evidence = %q, want empty: there is nothing to report", got.DeploymentEvidence)
	}
	if got.ArtifactScanID != "" {
		t.Errorf("artifact scan = %q, want empty", got.ArtifactScanID)
	}
}

// Only purl issues are classified.
//
// A CVE issue can span several packages and a file issue names none, so neither
// has a single presence to report. Inventing one would assert something about an
// issue that its key does not describe.
func TestOnlyComponentIssuesAreClassified(t *testing.T) {
	// Two findings sharing a CVE but different packages.
	subjects := []Subject{
		depSubject("a", "pkg:npm/one@1.0.0", scanners.CategoryDependency),
		depSubject("b", "pkg:npm/two@2.0.0", scanners.CategoryContainer),
	}

	res := CorrelateWith(subjects, Options{Artifact: artifactWith("pkg:npm/one@1.0.0")})
	for _, issue := range res.Issues {
		if issue.Key.Kind == KindComponent {
			continue
		}
		if issue.Deployment != DeploymentUnknown {
			t.Errorf("%s issue reported deployment %q; only a component key names "+
				"one package", issue.Key.Kind, issue.Deployment)
		}
	}
}

// An unnamed component cannot match anything.
//
// syft stores a component it could not name with an empty purl (ADR 035).
// Letting "" into the set would make every unnamed component match every issue
// that also had none.
func TestAnEmptyPURLIsNotAMatch(t *testing.T) {
	inv := NewInventory("s", time.Now(), []string{"", "  ", "pkg:npm/real@1.0.0"}, true)

	if len(inv.PURLs) != 1 {
		t.Errorf("purls = %v, want only the real one", sortedPURLs(inv))
	}
	if _, ok := inv.PURLs[""]; ok {
		t.Error("the empty purl is in the set")
	}
}
