//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func containerFinding(fingerprint, image, purl string) normalization.MergedFinding {
	return normalization.MergedFinding{
		Finding: normalization.Finding{
			Fingerprint:    fingerprint,
			Scanner:        "trivy",
			Title:          "CVE-2021-23840 in libcrypto1.1",
			Category:       scanners.CategoryContainer,
			Severity:       normalization.SeverityHigh,
			Confidence:     normalization.ConfidenceHigh,
			Package:        "libcrypto1.1",
			PackageVersion: "1.1.1g-r0",
			PURL:           purl,
			Image:          image,
			CVE:            "CVE-2021-23840",
			Status:         normalization.StatusOpen,
		},
		Sources: []string{"trivy"},
	}
}

// The image survives the round trip, which is what makes "everything wrong with
// this image" a query rather than a correlation key (ADR 025).
func TestContainerFindingRetainsItsImage(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("c")

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{containerFinding(fp, "ghcr.io/org/api", "pkg:apk/alpine/libcrypto1.1@1.1.1g-r0")},
		Occurrences: []normalization.Occurrence{{Fingerprint: fp, ScanID: scanID, Scanner: "trivy"}},
	}, []string{"trivy"}, time.Now().UTC()); err != nil {
		t.Fatalf("Record: %v", err)
	}

	stored, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{Limit: 10})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("findings = %d, want 1", len(stored))
	}
	if stored[0].Image != "ghcr.io/org/api" {
		t.Errorf("image = %q, want ghcr.io/org/api", stored[0].Image)
	}
	if stored[0].Category != scanners.CategoryContainer {
		t.Errorf("category = %q, want container", stored[0].Category)
	}
}

// A finding from a repository has no image, and NULL must read back as absence
// rather than as an image named "".
func TestNonContainerFindingsHaveNoImage(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("d")

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanID, "gitleaks", 12)},
	}, []string{"gitleaks"}, time.Now().UTC()); err != nil {
		t.Fatalf("Record: %v", err)
	}

	stored, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{Limit: 10})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("findings = %d, want 1", len(stored))
	}
	if stored[0].Image != "" {
		t.Errorf("image = %q, want empty for a secret finding", stored[0].Image)
	}
}

// Two images shipping the same vulnerable package are two findings, because
// they are two assets fixed separately. This is the collision the repository
// component of the fingerprint exists to prevent, checked where it matters:
// against the unique constraint on (project_id, fingerprint).
func TestTwoImagesWithOneVulnerabilityAreTwoFindings(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	purl := "pkg:apk/alpine/libcrypto1.1@1.1.1g-r0"

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings: []normalization.MergedFinding{
			containerFinding(fingerprintOf("e"), "ghcr.io/org/api", purl),
			containerFinding(fingerprintOf("f"), "ghcr.io/org/worker", purl),
		},
		Occurrences: []normalization.Occurrence{
			{Fingerprint: fingerprintOf("e"), ScanID: scanID, Scanner: "trivy"},
			{Fingerprint: fingerprintOf("f"), ScanID: scanID, Scanner: "trivy"},
		},
	}, []string{"trivy"}, time.Now().UTC()); err != nil {
		t.Fatalf("Record: %v", err)
	}

	stored, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{Limit: 10})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("findings = %d, want 2: two images are two assets", len(stored))
	}
	images := map[string]bool{}
	for _, f := range stored {
		images[f.Image] = true
	}
	if !images["ghcr.io/org/api"] || !images["ghcr.io/org/worker"] {
		t.Errorf("images = %v, want both repositories", images)
	}
}
