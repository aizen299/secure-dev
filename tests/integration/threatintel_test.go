//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func vulnFinding(fingerprint string, epss *normalization.EPSS) normalization.MergedFinding {
	return normalization.MergedFinding{
		Finding: normalization.Finding{
			Fingerprint: fingerprint, Scanner: "grype",
			Title:      "Vulnerable component",
			Category:   scanners.CategoryDependency,
			Severity:   normalization.SeverityCritical,
			Confidence: normalization.ConfidenceHigh,
			Status:     normalization.StatusOpen,
			CVE:        "GHSA-5cgq-3rg8-m6cv",
			Threat:     normalization.ThreatIntel{EPSS: epss},
		},
		Sources: []string{"grype"},
	}
}

func sampleEPSS() *normalization.EPSS {
	return &normalization.EPSS{
		Probability: 0.07314,
		Percentile:  0.93929,
		Source:      normalization.SourceGrype,
		ObservedAt:  time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}
}

// The value and all three provenance fields have to survive storage. A number
// that comes back without its source or its date is not evidence any more.
func TestEPSSSurvivesTheRoundTrip(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("7")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{vulnFinding(fp, sampleEPSS())},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanA, "grype", "go.mod")},
	}, []string{"grype"}, now); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	records, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("findings = %d, want 1", len(records))
	}

	got := records[0].Threat.EPSS
	if got == nil {
		t.Fatal("EPSS was lost in storage")
	}
	if got.Probability != 0.07314 {
		t.Errorf("probability = %v, want 0.07314", got.Probability)
	}
	if got.Percentile != 0.93929 {
		t.Errorf("percentile = %v, want 0.93929", got.Percentile)
	}
	if got.Source != normalization.SourceGrype {
		t.Errorf("source = %q, want %q: provenance is mandatory", got.Source, normalization.SourceGrype)
	}
	if !got.ObservedAt.Equal(time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("observed_at = %v, want 2026-08-30 UTC", got.ObservedAt)
	}
}

// The distinction the whole design exists to preserve. A finding with no EPSS
// must read back as "no signal", never as a probability of zero -- which is a
// real value meaning "essentially nobody is exploiting this".
func TestAbsentEPSSDoesNotBecomeZero(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("8")

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{vulnFinding(fp, nil)},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanA, "grype", "go.mod")},
	}, []string{"grype"}, time.Now().UTC()); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	records, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if records[0].Threat.EPSS != nil {
		t.Errorf("EPSS = %+v, want nil: absence must not materialise as a value", records[0].Threat.EPSS)
	}
	if records[0].Threat.Available() {
		t.Error("Available() is true with no signal stored")
	}

	// And the columns are genuinely NULL, not zeroes that happen to read back
	// as nil through the all-or-nothing check.
	var nulls bool
	if err := pool.QueryRow(t.Context(), `
		SELECT epss_probability IS NULL AND epss_percentile IS NULL
		   AND epss_source IS NULL AND epss_observed_at IS NULL
		  FROM findings WHERE project_id = $1 AND fingerprint = $2`,
		projectID, fp).Scan(&nulls); err != nil {
		t.Fatalf("check nulls: %v", err)
	}
	if !nulls {
		t.Error("absent EPSS was written as values rather than NULLs")
	}
}

// EPSS is recomputed daily, so a stored value goes stale where a title does
// not. A later scan reporting a newer value must replace the old one.
func TestEPSSIsRefreshedOnRescan(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("9")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{vulnFinding(fp, sampleEPSS())},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanA, "grype", "go.mod")},
	}, []string{"grype"}, now); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// Exploitation became far more likely, and the model date moved.
	updated := &normalization.EPSS{
		Probability: 0.88,
		Percentile:  0.99,
		Source:      normalization.SourceGrype,
		ObservedAt:  time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
	scanB := seedScanFor(t, pool, projectID)
	if err := store.RecordScan(t.Context(), projectID, scanB, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{vulnFinding(fp, updated)},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanB, "grype", "go.mod")},
	}, []string{"grype"}, now.Add(time.Hour)); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	records, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := records[0].Threat.EPSS
	if got == nil {
		t.Fatal("EPSS was lost on rescan")
	}
	if got.Probability != 0.88 {
		t.Errorf("probability = %v, want 0.88: a stale likelihood was kept", got.Probability)
	}
	if !got.ObservedAt.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("observed_at = %v, want the newer model date", got.ObservedAt)
	}
}

// The schema's own statement of the rule: a half-populated value is a number
// of unknown origin, and the database refuses it independently of the Go model.
func TestAPartialEPSSRowIsRejectedByTheDatabase(t *testing.T) {
	pool := testPool(t)
	_, projectID := seedScan(t, pool)

	_, err := pool.Exec(t.Context(), `
		INSERT INTO findings
		    (project_id, fingerprint, scanner, category, severity, confidence,
		     title, epss_probability)
		VALUES ($1, $2, 'grype', 'dependency', 'critical', 'high', 'x', 0.5)`,
		projectID, fingerprintOf("a"))
	if err == nil {
		t.Fatal("a probability with no source or date was accepted")
	}
	if !strings.Contains(err.Error(), "findings_epss_all_or_nothing") {
		t.Errorf("rejected by the wrong constraint: %v", err)
	}
}
