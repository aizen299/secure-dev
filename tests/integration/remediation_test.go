//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/remediation"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func fixableFinding(fingerprint, scanner, purl string, fix normalization.Fix) normalization.MergedFinding {
	return normalization.MergedFinding{
		Finding: normalization.Finding{
			Fingerprint: fingerprint, Scanner: scanner,
			Title:      "Vulnerable component",
			Category:   scanners.CategoryDependency,
			Severity:   normalization.SeverityCritical,
			Confidence: normalization.ConfidenceHigh,
			Status:     normalization.StatusOpen,
			PURL:       purl,
			Package:    "express",
			Fix:        fix,
		},
		Sources: []string{scanner},
	}
}

// The fact §11 calls authoritative has to survive storage intact. A fixed
// version that does not come back is a remediation the platform cannot offer.
func TestFixFactsSurviveTheRoundTrip(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("1")
	fix := normalization.Fix{
		State:         normalization.FixStateFixed,
		FixedVersions: []string{"4.19.2", "4.20.0"},
		References:    []string{"https://example.test/advisory/1"},
	}

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{fixableFinding(fp, "grype", "pkg:npm/express@4.17.1", fix)},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanID, "grype", "package-lock.json")},
	}, []string{"grype"}, time.Now().UTC()); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	records, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("findings = %d, want 1", len(records))
	}
	got := records[0].Fix

	if got.State != normalization.FixStateFixed {
		t.Errorf("state = %q, want fixed", got.State)
	}
	if len(got.FixedVersions) != 2 {
		t.Errorf("fixed versions = %v, want both", got.FixedVersions)
	}
	if len(got.References) != 1 {
		t.Errorf("references = %v, want the advisory link", got.References)
	}
	if !got.Available() {
		t.Error("Available() is false for a stored fix with versions")
	}
}

// Absence must read back as absence. A finding nobody reported a fix state for
// must not come back looking like one somebody declared unfixable.
func TestAbsentFixStateReadsBackAsUnknown(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("2")

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{fixableFinding(fp, "grype", "pkg:npm/lodash@4.17.20", normalization.Fix{})},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanID, "grype", "package-lock.json")},
	}, []string{"grype"}, time.Now().UTC()); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	records, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := records[0].Fix.State; got != normalization.FixStateUnknown {
		t.Errorf("state = %q, want unknown", got)
	}

	// And the column is genuinely NULL, not an enum value standing in for it.
	var isNull bool
	if err := pool.QueryRow(t.Context(),
		`SELECT fix_state IS NULL FROM findings WHERE project_id = $1 AND fingerprint = $2`,
		projectID, fp).Scan(&isNull); err != nil {
		t.Fatalf("check null: %v", err)
	}
	if !isNull {
		t.Error("absent fix state was written as a value")
	}
}

// The schema's own statement of the rule, independent of the Go model: a state
// saying no fix exists cannot carry the version that fixes it.
func TestTheDatabaseRejectsAVersionOnAnUnfixableState(t *testing.T) {
	pool := testPool(t)
	_, projectID := seedScan(t, pool)

	_, err := pool.Exec(t.Context(), `
		INSERT INTO findings
		    (project_id, fingerprint, scanner, category, severity, confidence,
		     title, fix_state, fix_versions)
		VALUES ($1, $2, 'grype', 'dependency', 'critical', 'high', 'x',
		        'wont-fix', ARRAY['9.9.9'])`,
		projectID, fingerprintOf("3"))
	if err == nil {
		t.Fatal("a wont-fix finding carrying a fixed version was accepted")
	}
	if !containsText(err.Error(), "findings_fix_versions_need_a_fix") {
		t.Errorf("rejected by the wrong constraint: %v", err)
	}
}

// The whole pipeline: stored findings become ranked, consolidated work.
func TestStoredFindingsBecomeARankedPlan(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fixed := normalization.Fix{State: normalization.FixStateFixed, FixedVersions: []string{"4.19.2"}}

	// One package, two scanners: one action. Plus an unrelated package.
	expressA := fingerprintOf("4")
	expressB := fingerprintOf("5")
	lodash := fingerprintOf("6")

	a := fixableFinding(expressA, "grype", "pkg:npm/express@4.17.1", fixed)
	b := fixableFinding(expressB, "trivy", "pkg:npm/express@4.17.1", fixed)
	c := fixableFinding(lodash, "grype", "pkg:npm/lodash@4.17.20", normalization.Fix{})
	c.Severity = normalization.SeverityLow

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings: []normalization.MergedFinding{a, b, c},
		Occurrences: []normalization.Occurrence{
			occurrenceIn(expressA, scanID, "grype", "package-lock.json"),
			occurrenceIn(expressB, scanID, "trivy", "package-lock.json"),
			occurrenceIn(lodash, scanID, "grype", "package-lock.json"),
		},
	}, []string{"grype", "trivy"}, time.Now().UTC()); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	subjects, projectCtx, err := store.LoadRiskInputs(t.Context(), projectID)
	if err != nil {
		t.Fatalf("load risk inputs: %v", err)
	}
	plan := remediation.Build(subjects, projectCtx)

	if len(plan.Actions) != 2 {
		t.Fatalf("actions = %d, want 2 (express consolidated, lodash separate)", len(plan.Actions))
	}
	top := plan.Actions[0]
	if top.Component != "pkg:npm/express@4.17.1" {
		t.Errorf("top action = %q, want the express upgrade", top.Component)
	}
	if len(top.Members) != 2 {
		t.Errorf("members = %d, want both scanners' findings consolidated", len(top.Members))
	}
	if top.Kind != remediation.KindUpgrade {
		t.Errorf("kind = %q, want upgrade", top.Kind)
	}
	if top.RiskRemoved <= 0 {
		t.Errorf("risk removed = %v, want positive", top.RiskRemoved)
	}
	// The fix version reached the plan from the database, not from memory.
	if len(top.FixedVersions) != 1 || top.FixedVersions[0] != "4.19.2" {
		t.Errorf("fixed versions = %v, want [4.19.2] loaded from storage", top.FixedVersions)
	}
}
