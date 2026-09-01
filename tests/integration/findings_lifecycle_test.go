//go:build integration

package integration

import (
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func fingerprintOf(seed string) string {
	return strings.Repeat(seed, 64)[:64]
}

func secretFinding(fingerprint, scanner string) normalization.MergedFinding {
	return normalization.MergedFinding{
		Finding: normalization.Finding{
			Fingerprint: fingerprint,
			Scanner:     scanner,
			Title:       "Exposed credential",
			Category:    scanners.CategorySecrets,
			Severity:    normalization.SeverityCritical,
			Confidence:  normalization.ConfidenceHigh,
			Status:      normalization.StatusOpen,
		},
		Sources: []string{scanner},
	}
}

func occurrenceOf(fingerprint, scanID, scanner string, line int) normalization.Occurrence {
	return normalization.Occurrence{
		Fingerprint: fingerprint, ScanID: scanID,
		File: "config/settings.py", StartLine: line, EndLine: line, Scanner: scanner,
	}
}

// The lifecycle the fingerprint design exists to make possible: a finding
// survives re-scanning, is resolved when it stops being reported, and is
// distinguishable as reopened when it comes back.
func TestFindingLifecycleAcrossScans(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("a")
	now := time.Now().UTC()

	// --- first scan: discovered -----------------------------------------
	err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanA, "gitleaks", 12)},
	}, []string{"gitleaks"}, now)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}

	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open", got)
	}
	if got := historyReasons(t, pool, projectID, fp); len(got) != 1 || got[0] != "first_seen" {
		t.Errorf("history = %v, want [first_seen]", got)
	}

	// --- second scan: still there, and it has MOVED ----------------------
	// The line changed, which is exactly what the fingerprint excludes. If
	// identity depended on position this would be a new finding and the old
	// one would look resolved.
	scanB := seedScanFor(t, pool, projectID)
	err = store.RecordScan(t.Context(), projectID, scanB, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanB, "gitleaks", 40)},
	}, []string{"gitleaks"}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if got := countFindings(t, pool, projectID); got != 1 {
		t.Errorf("findings = %d, want 1: the finding moved, it did not multiply", got)
	}
	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open", got)
	}
	// Still one transition: being seen again is not a state change.
	if got := historyReasons(t, pool, projectID, fp); len(got) != 1 {
		t.Errorf("history = %v, want no new transition for an unchanged finding", got)
	}
	if got := countOccurrences(t, pool, projectID, fp); got != 2 {
		t.Errorf("occurrences = %d, want 2: both sightings are kept", got)
	}

	// --- third scan: gone ------------------------------------------------
	scanC := seedScanFor(t, pool, projectID)
	err = store.RecordScan(t.Context(), projectID, scanC,
		normalization.DedupResult{}, []string{"gitleaks"}, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("third scan: %v", err)
	}
	if got := findingStatus(t, pool, projectID, fp); got != "resolved" {
		t.Errorf("status = %q, want resolved", got)
	}
	if got := historyReasons(t, pool, projectID, fp); len(got) != 2 || got[1] != "not_reported" {
		t.Errorf("history = %v, want [first_seen not_reported]", got)
	}

	// --- fourth scan: back again -----------------------------------------
	// Reopened rather than open: a fix that did not hold is a different
	// situation from one that was never made.
	scanD := seedScanFor(t, pool, projectID)
	err = store.RecordScan(t.Context(), projectID, scanD, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanD, "gitleaks", 12)},
	}, []string{"gitleaks"}, now.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("fourth scan: %v", err)
	}
	if got := findingStatus(t, pool, projectID, fp); got != "reopened" {
		t.Errorf("status = %q, want reopened", got)
	}
	if got := historyReasons(t, pool, projectID, fp); len(got) != 3 || got[2] != "reopened" {
		t.Errorf("history = %v, want a reopened transition", got)
	}
}

// The correctness property that matters most. A scan whose scanner failed says
// nothing about that scanner's findings, and resolving them would be a false
// "fixed" -- the same error as reporting a PARTIAL scan as clean (§13, ADR 010).
func TestAFailedScannerResolvesNothing(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("b")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanA, "gitleaks", 12)},
	}, []string{"gitleaks"}, now); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// A later scan where gitleaks did NOT complete: it reports nothing, and
	// the completed set does not include it.
	scanB := seedScanFor(t, pool, projectID)
	if err := store.RecordScan(t.Context(), projectID, scanB,
		normalization.DedupResult{}, []string{"semgrep"}, now.Add(time.Hour)); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open: a scanner that did not run cannot resolve its findings", got)
	}
}

// The same property, one level harder: it must hold for EVERY scanner that
// reports a finding, not just the one that reported it first.
//
// findings.scanner records the first reporter only, so a check written against
// it resolves a grype+trivy finding as soon as grype comes back clean -- even
// when trivy failed and was never asked. That is a false "fixed" reached by a
// different route than the test above.
func TestOneFailedReporterBlocksASharedFinding(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("e")
	now := time.Now().UTC()

	// grype saw it first, so findings.scanner is 'grype'. trivy reports the
	// same finding in the same scan.
	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings: []normalization.MergedFinding{{
			Finding: secretFinding(fp, "grype").Finding,
			Sources: []string{"grype", "trivy"},
		}},
		Occurrences: []normalization.Occurrence{
			occurrenceOf(fp, scanA, "grype", 1),
			occurrenceOf(fp, scanA, "trivy", 1),
		},
	}, []string{"grype", "trivy"}, now); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// Next scan: grype completes and no longer reports it. trivy FAILS, so it
	// is absent from the completed set and reported nothing.
	scanB := seedScanFor(t, pool, projectID)
	if err := store.RecordScan(t.Context(), projectID, scanB,
		normalization.DedupResult{}, []string{"grype"}, now.Add(time.Hour)); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open: trivy also reports this finding and did not run", got)
	}
	if got := historyReasons(t, pool, projectID, fp); len(got) != 1 {
		t.Errorf("history = %v, want no transition: nothing was decided", got)
	}

	// And once trivy does complete without reporting it, both reporters have
	// had their say and the finding resolves.
	scanC := seedScanFor(t, pool, projectID)
	if err := store.RecordScan(t.Context(), projectID, scanC,
		normalization.DedupResult{}, []string{"grype", "trivy"}, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("third scan: %v", err)
	}
	if got := findingStatus(t, pool, projectID, fp); got != "resolved" {
		t.Errorf("status = %q, want resolved: every reporter completed and none saw it", got)
	}
}

// A human decision must not be overruled by a scan. Acknowledged, ignored, and
// false_positive survive being reported again.
func TestScansDoNotOverruleHumanJudgement(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("c")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanA, "gitleaks", 1)},
	}, []string{"gitleaks"}, now); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	if _, err := pool.Exec(t.Context(),
		`UPDATE findings SET status = 'false_positive' WHERE project_id = $1 AND fingerprint = $2`,
		projectID, fp); err != nil {
		t.Fatalf("mark false positive: %v", err)
	}

	scanB := seedScanFor(t, pool, projectID)
	if err := store.RecordScan(t.Context(), projectID, scanB, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanB, "gitleaks", 1)},
	}, []string{"gitleaks"}, now.Add(time.Hour)); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if got := findingStatus(t, pool, projectID, fp); got != "false_positive" {
		t.Errorf("status = %q: a scan overruled a human decision", got)
	}
}

// Two scanners reporting one finding is one row with two occurrence sources,
// which is what the fingerprint excluding the scanner name buys.
func TestTwoScannersProduceOneFinding(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fp := fingerprintOf("d")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings: []normalization.MergedFinding{{
			Finding: secretFinding(fp, "grype").Finding,
			Sources: []string{"grype", "trivy"},
		}},
		Occurrences: []normalization.Occurrence{
			occurrenceOf(fp, scanA, "grype", 1),
			occurrenceOf(fp, scanA, "trivy", 1),
		},
	}, []string{"grype", "trivy"}, now); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if got := countFindings(t, pool, projectID); got != 1 {
		t.Errorf("findings = %d, want 1", got)
	}
	var sources int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(DISTINCT o.scanner) FROM finding_occurrences o
		  JOIN findings f ON f.id = o.finding_id
		 WHERE f.project_id = $1 AND f.fingerprint = $2`, projectID, fp).Scan(&sources); err != nil {
		t.Fatalf("count sources: %v", err)
	}
	if sources != 2 {
		t.Errorf("distinct reporting scanners = %d, want 2", sources)
	}
}

// --- helpers ---------------------------------------------------------------

func seedScanFor(t *testing.T, pool *pgxpool.Pool, projectID string) string {
	t.Helper()
	var scanID string
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO scans (project_id, status) VALUES ($1, 'queued') RETURNING id`,
		projectID).Scan(&scanID); err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	return scanID
}

func findingStatus(t *testing.T, pool *pgxpool.Pool, projectID, fingerprint string) string {
	t.Helper()
	var status string
	if err := pool.QueryRow(t.Context(),
		`SELECT status::text FROM findings WHERE project_id = $1 AND fingerprint = $2`,
		projectID, fingerprint).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return status
}

func historyReasons(t *testing.T, pool *pgxpool.Pool, projectID, fingerprint string) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT h.reason FROM finding_status_history h
		  JOIN findings f ON f.id = h.finding_id
		 WHERE f.project_id = $1 AND f.fingerprint = $2
		 ORDER BY h.changed_at, h.id`, projectID, fingerprint)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("scan history: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func countFindings(t *testing.T, pool *pgxpool.Pool, projectID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM findings WHERE project_id = $1`, projectID).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

func countOccurrences(t *testing.T, pool *pgxpool.Pool, projectID, fingerprint string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM finding_occurrences o
		  JOIN findings f ON f.id = o.finding_id
		 WHERE f.project_id = $1 AND f.fingerprint = $2`, projectID, fingerprint).Scan(&n); err != nil {
		t.Fatalf("count occurrences: %v", err)
	}
	return n
}
