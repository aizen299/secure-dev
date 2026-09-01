//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/correlation"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func depFinding(fingerprint, scanner string, category scanners.Category,
	severity normalization.Severity, purl, cve string,
) normalization.MergedFinding {
	return normalization.MergedFinding{
		Finding: normalization.Finding{
			Fingerprint: fingerprint, Scanner: scanner,
			Title:    "Vulnerable component",
			Category: category, Severity: severity,
			Confidence: normalization.ConfidenceHigh,
			Status:     normalization.StatusOpen,
			PURL:       purl, CVE: cve,
		},
		Sources: []string{scanner},
	}
}

func occurrenceIn(fingerprint, scanID, scanner, file string) normalization.Occurrence {
	return normalization.Occurrence{
		Fingerprint: fingerprint, ScanID: scanID,
		File: file, StartLine: 1, EndLine: 1, Scanner: scanner,
	}
}

// The round trip: findings in, correlation computed, issues back out with
// their members and evidence intact.
func TestCorrelationRoundTrip(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fpA, fpB := fingerprintOf("1"), fingerprintOf("2")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings: []normalization.MergedFinding{
			depFinding(fpA, "grype", scanners.CategoryDependency,
				normalization.SeverityMedium, "pkg:npm/express@4.17.1", "CVE-2026-1234"),
			depFinding(fpB, "semgrep", scanners.CategorySAST,
				normalization.SeverityMedium, "pkg:npm/express@4.17.1", "CVE-2026-1234"),
		},
		Occurrences: []normalization.Occurrence{
			occurrenceIn(fpA, scanA, "grype", "package-lock.json"),
			occurrenceIn(fpB, scanA, "semgrep", "server.ts"),
		},
	}, []string{"grype", "semgrep"}, now); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	subjects, err := store.ListLiveForCorrelation(t.Context(), projectID)
	if err != nil {
		t.Fatalf("list for correlation: %v", err)
	}
	if len(subjects) != 2 {
		t.Fatalf("subjects = %d, want 2", len(subjects))
	}
	// The file has to survive the round trip, or the file key never fires.
	var sawFile bool
	for _, s := range subjects {
		if len(s.Files) > 0 {
			sawFile = true
		}
	}
	if !sawFile {
		t.Error("no subject carried a file: occurrences did not reach correlation")
	}

	result := correlation.Correlate(subjects)
	if err := store.ReplaceCorrelation(t.Context(), projectID, result); err != nil {
		t.Fatalf("replace correlation: %v", err)
	}

	issues, _, err := store.ListIssues(t.Context(), projectID, findings.Page{})
	if err != nil {
		t.Fatalf("list issues: %v", err)
	}

	var cve *findings.IssueRecord
	for i := range issues {
		if issues[i].Key.Kind == correlation.KindCVE {
			cve = &issues[i]
		}
	}
	if cve == nil {
		t.Fatalf("no CVE issue; issues = %+v", issues)
	}
	if cve.Key.Value != "CVE-2026-1234" {
		t.Errorf("key = %q, want CVE-2026-1234", cve.Key.Value)
	}
	if len(cve.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(cve.Members))
	}
	for _, m := range cve.Members {
		if m.FindingID == "" || m.Evidence == "" || m.Title == "" {
			t.Errorf("member %+v is missing its finding id, evidence, or title", m)
		}
	}
	// Dependency and SAST corroborate, so medium becomes high -- and the
	// members keep the severity their scanners assigned.
	if cve.Severity != normalization.SeverityHigh || !cve.Escalated {
		t.Errorf("severity = %q escalated = %v, want high and escalated",
			cve.Severity, cve.Escalated)
	}
	for _, m := range cve.Members {
		if m.Severity != normalization.SeverityMedium {
			t.Errorf("member %s severity = %q, want medium: correlation must not rewrite its evidence",
				m.Fingerprint, m.Severity)
		}
	}

	if got := countLinks(t, pool, projectID); got == 0 {
		t.Error("no links were written")
	}
}

// Correlation is derived, so it must be replaced rather than accumulated. An
// issue whose members are gone would otherwise linger as a problem that no
// longer exists.
func TestCorrelationIsReplacedNotAccumulated(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fpA, fpB := fingerprintOf("3"), fingerprintOf("4")
	now := time.Now().UTC()

	record := func(scanID string, members []normalization.MergedFinding,
		occ []normalization.Occurrence, at time.Time,
	) {
		t.Helper()
		if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
			Findings: members, Occurrences: occ,
		}, []string{"grype", "semgrep"}, at); err != nil {
			t.Fatalf("record scan: %v", err)
		}
		subjects, err := store.ListLiveForCorrelation(t.Context(), projectID)
		if err != nil {
			t.Fatalf("list for correlation: %v", err)
		}
		if err := store.ReplaceCorrelation(
			t.Context(), projectID, correlation.Correlate(subjects)); err != nil {
			t.Fatalf("replace correlation: %v", err)
		}
	}

	record(scanA, []normalization.MergedFinding{
		depFinding(fpA, "grype", scanners.CategoryDependency, normalization.SeverityHigh, "", "CVE-9"),
		depFinding(fpB, "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "CVE-9"),
	}, []normalization.Occurrence{
		occurrenceIn(fpA, scanA, "grype", "a.json"),
		occurrenceIn(fpB, scanA, "semgrep", "b.ts"),
	}, now)

	if got := countIssues(t, pool, projectID); got != 1 {
		t.Fatalf("issues = %d, want 1 after the first scan", got)
	}

	// Second scan: both are fixed. Every reporter completed, so both resolve,
	// and an issue over resolved findings must not survive.
	scanB := seedScanFor(t, pool, projectID)
	record(scanB, nil, nil, now.Add(time.Hour))

	if got := countIssues(t, pool, projectID); got != 0 {
		t.Errorf("issues = %d, want 0: the findings were resolved, so the issue is gone", got)
	}
	if got := countLinks(t, pool, projectID); got != 0 {
		t.Errorf("links = %d, want 0: stale links outlived their findings", got)
	}
}

// Correlating a dismissed finding would resurrect a decision somebody already
// made, and put it back in front of them under a new name.
func TestDismissedFindingsAreNotCorrelated(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanA, projectID := seedScan(t, pool)
	fpA, fpB := fingerprintOf("5"), fingerprintOf("6")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanA, normalization.DedupResult{
		Findings: []normalization.MergedFinding{
			depFinding(fpA, "grype", scanners.CategoryDependency, normalization.SeverityHigh, "", "CVE-7"),
			depFinding(fpB, "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "CVE-7"),
		},
		Occurrences: []normalization.Occurrence{
			occurrenceIn(fpA, scanA, "grype", "a.json"),
			occurrenceIn(fpB, scanA, "semgrep", "b.ts"),
		},
	}, []string{"grype", "semgrep"}, now); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	if _, err := pool.Exec(t.Context(),
		`UPDATE findings SET status = 'false_positive' WHERE project_id = $1 AND fingerprint = $2`,
		projectID, fpB); err != nil {
		t.Fatalf("mark false positive: %v", err)
	}

	subjects, err := store.ListLiveForCorrelation(t.Context(), projectID)
	if err != nil {
		t.Fatalf("list for correlation: %v", err)
	}
	if len(subjects) != 1 {
		t.Fatalf("subjects = %d, want 1: a false positive is not a live finding", len(subjects))
	}

	if err := store.ReplaceCorrelation(
		t.Context(), projectID, correlation.Correlate(subjects)); err != nil {
		t.Fatalf("replace correlation: %v", err)
	}
	if got := countIssues(t, pool, projectID); got != 0 {
		t.Errorf("issues = %d, want 0: one live finding cannot form an issue", got)
	}
}

// --- helpers ---------------------------------------------------------------

func countIssues(t *testing.T, pool *pgxpool.Pool, projectID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM correlated_issues WHERE project_id = $1`,
		projectID).Scan(&n); err != nil {
		t.Fatalf("count issues: %v", err)
	}
	return n
}

func countLinks(t *testing.T, pool *pgxpool.Pool, projectID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM finding_links l
		 WHERE l.from_finding_id IN (SELECT id FROM findings WHERE project_id = $1)`,
		projectID).Scan(&n); err != nil {
		t.Fatalf("count links: %v", err)
	}
	return n
}
