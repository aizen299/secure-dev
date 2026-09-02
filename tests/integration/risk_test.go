//go:build integration

package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func riskFinding(fingerprint string, sev normalization.Severity) normalization.MergedFinding {
	return normalization.MergedFinding{
		Finding: normalization.Finding{
			Fingerprint: fingerprint, Scanner: "grype",
			Title:      "Vulnerable component",
			Category:   scanners.CategoryDependency,
			Severity:   sev,
			Confidence: normalization.ConfidenceHigh,
			Status:     normalization.StatusOpen,
		},
		Sources: []string{"grype"},
	}
}

// The score and everything needed to interpret it must survive storage. A
// number without its counts and its weights digest cannot be compared with
// anything, which makes a trend line meaningless.
func TestRiskScoreSurvivesTheRoundTrip(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	assessment := risk.Assessment{Score: 62.5, Total: 195.25, Live: 7, Dismissed: 2}
	digest := risk.DefaultWeights().Digest()
	now := time.Now().UTC().Truncate(time.Millisecond)

	if err := store.SaveRiskScore(t.Context(), projectID, scanID, assessment, digest, now); err != nil {
		t.Fatalf("save risk score: %v", err)
	}

	got, err := store.LatestRiskScore(t.Context(), projectID)
	if err != nil {
		t.Fatalf("latest risk score: %v", err)
	}
	if got.Score != 62.5 || got.Total != 195.25 {
		t.Errorf("score/total = %v/%v, want 62.5/195.25", got.Score, got.Total)
	}
	if got.LiveFindings != 7 || got.DismissedFindings != 2 {
		t.Errorf("live/dismissed = %d/%d, want 7/2", got.LiveFindings, got.DismissedFindings)
	}
	if got.WeightsDigest != digest {
		t.Errorf("digest = %q, want %q: without it the score is incomparable", got.WeightsDigest, digest)
	}
	if got.ScanID != scanID {
		t.Errorf("scan id = %q, want %q: a score is a statement about a moment", got.ScanID, scanID)
	}
	// The coverage the score rests on, joined rather than copied so it cannot
	// go stale. §12 forbids treating a partial scan as a complete one, and a
	// gate cannot honour that from a number that does not carry it.
	if got.ScanStatus != "queued" {
		t.Errorf("scan status = %q, want the scan's real status", got.ScanStatus)
	}

	// Move the scan on and the score must report the new coverage, not a
	// snapshot taken when it was written.
	if _, err := pool.Exec(t.Context(),
		`UPDATE scans SET status = 'partial', completed_at = now() WHERE id = $1`, scanID); err != nil {
		t.Fatalf("degrade scan: %v", err)
	}
	again, err := store.LatestRiskScore(t.Context(), projectID)
	if err != nil {
		t.Fatalf("latest risk score: %v", err)
	}
	if again.ScanStatus != "partial" {
		t.Errorf("scan status = %q, want partial: coverage must not be a stale copy", again.ScanStatus)
	}
}

// An unscored project must be distinguishable from a clean one. A zero here
// would be the most dangerous wrong answer the platform could give.
func TestAnUnscoredProjectReportsNoScoreRatherThanZero(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)

	_, err := store.LatestRiskScore(t.Context(), projectID)
	if !errors.Is(err, findings.ErrNoRiskScore) {
		t.Fatalf("error = %v, want ErrNoRiskScore", err)
	}
}

// One score per scan. A re-run replaces its score rather than appending, so
// the trend stays one point per scan instead of one per attempt.
func TestRescoringAScanReplacesItsScore(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	digest := risk.DefaultWeights().Digest()
	now := time.Now().UTC()

	for _, score := range []float64{40, 55} {
		if err := store.SaveRiskScore(t.Context(), projectID, scanID,
			risk.Assessment{Score: score, Total: score, Live: 1}, digest, now); err != nil {
			t.Fatalf("save %v: %v", score, err)
		}
	}

	history, err := store.RiskHistory(t.Context(), projectID, 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history = %d points, want 1: a rescan must not append", len(history))
	}
	if history[0].Score != 55 {
		t.Errorf("score = %v, want the replacement 55", history[0].Score)
	}
}

// The engine's inputs have to be assembled from three places -- the finding,
// the scanners that reported it, and the issue correlation put it in. If any
// of them is lost in the query, the score is computed on a different picture
// than the one the platform is showing.
func TestRiskInputsCarryScannersThreatIntelligenceAndIssueSeverity(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("f")
	now := time.Now().UTC()

	merged := riskFinding(fp, normalization.SeverityHigh)
	merged.Sources = []string{"grype", "trivy"}
	merged.CVE = "CVE-2026-9999"
	merged.Threat = normalization.ThreatIntel{EPSS: &normalization.EPSS{
		Probability: 0.5, Percentile: 0.97,
		Source: normalization.SourceGrype, ObservedAt: now.Truncate(24 * time.Hour),
	}}

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings: []normalization.MergedFinding{merged},
		Occurrences: []normalization.Occurrence{
			occurrenceIn(fp, scanID, "grype", "go.mod"),
			occurrenceIn(fp, scanID, "trivy", "go.mod"),
		},
	}, []string{"grype", "trivy"}, now); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	subjects, projectCtx, err := store.LoadRiskInputs(t.Context(), projectID)
	if err != nil {
		t.Fatalf("load risk inputs: %v", err)
	}
	if len(subjects) != 1 {
		t.Fatalf("subjects = %d, want 1", len(subjects))
	}
	s := subjects[0]

	if len(s.Sources) != 2 {
		t.Errorf("sources = %v, want both reporters: corroboration is computed from this", s.Sources)
	}
	if s.Threat.EPSS == nil || s.Threat.EPSS.Percentile != 0.97 {
		t.Errorf("threat = %+v, want the stored EPSS percentile", s.Threat.EPSS)
	}
	if s.Severity != normalization.SeverityHigh || s.Status != normalization.StatusOpen {
		t.Errorf("severity/status = %q/%q, want high/open", s.Severity, s.Status)
	}

	// The project's declared context comes back with it, so the engine scores
	// against the same picture the dashboard shows.
	if projectCtx.Environment != projects.EnvDevelopment {
		t.Errorf("environment = %q, want the project default", projectCtx.Environment)
	}

	// And the whole thing scores without error, end to end.
	assessment := risk.Assess(subjects, projectCtx)
	if assessment.Score <= 0 {
		t.Errorf("score = %v, want positive for an open high finding", assessment.Score)
	}
	if assessment.Live != 1 {
		t.Errorf("live = %d, want 1", assessment.Live)
	}
}

// Dismissed findings are loaded but contribute nothing, so a low score with
// many dismissals stays distinguishable from a genuinely clean project.
func TestDismissedFindingsAreLoadedButScoreZero(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("0")
	now := time.Now().UTC()

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{riskFinding(fp, normalization.SeverityCritical)},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanID, "grype", "go.mod")},
	}, []string{"grype"}, now); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	// The dismissal is applied here rather than on the recorded finding,
	// because the lifecycle belongs to the store: a scanner cannot declare its
	// own finding a false positive, and RecordScan is right to ignore it if it
	// tries. This stands in for the human action a future transition endpoint
	// will perform.
	if _, err := pool.Exec(t.Context(),
		`UPDATE findings SET status = 'false_positive' WHERE project_id = $1 AND fingerprint = $2`,
		projectID, fp); err != nil {
		t.Fatalf("dismiss finding: %v", err)
	}

	subjects, projectCtx, err := store.LoadRiskInputs(t.Context(), projectID)
	if err != nil {
		t.Fatalf("load risk inputs: %v", err)
	}
	if len(subjects) != 1 {
		t.Fatalf("subjects = %d, want the dismissed finding to still be loaded", len(subjects))
	}

	assessment := risk.Assess(subjects, projectCtx)
	if assessment.Score != 0 {
		t.Errorf("score = %v, want 0: a dismissed finding must not move the number", assessment.Score)
	}
	if assessment.Dismissed != 1 || assessment.Live != 0 {
		t.Errorf("live/dismissed = %d/%d, want 0/1", assessment.Live, assessment.Dismissed)
	}
}

// The schema's own statement of the range, independent of the Go model.
func TestTheDatabaseRejectsAnImpossibleScore(t *testing.T) {
	pool := testPool(t)
	scanID, projectID := seedScan(t, pool)

	_, err := pool.Exec(t.Context(), `
		INSERT INTO scan_risk_scores
		    (scan_id, project_id, score, total, live_findings, dismissed_findings, weights_digest)
		VALUES ($1, $2, 140, 10, 1, 0, 'x')`, scanID, projectID)
	if err == nil {
		t.Fatal("a score of 140 was accepted")
	}
	if !containsText(err.Error(), "scan_risk_scores_score_range") {
		t.Errorf("rejected by the wrong constraint: %v", err)
	}
}

func containsText(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
