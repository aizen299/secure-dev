package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/risk"
)

func riskRecord(scanID string, score float64, at time.Time) findings.RiskRecord {
	return findings.RiskRecord{
		ScanID:            scanID,
		Score:             score,
		Total:             score * 2,
		LiveFindings:      4,
		DismissedFindings: 1,
		WeightsDigest:     risk.DefaultWeights().Digest(),
		ComputedAt:        at,
	}
}

func TestGetProjectRisk(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	now := time.Now().UTC().Truncate(time.Second)
	s.findings.(*fakeFindingStore).seedRisk(project.ID,
		riskRecord(newTestUUID(80), 62.5, now),
		riskRecord(newTestUUID(81), 48.0, now.Add(-24*time.Hour)),
	)

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/risk", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	got := decodeBody[riskResponse](t, rec)
	if got.Score != 62.5 {
		t.Errorf("score = %v, want the latest 62.5", got.Score)
	}
	// Total is exposed alongside score, because score saturates and total does
	// not. Without it "are we getting worse?" is unanswerable near 100.
	if got.Total != 125 {
		t.Errorf("total = %v, want 125", got.Total)
	}
	if got.DismissedFindings != 1 {
		t.Errorf("dismissed = %d, want 1: a low score with dismissals is not the same as one without",
			got.DismissedFindings)
	}
	if got.WeightsDigest == "" {
		t.Error("no weights digest: a score with no configuration marker cannot be compared with a later one")
	}
	if len(got.History) != 2 {
		t.Errorf("history = %d points, want 2", len(got.History))
	}
}

// The most dangerous wrong answer this endpoint could give. An unscored
// project must not read as a secure one.
func TestAnUnscoredProjectIs404NotAZeroScore(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/risk", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); contains(body, `"score"`) {
		t.Errorf("an unscored project returned a score: %s", body)
	}
}

func TestRiskHistoryParameterIsBounded(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	s.findings.(*fakeFindingStore).seedRisk(project.ID, riskRecord(newTestUUID(82), 10, time.Now().UTC()))

	for _, tc := range []struct {
		query string
		want  int
	}{
		{"?history=0", http.StatusOK},
		{"?history=10", http.StatusOK},
		{"?history=201", http.StatusBadRequest},
		{"?history=-1", http.StatusBadRequest},
		{"?history=lots", http.StatusBadRequest},
	} {
		rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/risk"+tc.query, "")
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.query, rec.Code, tc.want)
		}
	}

	// history=0 means "no trend", not "no score".
	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/risk?history=0", "")
	got := decodeBody[riskResponse](t, rec)
	if got.Score != 10 || len(got.History) != 0 {
		t.Errorf("score = %v with %d history points, want the score and an empty trend",
			got.Score, len(got.History))
	}
}

func TestRiskRejectsAMalformedProjectID(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	rec := authed(t, s, http.MethodGet, "/api/v1/projects/not-a-uuid/risk", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// §12: a partial scan must never be evaluated as though it were complete. The
// score cannot carry that rule if it does not carry the coverage it rests on --
// a scanner that failed reported nothing, and fewer findings look exactly like
// an improvement.
func TestRiskReportsWhetherTheScanWasComplete(t *testing.T) {
	for status, wantComplete := range map[string]bool{
		"completed": true,
		"partial":   false,
		"failed":    false,
		"cancelled": false,
	} {
		t.Run(status, func(t *testing.T) {
			s, projectStore, _ := newWiredServer(t, func(*Options) {})
			project := seedProject(t, projectStore)

			rec := riskRecord(newTestUUID(90), 55, time.Now().UTC())
			rec.ScanStatus = status
			s.findings.(*fakeFindingStore).seedRisk(project.ID, rec)

			resp := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/risk", "")
			got := decodeBody[riskResponse](t, resp)

			if got.ScanStatus != status {
				t.Errorf("scan_status = %q, want %q", got.ScanStatus, status)
			}
			if got.Complete != wantComplete {
				t.Errorf("complete = %v for a %q scan, want %v", got.Complete, status, wantComplete)
			}
			if len(got.History) > 0 && got.History[0].Complete != wantComplete {
				t.Errorf("history point complete = %v, want %v", got.History[0].Complete, wantComplete)
			}
		})
	}
}
