package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/findings"
)

// riskResponse is a project's current risk, with the trend behind it.
//
// The single contextual number §2 promises, and the two things that stop it
// being an oracle: what it was computed over, and under which configuration.
type riskResponse struct {
	// Score is 0 (secure) to 100 (critical).
	Score float64 `json:"score"`
	// Total is the aggregate before saturation. Exposed because Score stops
	// separating projects near 100 while Total keeps rising -- without it,
	// "are we getting worse?" is unanswerable at the top of the scale.
	Total float64 `json:"total"`

	LiveFindings      int `json:"live_findings"`
	DismissedFindings int `json:"dismissed_findings"`

	// ScanID is the scan this score was computed for. A score is a statement
	// about a moment, not a standing property of the project.
	ScanID     string    `json:"scan_id"`
	ComputedAt time.Time `json:"computed_at"`

	// ScanStatus is that scan's status. Exposed because a score computed from
	// a `partial` scan rests on incomplete coverage: a scanner that failed
	// reported nothing, and fewer findings look exactly like an improvement.
	// §12 forbids evaluating a partial scan as a complete one, and a gate
	// cannot honour that rule from a number that does not carry it.
	ScanStatus string `json:"scan_status"`
	// Complete is that rule pre-applied, so a client cannot forget it.
	Complete bool `json:"complete"`

	// WeightsDigest identifies the weight configuration in force. Two scores
	// with different digests are not comparable, and a client drawing a trend
	// line across a change here would be drawing fiction.
	WeightsDigest string `json:"weights_digest"`

	// History is previous scores, newest first, for the trend §18 asks for.
	History []riskPointResponse `json:"history"`
}

// riskPointResponse is one point on the trend.
type riskPointResponse struct {
	ScanID        string    `json:"scan_id"`
	Score         float64   `json:"score"`
	Total         float64   `json:"total"`
	LiveFindings  int       `json:"live_findings"`
	ScanStatus    string    `json:"scan_status"`
	Complete      bool      `json:"complete"`
	WeightsDigest string    `json:"weights_digest"`
	ComputedAt    time.Time `json:"computed_at"`
}

// scanWasComplete reports whether a score rests on full scanner coverage.
//
// Only `completed` qualifies. `partial` explicitly does not, and neither does
// anything else -- §13 makes partial a distinct state precisely so it can never
// be read as a synonym for a clean, whole scan.
func scanWasComplete(status string) bool {
	return status == "completed"
}

// defaultRiskHistory is how many points a trend returns without asking.
const defaultRiskHistory = 30

// maxRiskHistory bounds the trend. An unbounded history query is a cheap
// denial-of-service against a project that has been scanned for years.
const maxRiskHistory = 200

func toRiskPoint(r findings.RiskRecord) riskPointResponse {
	return riskPointResponse{
		ScanID:        r.ScanID,
		Score:         r.Score,
		Total:         r.Total,
		LiveFindings:  r.LiveFindings,
		ScanStatus:    r.ScanStatus,
		Complete:      scanWasComplete(r.ScanStatus),
		WeightsDigest: r.WeightsDigest,
		ComputedAt:    r.ComputedAt,
	}
}

// handleGetProjectRisk serves a project's current risk score and its trend.
func (s *Server) handleGetProjectRisk() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.findings == nil {
			// A zero score would read as "this project is secure", which is
			// the most dangerous wrong answer this endpoint could give.
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"risk scoring is not available on this server")
			return
		}

		projectID := chi.URLParam(r, "projectID")
		if !isUUID(projectID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "project id must be a uuid")
			return
		}
		if _, err := s.projects.Get(r.Context(), projectID); err != nil {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "project not found")
			return
		}

		limit := defaultRiskHistory
		if raw := r.URL.Query().Get("history"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 || n > maxRiskHistory {
				writeError(w, r, http.StatusBadRequest, CodeInvalidRequest,
					"history must be an integer between 0 and "+strconv.Itoa(maxRiskHistory))
				return
			}
			limit = n
		}

		latest, err := s.findings.LatestRiskScore(r.Context(), projectID)
		if err != nil {
			if errors.Is(err, findings.ErrNoRiskScore) {
				// 404, never a zero score. "We have not assessed this project"
				// and "we assessed it and it is clean" are different claims,
				// and only one of them is safe to act on.
				writeError(w, r, http.StatusNotFound, CodeNotFound,
					"this project has not been scored yet")
				return
			}
			s.internalError(w, r, "latest risk score", err)
			return
		}

		out := riskResponse{
			Score:             latest.Score,
			Total:             latest.Total,
			LiveFindings:      latest.LiveFindings,
			DismissedFindings: latest.DismissedFindings,
			ScanID:            latest.ScanID,
			ComputedAt:        latest.ComputedAt,
			ScanStatus:        latest.ScanStatus,
			Complete:          scanWasComplete(latest.ScanStatus),
			WeightsDigest:     latest.WeightsDigest,
			History:           []riskPointResponse{},
		}

		if limit > 0 {
			history, err := s.findings.RiskHistory(r.Context(), projectID, limit)
			if err != nil {
				s.internalError(w, r, "risk history", err)
				return
			}
			for _, rec := range history {
				out.History = append(out.History, toRiskPoint(rec))
			}
		}

		writeJSON(w, r, http.StatusOK, out)
	}
}
