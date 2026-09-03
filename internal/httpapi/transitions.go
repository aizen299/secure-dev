package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
)

// transitionRequest is a human judgement about a finding.
type transitionRequest struct {
	// Status is the state to move to. `resolved` and `reopened` are refused:
	// they mean a scanner stopped or started reporting the finding, which is
	// an observation rather than an opinion (ADR 024).
	Status string `json:"status"`
	// Reason comes from a fixed vocabulary so it stays queryable.
	Reason string `json:"reason"`
	// Note is the argument behind the judgement. Optional, and the place the
	// actual reasoning goes: "accepted_risk" alone does not tell the next
	// reader what was accepted or on whose authority.
	Note string `json:"note,omitempty"`
}

type transitionResponse struct {
	FindingID string    `json:"finding_id"`
	From      string    `json:"from_status"`
	To        string    `json:"to_status"`
	Actor     string    `json:"actor"`
	Reason    string    `json:"reason"`
	Note      string    `json:"note,omitempty"`
	ChangedAt time.Time `json:"changed_at"`
}

type historyResponse struct {
	Transitions []transitionResponse `json:"transitions"`
}

func toTransitionResponse(rec findings.TransitionRecord) transitionResponse {
	return transitionResponse{
		FindingID: rec.FindingID,
		From:      string(rec.From),
		To:        string(rec.To),
		Actor:     rec.Actor,
		Reason:    rec.Reason,
		Note:      rec.Note,
		ChangedAt: rec.ChangedAt,
	}
}

// handleTransitionFinding changes a finding's status on a person's authority.
//
// The one endpoint that lets a human lower a project's risk score, remove
// remediation work, and turn a failing gate green. It is audited atomically
// with the change for exactly that reason (ADR 024 §4).
func (s *Server) handleTransitionFinding() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.findings == nil {
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"findings are not available on this server")
			return
		}

		findingID := chi.URLParam(r, "findingID")
		if !isUUID(findingID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "finding id must be a uuid")
			return
		}

		var req transitionRequest
		if err := decodeJSON(w, r, &req, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		rec, err := s.findings.Transition(r.Context(), findingID, findings.TransitionRequest{
			To:     normalization.Status(req.Status),
			Reason: req.Reason,
			Note:   req.Note,
		}, actorFrom(r))

		switch {
		case errors.Is(err, findings.ErrTransitionNotAllowed):
			// 422 rather than 400: the request is well-formed and the state is
			// real, but the transition is one a person may not make. A 400
			// would suggest a typo, and the caller would try again.
			writeError(w, r, http.StatusUnprocessableEntity, CodeInvalidRequest, err.Error())
			return
		case errors.Is(err, findings.ErrInvalidTransition):
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		case errors.Is(err, findings.ErrNotFound):
			writeError(w, r, http.StatusNotFound, CodeNotFound, "finding not found")
			return
		case err != nil:
			s.internalError(w, r, "transition finding", err)
			return
		}

		writeJSON(w, r, http.StatusOK, toTransitionResponse(rec))
	}
}

// handleGetFindingHistory serves a finding's status changes, newest first.
//
// §17 requires every transition to record who, when, why, and both states.
// Storing that and never serving it would satisfy the letter and none of the
// point: the history exists to answer "why is this finding in this state".
func (s *Server) handleGetFindingHistory() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.findings == nil {
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"findings are not available on this server")
			return
		}

		findingID := chi.URLParam(r, "findingID")
		if !isUUID(findingID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "finding id must be a uuid")
			return
		}

		records, err := s.findings.History(r.Context(), findingID)
		if err != nil {
			s.internalError(w, r, "finding history", err)
			return
		}

		out := historyResponse{Transitions: make([]transitionResponse, 0, len(records))}
		for _, rec := range records {
			out.Transitions = append(out.Transitions, toTransitionResponse(rec))
		}
		writeJSON(w, r, http.StatusOK, out)
	}
}
