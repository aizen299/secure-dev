package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/findings"
)

// issueResponse is the wire model for a correlated issue.
//
// The contextual answer §2 promises: not "here are 40 findings" but "here are
// the 9 problems, and this one is worse than its parts because three domains
// agree". Every claim it makes carries the evidence for it, because a
// relationship SecureOps cannot explain is one it should not assert (§9).
type issueResponse struct {
	ID string `json:"id"`

	// Key is what the members share, split into kind and value so a client can
	// filter or link on it without parsing a string.
	KeyKind  string `json:"key_kind"`
	KeyValue string `json:"key_value"`

	// Severity is derived from the members. It is a severity, not a risk
	// score -- the 0-100 project score is a separate, deterministic engine
	// and is not exposed here.
	Severity string `json:"severity"`
	// Escalated says whether correlation raised the severity above its worst
	// member. Exposed rather than inferred so a client never has to guess
	// whether a critical issue is critical on its own merits.
	Escalated bool `json:"escalated"`

	Categories  []string `json:"categories"`
	Explanation string   `json:"explanation"`

	Members []issueMemberResponse `json:"members"`
}

// issueMemberResponse is one finding's participation in an issue.
//
// Includes the finding's own id and severity: an issue links its members, it
// does not replace them, so a client can always navigate from the issue back
// to the individual finding and see what its scanner actually said.
type issueMemberResponse struct {
	FindingID   string `json:"finding_id"`
	Fingerprint string `json:"fingerprint"`
	Scanner     string `json:"scanner"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Evidence    string `json:"evidence"`
}

type issueListResponse struct {
	Issues  []issueResponse `json:"issues"`
	HasMore bool            `json:"has_more"`
}

func toIssueResponse(r findings.IssueRecord) issueResponse {
	categories := r.Categories
	if categories == nil {
		categories = []string{}
	}
	out := issueResponse{
		ID:          r.ID,
		KeyKind:     string(r.Key.Kind),
		KeyValue:    r.Key.Value,
		Severity:    string(r.Severity),
		Escalated:   r.Escalated,
		Categories:  categories,
		Explanation: r.Explanation,
		Members:     make([]issueMemberResponse, 0, len(r.Members)),
	}
	for _, m := range r.Members {
		out.Members = append(out.Members, issueMemberResponse{
			FindingID:   m.FindingID,
			Fingerprint: m.Fingerprint,
			Scanner:     m.Scanner,
			Severity:    string(m.Severity),
			Title:       m.Title,
			Evidence:    m.Evidence,
		})
	}
	return out
}

// handleListProjectIssues serves a project's correlated issues, worst first.
func (s *Server) handleListProjectIssues() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.findings == nil {
			// An empty list would say "this project has no correlated issues",
			// which is a different claim from "correlation is not available
			// here".
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"issues are not available on this server")
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

		limit, offset, err := pageFrom(r)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		}

		records, hasMore, err := s.findings.ListIssues(
			r.Context(), projectID, findings.Page{Limit: limit, Offset: offset})
		if err != nil {
			s.internalError(w, r, "list issues", err)
			return
		}

		out := issueListResponse{
			Issues:  make([]issueResponse, 0, len(records)),
			HasMore: hasMore,
		}
		for _, rec := range records {
			out.Issues = append(out.Issues, toIssueResponse(rec))
		}
		writeJSON(w, r, http.StatusOK, out)
	}
}
