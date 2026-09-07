package httpapi

import (
	"net/http"

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

	// Deployment says whether this issue's package reached the built artifact:
	// "deployed", "not_deployed", or "unknown".
	//
	// Evidence, never a judgement. It influenced neither `severity` nor
	// `escalated` above, and no risk score (ADR 037) -- a client that treats it
	// as a reason to ignore a finding is making that call itself.
	//
	// "unknown" is the honest answer for a project with no image scan, which is
	// most of them. It is not a gap awaiting data.
	Deployment string `json:"deployment"`
	// DeploymentEvidence is that state as prose, naming the image scan's date.
	// Absent when the state is unknown: there is nothing to say.
	DeploymentEvidence string `json:"deployment_evidence,omitempty"`
	// ArtifactScanID is the image scan compared against, so the claim is about
	// a particular artifact rather than the project. Absent when none was.
	ArtifactScanID string `json:"artifact_scan_id,omitempty"`

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
		// Evidence, carried through unchanged. The API does not interpret it
		// and must not: a client deciding a not_deployed finding is safe is
		// making that judgement, and should be able to see that it did.
		Deployment:         string(r.Deployment),
		DeploymentEvidence: r.DeploymentEvidence,
		ArtifactScanID:     r.ArtifactScanID,
		Members:            make([]issueMemberResponse, 0, len(r.Members)),
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

		// The project the middleware resolved, not a second lookup of it. See
		// projectFrom on why re-reading it here was wrong.
		projectID := projectFrom(r).ID

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
