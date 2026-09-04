package httpapi

import (
	"net/http"

	"github.com/aizen299/secure-dev/internal/remediation"
)

// remediationResponse is a project's ranked work.
//
// The answer to the question a risk score raises and cannot settle: not "how
// bad is this" but "what should I do first".
type remediationResponse struct {
	// Score is the project's current risk, so a client can see what the
	// rankings are measured against.
	Score float64 `json:"score"`
	// Addressable is how many live findings the plan covers. Every live
	// finding produces work, even when that work is deciding what to do about
	// something with no fix.
	Addressable int `json:"addressable_findings"`

	Actions []actionResponse `json:"actions"`
}

type actionResponse struct {
	Kind      string `json:"kind"`
	Key       string `json:"key"`
	Component string `json:"component"`

	// FixedVersions are every version the members' vendors reported. SecureOps
	// does not choose between them, because version ordering is
	// ecosystem-specific and a confidently wrong upgrade target is worse than
	// an honest list.
	FixedVersions []string `json:"fixed_versions"`
	References    []string `json:"references"`

	// RiskRemoved is how far the project score would fall if this action were
	// taken. It is the ranking, exposed rather than implied.
	RiskRemoved float64 `json:"risk_removed"`
	ScoreAfter  float64 `json:"score_after"`

	Statements []statementResponse    `json:"statements"`
	Members    []actionMemberResponse `json:"members"`
}

// statementResponse is one claim, with where it came from.
//
// §11 requires AI-derived content to be structurally distinguishable from
// verified data in the API as well as the model. `source` is that structure.
// No statement is ever `ai_explanation`: nothing in SecureOps produces one.
type statementResponse struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

type actionMemberResponse struct {
	Fingerprint string  `json:"fingerprint"`
	Scanner     string  `json:"scanner"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Risk        float64 `json:"risk"`
}

func toActionResponse(a remediation.Action) actionResponse {
	out := actionResponse{
		Kind:          string(a.Kind),
		Key:           a.Key,
		Component:     a.Component,
		FixedVersions: emptyIfNil(a.FixedVersions),
		References:    emptyIfNil(a.References),
		RiskRemoved:   a.RiskRemoved,
		ScoreAfter:    a.ScoreAfter,
		Statements:    make([]statementResponse, 0, len(a.Statements)),
		Members:       make([]actionMemberResponse, 0, len(a.Members)),
	}
	for _, s := range a.Statements {
		out.Statements = append(out.Statements, statementResponse{
			Source: string(s.Source), Text: s.Text,
		})
	}
	for _, m := range a.Members {
		out.Members = append(out.Members, actionMemberResponse{
			Fingerprint: m.Fingerprint,
			Scanner:     m.Scanner,
			Severity:    string(m.Severity),
			Title:       m.Title,
			Risk:        m.Risk,
		})
	}
	return out
}

func emptyIfNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// handleGetProjectRemediation serves a project's ranked remediation plan.
//
// Computed on read rather than read from storage, deliberately. §11 requires
// remediation status to track the finding lifecycle, and a stored action's
// status drifts from its members' the moment somebody marks one a false
// positive. Derived, it cannot drift (ADR 020 §4).
func (s *Server) handleGetProjectRemediation() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.findings == nil {
			// An empty plan would say "there is nothing to do", which is a
			// very different claim from "remediation is unavailable here".
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"remediation is not available on this server")
			return
		}

		// The project the middleware resolved, not a second lookup of it. See
		// projectFrom on why re-reading it here was wrong.
		projectID := projectFrom(r).ID

		subjects, projectCtx, err := s.findings.LoadRiskInputs(r.Context(), projectID)
		if err != nil {
			s.internalError(w, r, "load remediation inputs", err)
			return
		}

		plan := remediation.Build(subjects, projectCtx)
		out := remediationResponse{
			Score:       plan.Score,
			Addressable: plan.Addressable,
			Actions:     make([]actionResponse, 0, len(plan.Actions)),
		}
		for _, a := range plan.Actions {
			out.Actions = append(out.Actions, toActionResponse(a))
		}
		writeJSON(w, r, http.StatusOK, out)
	}
}
