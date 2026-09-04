package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/policies"
)

// policyResponse is a project's gate configuration.
type policyResponse struct {
	Rules []policyRuleResponse `json:"rules"`
	// IncompleteScan is how a scan that did not complete is treated. Never
	// "pass": a scanner that crashed reports nothing, and fewer findings look
	// exactly like an improvement (§12, §13).
	IncompleteScan string `json:"incomplete_scan"`
}

type policyRuleResponse struct {
	Kind     string  `json:"kind"`
	Selector string  `json:"selector,omitempty"`
	Max      float64 `json:"max"`
	Level    string  `json:"level"`
}

func toPolicyResponse(p policies.Policy) policyResponse {
	out := policyResponse{
		Rules:          make([]policyRuleResponse, 0, len(p.Rules)),
		IncompleteScan: string(p.IncompleteScan),
	}
	for _, r := range p.Rules {
		out.Rules = append(out.Rules, policyRuleResponse{
			Kind: string(r.Kind), Selector: r.Selector, Max: r.Max, Level: string(r.Level),
		})
	}
	return out
}

func fromPolicyRequest(in policyResponse) policies.Policy {
	p := policies.Policy{
		Rules:          make([]policies.Rule, 0, len(in.Rules)),
		IncompleteScan: policies.Level(in.IncompleteScan),
	}
	for _, r := range in.Rules {
		p.Rules = append(p.Rules, policies.Rule{
			Kind: policies.Kind(r.Kind), Selector: r.Selector, Max: r.Max, Level: policies.Level(r.Level),
		})
	}
	return p
}

// gateResponse is a scan's gate decision, in both the forms §12 requires.
type gateResponse struct {
	Verdict string `json:"verdict"`
	// Conditions covers every rule evaluated, breached or not. §12 forbids a
	// bare verdict, and a result listing only breaches makes a pass
	// unfalsifiable -- "clean project" and "policy that checks nothing" would
	// look identical.
	Conditions []gateConditionResponse `json:"conditions"`
	Coverage   gateCoverageResponse    `json:"coverage"`
	// Summary is the human-readable rendering, derived from the same
	// conditions, so the two forms cannot disagree.
	Summary     string `json:"summary"`
	ScanID      string `json:"scan_id"`
	EvaluatedAt string `json:"evaluated_at"`
}

type gateConditionResponse struct {
	Kind        string  `json:"kind"`
	Selector    string  `json:"selector,omitempty"`
	Max         float64 `json:"max"`
	Level       string  `json:"level"`
	Observed    float64 `json:"observed"`
	Breached    bool    `json:"breached"`
	Explanation string  `json:"explanation"`
}

type gateCoverageResponse struct {
	Complete   bool   `json:"complete"`
	ScanStatus string `json:"scan_status"`
	// Downgraded says the verdict was made worse because the scan was
	// incomplete, so a WARN caused by a crashed scanner is distinguishable
	// from one caused by a breached rule.
	Downgraded bool `json:"downgraded"`
}

func toGateResponse(rec policies.ResultRecord) gateResponse {
	out := gateResponse{
		Verdict:     string(rec.Result.Verdict),
		Conditions:  make([]gateConditionResponse, 0, len(rec.Result.Conditions)),
		Summary:     rec.Result.Summary,
		ScanID:      rec.ScanID,
		EvaluatedAt: rec.EvaluatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Coverage: gateCoverageResponse{
			Complete:   rec.Result.Coverage.Complete,
			ScanStatus: rec.Result.Coverage.ScanStatus,
			Downgraded: rec.Result.Coverage.Downgraded,
		},
	}
	for _, c := range rec.Result.Conditions {
		out.Conditions = append(out.Conditions, gateConditionResponse{
			Kind: string(c.Rule.Kind), Selector: c.Rule.Selector,
			Max: c.Rule.Max, Level: string(c.Rule.Level),
			Observed: c.Observed, Breached: c.Breached, Explanation: c.Explanation,
		})
	}
	return out
}

// handleGetProjectPolicy serves a project's gate configuration.
func (s *Server) handleGetProjectPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.policies == nil {
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"security policies are not available on this server")
			return
		}
		projectID, ok := s.requireProject(w, r)
		if !ok {
			return
		}

		p, err := s.policies.Get(r.Context(), projectID)
		if err != nil {
			s.internalError(w, r, "get policy", err)
			return
		}
		writeJSON(w, r, http.StatusOK, toPolicyResponse(p))
	}
}

// handleSetProjectPolicy replaces a project's gate configuration.
//
// This is the most security-sensitive write in the API: raising max_critical
// from 0 to 50 turns the gate off. The change and its audit record are written
// in one transaction (ADR 022).
//
// It is authenticated and **not authorized** — every valid token may edit every
// project's policy (T-23, Phase 11). The audit log records who made a change,
// not whether they were entitled to.
func (s *Server) handleSetProjectPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.policies == nil {
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"security policies are not available on this server")
			return
		}
		projectID, ok := s.requireProject(w, r)
		if !ok {
			return
		}

		var body policyResponse
		if err := decodeJSON(w, r, &body, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		policy := fromPolicyRequest(body)
		// Validated before anything is written, so a policy that cannot be
		// evaluated is a 400 rather than a gate that fails every scan later.
		if err := policy.Validate(); err != nil {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		}

		actor := audit.TokenActor("")
		if principal, ok := PrincipalFrom(r.Context()); ok {
			actor = audit.TokenActor(principal.Label)
		}

		if err := s.policies.Set(r.Context(), projectID, policy, actor); err != nil {
			if errors.Is(err, policies.ErrInvalidPolicy) {
				writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
				return
			}
			s.internalError(w, r, "set policy", err)
			return
		}
		writeJSON(w, r, http.StatusOK, toPolicyResponse(policy))
	}
}

// handleGetScanGate serves a scan's gate decision.
func (s *Server) handleGetScanGate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.policies == nil {
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"security policies are not available on this server")
			return
		}

		scanID := chi.URLParam(r, "scanID")
		if !isUUID(scanID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "scan id must be a uuid")
			return
		}

		// Scoped before the verdict is read, not after. A gate result names a
		// project's severity counts and its risk score -- a compact summary of
		// how bad things are somewhere the caller cannot otherwise look
		// (ADR 033, T-36). The answer matches the "not evaluated" one so an id
		// cannot be probed.
		scan, err := s.scans.Get(r.Context(), scanID)
		if err != nil || !s.inScope(r, scan.ProjectID) {
			writeError(w, r, http.StatusNotFound, CodeNotFound,
				"this scan has not been evaluated against a policy")
			return
		}

		rec, err := s.policies.GetResult(r.Context(), scanID)
		if err != nil {
			if errors.Is(err, policies.ErrNoResult) {
				// 404, never a pass. "No gate ran" and "the gate passed" are
				// different claims, and only one of them clears a change to
				// ship.
				writeError(w, r, http.StatusNotFound, CodeNotFound,
					"this scan has not been evaluated against a policy")
				return
			}
			s.internalError(w, r, "get gate result", err)
			return
		}
		writeJSON(w, r, http.StatusOK, toGateResponse(rec))
	}
}

// requireProject validates the project id and confirms the project exists.
// requireProject returns the project id the scopedProject middleware resolved.
//
// It used to validate the id and look the project up itself. Both now happen in
// the middleware, which also checks the caller's scope (ADR 033) -- so doing
// them again here would be a second database round trip per request for an
// answer already in hand, and a second place for the two checks to disagree.
func (s *Server) requireProject(_ http.ResponseWriter, r *http.Request) (string, bool) {
	return projectFrom(r).ID, true
}
