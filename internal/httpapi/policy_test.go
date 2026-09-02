package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/policies"
	"github.com/aizen299/secure-dev/internal/scans"
)

func TestGetProjectPolicyFallsBackToTheDefault(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/policy", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := decodeBody[policyResponse](t, rec)

	// A project with no configured policy is gated by the default, not by
	// nothing: an absent policy meaning "everything passes" would make
	// deleting a row a way to silently disable the gate.
	if len(got.Rules) == 0 {
		t.Error("an unconfigured project has no rules, so nothing gates it")
	}
	if got.IncompleteScan == "" {
		t.Error("no incomplete-scan treatment")
	}
}

func TestSetProjectPolicyRecordsTheActor(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	body := `{"rules":[{"kind":"severity_count","selector":"critical","max":0,"level":"fail"}],
	          "incomplete_scan":"fail"}`
	rec := authed(t, s, http.MethodPut, "/api/v1/projects/"+project.ID+"/policy", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	ps := s.policies.(*fakePolicyStore)
	if len(ps.audited) != 1 {
		t.Fatalf("audit entries = %d, want 1: a policy change nobody recorded is the gap ADR 022 exists to close",
			len(ps.audited))
	}
	entry := ps.audited[0]
	if entry.Actor.Kind != audit.ActorTokenLabel {
		t.Errorf("actor kind = %q, want a token label: SecureOps cannot name a person yet", entry.Actor.Kind)
	}
	if entry.Actor.Label == "" || entry.Actor.Label == "unknown" {
		t.Errorf("actor label = %q, want the authenticated token's label", entry.Actor.Label)
	}
}

// A policy that cannot be evaluated must be rejected at the boundary, not
// stored and then failed against every future scan.
func TestSetProjectPolicyRejectsAnUnusablePolicy(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	for name, body := range map[string]string{
		"incomplete scan may not pass": `{"rules":[],"incomplete_scan":"pass"}`,
		"unknown severity":             `{"rules":[{"kind":"severity_count","selector":"catastrophic","max":0,"level":"fail"}],"incomplete_scan":"warn"}`,
		"unknown kind":                 `{"rules":[{"kind":"phase_of_moon","max":0,"level":"fail"}],"incomplete_scan":"warn"}`,
		"risk ceiling off the scale":   `{"rules":[{"kind":"risk_score","max":140,"level":"fail"}],"incomplete_scan":"warn"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := authed(t, s, http.MethodPut, "/api/v1/projects/"+project.ID+"/policy", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}

	// Nothing was stored, and in particular no audit entry claims a change
	// that did not happen.
	if ps := s.policies.(*fakePolicyStore); len(ps.audited) != 0 {
		t.Errorf("audit entries = %d after only rejected requests", len(ps.audited))
	}
}

func TestGetScanGate(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	scan := scanStore.seed(scans.Scan{ID: newTestUUID(95), ProjectID: project.ID, Status: scans.StatusCompleted})

	result, err := policies.Evaluate(policies.DefaultPolicy(), policies.Input{
		SeverityCounts: nil, CategoryCounts: nil,
		RiskScore: 12, ScanStatus: "completed", ScanComplete: true,
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	s.policies.(*fakePolicyStore).seedResult(scan.ID, policies.ResultRecord{
		ScanID: scan.ID, ProjectID: project.ID, Result: result, EvaluatedAt: time.Now().UTC(),
	})

	rec := authed(t, s, http.MethodGet, "/api/v1/scans/"+scan.ID+"/gate", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	got := decodeBody[gateResponse](t, rec)

	if got.Verdict != "pass" {
		t.Errorf("verdict = %q, want pass", got.Verdict)
	}
	// §12 forbids a bare verdict. Satisfied rules are reported too, or a pass
	// is indistinguishable from a policy that checks nothing.
	if len(got.Conditions) != len(policies.DefaultPolicy().Rules) {
		t.Errorf("conditions = %d, want every rule reported on a pass", len(got.Conditions))
	}
	for _, c := range got.Conditions {
		if c.Explanation == "" {
			t.Errorf("condition %+v has no explanation", c)
		}
	}
	if got.Summary == "" {
		t.Error("no human-readable summary")
	}
	if !got.Coverage.Complete {
		t.Error("coverage is not reported as complete")
	}
}

// "No gate ran" and "the gate passed" are different claims, and only one of
// them clears a change to ship.
func TestAnUnevaluatedScanIs404NotAPass(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	scan := scanStore.seed(scans.Scan{ID: newTestUUID(95), ProjectID: project.ID, Status: scans.StatusCompleted})

	rec := authed(t, s, http.MethodGet, "/api/v1/scans/"+scan.ID+"/gate", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); contains(body, `"verdict"`) {
		t.Errorf("an unevaluated scan returned a verdict: %s", body)
	}
}
