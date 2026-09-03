package httpapi

import (
	"net/http"
	"testing"
)

func transitionBody(status, reason, note string) string {
	b := `{"status":"` + status + `","reason":"` + reason + `"`
	if note != "" {
		b += `,"note":"` + note + `"`
	}
	return b + `}`
}

// The gap this whole change exists to close. Three engines have honoured
// dismissed states since Phase 6 and nothing could produce one.
func TestAFindingCanBeDismissedAsAFalsePositive(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	id := newTestUUID(60)

	rec := authed(t, s, http.MethodPost, "/api/v1/findings/"+id+"/status",
		transitionBody("false_positive", "false_positive", "the rule matches our test fixtures, not production code"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	got := decodeBody[transitionResponse](t, rec)
	if got.To != "false_positive" {
		t.Errorf("to_status = %q, want false_positive", got.To)
	}
	if got.From != "open" {
		t.Errorf("from_status = %q, want open: both states are required (§17)", got.From)
	}
	if got.Actor == "" {
		t.Error("no actor recorded")
	}
	if got.Note == "" {
		t.Error("the note was dropped; the reasoning is the part a later reader needs")
	}
}

// The rule ADR 024 turns on. A person may judge a finding and may not declare
// it verified: `resolved` means a scanner stopped reporting it, and a
// hand-typed one would be indistinguishable from the real thing while dropping
// the risk score and turning a gate green.
func TestAPersonCannotMarkAFindingResolvedOrReopened(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	for _, status := range []string{"resolved", "reopened"} {
		rec := authed(t, s, http.MethodPost, "/api/v1/findings/"+newTestUUID(61)+"/status",
			transitionBody(status, "triaged", ""))

		// 422, not 400: the request is well-formed and the state is real, so
		// retrying it unchanged will not help.
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("setting %q = %d, want 422 (body: %s)", status, rec.Code, rec.Body.String())
		}
		// And the refusal explains itself, including what to do instead.
		if body := rec.Body.String(); !contains(body, "ignored") {
			t.Errorf("the refusal does not point at the honest alternative: %s", body)
		}
	}

	// The states a person may set still work, or the test above proves nothing.
	for _, status := range []string{"acknowledged", "in_progress", "ignored", "open"} {
		rec := authed(t, s, http.MethodPost, "/api/v1/findings/"+newTestUUID(62)+"/status",
			transitionBody(status, "triaged", ""))
		if rec.Code != http.StatusOK {
			t.Errorf("setting %q = %d, want 200 (body: %s)", status, rec.Code, rec.Body.String())
		}
	}
}

func TestATransitionRequiresAKnownReason(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	for _, body := range []string{
		transitionBody("ignored", "", ""),
		transitionBody("ignored", "because-i-said-so", ""),
		`{"status":"ignored"}`,
	} {
		rec := authed(t, s, http.MethodPost, "/api/v1/findings/"+newTestUUID(63)+"/status", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s = %d, want 400", body, rec.Code)
		}
	}
}

// Triage is what the people using this tool do all day. Gating it behind admin
// would make weakening the policy the easier route to the same outcome.
func TestTriageNeedsServiceNotAdmin(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	path := "/api/v1/findings/" + newTestUUID(64) + "/status"
	body := transitionBody("false_positive", "false_positive", "")

	if got := asToken(t, s, serviceToken, http.MethodPost, path, body); got != http.StatusOK {
		t.Errorf("service token = %d, want 200: triage is not administration", got)
	}
	if got := asToken(t, s, viewerToken, http.MethodPost, path, body); got != http.StatusForbidden {
		t.Errorf("viewer token = %d, want 403: reading is not judging", got)
	}
}

// §17 requires the history to be recorded. Recording it and never serving it
// would satisfy the letter and none of the point.
func TestAFindingsHistoryIsReadable(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	id := newTestUUID(65)

	authed(t, s, http.MethodPost, "/api/v1/findings/"+id+"/status",
		transitionBody("acknowledged", "triaged", ""))
	authed(t, s, http.MethodPost, "/api/v1/findings/"+id+"/status",
		transitionBody("ignored", "accepted_risk", "compensating control in the WAF"))

	rec := authed(t, s, http.MethodGet, "/api/v1/findings/"+id+"/history", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := decodeBody[historyResponse](t, rec)
	if len(got.Transitions) != 2 {
		t.Fatalf("transitions = %d, want 2", len(got.Transitions))
	}
	for _, tr := range got.Transitions {
		if tr.Actor == "" || tr.Reason == "" || tr.ChangedAt.IsZero() {
			t.Errorf("transition %+v is missing who, why, or when", tr)
		}
	}
}

func TestTransitionRejectsAMalformedFindingID(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	rec := authed(t, s, http.MethodPost, "/api/v1/findings/not-a-uuid/status",
		transitionBody("ignored", "accepted_risk", ""))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// §15.6 lists scan creation and project changes alongside policy changes. The
// actor has to reach the store, or the audit record names nobody.
func TestCreationsCarryTheirActor(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})

	authed(t, s, http.MethodPost, "/api/v1/projects", `{"name":"Audited"}`)
	if len(projectStore.createdBy) != 1 {
		t.Fatalf("project creations recorded = %d, want 1", len(projectStore.createdBy))
	}
	if projectStore.createdBy[0].Label != testTokenLabel {
		t.Errorf("project actor = %q, want the authenticated label", projectStore.createdBy[0].Label)
	}

	project := seedProject(t, projectStore)
	authed(t, s, http.MethodPost, "/api/v1/scans",
		`{"project_id":"`+project.ID+`","target":{"kind":"repository","repository_url":"https://x/y"}}`)
	if len(scanStore.createdBy) != 1 {
		t.Fatalf("scan creations recorded = %d, want 1", len(scanStore.createdBy))
	}
	if scanStore.createdBy[0].Label != testTokenLabel {
		t.Errorf("scan actor = %q, want the authenticated label", scanStore.createdBy[0].Label)
	}
}
