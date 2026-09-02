package httpapi

import (
	"net/http"
	"testing"
)

func asToken(t *testing.T, s *Server, token, method, path, body string) int {
	t.Helper()
	return send(t, s, request{method: method, path: path, body: body, token: token}).Code
}

const validPolicyBody = `{"rules":[{"kind":"severity_count","selector":"critical","max":0,"level":"fail"}],
                          "incomplete_scan":"warn"}`

// The scenario ADR 023 exists for. The credential every CI job holds is the
// most widely distributed secret in the system, and it must not be able to
// switch off the gate that is judging it.
func TestAServiceTokenCannotDisableTheGate(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	path := "/api/v1/projects/" + project.ID + "/policy"

	if got := asToken(t, s, serviceToken, http.MethodPut, path, validPolicyBody); got != http.StatusForbidden {
		t.Errorf("service token editing policy = %d, want 403", got)
	}
	// And nothing was written: a refused request must not have taken effect.
	if ps := s.policies.(*fakePolicyStore); len(ps.audited) != 0 {
		t.Errorf("audit entries = %d after a refused policy change", len(ps.audited))
	}

	// The same token may still do its actual job.
	if got := asToken(t, s, serviceToken, http.MethodGet, path, ""); got != http.StatusOK {
		t.Errorf("service token reading policy = %d, want 200: it must still see what it is judged by", got)
	}
	if got := asToken(t, s, testToken, http.MethodPut, path, validPolicyBody); got != http.StatusOK {
		t.Errorf("admin token editing policy = %d, want 200: the test above would be vacuous", got)
	}
}

func TestAViewerTokenCannotMutateAnything(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	mutations := []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/projects", `{"name":"New"}`},
		{http.MethodPost, "/api/v1/scans",
			`{"project_id":"` + project.ID + `","target":{"kind":"repository","repository_url":"https://x/y"}}`},
		{http.MethodPut, "/api/v1/projects/" + project.ID + "/policy", validPolicyBody},
	}
	for _, m := range mutations {
		if got := asToken(t, s, viewerToken, m.method, m.path, m.body); got != http.StatusForbidden {
			t.Errorf("viewer %s %s = %d, want 403", m.method, m.path, got)
		}
	}

	// Reads still work, which is the whole point of a viewer credential.
	for _, path := range []string{
		"/api/v1/projects",
		"/api/v1/projects/" + project.ID,
		"/api/v1/projects/" + project.ID + "/findings",
	} {
		if got := asToken(t, s, viewerToken, http.MethodGet, path, ""); got != http.StatusOK {
			t.Errorf("viewer GET %s = %d, want 200", path, got)
		}
	}
}

// 403 and 401 are different facts. Collapsing them would make a misconfigured
// CI token look like a broken deployment, and hiding the route's existence
// from a caller who authenticated is security through obscurity (§15.13).
func TestInsufficientPrivilegeIs403NotUnauthenticated(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	path := "/api/v1/projects/" + project.ID + "/policy"

	rec := send(t, s, request{method: http.MethodPut, path: path, body: validPolicyBody, token: viewerToken})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	got := decodeBody[ErrorEnvelope](t, rec)
	if got.Error.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", got.Error.Code, CodeForbidden)
	}
	// A refusal must not echo the credential that was refused.
	if body := rec.Body.String(); contains(body, viewerToken) {
		t.Error("the refused token was echoed in the response")
	}

	// No credential at all is still 401, not 403.
	anon := send(t, s, request{method: http.MethodPut, path: path, body: validPolicyBody})
	if anon.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d, want 401", anon.Code)
	}
}
