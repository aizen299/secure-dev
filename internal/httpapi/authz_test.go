package httpapi

import (
	"net/http"
	"testing"

	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/scans"
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

// Target validation is read-only and still gated at `service` (ADR 032).
//
// The argument for `viewer` is that it writes nothing. The argument against,
// which wins, is that it RESOLVES A CALLER-SUPPLIED HOSTNAME: an outbound
// lookup the caller chose. A read-only credential should not gain a side
// effect it does not otherwise have, and a `service` token can already reach
// this exact code by submitting a scan.
func TestValidatingATargetNeedsMoreThanAViewerToken(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	const path = "/api/v1/targets/validate"
	const body = `{"target":{"kind":"repository","repository_url":"https://github.com/owner/repo.git"}}`

	if got := asToken(t, s, viewerToken, http.MethodPost, path, body); got != http.StatusForbidden {
		t.Errorf("viewer validating a target = %d, want 403: it would gain an outbound lookup", got)
	}
	// And the test above is not vacuous: the role that should reach it, does.
	if got := asToken(t, s, serviceToken, http.MethodPost, path, body); got != http.StatusOK {
		t.Errorf("service validating a target = %d, want 200", got)
	}
}

// --- project scoping (ADR 033) ----------------------------------------------

// The T-23 scenario, stated as a test.
//
// Before ADR 033 every valid token reached every project: there was no tenancy
// boundary and no way to express one. A credential scoped to `team-a-project`
// must not be able to read `billing`, and the fact that it holds the ADMIN role
// must not help — role says what a credential may do, scope says where.
func TestAScopedTokenCannotReachAnotherProject(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	other := seedProject(t, projectStore) // slug "billing"
	mine := projectStore.seed(projects.Project{
		ID:          newTestUUID(31),
		Name:        "Team A",
		Slug:        scopedSlug,
		Environment: projects.EnvProduction,
		Criticality: projects.CriticalityHigh,
	})

	// Every read addressed by project id, so a route missed by the middleware
	// shows up here rather than in production.
	for _, suffix := range []string{"", "/scans", "/findings", "/issues", "/risk", "/remediation", "/policy"} {
		path := "/api/v1/projects/" + other.ID + suffix
		if got := asToken(t, s, scopedToken, http.MethodGet, path, ""); got != http.StatusNotFound {
			t.Errorf("scoped token GET %s = %d, want 404", path, got)
		}
	}

	// And the write that can switch the gate off.
	policyPath := "/api/v1/projects/" + other.ID + "/policy"
	if got := asToken(t, s, scopedToken, http.MethodPut, policyPath, validPolicyBody); got != http.StatusNotFound {
		t.Errorf("scoped token editing another project's policy = %d, want 404", got)
	}

	// The test is not vacuous: the same credential reaches its own project.
	if got := asToken(t, s, scopedToken, http.MethodGet, "/api/v1/projects/"+mine.ID, ""); got != http.StatusOK {
		t.Errorf("scoped token reading its OWN project = %d, want 200", got)
	}
	// And a global credential still reaches both, so this is a scope boundary
	// rather than a broken route.
	if got := asToken(t, s, testToken, http.MethodGet, "/api/v1/projects/"+other.ID, ""); got != http.StatusOK {
		t.Errorf("global token reading any project = %d, want 200", got)
	}
}

// 404 rather than 403, deliberately.
//
// A 403 confirms the id names a real project, which turns id enumeration into a
// map of the estate — the disclosure T-38 is about. "Not found" is also the
// literal truth from the caller's position.
func TestAnOutOfScopeProjectIsIndistinguishableFromAMissingOne(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	real := seedProject(t, projectStore)
	absent := "/api/v1/projects/" + newTestUUID(99)

	existing := send(t, s, request{
		method: http.MethodGet, path: "/api/v1/projects/" + real.ID, token: scopedToken,
	})
	missing := send(t, s, request{method: http.MethodGet, path: absent, token: scopedToken})

	if existing.Code != http.StatusNotFound || missing.Code != http.StatusNotFound {
		t.Fatalf("statuses = %d and %d, want both 404", existing.Code, missing.Code)
	}
	// Compared on code and message, not on the whole body: every response
	// carries its own request_id, which differs by construction and discloses
	// nothing about the project.
	a := decodeBody[ErrorEnvelope](t, existing).Error
	b := decodeBody[ErrorEnvelope](t, missing).Error
	if a.Code != b.Code || a.Message != b.Message {
		t.Errorf("an out-of-scope project answers differently from an absent one:\n  %s / %s\n  %s / %s",
			a.Code, a.Message, b.Code, b.Message)
	}
}

// The estate itself is scoped, not just each project in it.
//
// GET /projects returned every project regardless of scope until ADR 033 — the
// names and slugs of the whole estate, which is the T-36 disclosure with a
// pagination header on it. The filter has to be in the query: filtering a
// fetched page would return the in-scope rows but compute has_more from the
// whole page, so a caller paging through would see a truncated estate and, from
// the mismatch, learn how much was hidden.
func TestListingProjectsShowsOnlyWhatTheScopeReaches(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	seedProject(t, projectStore) // "billing", out of scope
	projectStore.seed(projects.Project{
		ID: newTestUUID(41), Name: "Team A", Slug: scopedSlug,
		Environment: projects.EnvProduction, Criticality: projects.CriticalityHigh,
	})

	rec := send(t, s, request{method: http.MethodGet, path: "/api/v1/projects", token: scopedToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := decodeBody[struct {
		Data []projects.Project `json:"data"`
	}](t, rec)
	if len(got.Data) != 1 {
		t.Fatalf("returned %d projects, want 1: the estate is visible to a scoped credential", len(got.Data))
	}
	if got.Data[0].Slug != scopedSlug {
		t.Errorf("returned %q, want %q", got.Data[0].Slug, scopedSlug)
	}

	// Not vacuous: a global credential still sees both.
	rec = send(t, s, request{method: http.MethodGet, path: "/api/v1/projects", token: testToken})
	if all := decodeBody[struct {
		Data []projects.Project `json:"data"`
	}](t, rec); len(all.Data) != 2 {
		t.Errorf("global credential saw %d projects, want 2", len(all.Data))
	}
}

// The five endpoints that take an opaque id and no project.
//
// These are why ADR 033 argues scoping cannot be middleware: there is no
// project in the URL to check before the lookup, so each resolves the entity
// and checks its owner. Without them, a scoped credential confined out of a
// project could still read that project's scans, findings and gate verdicts by
// id — which is most of what the project boundary exists to protect.
func TestAScopedTokenCannotReachAnotherProjectByEntityID(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})
	other := seedProject(t, projectStore) // "billing", out of scope
	scan := scanStore.seed(scans.Scan{
		ID: newTestUUID(51), ProjectID: other.ID, Status: scans.StatusCompleted,
	})
	findingID := newTestUUID(52)
	s.findings.(*fakeFindingStore).projectOf[findingID] = other.ID

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/scans/" + scan.ID, ""},
		{http.MethodGet, "/api/v1/scans/" + scan.ID + "/findings", ""},
		{http.MethodGet, "/api/v1/scans/" + scan.ID + "/gate", ""},
		{http.MethodGet, "/api/v1/findings/" + findingID + "/history", ""},
		{http.MethodPost, "/api/v1/findings/" + findingID + "/status",
			`{"status":"acknowledged","reason":"triaged","note":"looking at it now"}`},
	} {
		if got := asToken(t, s, scopedToken, c.method, c.path, c.body); got != http.StatusNotFound {
			t.Errorf("scoped token %s %s = %d, want 404", c.method, c.path, got)
		}
	}

	// Not vacuous: a global credential still reaches the same scan.
	if got := asToken(t, s, testToken, http.MethodGet, "/api/v1/scans/"+scan.ID, ""); got != http.StatusOK {
		t.Errorf("global token reading the scan = %d, want 200", got)
	}
}
