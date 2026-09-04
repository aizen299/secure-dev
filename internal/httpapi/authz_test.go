package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/scans"
	"github.com/aizen299/secure-dev/internal/users"
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

// --- user administration (ADR 033, change C) --------------------------------

func seedAdmin(t *testing.T, s *Server, id string) users.User {
	t.Helper()
	return s.users.(*fakeUserStore).seed(users.User{
		ID: id, Email: "admin-" + id[:8] + "@example.com", Role: users.RoleAdmin,
	})
}

// The roster names who can weaken a policy or dismiss a finding, which is the
// T-36 disclosure applied to people. There is no read for a non-admin.
func TestOnlyAnAdminCanSeeTheRoster(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	for _, token := range []string{viewerToken, serviceToken} {
		if got := asToken(t, s, token, http.MethodGet, "/api/v1/users", ""); got != http.StatusForbidden {
			t.Errorf("non-admin listing users = %d, want 403", got)
		}
	}
	if got := asToken(t, s, testToken, http.MethodGet, "/api/v1/users", ""); got != http.StatusOK {
		t.Errorf("admin listing users = %d, want 200", got)
	}
}

/**
 * The lockout guard, and the reason it is a 409 rather than a 403.
 *
 * A deployment with no enabled administrator cannot appoint one: every endpoint
 * that could is admin-only. The only way back is SQL against the database. So
 * the request is not forbidden to this caller -- it is impossible for anybody,
 * and the status should say so.
 */
func TestTheLastAdminCannotBeDemotedOrDisabled(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	only := seedAdmin(t, s, newTestUUID(70))
	path := "/api/v1/users/" + only.ID

	for name, body := range map[string]string{
		"demoting":  `{"role":"viewer"}`,
		"disabling": `{"disabled":true}`,
	} {
		rec := send(t, s, request{method: http.MethodPatch, path: path, body: body, token: testToken})
		if rec.Code != http.StatusConflict {
			t.Errorf("%s the last admin = %d, want 409", name, rec.Code)
		}
		// The message has to say what to do about it. "Conflict" alone leaves
		// somebody guessing at which constraint they hit.
		if body := rec.Body.String(); !contains(body, "administrator") {
			t.Errorf("%s: message does not name the constraint: %s", name, body)
		}
	}

	// And the guard is about the LAST one, not about admins in general: with a
	// second enabled admin, both operations succeed.
	seedAdmin(t, s, newTestUUID(71))
	for name, body := range map[string]string{
		"demoting":  `{"role":"viewer"}`,
		"disabling": `{"disabled":true}`,
	} {
		if got := asToken(t, s, testToken, http.MethodPatch, path, body); got != http.StatusOK {
			t.Errorf("%s an admin when another exists = %d, want 200", name, got)
		}
	}
}

// Omitting a field must leave it alone.
//
// Without this, a request changing only a role would also enable a disabled
// account and revoke every project grant -- silently, and in the direction of
// more access.
func TestAnOmittedFieldIsNotAChange(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	store := s.users.(*fakeUserStore)
	seedAdmin(t, s, newTestUUID(72)) // so the last-admin guard does not fire
	user := store.seed(users.User{
		ID: newTestUUID(73), Email: "someone@example.com", Role: users.RoleViewer, Disabled: true,
	})
	if err := store.SetMembership(t.Context(), user.ID, []string{"a-project"}, audit.Actor{}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	rec := send(t, s, request{
		method: http.MethodPatch, path: "/api/v1/users/" + user.ID,
		body: `{"role":"engineer"}`, token: testToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	got := decodeBody[userResponse](t, rec)
	if got.Role != users.RoleEngineer {
		t.Errorf("role = %q, want engineer", got.Role)
	}
	if !got.Disabled {
		t.Error("a disabled account was silently enabled by a role change")
	}
	if len(got.Projects) != 1 {
		t.Errorf("membership = %v, want it untouched by a role change", got.Projects)
	}
}

// `service` is a machine role and must not be assignable through the API.
func TestAUserCannotBeGivenTheServiceRole(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	user := s.users.(*fakeUserStore).seed(users.User{
		ID: newTestUUID(74), Email: "someone@example.com", Role: users.RoleViewer,
	})

	for path, body := range map[string]string{
		"/api/v1/users":            `{"email":"new@example.com","password":"a-long-enough-password","role":"service"}`,
		"/api/v1/users/" + user.ID: `{"role":"service"}`,
	} {
		method := http.MethodPost
		if path != "/api/v1/users" {
			method = http.MethodPatch
		}
		if got := asToken(t, s, testToken, method, path, body); got != http.StatusBadRequest {
			t.Errorf("%s %s with role=service = %d, want 400", method, path, got)
		}
	}
}

// Archive, never delete (§17). And only an admin, and only within scope.
func TestArchivingAProjectIsAdminOnlyAndScoped(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	path := "/api/v1/projects/" + project.ID + "/archive"

	for _, token := range []string{viewerToken, serviceToken} {
		if got := asToken(t, s, token, http.MethodPost, path, ""); got != http.StatusForbidden {
			t.Errorf("non-admin archiving = %d, want 403", got)
		}
	}
	// An admin scoped elsewhere gets 404, not 403: the scope middleware runs
	// first, and an out-of-scope project must not be confirmed to exist.
	if got := asToken(t, s, scopedToken, http.MethodPost, path, ""); got != http.StatusNotFound {
		t.Errorf("out-of-scope admin archiving = %d, want 404", got)
	}
	if got := asToken(t, s, testToken, http.MethodPost, path, ""); got != http.StatusOK {
		t.Errorf("admin archiving = %d, want 200", got)
	}
	if !projectStore.archived[project.ID] {
		t.Error("the project was not archived")
	}

	// Reversible.
	if got := asToken(t, s, testToken, http.MethodPost,
		"/api/v1/projects/"+project.ID+"/unarchive", ""); got != http.StatusOK {
		t.Errorf("unarchiving = %d, want 200", got)
	}
	if projectStore.archived[project.ID] {
		t.Error("the project was not restored")
	}
}

// There is no delete endpoint, and there should not be one. Destroying a
// project's security history through the API would be the API contradicting
// §17's rule about the records it exists to keep.
func TestThereIsNoProjectDeleteEndpoint(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	got := asToken(t, s, testToken, http.MethodDelete, "/api/v1/projects/"+project.ID, "")
	if got != http.StatusMethodNotAllowed && got != http.StatusNotFound {
		t.Errorf("DELETE on a project = %d; there must be no delete endpoint", got)
	}
}

// Archiving must not be a one-way door.
//
// The middleware resolves a project before any handler runs, and it used to use
// a lookup that filters archived projects out — so /unarchive could never find
// the project it exists to restore. Archiving hid a project so completely that
// only SQL could bring it back.
//
// Found by running it against a live database, not by reading the code, which
// is why this test exists.
func TestAnArchivedProjectCanBeBroughtBack(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	if got := asToken(t, s, testToken, http.MethodPost,
		"/api/v1/projects/"+project.ID+"/archive", ""); got != http.StatusOK {
		t.Fatalf("archive = %d, want 200", got)
	}
	if !projectStore.archived[project.ID] {
		t.Fatal("the project was not archived")
	}

	// The step that used to 404.
	if got := asToken(t, s, testToken, http.MethodPost,
		"/api/v1/projects/"+project.ID+"/unarchive", ""); got != http.StatusOK {
		t.Errorf("unarchive = %d, want 200: archiving must not be one-way", got)
	}
	if projectStore.archived[project.ID] {
		t.Error("the project was not restored")
	}

	// And an archived project stays readable. Archiving hides it from lists;
	// the findings and history gathered about it are not withdrawn.
	_ = asToken(t, s, testToken, http.MethodPost, "/api/v1/projects/"+project.ID+"/archive", "")
	if got := asToken(t, s, testToken, http.MethodGet,
		"/api/v1/projects/"+project.ID+"/findings", ""); got != http.StatusOK {
		t.Errorf("reading an archived project's findings = %d, want 200", got)
	}

	// The project's OWN record, which is the one that was still 404ing.
	//
	// The middleware resolved the project with GetAny and the handler then read
	// it again with Get, which filters archived rows -- two resolutions of the
	// same project, disagreeing. So the dashboard's project page 404'd once
	// archived, and the control that restores it is on that page: a one-way
	// door again, one layer up from the one above.
	//
	// Found the same way as its sibling: by archiving a project in a browser
	// and looking for the way back.
	response := send(t, s, request{
		method: http.MethodGet, path: "/api/v1/projects/" + project.ID, token: testToken,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("reading an archived project = %d, want 200", response.Code)
	}

	var body struct {
		Archived bool `json:"archived"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	// Reported, not hidden. A page that renders a restore control needs to know
	// the project is archived, and a caller that cannot tell would show the
	// wrong one.
	if !body.Archived {
		t.Error("archived project reported archived=false")
	}
}

// An archived project accepts no new scans.
//
// "Archiving hides a project from lists and blocks new scans; its findings,
// scans and history remain" (ADR 033 §6). The block comes from projects.Exists
// filtering archived rows, which predates this change — asserted here so it
// stays true, because the middleware now deliberately does NOT filter them.
func TestAnArchivedProjectAcceptsNoNewScans(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	projectStore.archived[project.ID] = true

	got := asToken(t, s, testToken, http.MethodPost, "/api/v1/scans", createScanBody(project.ID))
	if got != http.StatusNotFound {
		t.Errorf("scanning an archived project = %d, want 404", got)
	}
}

// /auth/me reports a person's OWN role, not the credential role it maps to.
//
// `engineer` maps onto the `service` credential role internally, because that is
// what requireRole understands. Reporting the mapped value told an engineer they
// were a "service" — wrong, and exactly the confusion two role vocabularies
// invite. Found by reading a live response rather than by a test.
func TestWhoAmIReportsThePersonsRoleNotTheMappedOne(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	user := s.users.(*fakeUserStore).seed(users.User{
		ID: newTestUUID(76), Email: "eng@example.com", Role: users.RoleEngineer,
	})
	token := s.sessions.Issue(user.ID, s.now())

	rec := send(t, s, request{method: http.MethodGet, path: "/api/v1/auth/me", token: token})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	got := decodeBody[struct {
		Role string `json:"role"`
	}](t, rec)
	if got.Role != "engineer" {
		t.Errorf("role = %q, want engineer: a person must not be told they are a %q", got.Role, got.Role)
	}
}

// Everything readable about a project stays readable once it is archived.
//
// ADR 033 §6: "archiving hides a project from lists and blocks new scans; its
// findings, scans and history remain". Four handlers broke that promise the
// same way -- each looked the project up again with a lookup that filters
// archived rows, instead of using the one the middleware had already resolved
// and scope-checked. The fake's Get was permissive enough that none of it
// showed until the fake was corrected.
//
// Table-driven on purpose: the failure was a pattern repeated across handlers,
// so the test that guards it enumerates the surface rather than picking one.
func TestAnArchivedProjectStaysReadable(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	projectStore.archived[project.ID] = true

	for _, path := range []string{
		"",
		"/scans",
		"/findings",
		"/issues",
		"/remediation",
		"/policy",
		// Not /risk: it answers 404 for a live project that has never been
		// scored, so it cannot distinguish "archived" from "never scored" and
		// would assert nothing here.
	} {
		t.Run(path, func(t *testing.T) {
			got := asToken(t, s, testToken, http.MethodGet, "/api/v1/projects/"+project.ID+path, "")
			if got != http.StatusOK {
				t.Errorf("GET %s on an archived project = %d, want 200", path, got)
			}
		})
	}
}
