package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// --- request helpers -------------------------------------------------------

type request struct {
	method string
	path   string
	body   string
	// token is sent as a bearer credential. Empty means no Authorization
	// header at all.
	token       string
	contentType string
}

func send(t *testing.T, s *Server, req request) *httptest.ResponseRecorder {
	t.Helper()

	var body *strings.Reader
	if req.body != "" {
		body = strings.NewReader(req.body)
	} else {
		body = strings.NewReader("")
	}

	r := httptest.NewRequestWithContext(t.Context(), req.method, req.path, body)
	if req.token != "" {
		r.Header.Set("Authorization", "Bearer "+req.token)
	}
	if req.body != "" {
		contentType := req.contentType
		if contentType == "" {
			contentType = "application/json"
		}
		r.Header.Set("Content-Type", contentType)
	} else if req.contentType != "" {
		r.Header.Set("Content-Type", req.contentType)
	}

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec
}

// authed sends an authenticated request with the test credential.
func authed(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, s, request{method: method, path: path, body: body, token: testToken})
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
	return out
}

func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode ErrorCode) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, wantStatus, rec.Body.String())
	}
	env := decodeBody[ErrorEnvelope](t, rec)
	if env.Error.Code != wantCode {
		t.Errorf("code = %q, want %q", env.Error.Code, wantCode)
	}
	if env.Error.RequestID == "" {
		t.Error("error envelope is missing a request_id")
	}
}

func seedProject(t *testing.T, store *fakeProjectStore) projects.Project {
	t.Helper()
	return store.seed(projects.Project{
		ID:          newTestUUID(7),
		Name:        "Billing",
		Slug:        "billing",
		Environment: projects.EnvProduction,
		Criticality: projects.CriticalityHigh,
	})
}

// --- authentication --------------------------------------------------------

// The reason ADR 006 exists: no write endpoint may be reachable without a
// credential. This enumerates the whole authenticated surface rather than
// spot-checking, so a route added without the gate fails here.
func TestEveryResourceEndpointRequiresAuthentication(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	scan := scanStore.seed(scans.Scan{ID: newTestUUID(8), ProjectID: project.ID, Status: scans.StatusQueued})

	endpoints := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/projects"},
		{http.MethodGet, "/api/v1/projects"},
		{http.MethodGet, "/api/v1/projects/" + project.ID},
		{http.MethodGet, "/api/v1/projects/" + project.ID + "/scans"},
		{http.MethodPost, "/api/v1/scans"},
		{http.MethodGet, "/api/v1/scans/" + scan.ID},
	}

	for _, e := range endpoints {
		t.Run(e.method+" "+e.path, func(t *testing.T) {
			rec := send(t, s, request{method: e.method, path: e.path, body: "{}"})
			assertErrorCode(t, rec, http.StatusUnauthorized, CodeUnauthenticated)

			if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
				t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", got)
			}
		})
	}
}

func TestBadCredentialsAreRejected(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	tests := []struct {
		name   string
		header string
	}{
		{"wrong token", "Bearer secureops-other-token-not-secret1"},
		{"wrong scheme", "Basic " + testToken},
		{"no scheme", testToken},
		{"empty", ""},
		{"token prefix", "Bearer " + testToken[:16]},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/projects", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, r)

			assertErrorCode(t, rec, http.StatusUnauthorized, CodeUnauthenticated)
		})
	}
}

// Health endpoints stay open: a liveness check that needs a credential fails
// during a rotation, and an orchestrator would then kill a healthy process.
func TestHealthEndpointsStayUnauthenticated(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	for _, path := range []string{"/healthz", "/readyz", "/api/v1/health"} {
		t.Run(path, func(t *testing.T) {
			rec := send(t, s, request{method: http.MethodGet, path: path})
			if rec.Code == http.StatusUnauthorized {
				t.Fatalf("%s requires authentication; probes must not", path)
			}
		})
	}
}

// A 401 must not distinguish "no such project" from "wrong credential", or an
// unauthenticated caller could enumerate project IDs.
func TestUnauthenticatedRequestsRevealNothingAboutExistence(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	existing := seedProject(t, projectStore)

	realRec := send(t, s, request{method: http.MethodGet, path: "/api/v1/projects/" + existing.ID})
	fakeRec := send(t, s, request{method: http.MethodGet, path: "/api/v1/projects/" + unknownUUID})

	if realRec.Code != fakeRec.Code {
		t.Errorf("status differs by existence: %d vs %d", realRec.Code, fakeRec.Code)
	}
	realEnv := decodeBody[ErrorEnvelope](t, realRec)
	fakeEnv := decodeBody[ErrorEnvelope](t, fakeRec)
	if realEnv.Error.Message != fakeEnv.Error.Message {
		t.Errorf("message differs by existence: %q vs %q", realEnv.Error.Message, fakeEnv.Error.Message)
	}
}

// A rejected credential must never reach the logs or the response.
func TestTheRejectedTokenIsNeverEchoed(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	const presented = "distinctive-wrong-token-not-a-secret"

	rec := send(t, s, request{method: http.MethodGet, path: "/api/v1/projects", token: presented})

	if strings.Contains(rec.Body.String(), presented) {
		t.Error("the response echoed the presented token")
	}
	if strings.Contains(rec.Header().Get("WWW-Authenticate"), presented) {
		t.Error("the WWW-Authenticate header echoed the presented token")
	}
}

// --- projects --------------------------------------------------------------

func TestCreateProject(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	rec := authed(t, s, http.MethodPost, "/api/v1/projects",
		`{"name":"Payments API","environment":"production","criticality":"critical","internet_facing":true}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	got := decodeBody[projects.Project](t, rec)
	if got.Slug != "payments-api" {
		t.Errorf("slug = %q, want %q", got.Slug, "payments-api")
	}
	if got.Environment != projects.EnvProduction || !got.InternetFacing {
		t.Errorf("risk inputs not persisted: %+v", got)
	}
	if want := "/api/v1/projects/" + got.ID; rec.Header().Get("Location") != want {
		t.Errorf("Location = %q, want %q", rec.Header().Get("Location"), want)
	}
}

func TestCreateProjectRejectsInvalidBodies(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   ErrorCode
	}{
		{"empty name", `{"name":""}`, http.StatusBadRequest, CodeInvalidRequest},
		{"missing name", `{}`, http.StatusBadRequest, CodeInvalidRequest},
		{"bad environment", `{"name":"x","environment":"prod"}`, http.StatusBadRequest, CodeInvalidRequest},
		{"bad criticality", `{"name":"x","criticality":"extreme"}`, http.StatusBadRequest, CodeInvalidRequest},
		{"bad slug", `{"name":"x","slug":"Not A Slug"}`, http.StatusBadRequest, CodeInvalidRequest},
		{"malformed json", `{"name":`, http.StatusBadRequest, CodeInvalidRequest},
		{"not an object", `"a string"`, http.StatusBadRequest, CodeInvalidRequest},
		{"wrong field type", `{"name":123}`, http.StatusBadRequest, CodeInvalidRequest},
		// A typo in a field name must fail loudly rather than being ignored:
		// silently dropping "criticalty" would create a project at the default
		// risk weight while the caller believes it set one.
		{"unknown field", `{"name":"x","criticalty":"high"}`, http.StatusBadRequest, CodeInvalidRequest},
		{"two documents", `{"name":"a"}{"name":"b"}`, http.StatusBadRequest, CodeInvalidRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := newWiredServer(t, func(*Options) {})
			rec := authed(t, s, http.MethodPost, "/api/v1/projects", tc.body)
			assertErrorCode(t, rec, tc.wantStatus, tc.wantCode)
		})
	}
}

func TestCreateProjectRequiresJSONContentType(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	rec := send(t, s, request{
		method: http.MethodPost, path: "/api/v1/projects",
		body: `{"name":"x"}`, token: testToken, contentType: "text/plain",
	})
	assertErrorCode(t, rec, http.StatusUnsupportedMediaType, CodeUnsupportedMedia)
}

// The body cap is a resource-exhaustion control (§15.8), so it is asserted
// rather than assumed.
func TestOversizedBodyIsRejected(t *testing.T) {
	s, _, _ := newWiredServer(t, func(o *Options) { o.MaxRequestBytes = 256 })

	body := fmt.Sprintf(`{"name":"x","description":%q}`, strings.Repeat("a", 4096))
	rec := authed(t, s, http.MethodPost, "/api/v1/projects", body)

	assertErrorCode(t, rec, http.StatusRequestEntityTooLarge, CodePayloadTooLarge)
}

func TestCreateProjectReportsSlugConflict(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	first := authed(t, s, http.MethodPost, "/api/v1/projects", `{"name":"Billing"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create: status = %d, want 201", first.Code)
	}

	second := authed(t, s, http.MethodPost, "/api/v1/projects", `{"name":"Billing"}`)
	assertErrorCode(t, second, http.StatusConflict, CodeConflict)
}

func TestGetProject(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := decodeBody[projects.Project](t, rec); got.ID != project.ID {
		t.Errorf("id = %q, want %q", got.ID, project.ID)
	}
}

func TestGetProjectNotFound(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+unknownUUID, "")
	assertErrorCode(t, rec, http.StatusNotFound, CodeNotFound)
}

// A malformed ID is a client mistake, so it must be a 400. Without the check
// it reaches pgx and becomes a 500.
func TestMalformedIDsAreBadRequestsNotServerErrors(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	for _, id := range []string{"not-a-uuid", "123", "'; DROP TABLE projects; --", "../../etc/passwd"} {
		t.Run(id, func(t *testing.T) {
			rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+url.PathEscape(id), "")
			assertErrorCode(t, rec, http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

func TestListProjectsIsPaginated(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	for i := range 3 {
		body := fmt.Sprintf(`{"name":"Project %d"}`, i)
		if rec := authed(t, s, http.MethodPost, "/api/v1/projects", body); rec.Code != http.StatusCreated {
			t.Fatalf("seed %d: status = %d", i, rec.Code)
		}
	}

	rec := authed(t, s, http.MethodGet, "/api/v1/projects?limit=2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	page := decodeBody[listResponse[projects.Project]](t, rec)
	if len(page.Data) != 2 {
		t.Errorf("returned %d projects, want 2", len(page.Data))
	}
	if !page.Pagination.HasMore {
		t.Error("has_more = false, want true")
	}
	if page.Pagination.Limit != 2 {
		t.Errorf("limit = %d, want 2", page.Pagination.Limit)
	}
}

// An unbounded list endpoint is a denial-of-service primitive once the table
// is large, so the ceiling is enforced rather than silently clamped.
func TestListRejectsOutOfRangePagination(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	for _, query := range []string{
		"?limit=0", "?limit=-1", "?limit=" + fmt.Sprint(MaxPageLimit+1),
		"?limit=abc", "?offset=-1", "?offset=abc",
	} {
		t.Run(query, func(t *testing.T) {
			rec := authed(t, s, http.MethodGet, "/api/v1/projects"+query, "")
			assertErrorCode(t, rec, http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

func TestEmptyListEncodesAsAnArray(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	rec := authed(t, s, http.MethodGet, "/api/v1/projects", "")
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"data":[]`)) {
		t.Errorf("empty list should encode data as [], got %s", rec.Body.String())
	}
}

// --- scans -----------------------------------------------------------------

func createScanBody(projectID string) string {
	return fmt.Sprintf(
		`{"project_id":%q,"target":{"kind":"repository","repository_url":"https://github.com/acme/app"}}`,
		projectID)
}

// The §13 contract: the request returns immediately with 202, never 200, and
// never blocks on scanner execution.
func TestCreateScanReturns202AndQueuesTheJob(t *testing.T) {
	var q *queue.Memory
	s, projectStore, _ := newWiredServer(t, func(o *Options) {
		q = queue.NewMemory()
		o.Queue = q
	})
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodPost, "/api/v1/scans", createScanBody(project.ID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
	}

	got := decodeBody[scanResponse](t, rec)
	if got.Status != scans.StatusQueued {
		t.Errorf("status = %q, want %q", got.Status, scans.StatusQueued)
	}
	if want := "/api/v1/scans/" + got.ID; rec.Header().Get("Location") != want {
		t.Errorf("Location = %q, want %q", rec.Header().Get("Location"), want)
	}

	n, err := q.Len(t.Context())
	if err != nil {
		t.Fatalf("queue length: %v", err)
	}
	if n != 1 {
		t.Errorf("queued %d jobs, want 1", n)
	}
}

// A queued scan has not run, so it has no coverage. Reporting complete_coverage
// true here would be the exact false reassurance §12 forbids.
func TestAQueuedScanDoesNotClaimCompleteCoverage(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodPost, "/api/v1/scans", createScanBody(project.ID))
	got := decodeBody[scanResponse](t, rec)

	if got.CompleteCoverage {
		t.Error("a queued scan must not report complete coverage")
	}
}

// The SSRF guard at the API boundary (§14.6). A target that resolves to a
// blocked range must never reach the queue.
func TestCreateScanRejectsSSRFTargets(t *testing.T) {
	q := queue.NewMemory()
	s, projectStore, _ := newWiredServer(t, func(o *Options) {
		o.Queue = q
		// Every hostname resolves to loopback: the shape of DNS rebinding
		// against an internal service.
		o.Validator = scanners.Validator{
			WorkspaceRoot: "/tmp/secureops-test",
			Resolver:      blockedResolver{},
		}
	})
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodPost, "/api/v1/scans", createScanBody(project.ID))
	assertErrorCode(t, rec, http.StatusBadRequest, CodeInvalidRequest)

	n, err := q.Len(t.Context())
	if err != nil {
		t.Fatalf("queue length: %v", err)
	}
	if n != 0 {
		t.Errorf("a blocked target was enqueued anyway (%d jobs)", n)
	}
}

// A filesystem target means "a path inside the worker's workspace". Accepting
// one from a client would turn POST /scans into a way to read the worker's own
// disk, so the kind is not client-submittable at all.
//
// The assertion is on the exact message, not merely on a 400. A filesystem
// target with no path is rejected further down the handler anyway ("path is
// required"), so a status-only check passes even when the kind IS submittable
// -- it proves nothing. Pinning the message ties the test to the gate that
// actually enforces this.
func TestCreateScanRejectsFilesystemTargets(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	body := fmt.Sprintf(`{"project_id":%q,"target":{"kind":"filesystem"}}`, project.ID)
	rec := authed(t, s, http.MethodPost, "/api/v1/scans", body)

	assertErrorCode(t, rec, http.StatusBadRequest, CodeInvalidRequest)

	env := decodeBody[ErrorEnvelope](t, rec)
	const want = "target.kind must be one of repository, image, endpoint"
	if env.Error.Message != want {
		t.Errorf("message = %q, want %q\n"+
			"(a different message means the rejection came from somewhere other than "+
			"the submittable-kind gate, so this test is not proving what it claims)",
			env.Error.Message, want)
	}
}

// Path is not part of the client-facing target at all. Even if the kind gate
// were bypassed, there is no way to say which path to scan.
func TestCreateScanRejectsAPathInTheTarget(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	body := fmt.Sprintf(
		`{"project_id":%q,"target":{"kind":"repository","repository_url":"https://github.com/a/b",`+
			`"path":"/etc"}}`, project.ID)
	rec := authed(t, s, http.MethodPost, "/api/v1/scans", body)

	assertErrorCode(t, rec, http.StatusBadRequest, CodeInvalidRequest)
}

func TestCreateScanRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name       string
		body       func(projectID string) string
		wantStatus int
		wantCode   ErrorCode
	}{
		{"unknown project", func(string) string { return createScanBody(unknownUUID) },
			http.StatusNotFound, CodeNotFound},
		{"malformed project id", func(string) string { return createScanBody("not-a-uuid") },
			http.StatusBadRequest, CodeInvalidRequest},
		{"unknown target kind", func(id string) string {
			return fmt.Sprintf(`{"project_id":%q,"target":{"kind":"kubernetes"}}`, id)
		}, http.StatusBadRequest, CodeInvalidRequest},
		{"missing target", func(id string) string {
			return fmt.Sprintf(`{"project_id":%q}`, id)
		}, http.StatusBadRequest, CodeInvalidRequest},
		{"repository url with bad scheme", func(id string) string {
			return fmt.Sprintf(
				`{"project_id":%q,"target":{"kind":"repository","repository_url":"file:///etc/passwd"}}`, id)
		}, http.StatusBadRequest, CodeInvalidRequest},
		{"bad commit sha", func(id string) string {
			return fmt.Sprintf(
				`{"project_id":%q,"target":{"kind":"repository","repository_url":"https://github.com/a/b"},`+
					`"commit_sha":"nothex"}`, id)
		}, http.StatusBadRequest, CodeInvalidRequest},
		{"branch with argument injection", func(id string) string {
			return fmt.Sprintf(
				`{"project_id":%q,"target":{"kind":"repository","repository_url":"https://github.com/a/b"},`+
					`"branch":"--upload-pack=id"}`, id)
		}, http.StatusBadRequest, CodeInvalidRequest},
		{"bad scanner name", func(id string) string {
			return fmt.Sprintf(
				`{"project_id":%q,"target":{"kind":"repository","repository_url":"https://github.com/a/b"},`+
					`"scanners":["../../bin/sh"]}`, id)
		}, http.StatusBadRequest, CodeInvalidRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, projectStore, _ := newWiredServer(t, func(*Options) {})
			project := seedProject(t, projectStore)

			rec := authed(t, s, http.MethodPost, "/api/v1/scans", tc.body(project.ID))
			assertErrorCode(t, rec, tc.wantStatus, tc.wantCode)
		})
	}
}

// A scan whose job never reached the queue would otherwise sit in QUEUED
// forever, looking merely slow rather than broken.
func TestAScanThatCannotBeEnqueuedIsFailed(t *testing.T) {
	var scanStore *fakeScanStore
	s, projectStore, ss := newWiredServer(t, func(o *Options) {
		o.Queue = failingQueue{err: errors.New("redis is down")}
	})
	scanStore = ss
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodPost, "/api/v1/scans", createScanBody(project.ID))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	scanStore.mu.Lock()
	defer scanStore.mu.Unlock()
	if len(scanStore.finalized) != 1 {
		t.Fatalf("finalized %d scans, want 1", len(scanStore.finalized))
	}
	for id, reason := range scanStore.finalized {
		if reason != scans.FailureNotEnqueued {
			t.Errorf("scan %s: reason = %q, want %q", id, reason, scans.FailureNotEnqueued)
		}
		if got := scanStore.items[id].Status; got != scans.StatusFailed {
			t.Errorf("scan %s: status = %q, want failed", id, got)
		}
	}
}

func TestGetScanReturnsPerScannerDetail(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	scan := scanStore.seed(scans.Scan{
		ID:        newTestUUID(42),
		ProjectID: project.ID,
		Status:    scans.StatusPartial,
		Target:    scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://github.com/a/b"},
		Results: []scans.ScannerResult{
			{Scanner: "gitleaks", Status: scans.ScannerSucceeded, Version: "8.30.1"},
			{Scanner: "semgrep", Status: scans.ScannerFailed, Error: "scanner execution failed"},
		},
	})

	rec := authed(t, s, http.MethodGet, "/api/v1/scans/"+scan.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := decodeBody[scanResponse](t, rec)
	if len(got.Results) != 2 {
		t.Fatalf("returned %d results, want 2", len(got.Results))
	}
	// The whole point of PARTIAL: degraded coverage stays visible.
	if got.CompleteCoverage {
		t.Error("complete_coverage = true for a partial scan")
	}
	if len(got.DegradedScanners) != 1 || got.DegradedScanners[0] != "semgrep" {
		t.Errorf("degraded_scanners = %v, want [semgrep]", got.DegradedScanners)
	}
}

// A degradation reason must reach the client as a reason, not merely as a
// scanner name in degraded_scanners. A gate consuming this API has to be able
// to say WHY coverage is incomplete (§12).
//
// The JSON is asserted on the raw bytes rather than the decoded struct because
// the distinction that matters here -- `[]` versus `null` -- disappears once Go
// has unmarshalled it, and a client that has to special-case null is a client
// that will eventually forget to.
func TestScannerDegradationsReachTheClient(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	scan := scanStore.seed(scans.Scan{
		ID:        newTestUUID(43),
		ProjectID: project.ID,
		Status:    scans.StatusPartial,
		Target:    scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://github.com/a/b"},
		Results: []scans.ScannerResult{
			{Scanner: "gitleaks", Status: scans.ScannerSucceeded, Version: "8.30.1"},
			{Scanner: "syft", Status: scans.ScannerSucceeded, Version: "1.51.0",
				Degradations: []scanners.Degradation{scanners.DegradedOutputTruncated}},
		},
	})

	rec := authed(t, s, http.MethodGet, "/api/v1/scans/"+scan.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"degradations":["output_truncated"]`) {
		t.Errorf("response does not carry the reason: %s", body)
	}
	// The undegraded scanner must render an empty array, never null.
	if !strings.Contains(body, `"degradations":[]`) {
		t.Errorf("an undegraded result rendered null rather than []: %s", body)
	}
	if strings.Contains(body, `"degradations":null`) {
		t.Errorf("null degradations in response: %s", body)
	}

	got := decodeBody[scanResponse](t, rec)
	if got.CompleteCoverage {
		t.Error("complete_coverage = true despite a degraded scanner")
	}
	if len(got.DegradedScanners) != 1 || got.DegradedScanners[0] != "syft" {
		t.Errorf("degraded_scanners = %v, want [syft]", got.DegradedScanners)
	}
}

func TestGetScanNotFound(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	rec := authed(t, s, http.MethodGet, "/api/v1/scans/"+unknownUUID, "")
	assertErrorCode(t, rec, http.StatusNotFound, CodeNotFound)
}

func TestListProjectScans(t *testing.T) {
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)
	other := projectStore.seed(projects.Project{ID: newTestUUID(9), Name: "Other", Slug: "other"})

	scanStore.seed(scans.Scan{ID: newTestUUID(50), ProjectID: project.ID, Status: scans.StatusCompleted})
	scanStore.seed(scans.Scan{ID: newTestUUID(51), ProjectID: other.ID, Status: scans.StatusCompleted})

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/scans", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	page := decodeBody[listResponse[scanResponse]](t, rec)
	if len(page.Data) != 1 {
		t.Fatalf("returned %d scans, want 1 (the other project's scan leaked in)", len(page.Data))
	}
	if page.Data[0].ProjectID != project.ID {
		t.Errorf("project_id = %q, want %q", page.Data[0].ProjectID, project.ID)
	}
}

func TestListScansForUnknownProject(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+unknownUUID+"/scans", "")
	assertErrorCode(t, rec, http.StatusNotFound, CodeNotFound)
}

// --- information disclosure ------------------------------------------------

// A store failure must produce a fixed message. The driver error can carry a
// DSN, a hostname, or repository content (§15.3, §15.13).
func TestInternalErrorsDoNotLeakTheUnderlyingFailure(t *testing.T) {
	const secret = "postgres://secureops:hunter2@db.internal:5432/secureops"

	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	projectStore.listErr = errors.New("dial " + secret + ": connection refused")

	rec := authed(t, s, http.MethodGet, "/api/v1/projects", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("the response leaked the underlying error: %s", rec.Body.String())
	}

	env := decodeBody[ErrorEnvelope](t, rec)
	if env.Error.Message != "internal error" {
		t.Errorf("message = %q, want a fixed non-sensitive string", env.Error.Message)
	}
}

// Validation messages are logged, so a rejected value must not travel back
// through the error envelope.
func TestValidationErrorsDoNotEchoHostileInput(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	const hostile = "main$(curl attacker.example)"
	body := fmt.Sprintf(
		`{"project_id":%q,"target":{"kind":"repository","repository_url":"https://github.com/a/b"},"branch":%q}`,
		project.ID, hostile)

	rec := authed(t, s, http.MethodPost, "/api/v1/scans", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "curl") {
		t.Errorf("the error echoed the rejected branch: %s", rec.Body.String())
	}
}

// Every response carries the hardening headers, including error responses,
// which are the ones most likely to be rendered somewhere unexpected.
func TestSecurityHeadersArePresentOnErrors(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})

	rec := send(t, s, request{method: http.MethodGet, path: "/api/v1/projects"})

	for header, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Cache-Control":           "no-store",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}
