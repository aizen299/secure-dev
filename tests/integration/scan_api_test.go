//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/httpapi"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// Synthetic credential. Real secrets in fixtures are forbidden (§19).
// Word-shaped rather than random hex: see internal/auth/auth_test.go.
const apiTestToken = "secureops-integration-not-a-secret"

// publicResolver keeps target validation off the network. Without it this test
// would depend on DNS, and on whatever github.com happens to resolve to.
type publicResolver struct{}

func (publicResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

// newAPI wires the real stores and the real Redis queue behind the real router.
// Only DNS is substituted.
func newAPI(t *testing.T, pool *pgxpool.Pool, q queue.Queue) *httptest.Server {
	t.Helper()

	authenticator, err := auth.New([]string{"integration:admin:*:" + apiTestToken})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	handler, err := httpapi.New(httpapi.Options{
		Service:       "secureops-api",
		Version:       "itest",
		Logger:        slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Authenticator: authenticator,
		Projects:      projects.NewStore(pool),
		Scans:         scans.NewStore(pool),
		Queue:         q,
		Validator: scanners.Validator{
			WorkspaceRoot: t.TempDir(),
			Resolver:      publicResolver{},
		},
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func apiRequest(t *testing.T, srv *httptest.Server, method, path, body, token string) (int, []byte) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, payload
}

// cleanupProject removes a project and everything cascading from it.
func cleanupProject(t *testing.T, pool *pgxpool.Pool, projectID string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, projectID)
	})
}

// The whole Phase 3 path against real infrastructure: authenticate, create a
// project, submit a scan, confirm it is persisted and enqueued, and read it
// back with its per-scanner detail.
func TestScanAPIEndToEnd(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)

	key := "itest:api:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	srv := newAPI(t, pool, queue.NewRedis(client, key))

	// --- create a project ---
	slug := "itest-" + uuid.NewString()[:8]
	status, body := apiRequest(t, srv, http.MethodPost, "/api/v1/projects",
		fmt.Sprintf(`{"name":"Integration","slug":%q,"environment":"production","criticality":"high"}`, slug),
		apiTestToken)
	if status != http.StatusCreated {
		t.Fatalf("create project: status = %d, want 201 (body: %s)", status, body)
	}

	var project projects.Project
	if err := json.Unmarshal(body, &project); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	cleanupProject(t, pool, project.ID)

	if project.Environment != projects.EnvProduction {
		t.Errorf("environment = %q, want production", project.Environment)
	}

	// --- submit a scan ---
	scanBody := fmt.Sprintf(
		`{"project_id":%q,"target":{"kind":"repository","repository_url":"https://github.com/acme/app"},`+
			`"branch":"main","commit_sha":"abcdef1234567","scanners":["gitleaks","semgrep"]}`, project.ID)

	status, body = apiRequest(t, srv, http.MethodPost, "/api/v1/scans", scanBody, apiTestToken)
	if status != http.StatusAccepted {
		t.Fatalf("create scan: status = %d, want 202 (body: %s)", status, body)
	}

	var created struct {
		ID                string       `json:"id"`
		Status            scans.Status `json:"status"`
		RequestedScanners []string     `json:"requested_scanners"`
		CompleteCoverage  bool         `json:"complete_coverage"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	if created.Status != scans.StatusQueued {
		t.Errorf("status = %q, want queued", created.Status)
	}
	// A queued scan has run nothing, so it cannot claim coverage.
	if created.CompleteCoverage {
		t.Error("a queued scan reported complete coverage")
	}
	// Stored sorted and deduplicated, so the same request always yields the
	// same selection.
	if len(created.RequestedScanners) != 2 ||
		created.RequestedScanners[0] != "gitleaks" || created.RequestedScanners[1] != "semgrep" {
		t.Errorf("requested_scanners = %v, want [gitleaks semgrep]", created.RequestedScanners)
	}

	// --- the job really reached Redis ---
	n, err := queue.NewRedis(client, key).Len(t.Context())
	if err != nil {
		t.Fatalf("queue length: %v", err)
	}
	if n != 1 {
		t.Fatalf("queue holds %d jobs, want 1", n)
	}

	// --- the target round-trips through jsonb intact ---
	var storedTarget []byte
	err = pool.QueryRow(t.Context(), `SELECT target FROM scans WHERE id = $1`, created.ID).Scan(&storedTarget)
	if err != nil {
		t.Fatalf("read stored target: %v", err)
	}
	var target scanners.Target
	if err := json.Unmarshal(storedTarget, &target); err != nil {
		t.Fatalf("decode stored target: %v", err)
	}
	if target.Kind != scanners.KindRepository || target.RepositoryURL != "https://github.com/acme/app" {
		t.Errorf("stored target = %+v, want the submitted repository target", target)
	}

	// --- read it back ---
	status, body = apiRequest(t, srv, http.MethodGet, "/api/v1/scans/"+created.ID, "", apiTestToken)
	if status != http.StatusOK {
		t.Fatalf("get scan: status = %d, want 200 (body: %s)", status, body)
	}

	// --- and it appears in the project's history ---
	status, body = apiRequest(t, srv, http.MethodGet,
		"/api/v1/projects/"+project.ID+"/scans", "", apiTestToken)
	if status != http.StatusOK {
		t.Fatalf("list scans: status = %d, want 200 (body: %s)", status, body)
	}
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode scan list: %v", err)
	}
	if len(page.Data) != 1 || page.Data[0].ID != created.ID {
		t.Errorf("scan list = %+v, want exactly the created scan", page.Data)
	}
}

// The per-scanner detail a PARTIAL scan needs must survive the round trip
// through PostgreSQL, or the API would report a status nobody can act on.
func TestScanAPIReturnsPersistedScannerResults(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)

	key := "itest:api:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	srv := newAPI(t, pool, queue.NewRedis(client, key))
	store := scans.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	_ = projectID

	started := time.Now().UTC().Truncate(time.Millisecond)
	results := []scans.ScannerResult{
		{
			Scanner: "gitleaks", Status: scans.ScannerSucceeded,
			Version: "8.30.1", ExitCode: 0, Duration: 1500 * time.Millisecond, StartedAt: &started,
		},
		{
			Scanner: "semgrep", Status: scans.ScannerFailed,
			ExitCode: 2, Duration: 300 * time.Millisecond,
			Error: "scanner execution failed", StartedAt: &started,
		},
	}
	for _, r := range results {
		if err := store.RecordScannerResult(t.Context(), scanID, r); err != nil {
			t.Fatalf("record %s: %v", r.Scanner, err)
		}
	}
	if err := store.MarkRunning(t.Context(), scanID, started); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	if err := store.Finalize(t.Context(), scanID, scans.StatusPartial, "", time.Now().UTC()); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	status, body := apiRequest(t, srv, http.MethodGet, "/api/v1/scans/"+scanID, "", apiTestToken)
	if status != http.StatusOK {
		t.Fatalf("get scan: status = %d, want 200 (body: %s)", status, body)
	}

	var got struct {
		Status           scans.Status `json:"status"`
		CompleteCoverage bool         `json:"complete_coverage"`
		DegradedScanners []string     `json:"degraded_scanners"`
		Results          []struct {
			Scanner    string `json:"scanner"`
			Status     string `json:"status"`
			Version    string `json:"version"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode scan: %v", err)
	}

	if got.Status != scans.StatusPartial {
		t.Errorf("status = %q, want partial", got.Status)
	}
	// The §13 guarantee, asserted against real persistence: a scan with a
	// failed scanner never reads as complete coverage.
	if got.CompleteCoverage {
		t.Error("complete_coverage = true for a scan with a failed scanner")
	}
	if len(got.DegradedScanners) != 1 || got.DegradedScanners[0] != "semgrep" {
		t.Errorf("degraded_scanners = %v, want [semgrep]", got.DegradedScanners)
	}
	if len(got.Results) != 2 {
		t.Fatalf("returned %d results, want 2", len(got.Results))
	}
	if got.Results[0].Scanner != "gitleaks" || got.Results[0].Version != "8.30.1" {
		t.Errorf("first result = %+v, want the gitleaks result with its version", got.Results[0])
	}
	if got.Results[0].DurationMS != 1500 {
		t.Errorf("duration_ms = %d, want 1500", got.Results[0].DurationMS)
	}
}

// A failure reason is persisted and returned, so a scan that failed before any
// scanner ran can still explain itself.
func TestFailureReasonRoundTrips(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)

	key := "itest:api:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	srv := newAPI(t, pool, queue.NewRedis(client, key))
	store := scans.NewStore(pool)

	scanID, _ := seedScan(t, pool)
	err := store.Finalize(t.Context(), scanID, scans.StatusFailed,
		scans.FailureNoScannerAvailable, time.Now().UTC())
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}

	status, body := apiRequest(t, srv, http.MethodGet, "/api/v1/scans/"+scanID, "", apiTestToken)
	if status != http.StatusOK {
		t.Fatalf("get scan: status = %d, want 200", status)
	}

	var got struct {
		Status        scans.Status `json:"status"`
		FailureReason string       `json:"failure_reason"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	if got.Status != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got.Status)
	}
	if got.FailureReason != string(scans.FailureNoScannerAvailable) {
		t.Errorf("failure_reason = %q, want %q", got.FailureReason, scans.FailureNoScannerAvailable)
	}
}

// The slug uniqueness constraint must surface as a 409, not a 500 from a
// driver error escaping the store.
func TestDuplicateSlugIsAConflict(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)

	key := "itest:api:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })
	srv := newAPI(t, pool, queue.NewRedis(client, key))

	slug := "itest-" + uuid.NewString()[:8]
	body := fmt.Sprintf(`{"name":"Integration","slug":%q}`, slug)

	status, payload := apiRequest(t, srv, http.MethodPost, "/api/v1/projects", body, apiTestToken)
	if status != http.StatusCreated {
		t.Fatalf("first create: status = %d, want 201 (body: %s)", status, payload)
	}
	var project projects.Project
	if err := json.Unmarshal(payload, &project); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	cleanupProject(t, pool, project.ID)

	status, payload = apiRequest(t, srv, http.MethodPost, "/api/v1/projects", body, apiTestToken)
	if status != http.StatusConflict {
		t.Fatalf("duplicate slug: status = %d, want 409 (body: %s)", status, payload)
	}
}

// Authentication is enforced against the real router, not only in unit tests.
func TestIntegrationEndpointsRejectMissingCredentials(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)

	key := "itest:api:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })
	srv := newAPI(t, pool, queue.NewRedis(client, key))

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/projects", `{"name":"x"}`},
		{http.MethodGet, "/api/v1/projects", ""},
		{http.MethodPost, "/api/v1/scans", `{}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			status, _ := apiRequest(t, srv, tc.method, tc.path, tc.body, "")
			if status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", status)
			}
		})
	}
}
