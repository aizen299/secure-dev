package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/users"
)

type stubProbe struct {
	name  string
	err   error
	delay time.Duration
}

func (s stubProbe) Name() string { return s.name }

func (s stubProbe) Check(ctx context.Context) error {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func newTestServer(probes ...Probe) *Server {
	s, _, _ := newWiredServer(&testingT{}, func(*Options) {}, probes...)
	return s
}

// testingT satisfies the minimal interface testAuthenticator needs when there
// is no *testing.T to hand.
type testingT struct{}

func (testingT) Fatalf(format string, args ...any) { panic(fmt.Sprintf(format, args...)) }

// newWiredServer builds a Server with in-memory collaborators, returning them
// so a test can seed data and inject failures.
func newWiredServer(
	t interface{ Fatalf(string, ...any) }, customise func(*Options), probes ...Probe,
) (*Server, *fakeProjectStore, *fakeScanStore) {
	projectStore := newFakeProjectStore()
	scanStore := newFakeScanStore()
	findingStore := newFakeFindingStore()
	policyStore := &fakePolicyStore{}
	userStore := newFakeUserStore()

	opts := Options{
		Service:       "api",
		Version:       "test",
		Logger:        discardLogger(),
		Probes:        probes,
		Authenticator: testAuthenticator(t),
		Projects:      projectStore,
		Scans:         scanStore,
		Findings:      findingStore,
		Policies:      policyStore,
		Users:         userStore,
		Sessions:      users.NewSessions("a-test-signing-key-not-a-secret"),
		Queue:         queue.NewMemory(),
		// A fixed resolver keeps target validation off the network: a unit
		// test must not depend on DNS, and must not emit lookups for values
		// under test.
		Validator: scanners.Validator{
			WorkspaceRoot: "/tmp/secureops-test",
			Resolver:      publicResolver{},
		},
	}
	customise(&opts)

	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, projectStore, scanStore
}

// publicResolver answers every lookup with a routable public address, so the
// SSRF policy's decisions are driven by the test's input rather than by
// whatever the host's DNS happens to return.
type publicResolver struct{}

func (publicResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

// blockedResolver answers every lookup with a loopback address, the shape of a
// DNS-rebinding attempt against an internal service.
type blockedResolver struct{}

func (blockedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
}

func do(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	return rec
}

func TestLivenessIsIndependentOfDependencies(t *testing.T) {
	// A failing dependency must not make the process look dead, or an
	// orchestrator will restart a perfectly healthy API instance.
	s := newTestServer(stubProbe{name: "postgres", err: errors.New("down")})

	rec := do(t, s, http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body LivenessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body.Status != statusOK {
		t.Errorf("status = %q, want %q", body.Status, statusOK)
	}
	if body.Service != "api" || body.Version != "test" {
		t.Errorf("service/version = %q/%q, want api/test", body.Service, body.Version)
	}
}

func TestReadinessAllHealthy(t *testing.T) {
	s := newTestServer(stubProbe{name: "postgres"}, stubProbe{name: "redis"})

	rec := do(t, s, http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body ReadinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body.Status != statusOK {
		t.Errorf("status = %q, want %q", body.Status, statusOK)
	}
	if len(body.Dependencies) != 2 {
		t.Fatalf("dependencies = %d, want 2", len(body.Dependencies))
	}
	for _, d := range body.Dependencies {
		if d.Status != statusOK {
			t.Errorf("dependency %s = %q, want ok", d.Name, d.Status)
		}
	}
}

func TestReadinessReportsUnavailableDependency(t *testing.T) {
	s := newTestServer(
		stubProbe{name: "postgres"},
		stubProbe{name: "redis", err: errors.New("connection refused")},
	)

	rec := do(t, s, http.MethodGet, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	var body ReadinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body.Status != statusDegraded {
		t.Errorf("status = %q, want %q", body.Status, statusDegraded)
	}

	byName := map[string]DependencyState{}
	for _, d := range body.Dependencies {
		byName[d.Name] = d
	}
	if byName["postgres"].Status != statusOK {
		t.Errorf("postgres = %q, want ok", byName["postgres"].Status)
	}
	if byName["redis"].Status != statusUnavailable {
		t.Errorf("redis = %q, want unavailable", byName["redis"].Status)
	}
}

// A readiness endpoint is typically unauthenticated, so its body must not
// disclose internal topology or driver detail. See CLAUDE.md §15.3.
func TestReadinessDoesNotLeakDependencyErrorDetail(t *testing.T) {
	s := newTestServer(stubProbe{
		name: "postgres",
		err:  errors.New(`failed to connect to host=db.internal user=secureops password=hunter2`),
	})

	rec := do(t, s, http.MethodGet, "/readyz")
	body := rec.Body.String()

	for _, leak := range []string{"hunter2", "db.internal", "password"} {
		if strings.Contains(body, leak) {
			t.Errorf("readiness body leaked %q: %s", leak, body)
		}
	}
}

func TestReadinessWithNoProbesIsHealthy(t *testing.T) {
	rec := do(t, newTestServer(), http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadinessProbeTimeoutIsBounded(t *testing.T) {
	// The probe blocks far longer than probeTimeout; readiness must still
	// return rather than hanging the endpoint open.
	s := newTestServer(stubProbe{name: "slow", delay: 30 * time.Second})

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- do(t, s, http.MethodGet, "/readyz") }()

	select {
	case rec := <-done:
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", rec.Code)
		}
	case <-time.After(probeTimeout + 5*time.Second):
		t.Fatal("readiness did not return within the probe timeout")
	}
}

func TestVersionedHealthEndpoint(t *testing.T) {
	rec := do(t, newTestServer(), http.MethodGet, "/api/v1/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestNotFoundUsesErrorEnvelope(t *testing.T) {
	rec := do(t, newTestServer(), http.MethodGet, "/api/v1/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var body ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body.Error.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", body.Error.Code, CodeNotFound)
	}
	if body.Error.RequestID == "" {
		t.Error("error envelope is missing request_id")
	}
}

func TestMethodNotAllowedUsesErrorEnvelope(t *testing.T) {
	rec := do(t, newTestServer(), http.MethodDelete, "/healthz")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}

	var body ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body.Error.Code != CodeMethodInvalid {
		t.Errorf("code = %q, want %q", body.Error.Code, CodeMethodInvalid)
	}
}

func TestRequestIDIsServerGeneratedAndNotClientControlled(t *testing.T) {
	// Trusting a client-supplied request ID would let a caller poison log
	// correlation across tenants. See CLAUDE.md §15.7.
	s := newTestServer()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "attacker-supplied-id")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	got := rec.Header().Get("X-Request-Id")
	if got == "attacker-supplied-id" {
		t.Fatal("server echoed the client-supplied request ID")
	}
	if len(got) != 32 {
		t.Errorf("request id = %q, want 32 hex characters", got)
	}
}

func TestRequestIDsAreUnique(t *testing.T) {
	s := newTestServer()
	seen := map[string]bool{}
	for range 50 {
		rec := do(t, s, http.MethodGet, "/healthz")
		id := rec.Header().Get("X-Request-Id")
		if seen[id] {
			t.Fatalf("duplicate request id: %s", id)
		}
		seen[id] = true
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	rec := do(t, newTestServer(), http.MethodGet, "/healthz")

	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Cache-Control":           "no-store",
	}
	for header, expected := range want {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("%s = %q, want %q", header, got, expected)
		}
	}
}

func TestPanicIsRecoveredWithoutLeakingDetail(t *testing.T) {
	s := newTestServer()
	s.router.Get("/boom", func(http.ResponseWriter, *http.Request) {
		panic("secret internal detail: password=hunter2")
	})

	rec := do(t, s, http.MethodGet, "/boom")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Errorf("panic detail leaked to the client: %s", rec.Body.String())
	}

	var body ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body.Error.Code != CodeInternal {
		t.Errorf("code = %q, want %q", body.Error.Code, CodeInternal)
	}
}

func TestResponsesAreJSON(t *testing.T) {
	for _, path := range []string{"/healthz", "/readyz", "/api/v1/health", "/nope"} {
		rec := do(t, newTestServer(), http.MethodGet, path)
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s Content-Type = %q, want application/json", path, ct)
		}
	}
}
