package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"

	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// specPath is the contract. CLAUDE.md §18 requires it to stay in sync with the
// handlers, and §25.17 forbids changing a public API contract silently. Until
// this file existed both were enforced by discipline alone: a handler could
// change shape and every check still passed.
const specPath = "../../docs/api/openapi.yaml"

func loadSpec(t *testing.T) (libopenapi.Document, validator.Validator) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}
	doc, err := libopenapi.NewDocument(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	v, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		t.Fatalf("build validator: %v", errs)
	}
	return doc, v
}

// TestOpenAPISpecIsValid is the weak check: the document itself is well formed.
//
// It catches a malformed spec -- a broken $ref, an undefined schema, an invalid
// type -- and nothing else. On its own it would NOT satisfy §18, because a spec
// can be perfectly valid and still describe an API the handlers no longer
// serve. TestOpenAPIMatchesHandlers below is the one that catches drift.
func TestOpenAPISpecIsValid(t *testing.T) {
	doc, v := loadSpec(t)

	if got := doc.GetVersion(); !strings.HasPrefix(got, "3.1") {
		t.Errorf("spec version = %q, want 3.1.x", got)
	}
	if _, err := doc.BuildV3Model(); err != nil {
		t.Fatalf("build model: %v", err)
	}

	ok, errs := v.ValidateDocument()
	for _, e := range errs {
		t.Errorf("spec: %s", e.Message)
		for _, sv := range e.SchemaValidationErrors {
			t.Errorf("  %s", sv.Reason)
		}
	}
	if !ok {
		t.Error("openapi.yaml is not a valid OpenAPI document")
	}
}

// TestEveryRouteIsDocumented closes the hole in the test below.
//
// TestOpenAPIMatchesHandlers walks a hand-written list of routes, so an
// endpoint added to the router and forgotten in the spec would simply never be
// exercised -- the check would pass by not looking. This walks the real chi
// router instead and compares it against the spec's declared paths in both
// directions: a route with no documentation, and documentation for a route that
// does not exist.
func TestEveryRouteIsDocumented(t *testing.T) {
	doc, _ := loadSpec(t)
	model, err := doc.BuildV3Model()
	if err != nil {
		t.Fatalf("build model: %v", err)
	}

	documented := map[string]bool{}
	for pair := model.Model.Paths.PathItems.First(); pair != nil; pair = pair.Next() {
		documented[normalisePath(pair.Key())] = true
	}

	s, _, _ := newWiredServer(t, func(*Options) {})
	routed := map[string]bool{}
	walkErr := chi.Walk(s.router, func(
		method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler,
	) error {
		routed[normalisePath(route)] = true
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk router: %v", walkErr)
	}

	for route := range routed {
		if !documented[route] {
			t.Errorf("route %s is served but not in openapi.yaml (§18)", route)
		}
	}
	for path := range documented {
		if !routed[path] {
			t.Errorf("openapi.yaml documents %s, which no route serves", path)
		}
	}
}

// normalisePath reduces chi's "/{projectID}" and the spec's "/{projectID}" to a
// common form, so the comparison is about which endpoints exist rather than
// what each side happened to name its parameters, and ignores chi's trailing
// slash on subrouters.
func normalisePath(p string) string {
	p = braces.ReplaceAllString(p, "{}")
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

var braces = regexp.MustCompile(`\{[^}]*\}`)

// TestOpenAPIMatchesHandlers is the check that actually enforces §18.
//
// It drives the real router and validates every response against the schema the
// spec publishes for that route and status. A handler that gains, loses, or
// renames a field without the spec following fails here -- which is the drift
// the rule is about, and which no amount of linting the YAML would catch.
//
// Responses are validated, requests are not: request validation would only
// re-test the handlers' own input validation, which is covered directly
// elsewhere. What has no other coverage is whether what we SEND matches what we
// PUBLISHED.
func TestOpenAPIMatchesHandlers(t *testing.T) {
	_, v := loadSpec(t)
	s, projectStore, scanStore := newWiredServer(t, func(*Options) {})

	project := seedProject(t, projectStore)
	scan := scanStore.seed(scans.Scan{
		ID:        newTestUUID(91),
		ProjectID: project.ID,
		Status:    scans.StatusPartial,
		Target:    scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://github.com/a/b"},
		Results: []scans.ScannerResult{
			{Scanner: "gitleaks", Status: scans.ScannerSucceeded, Version: "8.30.1"},
			{Scanner: "syft", Status: scans.ScannerSucceeded, Version: "1.51.0",
				Degradations: []scanners.Degradation{scanners.DegradedOutputTruncated}},
			{Scanner: "semgrep", Status: scans.ScannerFailed, Error: "scanner execution failed"},
		},
	})

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		auth   bool
		want   int
	}{
		{"liveness", http.MethodGet, "/healthz", "", false, http.StatusOK},
		{"readiness", http.MethodGet, "/readyz", "", false, http.StatusOK},
		{"health", http.MethodGet, "/api/v1/health", "", true, http.StatusOK},
		{"list projects", http.MethodGet, "/api/v1/projects", "", true, http.StatusOK},
		{"get project", http.MethodGet, "/api/v1/projects/" + project.ID, "", true, http.StatusOK},
		{"list project scans", http.MethodGet, "/api/v1/projects/" + project.ID + "/scans", "", true, http.StatusOK},
		{"get scan", http.MethodGet, "/api/v1/scans/" + scan.ID, "", true, http.StatusOK},
		{
			"create project", http.MethodPost, "/api/v1/projects",
			`{"name":"Payments","slug":"payments","environment":"production","criticality":"high"}`,
			true, http.StatusCreated,
		},
		{
			"create scan", http.MethodPost, "/api/v1/scans",
			`{"project_id":"` + project.ID + `","target":{"kind":"repository","repository_url":"https://github.com/a/b"}}`,
			true, http.StatusAccepted,
		},
		// Error envelopes are part of the published contract too, and are the
		// responses most likely to drift: they are rarely looked at.
		{"not found", http.MethodGet, "/api/v1/scans/" + newTestUUID(200), "", true, http.StatusNotFound},
		{"unauthenticated", http.MethodGet, "/api/v1/projects", "", false, http.StatusUnauthorized},
		{"malformed body", http.MethodPost, "/api/v1/projects", `{`, true, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := request{method: tc.method, path: tc.path, body: tc.body}
			if tc.auth {
				req.token = testToken
			}
			rec := send(t, s, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
			assertMatchesSpec(t, v, tc.method, tc.path, rec)
		})
	}
}

// assertMatchesSpec validates one recorded response against the specification.
func assertMatchesSpec(
	t *testing.T, v validator.Validator, method, path string, rec *httptest.ResponseRecorder,
) {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(), method, "http://secureops.test"+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp := &http.Response{
		StatusCode: rec.Code,
		Header:     rec.Header().Clone(),
		Body:       io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
	}

	ok, errs := v.ValidateHttpResponse(req, resp)
	if ok {
		return
	}
	for _, e := range errs {
		t.Errorf("response does not match the published contract: %s", e.Message)
		for _, sv := range e.SchemaValidationErrors {
			t.Errorf("  %s", sv.Reason)
		}
	}
	t.Errorf("  body was: %s", rec.Body.String())
}
