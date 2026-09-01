package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// ProjectStore is the persistence this package needs for projects.
//
// The stores are interfaces so the HTTP layer can be tested without a
// database. They are declared here, at the consumer, so that the API depends on
// the operations it uses rather than on everything the store happens to expose.
type ProjectStore interface {
	Create(ctx context.Context, input projects.NewProject) (projects.Project, error)
	Get(ctx context.Context, id string) (projects.Project, error)
	Exists(ctx context.Context, id string) (bool, error)
	List(ctx context.Context, page projects.Page) ([]projects.Project, bool, error)
}

// ScanStore is the persistence this package needs for scans.
type ScanStore interface {
	Create(ctx context.Context, input scans.NewScan) (scans.Scan, error)
	Get(ctx context.Context, id string) (scans.Scan, error)
	ListByProject(ctx context.Context, projectID string, page scans.Page) ([]scans.Scan, bool, error)
	// Finalize is used on exactly one path: failing a scan whose job could not
	// be enqueued. The API never advances a scan's lifecycle otherwise -- that
	// is the worker's job.
	Finalize(ctx context.Context, scanID string, status scans.Status,
		reason scans.FailureReason, at time.Time) error
}

// FindingStore reads the canonical findings a scan produced.
//
// An interface so the API can be tested without a database, and so the handler
// layer depends on the question it asks rather than on pgx.
type FindingStore interface {
	ListByProject(ctx context.Context, projectID string,
		filter findings.Filter, page findings.Page) ([]findings.Record, bool, error)
	ListByScan(ctx context.Context, scanID string,
		page findings.Page) ([]findings.Record, bool, error)
	// ListIssues reads the correlated issues -- the contextual answer, as
	// opposed to the list of individual findings above.
	ListIssues(ctx context.Context, projectID string,
		page findings.Page) ([]findings.IssueRecord, bool, error)
}

// Server holds the API's dependencies and exposes the configured router.
type Server struct {
	service string
	version string
	logger  *slog.Logger
	probes  []Probe
	router  chi.Router

	authenticator   *auth.Authenticator
	projects        ProjectStore
	scans           ScanStore
	queue           queue.Queue
	validator       scanners.Validator
	findings        FindingStore
	maxRequestBytes int64
}

// Options configures a Server.
type Options struct {
	Service string
	Version string
	Logger  *slog.Logger
	Probes  []Probe

	// Authenticator gates every /api/v1 endpoint except health. Required: a
	// server built without one would serve an open API (ADR 006).
	Authenticator *auth.Authenticator
	Projects      ProjectStore
	Scans         ScanStore
	Queue         queue.Queue
	// Validator enforces the SSRF and path policy on submitted targets.
	Validator scanners.Validator
	// Findings reads the canonical findings a scan produced. Optional: a
	// server without one still serves scans, and the findings endpoints
	// report that they are unavailable rather than returning a misleading
	// empty list.
	Findings FindingStore
	// MaxRequestBytes caps a request body before it is parsed (§15.8).
	MaxRequestBytes int64
}

// DefaultMaxRequestBytes is used when Options leaves the cap unset. An
// unbounded body is a memory-exhaustion primitive, so there is no "no limit".
const DefaultMaxRequestBytes = 1 << 20

// New builds the API server and wires its routes.
//
// It returns an error rather than degrading, because every missing dependency
// here is a security-relevant misconfiguration: no authenticator means an open
// API, and a missing store means endpoints that 500 on first use. Both are
// failures that must stop startup, not surface as runtime surprises.
func New(opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxBytes := opts.MaxRequestBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxRequestBytes
	}

	var errs []error
	if opts.Authenticator == nil {
		errs = append(errs, errors.New("httpapi: an authenticator is required"))
	}
	if opts.Projects == nil {
		errs = append(errs, errors.New("httpapi: a project store is required"))
	}
	if opts.Scans == nil {
		errs = append(errs, errors.New("httpapi: a scan store is required"))
	}
	if opts.Queue == nil {
		errs = append(errs, errors.New("httpapi: a queue is required"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	s := &Server{
		service:         opts.Service,
		version:         opts.Version,
		logger:          logger,
		probes:          opts.Probes,
		authenticator:   opts.Authenticator,
		projects:        opts.Projects,
		scans:           opts.Scans,
		queue:           opts.Queue,
		validator:       opts.Validator,
		findings:        opts.Findings,
		maxRequestBytes: maxBytes,
	}
	s.router = s.routes()
	return s, nil
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()

	r.Use(requestID)
	r.Use(accessLog(s.logger))
	r.Use(recoverPanic)
	r.Use(securityHeaders)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "resource not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusMethodNotAllowed, CodeMethodInvalid, "method not allowed")
	})

	// Operational endpoints live outside /api/v1: they are probe targets for
	// Docker and Kubernetes, not part of the versioned public contract. They
	// are also deliberately unauthenticated -- a liveness check that needs a
	// credential is a liveness check that fails during a rotation.
	r.Get("/healthz", s.handleLiveness())
	r.Get("/readyz", s.handleReadiness())

	r.Route("/api/v1", func(r chi.Router) {
		// Health stays outside the authenticated group, for the same reason.
		r.Get("/health", s.handleLiveness())

		// Everything below requires a credential. The gate is applied to the
		// group rather than to each route, so a route added later is
		// authenticated by default rather than by remembering to say so.
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(auditLog)

			r.Route("/projects", func(r chi.Router) {
				r.Post("/", s.handleCreateProject())
				r.Get("/", s.handleListProjects())
				r.Get("/{projectID}", s.handleGetProject())
				r.Get("/{projectID}/scans", s.handleListProjectScans())
				r.Get("/{projectID}/findings", s.handleListProjectFindings())
				r.Get("/{projectID}/issues", s.handleListProjectIssues())
			})

			r.Route("/scans", func(r chi.Router) {
				// 202, never 200: the request must not block on scanner
				// execution (§13).
				r.Post("/", s.handleCreateScan())
				r.Get("/{scanID}", s.handleGetScan())
				r.Get("/{scanID}/findings", s.handleListScanFindings())
			})
		})
	})

	return r
}
