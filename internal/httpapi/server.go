package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/policies"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
	"github.com/aizen299/secure-dev/internal/users"
)

// ProjectStore is the persistence this package needs for projects.
//
// The stores are interfaces so the HTTP layer can be tested without a
// database. They are declared here, at the consumer, so that the API depends on
// the operations it uses rather than on everything the store happens to expose.
type ProjectStore interface {
	Create(ctx context.Context, input projects.NewProject, actor audit.Actor) (projects.Project, error)
	Get(ctx context.Context, id string) (projects.Project, error)
	Exists(ctx context.Context, id string) (bool, error)
	// List takes a scope, so a handler cannot forget to pass one: the compiler
	// asks for it (ADR 033).
	List(ctx context.Context, page projects.Page, scope auth.Scope) ([]projects.Project, bool, error)
}

// ScanStore is the persistence this package needs for scans.
type ScanStore interface {
	Create(ctx context.Context, input scans.NewScan, actor audit.Actor) (scans.Scan, error)
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
	// LatestRiskScore and RiskHistory serve the project score (§10). Reads
	// only: the API never computes a score, because scoring runs after
	// correlation on the worker and an API-side recomputation would answer
	// "what would we say now" rather than "what did we say then".
	LatestRiskScore(ctx context.Context, projectID string) (findings.RiskRecord, error)
	RiskHistory(ctx context.Context, projectID string, limit int) ([]findings.RiskRecord, error)
	// LoadRiskInputs serves remediation, which is derived on read rather than
	// stored so an action's status cannot drift from its members' (ADR 020).
	LoadRiskInputs(ctx context.Context, projectID string) ([]risk.Subject, risk.Context, error)
	// Transition and History are the human half of the finding lifecycle
	// (ADR 024). Triage, so they require `service` rather than `admin`:
	// gating dismissal behind admin would push teams to weaken the policy
	// instead, which is the worse outcome.
	Transition(ctx context.Context, findingID string,
		req findings.TransitionRequest, actor audit.Actor) (findings.TransitionRecord, error)
	History(ctx context.Context, findingID string) ([]findings.TransitionRecord, error)
	// ProjectOf resolves a finding's owner, so an endpoint addressed by
	// finding id can be scope-checked before it answers (ADR 033).
	ProjectOf(ctx context.Context, findingID string) (string, error)
}

// PolicyStore reads and writes gate configuration and its verdicts.
//
// Separate from FindingStore because a policy is a human's configuration
// rather than a scan's output, and because changing one is the most
// security-sensitive write in the API (ADR 022).
type PolicyStore interface {
	Get(ctx context.Context, projectID string) (policies.Policy, error)
	Set(ctx context.Context, projectID string, policy policies.Policy, actor audit.Actor) error
	GetResult(ctx context.Context, scanID string) (policies.ResultRecord, error)
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
	policies        PolicyStore
	users           UserStore
	sessions        *users.Sessions
	maxRequestBytes int64

	// now is the clock, injectable so session expiry can be tested without
	// sleeping. Defaults to time.Now.
	now func() time.Time
}

// Options configures a Server.
type Options struct {
	Service string
	Version string
	Logger  *slog.Logger
	Probes  []Probe

	// Users and Sessions enable person-based authentication (ADR 033).
	//
	// Optional together: a deployment without them still authenticates
	// configured tokens, and a session token simply is not a credential it can
	// verify. Wiring one without the other is a configuration error rather
	// than a half-working login, so New refuses it.
	Users    UserStore
	Sessions *users.Sessions

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
	// Policies reads and writes the security gate. Optional: without it the
	// policy and gate endpoints report themselves unavailable rather than
	// implying a project has no gate.
	Policies PolicyStore
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
	// Both or neither. One without the other is a login that authenticates and
	// cannot resolve a role, or a session verifier with nobody to verify --
	// either way a half-working identity system, which is worse than none
	// because it looks like it works.
	if (opts.Users == nil) != (opts.Sessions == nil) {
		errs = append(errs, errors.New(
			"httpapi: a user store and a session signer must be provided together"))
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
		policies:        opts.Policies,
		users:           opts.Users,
		sessions:        opts.Sessions,
		maxRequestBytes: maxBytes,
		now:             time.Now,
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
		// Outside requireAuth, and the only endpoint that is: it exists to
		// obtain a credential, so requiring one would be circular (ADR 033).
		r.Post("/auth/login", s.handleLogin())

		// Health stays outside the authenticated group, for the same reason.
		r.Get("/health", s.handleLiveness())

		// Everything below requires a credential. The gate is applied to the
		// group rather than to each route, so a route added later is
		// authenticated by default rather than by remembering to say so.
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(auditLog)

			r.Route("/projects", func(r chi.Router) {
				r.With(requireRole(auth.RoleService)).Post("/", s.handleCreateProject())
				r.Get("/", s.handleListProjects())

				// Everything addressed by project id goes through
				// scopedProject, which resolves the project and refuses one the
				// caller's scope does not reach (ADR 033). A subtree rather
				// than a call per handler: a route added below is scoped by
				// existing, not by somebody remembering.
				r.Group(func(r chi.Router) {
					r.Use(s.scopedProject)

					r.Get("/{projectID}", s.handleGetProject())
					r.Get("/{projectID}/scans", s.handleListProjectScans())
					r.Get("/{projectID}/findings", s.handleListProjectFindings())
					r.Get("/{projectID}/issues", s.handleListProjectIssues())
					r.Get("/{projectID}/risk", s.handleGetProjectRisk())
					r.Get("/{projectID}/remediation", s.handleGetProjectRemediation())
					r.Get("/{projectID}/policy", s.handleGetProjectPolicy())
					// The most security-sensitive write in the API: it can
					// switch the gate off. Admin only, so the CI credential
					// that submits scans cannot disable the gate judging them
					// (ADR 023) -- and now only for a project that credential
					// is scoped to (ADR 033).
					r.With(requireRole(auth.RoleAdmin)).Put("/{projectID}/policy", s.handleSetProjectPolicy())
				})
			})

			r.Route("/findings", func(r chi.Router) {
				r.Get("/{findingID}/history", s.handleGetFindingHistory())
				// Triage, not administration. Requiring admin here would make
				// weakening the policy the easier path to the same outcome.
				r.With(requireRole(auth.RoleService)).
					Post("/{findingID}/status", s.handleTransitionFinding())
			})

			// Read-only, and `service` rather than `viewer` because it
			// resolves a caller-supplied hostname (ADR 032). Its own route
			// rather than a query on /scans: nothing about it creates a scan.
			r.Get("/auth/me", s.handleWhoAmI())

			r.Route("/targets", func(r chi.Router) {
				r.With(requireRole(auth.RoleService)).Post("/validate", s.handleValidateTarget())
			})

			r.Route("/scans", func(r chi.Router) {
				// 202, never 200: the request must not block on scanner
				// execution (§13).
				r.With(requireRole(auth.RoleService)).Post("/", s.handleCreateScan())
				r.Get("/{scanID}", s.handleGetScan())
				r.Get("/{scanID}/findings", s.handleListScanFindings())
				r.Get("/{scanID}/gate", s.handleGetScanGate())
			})
		})
	})

	return r
}
