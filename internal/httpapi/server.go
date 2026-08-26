package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Server holds the API's dependencies and exposes the configured router.
type Server struct {
	service string
	version string
	logger  *slog.Logger
	probes  []Probe
	router  chi.Router
}

// Options configures a Server.
type Options struct {
	Service string
	Version string
	Logger  *slog.Logger
	Probes  []Probe
}

// New builds the API server and wires its routes.
func New(opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		service: opts.Service,
		version: opts.Version,
		logger:  logger,
		probes:  opts.Probes,
	}
	s.router = s.routes()
	return s
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
	// Docker and Kubernetes, not part of the versioned public contract.
	r.Get("/healthz", s.handleLiveness())
	r.Get("/readyz", s.handleReadiness())

	// The versioned API surface. Phase 1 establishes the mount point and the
	// error contract; resources arrive in later phases.
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleLiveness())
	})

	return r
}
