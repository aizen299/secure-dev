package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// probeTimeout bounds every dependency check so a hung backend cannot pin the
// readiness endpoint open (CLAUDE.md §14: bound every external interaction).
const probeTimeout = 2 * time.Second

// Probe is a readiness check for one downstream dependency.
type Probe interface {
	Name() string
	Check(ctx context.Context) error
}

// LivenessResponse is returned by GET /healthz.
type LivenessResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

// ReadinessResponse is returned by GET /readyz.
type ReadinessResponse struct {
	Status       string            `json:"status"`
	Dependencies []DependencyState `json:"dependencies"`
}

// DependencyState reports the outcome of a single probe.
type DependencyState struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	// Error is a fixed string, never the driver error, because a driver error
	// can contain host and credential detail (§15.3).
	Error string `json:"error,omitempty"`
}

const (
	statusOK          = "ok"
	statusDegraded    = "degraded"
	statusUnavailable = "unavailable"
)

// handleLiveness reports process health only. It never touches a dependency:
// a database outage must not cause orchestrators to kill healthy API pods.
func (s *Server) handleLiveness() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, r, http.StatusOK, LivenessResponse{
			Status:  statusOK,
			Service: s.service,
			Version: s.version,
		})
	}
}

// handleReadiness probes every dependency concurrently and returns 503 when any
// is unhealthy, so traffic is not routed to an instance that cannot serve it.
func (s *Server) handleReadiness() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
		defer cancel()

		states := make([]DependencyState, len(s.probes))
		var wg sync.WaitGroup

		for i, p := range s.probes {
			wg.Add(1)
			go func(i int, p Probe) {
				defer wg.Done()
				state := DependencyState{Name: p.Name(), Status: statusOK}
				if err := p.Check(ctx); err != nil {
					state.Status = statusUnavailable
					state.Error = "dependency check failed"
					loggerFrom(r.Context()).Warn("readiness probe failed",
						slog.String("dependency", p.Name()),
						slog.String("error", err.Error()),
					)
				}
				states[i] = state
			}(i, p)
		}
		wg.Wait()

		status := http.StatusOK
		overall := statusOK
		for _, st := range states {
			if st.Status != statusOK {
				status = http.StatusServiceUnavailable
				overall = statusDegraded
				break
			}
		}

		writeJSON(w, r, status, ReadinessResponse{Status: overall, Dependencies: states})
	}
}
