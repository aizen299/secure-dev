package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aizen299/secure-dev/internal/auth"
)

// PrincipalFrom returns the authenticated client bound to ctx.
//
// The boolean is not decoration: a handler that reads a principal from an
// unauthenticated route would silently get the zero value, and attribute an
// action to "". Callers must check it.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(principalKey).(auth.Principal)
	return p, ok
}

// requireAuth rejects any request without a recognised bearer token.
//
// This is the interim gate from ADR 006: it authenticates, it does not
// authorize. Every valid token reaches every project, so this is safe only for
// a single-tenant deployment. Phase 11 replaces it with real identity and RBAC.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.authenticator.Authenticate(r.Header.Get("Authorization"))
		if err != nil {
			// WWW-Authenticate tells a well-behaved client what to present.
			// It carries no detail about why this attempt failed.
			w.Header().Set("WWW-Authenticate", `Bearer realm="secureops"`)

			// Logged at warn: repeated failures are the signal that someone is
			// probing. The presented token is never logged, not even a prefix.
			loggerFrom(r.Context()).Warn("authentication failed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			)
			writeError(w, r, http.StatusUnauthorized, CodeUnauthenticated, "valid credentials are required")
			return
		}

		ctx := context.WithValue(r.Context(), principalKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// auditLog records security-sensitive actions with their actor.
//
// This is an interim measure, and it is not the audit log §15.6 requires: there
// is no append-only store, no before/after values, and no queryable history.
// Phase 11 owns that. What it does buy now is that no mutating request reaches
// a handler without the actor being recorded somewhere, so the audit trail does
// not start at zero when the table arrives.
func auditLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMutation(r.Method) {
			next.ServeHTTP(w, r)
			return
		}

		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		principal, ok := PrincipalFrom(r.Context())
		actor := "unauthenticated"
		if ok {
			actor = principal.Label
		}

		loggerFrom(r.Context()).Info("security-sensitive action",
			slog.String("actor", actor),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
		)
	})
}

func isMutation(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
