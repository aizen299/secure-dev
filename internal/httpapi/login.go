package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/aizen299/secure-dev/internal/users"
)

// loginRequest is the wire shape of POST /api/v1/auth/login.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginResponse carries the session and who it belongs to.
//
// The user is returned alongside the token so the caller can render a name and
// a role without a second request. It is the same User the store produces,
// which carries no password hash by construction.
type loginResponse struct {
	Token     string     `json:"token"`
	ExpiresAt time.Time  `json:"expires_at"`
	User      users.User `json:"user"`
}

// loginDelay is applied to every attempt, correct or not.
//
// Not a rate limiter. It makes each guess cost something, and it is applied
// uniformly so the delay itself reveals nothing -- the same reasoning ADR 029's
// login handler uses, kept identical so the two cannot disagree about how long
// a failure takes.
const loginDelay = 400 * time.Millisecond

// handleLogin exchanges an email and password for a session token (ADR 033).
//
// The one endpoint reachable without a credential, which governs everything
// about how it answers. Every failure is the same 401 with the same message:
// an unknown email, a wrong password, and a disabled account are
// indistinguishable, because distinguishing them tells an attacker which
// addresses are registered.
//
// The store does the matching work in every case, verifying against a decoy
// hash when no user matched, so the response time does not separate "no such
// user" from "wrong password" either.
func (s *Server) handleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.users == nil || s.sessions == nil {
			// A deployment with no identity configured. 501 rather than 401:
			// the credentials are not wrong, the feature is absent, and an
			// operator reading this needs to know the difference.
			writeError(w, r, http.StatusNotImplemented, CodeInternal,
				"user accounts are not configured on this server")
			return
		}

		var req loginRequest
		if err := decodeJSON(w, r, &req, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		time.Sleep(loginDelay)

		user, err := s.users.Authenticate(r.Context(), req.Email, req.Password)
		if err != nil {
			// A malformed stored hash is an operator's problem and reaches the
			// logs; the person at the form sees the same refusal either way.
			// Without this the difference would be visible as a 500.
			if !errors.Is(err, users.ErrNotFound) {
				loggerFrom(r.Context()).Error("login could not be evaluated",
					slog.String("error", err.Error()))
			} else {
				// Warn rather than info: repeated failures are the signal that
				// somebody is working through a list. The email is not logged
				// -- it is attacker-supplied, and logging it would let a log
				// reader harvest addresses somebody guessed at.
				loggerFrom(r.Context()).Warn("login failed")
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="secureops"`)
			writeError(w, r, http.StatusUnauthorized, CodeUnauthenticated,
				"the email or password is incorrect")
			return
		}

		now := s.now()
		token := s.sessions.Issue(user.ID, now)

		// Best-effort, and deliberately after the session is minted. A failure
		// to stamp the login time must not fail the sign-in: the timestamp is
		// observability, the sign-in is the security decision.
		if err := s.users.RecordLogin(r.Context(), user.ID); err != nil {
			loggerFrom(r.Context()).Warn("could not record the login time",
				slog.String("error", err.Error()))
		}

		loggerFrom(r.Context()).Info("signed in",
			slog.String("user_id", user.ID),
			slog.String("role", string(user.Role)))

		writeJSON(w, r, http.StatusOK, loginResponse{
			Token:     token,
			ExpiresAt: now.Add(users.SessionTTL),
			User:      user,
		})
	}
}

// handleWhoAmI reports the authenticated principal.
//
// Exists so the dashboard can render who is signed in and what they may do
// without keeping a second copy of that state in a cookie -- a copy the client
// would then be asserting rather than the server deciding.
func (s *Server) handleWhoAmI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFrom(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, CodeUnauthenticated, "valid credentials are required")
			return
		}

		type identity struct {
			Label  string   `json:"label"`
			Role   string   `json:"role"`
			UserID string   `json:"user_id,omitempty"`
			Global bool     `json:"global_scope"`
			Slugs  []string `json:"projects,omitempty"`
		}

		// A person's own role, not the credential role it maps onto.
		//
		// `engineer` maps to the `service` credential role internally, because
		// that is what requireRole understands (ADR 033 §2). Reporting that
		// here told an engineer they were a "service", which is both wrong and
		// exactly the confusion two role vocabularies invite. Found by reading
		// the response rather than by a test, which is why one exists now.
		role := string(principal.Role)
		if principal.IsUser() && s.users != nil {
			if user, err := s.users.ByID(r.Context(), principal.UserID); err == nil {
				role = string(user.Role)
			}
		}

		writeJSON(w, r, http.StatusOK, identity{
			Label:  principal.Label,
			Role:   role,
			UserID: principal.UserID,
			Global: principal.Scope.IsGlobal(),
			Slugs:  principal.Scope.Slugs(),
		})
	}
}
