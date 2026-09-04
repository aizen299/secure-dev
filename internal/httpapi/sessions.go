package httpapi

import (
	"context"
	"errors"
	"strings"

	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/users"
)

// UserStore is what the API needs from the users package.
//
// An interface here rather than the concrete store, for the same reason every
// other store is one: the handler tests must be able to exercise the
// authentication paths -- which is where information disclosure happens --
// without a database.
type UserStore interface {
	Authenticate(ctx context.Context, email, password string) (users.User, error)
	ByID(ctx context.Context, id string) (users.User, error)
	ScopeOf(ctx context.Context, user users.User) (auth.Scope, error)
	RecordLogin(ctx context.Context, userID string) error
}

// principalForSession turns a verified session token into a principal.
//
// The user is loaded on EVERY request rather than trusted from the token. That
// is what makes a stateless session revocable: disabling an account takes
// effect on the next request instead of at the next restart (ADR 033 §5a).
//
// Role and scope come from the database for the same reason. A token that
// carried them would keep granting yesterday's access after an admin changed
// them, and the change would appear to have worked.
func (s *Server) principalForSession(ctx context.Context, token string) (auth.Principal, error) {
	if s.sessions == nil || s.users == nil {
		// A deployment without identity wired: a session token is simply not a
		// credential it can verify, and must not be treated as one.
		return auth.Principal{}, auth.ErrUnauthenticated
	}

	userID, err := s.sessions.Verify(token, s.now())
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}

	user, err := s.users.ByID(ctx, userID)
	if err != nil {
		// Includes a user that has been deleted since the token was issued.
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	if user.Disabled {
		return auth.Principal{}, auth.ErrUnauthenticated
	}

	scope, err := s.users.ScopeOf(ctx, user)
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}

	return auth.Principal{
		// The label is the email, because this one IS shown: it is what a log
		// line and an error message need to be readable by a person. The audit
		// trail uses the id instead, which is stable across a rename.
		Label:  user.Email,
		Role:   roleForUser(user.Role),
		Scope:  scope,
		UserID: user.ID,
	}, nil
}

// roleForUser maps a person's role onto the credential roles the API's
// requireRole middleware already understands.
//
// Two vocabularies rather than one, deliberately (ADR 033 §2): `service` is a
// machine role no person can hold, and `engineer` is a person's role no token
// can hold. This is the one place they meet, and it is a total function so a
// new user role cannot silently fall through to something permissive.
func roleForUser(r users.Role) auth.Role {
	switch r {
	case users.RoleAdmin:
		return auth.RoleAdmin
	case users.RoleEngineer:
		// Everything a service credential may do -- submit scans, triage
		// findings -- plus policy editing, which requireRole gates at admin.
		// An engineer editing a policy is handled by the handler's own check
		// rather than by widening this, because widening it would also grant
		// user management.
		return auth.RoleService
	case users.RoleViewer:
		return auth.RoleViewer
	default:
		// Unreachable: users.Role is validated on the way in. Stated as the
		// least privilege rather than left to a zero value, so a role added
		// later without updating this map fails closed.
		return auth.RoleViewer
	}
}

// bearerToken extracts the value of an Authorization header.
//
// Duplicated from the authenticator rather than exported from it, because the
// authenticator's copy is on the constant-time path and must not grow callers
// that change its shape.
func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return header[len(prefix):]
}

// authenticate resolves a request's principal from either kind of credential.
//
// Routed by prefix, never by trying one and falling back to the other: a
// fallback would mean a failed session verification silently reaching the
// token path, where a value crafted to look like both could be tested against
// two verifiers.
func (s *Server) authenticate(ctx context.Context, header string) (auth.Principal, error) {
	if token := bearerToken(header); users.LooksLikeSession(token) {
		return s.principalForSession(ctx, token)
	}
	principal, err := s.authenticator.Authenticate(header)
	if err != nil {
		return auth.Principal{}, errors.Join(err)
	}
	return principal, nil
}
