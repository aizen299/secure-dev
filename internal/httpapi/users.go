package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/users"
)

// userResponse wraps a user with the membership an administrator edits.
//
// Membership is project ids, not the slugs a Scope carries: this answers "what
// is configured for this person", while a scope answers "what may they reach".
// An admin's global reach comes from their role and is not a membership list,
// so showing one here would invite an administrator to edit something that has
// no effect.
type userResponse struct {
	users.User
	Projects []string `json:"projects"`
}

type createUserRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

// updateUserRequest changes a role, an enabled state, or membership.
//
// Every field is a pointer so "not mentioned" and "set to the zero value" are
// different requests. Without that, a caller changing only a role would also be
// asking to enable a disabled account and to revoke every project grant --
// silently, and in the direction of more access.
type updateUserRequest struct {
	Role     *string   `json:"role"`
	Disabled *bool     `json:"disabled"`
	Projects *[]string `json:"projects"`
}

// handleListUsers returns the operator roster. Admin only.
func (s *Server) handleListUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.users == nil {
			writeError(w, r, http.StatusNotImplemented, CodeInternal,
				"user accounts are not configured on this server")
			return
		}

		found, err := s.users.List(r.Context())
		if err != nil {
			s.internalError(w, r, "list users", err)
			return
		}

		out := make([]userResponse, 0, len(found))
		for _, user := range found {
			projects, err := s.users.MembershipOf(r.Context(), user.ID)
			if err != nil {
				s.internalError(w, r, "list user membership", err)
				return
			}
			out = append(out, userResponse{User: user, Projects: projects})
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"data": out})
	}
}

// handleCreateUser adds an account. Admin only.
//
// The counterpart to cmd/useradd, which exists only for the first admin. This
// one is audited against the administrator who called it, which the bootstrap
// command cannot be.
func (s *Server) handleCreateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.users == nil {
			writeError(w, r, http.StatusNotImplemented, CodeInternal,
				"user accounts are not configured on this server")
			return
		}

		var req createUserRequest
		if err := decodeJSON(w, r, &req, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		role := users.RoleViewer
		if req.Role != "" {
			parsed, ok := users.ParseRole(req.Role)
			if !ok {
				// The message names the roles a PERSON may hold. `service` is a
				// machine role and is deliberately not among them (ADR 033).
				writeError(w, r, http.StatusBadRequest, CodeInvalidRequest,
					"role must be one of viewer, engineer, admin")
				return
			}
			role = parsed
		}

		user, err := s.users.Create(r.Context(), users.NewUser{
			Email:       req.Email,
			Password:    req.Password,
			DisplayName: req.DisplayName,
			Role:        role,
		}, actorFrom(r))
		switch {
		case errors.Is(err, users.ErrEmailTaken):
			writeError(w, r, http.StatusConflict, CodeConflict, "an account already exists for that email")
			return
		case errors.Is(err, users.ErrInvalidUser), errors.Is(err, users.ErrPasswordTooShort):
			// The validator's messages name the rule broken and never echo the
			// value, so they are safe to forward -- and "password must be at
			// least 12 characters" is exactly what the caller needs.
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		case err != nil:
			s.internalError(w, r, "create user", err)
			return
		}

		writeJSON(w, r, http.StatusCreated, userResponse{User: user, Projects: []string{}})
	}
}

// handleUpdateUser changes a role, an enabled state, or membership. Admin only.
//
// The store refuses to demote or disable the last enabled administrator, and
// that refusal is a 409 rather than a 403: the request is not forbidden to this
// caller, it is impossible for anybody. A deployment with no administrator
// cannot appoint one, and the only way back is SQL.
func (s *Server) handleUpdateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.users == nil {
			writeError(w, r, http.StatusNotImplemented, CodeInternal,
				"user accounts are not configured on this server")
			return
		}

		id := chi.URLParam(r, "userID")
		if !isUUID(id) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "user id must be a uuid")
			return
		}

		var req updateUserRequest
		if err := decodeJSON(w, r, &req, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		actor := actorFrom(r)
		user, err := s.users.ByID(r.Context(), id)
		if err != nil {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "user not found")
			return
		}

		if req.Role != nil {
			role, ok := users.ParseRole(*req.Role)
			if !ok {
				writeError(w, r, http.StatusBadRequest, CodeInvalidRequest,
					"role must be one of viewer, engineer, admin")
				return
			}
			if user, err = s.users.SetRole(r.Context(), id, role, actor); err != nil {
				s.writeUserError(w, r, "set role", err)
				return
			}
		}

		if req.Disabled != nil {
			if user, err = s.users.SetDisabled(r.Context(), id, *req.Disabled, actor); err != nil {
				s.writeUserError(w, r, "set disabled", err)
				return
			}
		}

		if req.Projects != nil {
			if err := s.users.SetMembership(r.Context(), id, *req.Projects, actor); err != nil {
				s.writeUserError(w, r, "set membership", err)
				return
			}
		}

		projects, err := s.users.MembershipOf(r.Context(), id)
		if err != nil {
			s.internalError(w, r, "read user membership", err)
			return
		}
		writeJSON(w, r, http.StatusOK, userResponse{User: user, Projects: projects})
	}
}

// writeUserError maps the store's refusals onto status codes.
func (s *Server) writeUserError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	switch {
	case errors.Is(err, users.ErrNotFound):
		writeError(w, r, http.StatusNotFound, CodeNotFound, "user not found")
	case errors.Is(err, users.ErrLastAdmin):
		writeError(w, r, http.StatusConflict, CodeConflict,
			"this would leave no enabled administrator; appoint another one first")
	case errors.Is(err, users.ErrUnknownProject), errors.Is(err, users.ErrInvalidUser):
		// Both name the rule broken and never echo a secret, so both are safe
		// to forward. A membership change naming a missing project is the
		// caller's mistake, not a server failure -- it used to be a 500.
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
	default:
		s.internalError(w, r, operation, err)
	}
}

// handleArchiveProject hides a project, or brings it back. Admin only.
//
// Archive rather than delete, per §17: the scans, findings and history stay.
// The scoped-project middleware has already resolved and scope-checked the
// project, so an admin confined to a set of projects can only archive one of
// those.
func (s *Server) handleArchiveProject(archived bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project := projectFrom(r)

		updated, err := s.projects.SetArchived(r.Context(), project.ID, archived, actorFrom(r))
		if err != nil {
			s.internalError(w, r, "archive project", err)
			return
		}
		writeJSON(w, r, http.StatusOK, updated)
	}
}
