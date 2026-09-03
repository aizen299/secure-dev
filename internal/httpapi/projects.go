package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/aizen299/secure-dev/internal/projects"
)

// createProjectRequest is the wire shape of POST /api/v1/projects.
//
// It is a distinct type from projects.NewProject on purpose. Binding a request
// straight onto a domain struct is how server-assigned fields end up
// client-settable; the boundary is where that has to be prevented, not where
// it is convenient to skip a conversion.
type createProjectRequest struct {
	Name string `json:"name"`
	// Slug is optional; it is derived from the name when absent.
	Slug        string `json:"slug"`
	Description string `json:"description"`
	// Environment, Criticality, and InternetFacing are risk-engine inputs
	// (§10), which is why they are set at creation rather than inferred.
	Environment    string `json:"environment"`
	Criticality    string `json:"criticality"`
	InternetFacing bool   `json:"internet_facing"`
}

func (s *Server) handleCreateProject() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createProjectRequest
		if err := decodeJSON(w, r, &req, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		project, err := s.projects.Create(r.Context(), projects.NewProject{
			Name:           req.Name,
			Slug:           req.Slug,
			Description:    req.Description,
			Environment:    projects.Environment(req.Environment),
			Criticality:    projects.Criticality(req.Criticality),
			InternetFacing: req.InternetFacing,
		}, actorFrom(r))
		switch {
		case errors.Is(err, projects.ErrInvalidProject):
			// Validation messages are written to be client-safe: they name the
			// rule that was broken, never the value that broke it.
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		case errors.Is(err, projects.ErrSlugTaken):
			writeError(w, r, http.StatusConflict, CodeConflict, "a project with that slug already exists")
			return
		case err != nil:
			s.internalError(w, r, "create project", err)
			return
		}

		w.Header().Set("Location", "/api/v1/projects/"+project.ID)
		writeJSON(w, r, http.StatusCreated, project)
	}
}

func (s *Server) handleGetProject() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := pathUUID(r, "projectID")
		if err != nil {
			writeRequestError(w, r, err)
			return
		}

		project, err := s.projects.Get(r.Context(), id)
		switch {
		case errors.Is(err, projects.ErrNotFound):
			writeError(w, r, http.StatusNotFound, CodeNotFound, "project not found")
			return
		case err != nil:
			s.internalError(w, r, "get project", err)
			return
		}

		writeJSON(w, r, http.StatusOK, project)
	}
}

func (s *Server) handleListProjects() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset, err := pageFrom(r)
		if err != nil {
			writeRequestError(w, r, err)
			return
		}

		found, hasMore, err := s.projects.List(r.Context(), projects.Page{Limit: limit, Offset: offset})
		if err != nil {
			s.internalError(w, r, "list projects", err)
			return
		}

		writeListResponse(w, r, found, limit, offset, hasMore)
	}
}

// internalError logs the underlying failure and returns a fixed message.
//
// The error text can carry a DSN, a hostname, or repository content, so it
// goes to the logs and never to the client (§15.3, §15.13).
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	loggerFrom(r.Context()).Error(operation,
		slog.String("error", err.Error()),
		slog.String("path", r.URL.Path),
	)
	writeError(w, r, http.StatusInternalServerError, CodeInternal, "internal error")
}
