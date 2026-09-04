package httpapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/projects"
)

// projectKey carries the resolved, in-scope project down to the handler.
type projectKeyType struct{}

var projectKey projectKeyType

// scopedProject resolves the project named in the URL and refuses it when the
// caller's scope does not reach it (ADR 033).
//
// Middleware on the whole `/projects/{projectID}` subtree rather than a call at
// the top of each handler, and the difference matters: a route added later is
// scoped by existing, not by somebody remembering to add a line. That is the
// same deny-by-default reasoning the dashboard's route matcher uses, applied to
// the API.
//
// It resolves the project ONCE and stashes it, so a handler that needs the
// project reads it from the request rather than querying again. Before this,
// two handlers looked it up and three did not look at all.
//
// An out-of-scope project is **404, not 403**. A 403 would confirm the id names
// a real project, which is precisely the disclosure T-38 is about: an
// enumeration of ids that exist is a map of the estate. "Not found" is also the
// literal truth from the caller's position -- for them, it does not.
func (s *Server) scopedProject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "projectID")
		if !isUUID(id) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "project id must be a uuid")
			return
		}

		// GetAny, not Get: an archived project must still resolve here, or
		// /unarchive could never find the project it is meant to restore.
		// Archiving hides from lists; it does not make a project unreachable
		// (ADR 033 §6). Handlers that must refuse an archived project check
		// Archived themselves -- scan submission is the only one.
		project, err := s.projects.GetAny(r.Context(), id)
		if err != nil {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "project not found")
			return
		}

		if !scopeFrom(r).Allows(project.Slug) {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "project not found")
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), projectKey, project)))
	})
}

// projectFrom returns the project scopedProject resolved.
//
// Panics if the middleware did not run, which is deliberate: a handler under
// the project subtree that reaches this without a project is a routing mistake,
// and the alternative -- returning a zero project -- would serve somebody
// else's data rather than fail.
//
// **Use this rather than looking the project up again.** Six handlers under the
// subtree did read it a second time, through a query that filters archived
// rows, and the two resolutions disagreed the moment archiving started being
// used: a project's own page, its scans, findings, issues and remediation all
// answered 404 once archived -- and the control that restores it lives on that
// page, so archive became a one-way door wearing a reversible name (ADR 033
// §6). A second read of an entity the middleware already resolved is not a
// redundant query, it is a second source of truth.
//
// A handler that must refuse an archived project checks project.Archived, or
// asks projects.Exists, which is what scan submission does.
func projectFrom(r *http.Request) projects.Project {
	project, ok := r.Context().Value(projectKey).(projects.Project)
	if !ok {
		panic("httpapi: project handler reached without the scopedProject middleware")
	}
	return project
}

// scopeFrom returns the authenticated caller's project scope.
//
// The zero Scope reaches nothing, so a request that somehow arrives without a
// principal -- unreachable behind requireAuth, but worth being safe about --
// yields a scope that reads no rows rather than every row. That fallback is the
// reason this returns a value rather than an (auth.Scope, bool): there is no
// caller that should be deciding what to do when the scope is missing.
func scopeFrom(r *http.Request) auth.Scope {
	if principal, ok := PrincipalFrom(r.Context()); ok {
		return principal.Scope
	}
	return auth.Scope{}
}

// inScope reports whether the caller may see something owned by a project id.
//
// For endpoints addressed by an opaque id — a scan, a finding — where there is
// no project in the URL to check before the lookup. The entity is resolved
// first and its owner checked second, which is safe because nothing has left
// the process: the read is not the disclosure, the response is.
//
// That reasoning does NOT extend to list endpoints. A list filtered after the
// fact returns the right rows and the wrong `has_more`, which leaks the size of
// what the caller cannot see — so those filter in the query instead
// (see projects.Store.List).
//
// A false answer must become 404, never 403. A 403 confirms the id names
// something real, which turns id enumeration into a map of the estate (T-38).
func (s *Server) inScope(r *http.Request, projectID string) bool {
	scope := scopeFrom(r)
	if scope.IsGlobal() {
		return true
	}
	// Only reached for a non-global scope, so the extra lookup is not on the
	// hot path for the credentials that have the whole estate anyway.
	//
	// GetAny, so that archiving a project does not quietly revoke a scoped
	// caller's access to findings they could already reach -- while a global
	// caller, who short-circuits above, keeps it. That asymmetry would make
	// archiving act as a scope change for some callers and not others. What a
	// caller may reach is membership; whether a project is archived is a
	// separate question, answered separately.
	project, err := s.projects.GetAny(r.Context(), projectID)
	if err != nil {
		return false
	}
	return scope.Allows(project.Slug)
}

// findingInScope resolves a finding's owner and checks the caller's scope.
//
// Writes the refusal itself, because both callers must answer identically
// whether the finding is missing or merely out of reach -- and a helper that
// returned a bool would leave that identical wording to be repeated correctly
// twice (ADR 033, T-38).
func (s *Server) findingInScope(w http.ResponseWriter, r *http.Request, findingID string) bool {
	// A global credential reaches every project, so resolving the owner would
	// be a query whose answer cannot change the outcome. Same short-circuit as
	// inScope, and the reason both take it: scoping must not make the
	// unscoped path slower than it was.
	if scopeFrom(r).IsGlobal() {
		return true
	}

	projectID, err := s.findings.ProjectOf(r.Context(), findingID)
	if err != nil || !s.inScope(r, projectID) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "finding not found")
		return false
	}
	return true
}
