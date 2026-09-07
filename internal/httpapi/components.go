package httpapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/sbom"
)

// ComponentStore reads what a scan found a project to be made of.
//
// Optional on the server, like PolicyStore: a deployment without it answers 501
// for these two routes and serves everything else. An inventory is additive,
// and a missing one must not take the rest of the API with it.
type ComponentStore interface {
	ByScan(ctx context.Context, scanID string, page sbom.Page) ([]sbom.Record, bool, error)
	ByProject(ctx context.Context, projectID string, page sbom.Page) ([]sbom.Record, bool, error)
}

// handleListScanComponents returns one scan's bill of materials.
//
// Scoped by the scan's owning project, through the same check every other
// scan-addressed route uses: a scan id in the URL has no project in it, so the
// owner is resolved and tested rather than assumed (ADR 033).
func (s *Server) handleListScanComponents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.components == nil {
			writeError(w, r, http.StatusNotImplemented, CodeInternal,
				"component storage is not configured on this server")
			return
		}

		scanID := chi.URLParam(r, "scanID")
		if !isUUID(scanID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "scan id must be a uuid")
			return
		}
		// Resolved and scope-checked together, exactly as the other
		// scan-addressed routes do: an out-of-scope scan answers as a missing
		// one does, so an id cannot be probed for existence (ADR 033, T-38).
		scan, err := s.scans.Get(r.Context(), scanID)
		if err != nil || !s.inScope(r, scan.ProjectID) {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "scan not found")
			return
		}

		limit, offset, err := pageFrom(r)
		if err != nil {
			writeRequestError(w, r, err)
			return
		}

		found, hasMore, err := s.components.ByScan(r.Context(), scanID,
			sbom.Page{Limit: limit, Offset: offset})
		if err != nil {
			s.internalError(w, r, "list scan components", err)
			return
		}
		writeListResponse(w, r, found, limit, offset, hasMore)
	}
}

// handleListProjectComponents returns a project's current inventory.
//
// The most recent scan that produced components, not a union across scans:
// "what is in this project" is a question about now, and a union would list
// versions replaced months ago beside the current one with nothing to tell them
// apart (ADR 035).
func (s *Server) handleListProjectComponents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.components == nil {
			writeError(w, r, http.StatusNotImplemented, CodeInternal,
				"component storage is not configured on this server")
			return
		}

		// Resolved and scope-checked by the scopedProject middleware. Not read
		// again here: a second lookup is a second source of truth, and the two
		// disagreed the last time this package had one (ADR 033 §6).
		projectID := projectFrom(r).ID

		limit, offset, err := pageFrom(r)
		if err != nil {
			writeRequestError(w, r, err)
			return
		}

		found, hasMore, err := s.components.ByProject(r.Context(), projectID,
			sbom.Page{Limit: limit, Offset: offset})
		if err != nil {
			s.internalError(w, r, "list project components", err)
			return
		}
		writeListResponse(w, r, found, limit, offset, hasMore)
	}
}
