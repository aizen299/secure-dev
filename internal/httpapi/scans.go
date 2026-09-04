package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// submittableKinds are the target kinds a client may submit.
//
// KindFilesystem is deliberately absent. It means "a directory inside the
// worker's workspace", which is an internal step in the pipeline (clone a
// repository, then scan the checkout), not something a caller should be able to
// point wherever it likes. Accepting it from a client would turn POST /scans
// into a way to read the worker's own disk (§14.1, §14.5).
var submittableKinds = []scanners.Kind{
	scanners.KindRepository,
	scanners.KindImage,
	scanners.KindEndpoint,
}

func isSubmittableKind(k scanners.Kind) bool {
	for _, allowed := range submittableKinds {
		if k == allowed {
			return true
		}
	}
	return false
}

func joinKinds(kinds []scanners.Kind) string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ", ")
}

// createScanRequest is the wire shape of POST /api/v1/scans.
type createScanRequest struct {
	ProjectID    string      `json:"project_id"`
	RepositoryID *string     `json:"repository_id"`
	Target       targetInput `json:"target"`
	CommitSHA    string      `json:"commit_sha"`
	Branch       string      `json:"branch"`
	// Scanners optionally narrows the selection. Empty means "every scanner
	// that supports this target kind", resolved by the worker's registry --
	// the API has no knowledge of which adapters exist (§7).
	Scanners []string `json:"scanners"`
}

// targetInput is the client-facing target. It mirrors scanners.Target minus
// Path, which is not a client-settable field: see submittableKinds.
type targetInput struct {
	Kind          string `json:"kind"`
	RepositoryURL string `json:"repository_url"`
	Ref           string `json:"ref"`
	Image         string `json:"image"`
	EndpointURL   string `json:"endpoint_url"`
}

// scanResponse is the wire shape of a scan.
//
// Per-scanner detail is part of the contract, not an optional extra: a status
// without it is the "clean scan" illusion §13 exists to prevent.
type scanResponse struct {
	ID           string          `json:"id"`
	ProjectID    string          `json:"project_id"`
	RepositoryID *string         `json:"repository_id,omitempty"`
	Status       scans.Status    `json:"status"`
	Target       scanners.Target `json:"target"`
	CommitSHA    string          `json:"commit_sha,omitempty"`
	Branch       string          `json:"branch,omitempty"`

	RequestedScanners []string `json:"requested_scanners"`
	// CompleteCoverage is false whenever any scanner failed, was skipped, or
	// reported a degradation. A gate evaluated against degraded coverage must be
	// labelled as such (§12), so the flag is computed here rather than left
	// for every client to re-derive from the results.
	CompleteCoverage bool     `json:"complete_coverage"`
	DegradedScanners []string `json:"degraded_scanners"`
	FailureReason    string   `json:"failure_reason,omitempty"`

	Results []scannerResultResponse `json:"results"`

	QueuedAt    time.Time  `json:"queued_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// scannerResultResponse is one scanner's outcome.
type scannerResultResponse struct {
	Scanner    string              `json:"scanner"`
	Status     scans.ScannerStatus `json:"status"`
	Version    string              `json:"version,omitempty"`
	ExitCode   int                 `json:"exit_code"`
	DurationMS int64               `json:"duration_ms"`
	// Error is the structured summary the worker recorded. It is never raw
	// scanner stderr, which can quote repository content and detected secrets.
	Error string `json:"error,omitempty"`
	// Degradations names why this scanner's coverage is not fully trustworthy.
	// Non-empty means the findings are an under-count, so the scan is PARTIAL
	// and a gate must not read it as clean (ADR 010).
	Degradations []string   `json:"degradations"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
}

// degradationStrings renders the typed reasons as plain strings, empty rather
// than null so a typed client need not special-case the absent case.
func degradationStrings(ds []scanners.Degradation) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, string(d))
	}
	return out
}

// toScanResponse converts the domain model to the wire model.
//
// The conversion is explicit so that adding a field to the domain model does
// not silently widen the public API contract (§18).
func toScanResponse(s scans.Scan) scanResponse {
	results := make([]scannerResultResponse, 0, len(s.Results))
	for _, r := range s.Results {
		results = append(results, scannerResultResponse{
			Scanner:      r.Scanner,
			Status:       r.Status,
			Version:      r.Version,
			ExitCode:     r.ExitCode,
			DurationMS:   r.Duration.Milliseconds(),
			Error:        r.Error,
			Degradations: degradationStrings(r.Degradations),
			StartedAt:    r.StartedAt,
		})
	}

	// Empty slices rather than null, so a typed client does not have to
	// special-case the absent case on three separate fields.
	requested := s.RequestedScanners
	if requested == nil {
		requested = []string{}
	}
	degraded := s.DegradedScanners()
	if degraded == nil {
		degraded = []string{}
	}

	return scanResponse{
		ID:                s.ID,
		ProjectID:         s.ProjectID,
		RepositoryID:      s.RepositoryID,
		Status:            s.Status,
		Target:            s.Target,
		CommitSHA:         s.CommitSHA,
		Branch:            s.Branch,
		RequestedScanners: requested,
		CompleteCoverage:  s.HasCompleteCoverage(),
		DegradedScanners:  degraded,
		FailureReason:     s.FailureReason,
		Results:           results,
		QueuedAt:          s.QueuedAt,
		StartedAt:         s.StartedAt,
		CompletedAt:       s.CompletedAt,
	}
}

// validateTargetRequest is the wire shape of POST /api/v1/targets/validate.
//
// The target alone: no project, no branch, nothing that would imply this
// creates something. It does not.
type validateTargetRequest struct {
	Target targetInput `json:"target"`
}

// validateTargetResponse reports the normalised target.
//
// Only the valid case has a body. A refusal is the standard error envelope with
// the validator's own message, which is the same thing POST /scans returns for
// the same input -- so a client sees one wording for one rule, whichever
// endpoint it asked.
type validateTargetResponse struct {
	Target scanners.Target `json:"target"`
}

// handleValidateTarget answers whether a target would be accepted (ADR 032).
//
// Read-only: it creates nothing, enqueues nothing, and writes nothing. It
// exists so a client can find out before it builds state around a target the
// platform will refuse -- the dashboard was creating a project and then
// discovering the address policy had rejected the URL, leaving a project named
// after a target that was never scanned.
//
// This is deliberately NOT a second implementation of the policy. It runs the
// same Validator the scan handler runs, reached earlier. A copy of these rules
// anywhere else would be a place for the two to disagree, and the weaker one
// would be the one deciding.
//
// Requires `service` despite being read-only. Validation resolves a
// caller-supplied hostname, which is an outbound lookup the caller chose;
// `viewer` should not gain a side effect it does not otherwise have, and
// `service` can already reach this exact code by submitting a scan (ADR 032).
func (s *Server) handleValidateTarget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req validateTargetRequest
		if err := decodeJSON(w, r, &req, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		kind := scanners.Kind(req.Target.Kind)
		if !isSubmittableKind(kind) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest,
				fmt.Sprintf("target.kind must be one of %s", joinKinds(submittableKinds)))
			return
		}

		target, err := s.validator.Validate(r.Context(), scanners.Target{
			Kind:          kind,
			RepositoryURL: req.Target.RepositoryURL,
			Ref:           req.Target.Ref,
			Image:         req.Target.Image,
			EndpointURL:   req.Target.EndpointURL,
		})
		if err != nil {
			if errors.Is(err, scanners.ErrInvalidTarget) {
				writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
				return
			}
			s.internalError(w, r, "validate target", err)
			return
		}

		writeJSON(w, r, http.StatusOK, validateTargetResponse{Target: target})
	}
}

// handleCreateScan accepts a scan request and returns 202 immediately.
//
// The handler never executes a scanner and never blocks on one (§13, §25.2).
// It validates, persists a queued scan, and enqueues a job. Everything after
// that happens in a worker.
func (s *Server) handleCreateScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createScanRequest
		if err := decodeJSON(w, r, &req, s.maxRequestBytes); err != nil {
			writeRequestError(w, r, err)
			return
		}

		// Checked before the database is touched, so a malformed ID is the 400
		// it actually is rather than a pgx "invalid uuid syntax" 500.
		if !isUUID(req.ProjectID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "project_id must be a UUID")
			return
		}

		kind := scanners.Kind(req.Target.Kind)
		if !isSubmittableKind(kind) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest,
				fmt.Sprintf("target.kind must be one of %s", joinKinds(submittableKinds)))
			return
		}

		// Validate the target here, at the API boundary, before anything is
		// persisted or enqueued. This is the SSRF check (§14.6): it resolves
		// the host and rejects loopback, link-local, and private ranges. The
		// worker repeats it on arrival, because a payload that crossed the
		// queue is untrusted regardless of which component wrote it.
		target, err := s.validator.Validate(r.Context(), scanners.Target{
			Kind:          kind,
			RepositoryURL: req.Target.RepositoryURL,
			Ref:           req.Target.Ref,
			Image:         req.Target.Image,
			EndpointURL:   req.Target.EndpointURL,
		})
		if err != nil {
			if errors.Is(err, scanners.ErrInvalidTarget) {
				// The validator's messages are written to be client-safe: they
				// name the rule broken, never echo the value that broke it.
				writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
				return
			}
			s.internalError(w, r, "validate scan target", err)
			return
		}

		// Check the project first, so an unknown one is a 404 rather than a
		// foreign-key violation surfacing as a 500.
		exists, err := s.projects.Exists(r.Context(), req.ProjectID)
		if err != nil {
			s.internalError(w, r, "check project exists", err)
			return
		}
		if !exists {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "project not found")
			return
		}

		scan, err := s.scans.Create(r.Context(), scans.NewScan{
			ProjectID:    req.ProjectID,
			RepositoryID: req.RepositoryID,
			Target:       target,
			CommitSHA:    req.CommitSHA,
			Branch:       req.Branch,
			Scanners:     req.Scanners,
		}, actorFrom(r))
		switch {
		case errors.Is(err, scans.ErrInvalidScan):
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		case err != nil:
			s.internalError(w, r, "create scan", err)
			return
		}

		job := queue.Job{
			ScanID:     scan.ID,
			ProjectID:  scan.ProjectID,
			Target:     target,
			Scanners:   scan.RequestedScanners,
			EnqueuedAt: time.Now().UTC(),
			Attempt:    1,
		}
		if err := s.queue.Enqueue(r.Context(), job); err != nil {
			// The scan row exists but no worker will ever pick it up, so it
			// would sit in QUEUED forever. Fail it now, with a reason, rather
			// than leaving behind a scan that never resolves.
			s.failUnqueuedScan(r, scan.ID)
			s.internalError(w, r, "enqueue scan job", err)
			return
		}

		w.Header().Set("Location", "/api/v1/scans/"+scan.ID)
		writeJSON(w, r, http.StatusAccepted, toScanResponse(scan))
	}
}

// failUnqueuedScan marks a scan failed when its job could not be enqueued.
//
// Best effort by nature: the enqueue already failed, so the datastore may be
// unhealthy too. A failure here is logged and nothing more, because the client
// is about to receive a 500 either way.
func (s *Server) failUnqueuedScan(r *http.Request, scanID string) {
	err := s.scans.Finalize(r.Context(), scanID, scans.StatusFailed,
		scans.FailureNotEnqueued, time.Now().UTC())
	if err != nil {
		loggerFrom(r.Context()).Error("could not fail an unqueued scan",
			slog.String("scan_id", scanID), slog.String("error", err.Error()))
	}
}

func (s *Server) handleGetScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := pathUUID(r, "scanID")
		if err != nil {
			writeRequestError(w, r, err)
			return
		}

		scan, err := s.scans.Get(r.Context(), id)
		switch {
		case errors.Is(err, scans.ErrNotFound):
			writeError(w, r, http.StatusNotFound, CodeNotFound, "scan not found")
			return
		case err != nil:
			s.internalError(w, r, "get scan", err)
			return
		}
		// Same answer as a missing scan, deliberately: a 403 here would confirm
		// the id is real (ADR 033, T-38).
		if !s.inScope(r, scan.ProjectID) {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "scan not found")
			return
		}

		writeJSON(w, r, http.StatusOK, toScanResponse(scan))
	}
}

func (s *Server) handleListProjectScans() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Resolved and scope-checked by the scopedProject middleware.
		//
		// Exists is deliberately NOT used here, though it is used when a scan
		// is created a few handlers up. The two ask different questions: "may
		// this project take new work" excludes an archived one, and "what work
		// has this project already had" does not. Reading them as the same
		// question made an archived project's scan history unreachable.
		projectID := projectFrom(r).ID

		limit, offset, err := pageFrom(r)
		if err != nil {
			writeRequestError(w, r, err)
			return
		}

		found, hasMore, err := s.scans.ListByProject(r.Context(), projectID,
			scans.Page{Limit: limit, Offset: offset})
		if err != nil {
			s.internalError(w, r, "list scans", err)
			return
		}

		out := make([]scanResponse, 0, len(found))
		for _, scan := range found {
			out = append(out, toScanResponse(scan))
		}
		writeListResponse(w, r, out, limit, offset, hasMore)
	}
}
