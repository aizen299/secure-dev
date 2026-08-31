// Package worker executes scan jobs.
//
// Workers are the only component that touches untrusted target content
// (CLAUDE.md §14.2). Everything here is written on the assumption that the
// target is hostile: the job payload is re-validated on arrival, each scanner
// runs in an ephemeral workspace under a hard timeout, and a scanner that
// fails, hangs, or floods its output degrades that one result rather than
// taking down the scan or the worker.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aizen299/secure-dev/internal/fetch"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// ScanStore persists scan progress. It is an interface so the runner can be
// tested without a database.
type ScanStore interface {
	MarkRunning(ctx context.Context, scanID string, at time.Time) error
	RecordScannerResult(ctx context.Context, scanID string, result scans.ScannerResult) error
	Finalize(ctx context.Context, scanID string, status scans.Status,
		reason scans.FailureReason, at time.Time) error
}

// ResultSink receives raw scanner output for storage.
//
// Raw output is persisted verbatim so results can be re-parsed when
// normalization improves (§8). Phase 4 implements the storage behind this.
type ResultSink interface {
	StoreRaw(ctx context.Context, scanID string, result scanners.RawResult) error
}

// Options configures a Runner.
type Options struct {
	Registry      *scanners.Registry
	Queue         queue.Queue
	Store         ScanStore
	Sink          ResultSink
	Validator     scanners.Validator
	WorkspaceRoot string
	Logger        *slog.Logger

	// Concurrency caps simultaneously executing jobs (§14 resource limits).
	Concurrency int
	// JobTimeout bounds one whole scan job.
	JobTimeout time.Duration
	// ScannerTimeout bounds a single scanner within a job.
	ScannerTimeout time.Duration
	// MaxOutputBytes caps a single scanner's captured output.
	MaxOutputBytes int64
	// PollTimeout is how long a dequeue blocks before looping.
	PollTimeout time.Duration
	// MaxAttempts retires a job after this many delivery attempts, so a job
	// that reliably kills its handler cannot cycle forever.
	MaxAttempts int

	// Fetch bounds repository fetching (ADR 008). Untrusted content is pulled
	// onto this machine, so every limit here is a security control.
	Fetch fetch.Options
	// Fetcher obtains a repository. It is a field rather than a direct call so
	// the runner can be tested without a git remote; nil uses fetch.Repository.
	Fetcher Fetcher
}

// Fetcher obtains untrusted target content into a workspace.
type Fetcher func(
	ctx context.Context, opts fetch.Options, workspace string, target scanners.Target,
) (fetch.Result, error)

func (o *Options) applyDefaults() {
	if o.Concurrency <= 0 {
		o.Concurrency = 2
	}
	if o.JobTimeout <= 0 {
		o.JobTimeout = 30 * time.Minute
	}
	if o.ScannerTimeout <= 0 {
		o.ScannerTimeout = scanners.DefaultTimeout
	}
	if o.MaxOutputBytes <= 0 {
		o.MaxOutputBytes = scanners.DefaultMaxOutputBytes
	}
	if o.PollTimeout <= 0 {
		o.PollTimeout = 5 * time.Second
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 3
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Fetcher == nil {
		o.Fetcher = fetch.Repository
	}
}

// Runner consumes jobs from the queue and executes them.
type Runner struct {
	opts Options
	sem  chan struct{}
	wg   sync.WaitGroup
	now  func() time.Time
}

// New builds a Runner.
func New(opts Options) (*Runner, error) {
	opts.applyDefaults()

	if opts.Registry == nil {
		return nil, fmt.Errorf("worker: registry is required")
	}
	if opts.Queue == nil {
		return nil, fmt.Errorf("worker: queue is required")
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("worker: store is required")
	}
	if opts.WorkspaceRoot == "" {
		return nil, fmt.Errorf("worker: workspace root is required")
	}

	return &Runner{
		opts: opts,
		sem:  make(chan struct{}, opts.Concurrency),
		now:  func() time.Time { return time.Now().UTC() },
	}, nil
}

// Run consumes jobs until ctx is cancelled, then waits for in-flight jobs.
func (r *Runner) Run(ctx context.Context) error {
	r.opts.Logger.Info("worker started",
		slog.Int("concurrency", r.opts.Concurrency),
		slog.String("scanners", fmt.Sprint(r.opts.Registry.Names())),
	)

consume:
	for ctx.Err() == nil {
		job, err := r.opts.Queue.Dequeue(ctx, r.opts.PollTimeout)
		if err != nil {
			if errors.Is(err, queue.ErrEmpty) || errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if errors.Is(err, context.Canceled) {
				break
			}
			// A malformed payload must not spin the loop hot.
			r.opts.Logger.Error("dequeue failed", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
			continue
		}

		// Acquire a slot before starting, so concurrency is genuinely bounded.
		// The label matters: a bare break here would leave the select only,
		// and the job would then run without holding a slot.
		select {
		case r.sem <- struct{}{}:
		case <-ctx.Done():
			r.opts.Logger.Warn("shutting down before job start", slog.String("scan_id", job.ScanID))
			break consume
		}

		r.wg.Add(1)
		go func(job queue.Job) {
			defer r.wg.Done()
			defer func() { <-r.sem }()

			// A panic in one job must not take the worker down with it.
			defer func() {
				if rec := recover(); rec != nil {
					r.opts.Logger.Error("recovered panic while executing job",
						slog.String("scan_id", job.ScanID), slog.Any("panic", rec))
				}
			}()

			r.executeJob(ctx, job)
		}(job)
	}

	r.opts.Logger.Info("worker draining in-flight jobs")
	r.wg.Wait()
	r.opts.Logger.Info("worker stopped")
	return nil
}

// effectiveKind maps a submitted target kind to the kind adapters receive.
//
// Only repositories are transformed, because only they are fetched. This
// branches on target kind, never on a scanner's name (§7 rule 2).
func effectiveKind(k scanners.Kind) scanners.Kind {
	if k == scanners.KindRepository {
		return scanners.KindFilesystem
	}
	return k
}

// executeJob runs one scan job to a terminal state.
func (r *Runner) executeJob(ctx context.Context, job queue.Job) {
	log := r.opts.Logger.With(
		slog.String("scan_id", job.ScanID),
		slog.String("project_id", job.ProjectID),
		slog.String("target_kind", string(job.Target.Kind)),
	)

	if job.Attempt > r.opts.MaxAttempts {
		log.Error("job exceeded max attempts; retiring", slog.Int("attempt", job.Attempt))
		r.finalize(ctx, log, job.ScanID, scans.StatusFailed, scans.FailureMaxAttemptsExceeded)
		return
	}

	jobCtx, cancel := context.WithTimeout(ctx, r.opts.JobTimeout)
	defer cancel()

	// Re-validate on arrival. The payload crossed a trust boundary, and a
	// target that was valid at enqueue time may not be now (§15.7).
	target, err := r.opts.Validator.Validate(jobCtx, job.Target)
	if err != nil {
		log.Error("target failed validation", slog.String("error", err.Error()))
		r.finalize(ctx, log, job.ScanID, scans.StatusFailed, scans.FailureTargetInvalid)
		return
	}

	// Selection uses the kind adapters will actually be handed, not the kind
	// the client submitted. A repository is fetched first and presented as a
	// checkout (ADR 008), so an adapter that declares KindFilesystem is the
	// right choice for a repository target -- resolving against
	// KindRepository would select nothing at all.
	//
	// Resolving before the fetch is deliberate: there is no point cloning an
	// untrusted repository only to discover nothing can scan it.
	selected, err := r.opts.Registry.Resolve(effectiveKind(target.Kind), job.Scanners)
	if err != nil {
		// Two distinct operator problems, so they get distinct reasons: an
		// explicit selection naming something unregistered is a client
		// mistake, while an empty selection resolving to nothing means this
		// deployment has no adapter for the kind at all. Until Phase 3
		// registers adapters, the second is every scan's outcome.
		reason := scans.FailureNoScannerAvailable
		if len(job.Scanners) > 0 {
			reason = scans.FailureScannerNotRegistered
		}
		log.Error("scanner selection failed", slog.String("error", err.Error()))
		r.finalize(ctx, log, job.ScanID, scans.StatusFailed, reason)
		return
	}

	if err := r.opts.Store.MarkRunning(jobCtx, job.ScanID, r.now()); err != nil {
		log.Error("could not mark scan running", slog.String("error", err.Error()))
		return
	}

	workspace, err := scanners.NewWorkspace(r.opts.WorkspaceRoot, job.ScanID)
	if err != nil {
		log.Error("could not create workspace", slog.String("error", err.Error()))
		r.finalize(ctx, log, job.ScanID, scans.StatusFailed, scans.FailureWorkspaceUnavailable)
		return
	}
	// Untrusted content never outlives the job that fetched it (§14.3).
	defer func() {
		if err := workspace.Remove(); err != nil {
			log.Error("could not remove workspace", slog.String("error", err.Error()))
		}
	}()

	// Fetch phase. A repository target names a remote; adapters need bytes on
	// disk. The worker clones into the ephemeral workspace and rewrites the
	// target to the checkout, so no adapter ever fetches anything (ADR 008).
	//
	// This is where SecureOps pulls attacker-controlled content onto a machine
	// it owns, so a failure here is recorded distinctly from a scanner
	// failure: "we could not get the code" must never read as "we scanned it
	// and found nothing".
	scanTarget := target
	if target.Kind == scanners.KindRepository {
		fetched, err := r.opts.Fetcher(jobCtx, r.opts.Fetch, workspace.Path, target)
		if err != nil {
			reason := scans.FailureFetchFailed
			if errors.Is(err, fetch.ErrTooLarge) {
				reason = scans.FailureTargetTooLarge
			}
			// git's stderr quotes the remote's response, so the detail is
			// logged and the stored reason stays fixed (§15.3).
			log.Error("could not fetch the repository", slog.String("error", err.Error()))
			r.finalize(ctx, log, job.ScanID, scans.StatusFailed, reason)
			return
		}

		log.Info("fetched repository",
			slog.Int64("bytes", fetched.Bytes),
			slog.Int("files", fetched.Files),
			slog.String("commit", fetched.CommitSHA),
			slog.Duration("duration", fetched.Duration),
		)
		// Adapters see a local path and nothing else.
		scanTarget = scanners.Target{Kind: scanners.KindFilesystem, Path: fetched.Path}
	}

	scan := &scans.Scan{ID: job.ScanID, Status: scans.StatusRunning, Target: target}

	for _, scanner := range selected {
		result := r.runScanner(jobCtx, log, job.ScanID, scanner, scanTarget)
		scan.RecordResult(result)

		if err := r.opts.Store.RecordScannerResult(ctx, job.ScanID, result); err != nil {
			log.Error("could not record scanner result",
				slog.String("scanner", scanner.Name()), slog.String("error", err.Error()))
		}

		// Stop dispatching further scanners once the job is cancelled, but
		// still finalize below so the scan reaches a terminal state.
		if jobCtx.Err() != nil {
			break
		}
	}

	status := scan.TerminalStatus()
	if errors.Is(ctx.Err(), context.Canceled) {
		status = scans.StatusCancelled
	}

	// A reason is recorded only when the scan produced no usable coverage. A
	// PARTIAL scan already explains itself through its per-scanner results,
	// and a cancelled one was not a failure of the scan.
	var reason scans.FailureReason
	if status == scans.StatusFailed {
		reason = scans.FailureAllScannersDegraded
	}

	log.Info("scan finished",
		slog.String("status", string(status)),
		slog.Int("scanners_run", len(scan.Results)),
		slog.Any("degraded", scan.DegradedScanners()),
	)
	r.finalize(ctx, log, job.ScanID, status, reason)
}

// runScanner executes one scanner and converts every outcome -- success,
// failure, missing binary, timeout, oversized output -- into a structured
// result. It never returns an error: a broken scanner degrades its own result,
// nothing more (§13).
func (r *Runner) runScanner(
	ctx context.Context, log *slog.Logger, scanID string,
	scanner scanners.Scanner, target scanners.Target,
) scans.ScannerResult {
	name := scanner.Name()
	started := r.now()
	result := scans.ScannerResult{Scanner: name, Status: scans.ScannerRunning, StartedAt: &started}

	version, err := scanner.Version(ctx)
	if err != nil {
		// A missing binary is absent coverage, not a broken scan. It must be
		// visibly distinct from a scanner that ran and failed (§4).
		if errors.Is(err, scanners.ErrBinaryMissing) {
			log.Warn("scanner is not installed; skipping", slog.String("scanner", name))
			result.Status = scans.ScannerSkipped
			result.Error = "scanner binary is not installed"
			return result
		}
		log.Error("could not determine scanner version",
			slog.String("scanner", name), slog.String("error", err.Error()))
	}
	result.Version = version

	scanCtx, cancel := context.WithTimeout(ctx, r.opts.ScannerTimeout)
	defer cancel()

	raw, err := scanner.Scan(scanCtx, target)
	result.Duration = r.now().Sub(started)
	result.ExitCode = raw.ExitCode
	// Reasons travel from the adapter unchanged. The worker records what the
	// adapter reported and never interprets it, which is how a scanner-specific
	// cause reaches the API without any core code branching on scanner name.
	result.Degradations = raw.Degradations

	switch {
	case err == nil:
		result.Status = scans.ScannerSucceeded
		// A degraded result stays succeeded: its findings are real, merely an
		// under-count. Succeeded() is false while any reason is present, so the
		// scan still settles at PARTIAL. No Error is set -- the reason is
		// structured, and prose duplicating it would be a second source of
		// truth (ADR 010).
		if r.opts.Sink != nil {
			if storeErr := r.opts.Sink.StoreRaw(ctx, scanID, raw); storeErr != nil {
				log.Error("could not store raw result",
					slog.String("scanner", name), slog.String("error", storeErr.Error()))
			}
		}

	case errors.Is(err, scanners.ErrBinaryMissing):
		result.Status = scans.ScannerSkipped
		result.Error = "scanner binary is not installed"

	case errors.Is(err, scanners.ErrExecTimeout):
		result.Status = scans.ScannerFailed
		result.Error = "scanner exceeded its execution timeout"

	case errors.Is(err, scanners.ErrOutputTooLarge):
		result.Status = scans.ScannerFailed
		result.Degradations = []scanners.Degradation{scanners.DegradedOutputTruncated}
		result.Error = "scanner output exceeded the size limit"

	case errors.Is(err, context.Canceled):
		result.Status = scans.ScannerFailed
		result.Error = "scan was cancelled"

	default:
		result.Status = scans.ScannerFailed
		// The message is a fixed summary. The underlying error can quote
		// repository content or a detected secret, so it is logged, not stored.
		result.Error = "scanner execution failed"
		log.Error("scanner failed",
			slog.String("scanner", name), slog.String("error", err.Error()))
	}

	return result
}

func (r *Runner) finalize(
	ctx context.Context, log *slog.Logger, scanID string,
	status scans.Status, reason scans.FailureReason,
) {
	// Finalization must survive job cancellation, or a cancelled scan would be
	// left stuck in RUNNING forever.
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	if err := r.opts.Store.Finalize(finalCtx, scanID, status, reason, r.now()); err != nil {
		log.Error("could not finalize scan",
			slog.String("status", string(status)), slog.String("error", err.Error()))
	}
}
