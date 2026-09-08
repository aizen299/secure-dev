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

	"github.com/aizen299/secure-dev/internal/correlation"
	"github.com/aizen299/secure-dev/internal/fetch"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/policies"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/sbom"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// ScanStore persists scan progress. It is an interface so the runner can be
// tested without a database.
type ScanStore interface {
	MarkRunning(ctx context.Context, scanID string, at time.Time) error
	RecordCheckout(ctx context.Context, scanID, commitSHA, branch string) error
	RecordScannerResult(ctx context.Context, scanID string, result scans.ScannerResult) error
	Finalize(ctx context.Context, scanID string, status scans.Status,
		reason scans.FailureReason, at time.Time) error
}

// FindingStore persists the findings a scan produced.
//
// An interface so the runner can be tested without a database, and so the
// worker depends on the shape of the operation rather than on pgx.
type FindingStore interface {
	RecordScan(ctx context.Context, projectID, scanID string,
		result normalization.DedupResult, completeScanners []string, at time.Time) error
	// ListLiveForCorrelation and ReplaceCorrelation are the correlation half.
	// Kept on this interface rather than a second one because correlation runs
	// on the findings this store just wrote, in the same step, and splitting
	// it would mean two stores that must be given the same database or the
	// pipeline silently correlates nothing.
	ListLiveForCorrelation(ctx context.Context, projectID string) ([]correlation.Subject, error)
	ReplaceCorrelation(ctx context.Context, projectID string, result correlation.Result) error
	// LoadRiskInputs and SaveRiskScore are the risk half, on this interface for
	// the same reason: scoring runs on the findings and issues the two steps
	// above just wrote, and a separately-configured store could silently score
	// a different project's data.
	LoadRiskInputs(ctx context.Context, projectID string) ([]risk.Subject, risk.Context, error)
	SaveRiskScore(ctx context.Context, projectID, scanID string,
		assessment risk.Assessment, weightsDigest string, at time.Time) error
}

// ComponentStore persists what a scan found a project to be made of.
//
// Separate from FindingStore, because an inventory is not a finding and the two
// have no step in common: components are written as a scanner reports them,
// while findings go through dedup, correlation and scoring first. A deployment
// may also run without one -- an inventory is additive, and a nil store means
// no components rather than a failed scan (ADR 035).
type ComponentStore interface {
	RecordScan(ctx context.Context, scanID, projectID, scanner string,
		components []sbom.Component) error

	// ArtifactFor reads what a project's most recent image scan found
	// installed, for the deployment evidence correlation records (ADR 037).
	ArtifactFor(ctx context.Context, projectID string) (sbom.Artifact, error)
}

// PolicyStore reads a project's gate configuration and records its verdicts.
//
// Separate from FindingStore because the gate is the one stage that consumes a
// human's configuration rather than a scan's output, and because a deployment
// may reasonably run without one.
type PolicyStore interface {
	Get(ctx context.Context, projectID string) (policies.Policy, error)
	SaveResult(ctx context.Context, projectID, scanID string,
		policy policies.Policy, result policies.Result, at time.Time) error
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
	Registry *scanners.Registry
	Queue    queue.Queue
	Store    ScanStore
	Sink     ResultSink
	// Findings persists normalized findings. Optional: without it a scan still
	// runs and stores raw output, it simply produces no findings.
	Findings FindingStore
	// Components persists a scan's bill of materials. Optional for the same
	// reason: a scan without it still records everything it found, it simply
	// keeps no inventory.
	Components ComponentStore
	// Policies evaluates the security gate. Optional for the same reason: a
	// scan without it still records everything it found, it simply reaches no
	// verdict.
	Policies      PolicyStore
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

	// Executor obtains target content and runs the scanners (ADR 039). Nil
	// builds an InProcess executor from the fields above, which is what
	// docker-compose and every existing test get. A Kubernetes deployment
	// supplies one that creates a Job per scan instead.
	Executor Executor
}

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

// executor returns the configured executor, or builds the default one.
//
// Built per job rather than once in New, and that is not laziness. The default
// executor reads Options fields that were previously read at call time --
// Fetcher above all -- so constructing it once would move when they are bound.
// A test that sets a fake fetcher on an already-built Runner would silently
// keep the real one, which is exactly what happened when this was written the
// other way round.
//
// The cost is a struct literal per scan, against a scan that clones a
// repository and runs six subprocesses.

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
	selected, err := r.opts.Registry.Resolve(scanners.EffectiveKind(target.Kind), job.Scanners)
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

	scan := &scans.Scan{ID: job.ScanID, Status: scans.StatusRunning, Target: target}

	// Normalized results are collected rather than persisted per scanner: a
	// finding is deduplicated across every scanner in the scan, so nothing can
	// be written until all of them have run.
	var normalized []normalization.Result

	// Everything that touches untrusted content is behind the executor
	// (ADR 039). Everything below the callback -- storing raw output, parsing
	// an inventory, normalizing findings -- is the same whatever produced the
	// bytes, so it stays here and runs against a database the executor may not
	// even be able to reach.
	err = r.executor().Execute(jobCtx, Request{
		ScanID:    job.ScanID,
		ProjectID: job.ProjectID,
		Target:    target,
		Scanners:  selected,
	}, Events{
		// Record what was actually scanned, as soon as the fetch knows it. The
		// revision is only knowable after the clone: the request names a URL
		// and at most a ref, and a ref moves. Logging it is not enough --
		// a finding's lifecycle is anchored to the revision it was seen in,
		// and a log line is not queryable.
		//
		// Not fatal. A scan that ran is worth more than a scan discarded over
		// missing provenance, and the failure is loud rather than silent.
		Checkout: func(commitSHA, branch string) {
			if err := r.opts.Store.RecordCheckout(ctx, job.ScanID, commitSHA, branch); err != nil {
				log.Error("could not record the scanned revision",
					slog.String("error", err.Error()))
			}
		},
		Scanner: func(x Execution) {
			// ingest before RecordResult: parsing the inventory can add a
			// degradation, and a reason that arrived after the result was
			// recorded would never reach the gate.
			result, norm := r.ingest(ctx, log, job, x)
			scan.RecordResult(result)

			if err := r.opts.Store.RecordScannerResult(ctx, job.ScanID, result); err != nil {
				log.Error("could not record scanner result",
					slog.String("scanner", result.Scanner), slog.String("error", err.Error()))
			}
			if norm != nil {
				normalized = append(normalized, *norm)
			}
		},
	})
	if err != nil {
		var fe *FatalError
		if errors.As(err, &fe) {
			// Logged as well as recorded. The stored reason is a fixed,
			// non-sensitive summary (§15.3), which makes it safe and useless
			// for diagnosis -- "the worker could not create an isolated
			// workspace" does not say whether that was RBAC, storage, or a
			// name collision. Found by hitting exactly that in a cluster.
			log.Error("scan execution failed",
				slog.String("reason", string(fe.Reason)),
				slog.String("error", err.Error()))
			r.finalize(ctx, log, job.ScanID, scans.StatusFailed, fe.Reason)
			return
		}
		log.Error("scan execution failed", slog.String("error", err.Error()))
		r.finalize(ctx, log, job.ScanID, scans.StatusFailed, scans.FailureAllScannersDegraded)
		return
	}

	sc := r.persistFindings(ctx, log, job, scan, normalized)

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
	// The gate runs after the status is settled, because "did this scan
	// actually complete" is an input to the verdict rather than a footnote.
	r.gate(ctx, log, job, sc, status)
	r.finalize(ctx, log, job.ScanID, status, reason)
}

// ingest is the controller's half of one scanner's outcome.
//
// Storing raw bytes, parsing a bill of materials, and normalizing findings all
// need a database and none of them touch a subprocess -- so under ADR 039 they
// stay here, in the process that holds the credential, whether the bytes came
// from a local scanner or from a Job that has no credential at all.
//
// Nothing here can fail a scan. Raw output is persisted verbatim, so an
// inventory or a mapper that breaks can be replayed once it is fixed, while a
// scan failed over it would discard what every other scanner produced (§8).
func (r *Runner) ingest(
	ctx context.Context, log *slog.Logger, job queue.Job, x Execution,
) (scans.ScannerResult, *normalization.Result) {
	result := x.Result
	if result.Status != scans.ScannerSucceeded {
		return result, nil
	}
	name := result.Scanner

	if r.opts.Sink != nil {
		if err := r.opts.Sink.StoreRaw(ctx, job.ScanID, x.Raw); err != nil {
			log.Error("could not store raw result",
				slog.String("scanner", name), slog.String("error", err.Error()))
		}
	}

	// The adapter is asked what it can do; nothing here branches on its name
	// (§7 rule 2). Looked up from the registry rather than carried through the
	// executor, because a Kubernetes Job returns bytes and a scanner name, not
	// a Go value -- and normalization needs no binary, only the parser.
	adapter, known := r.opts.Registry.Get(name)
	if !known {
		log.Error("no adapter registered for a result", slog.String("scanner", name))
		return result, nil
	}

	// An SBOM either IS the scan output (syft) or comes from a separate run the
	// executor already made (trivy, ADR 037). Either way it is parsed here.
	if inv, ok := adapter.(sbom.Inventorier); ok {
		bom := x.Inventory
		if len(bom) == 0 {
			bom = x.Raw.Output
		}
		if len(bom) > 0 {
			result.Degradations = append(result.Degradations,
				r.recordInventory(ctx, log, inv, job.ScanID, job.ProjectID, name, bom)...)
		}
	}

	// Adapters that produce findings implement Normalizer. Syft does not,
	// because an SBOM is an inventory and nothing in it is wrong.
	var normalized *normalization.Result
	if n, ok := adapter.(normalization.Normalizer); ok && len(x.Raw.Output) > 0 {
		res, err := n.Normalize(x.Raw.Output, job.ScanID)
		if err != nil {
			// A scanner that ran but whose output cannot be normalized has
			// produced no usable findings, and saying so is the point.
			log.Error("could not normalize scanner output",
				slog.String("scanner", name), slog.String("error", err.Error()))
		} else {
			normalized = &res
		}
	}
	return result, normalized
}

func (r *Runner) executor() Executor {
	if r.opts.Executor != nil {
		return r.opts.Executor
	}
	return &InProcess{
		WorkspaceRoot:  r.opts.WorkspaceRoot,
		Fetcher:        r.opts.Fetcher,
		Fetch:          r.opts.Fetch,
		ScannerTimeout: r.opts.ScannerTimeout,
		Logger:         r.opts.Logger,
		Now:            r.now,
	}
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

// inventoryOutput runs an adapter's separate inventory pass.
//
// Returns nothing when the adapter has no inventory for this target kind, which
// is the common case: trivy inventories images and not filesystems, because
// syft already inventories a checkout and two inventories of one thing would
// disagree the moment their cataloguers did.
//
// A failure here costs an inventory and never the scan. The findings from the
// pass that already succeeded are worth more than the evidence this would have
// added.
// recordInventory parses and stores a scanner's bill of materials.
//
// Returns degradations to record against the scanner, so a truncated inventory
// travels the same route as every other partial result (ADR 010) and reaches
// the gate, rather than being logged and forgotten.
//
// Never fails the scan. An inventory is additive: the raw SBOM is persisted
// verbatim whatever happens here, so a parse that breaks can be replayed once
// the parser is fixed -- while a scan failed over it would discard the findings
// every other scanner produced.
func (r *Runner) recordInventory(
	ctx context.Context, log *slog.Logger, inv sbom.Inventorier,
	scanID, projectID, scanner string, raw []byte,
) []scanners.Degradation {
	if r.opts.Components == nil {
		// No store configured. The scan still runs and still stores raw output;
		// it simply keeps no inventory.
		return nil
	}

	result, err := inv.Inventory(raw)
	if err != nil {
		log.Error("could not read the scanner's bill of materials",
			slog.String("scanner", scanner), slog.String("error", err.Error()))
		return nil
	}

	if err := r.opts.Components.RecordScan(ctx, scanID, projectID, scanner, result.Components); err != nil {
		log.Error("could not store the bill of materials",
			slog.String("scanner", scanner), slog.String("error", err.Error()))
		return nil
	}

	log.Info("inventory recorded",
		slog.String("scanner", scanner), slog.Int("components", len(result.Components)))
	return result.Degradations
}

// persistFindings normalizes and stores what the scan found.
//
// Not fatal. A scan that ran and stored its raw output is worth more than one
// discarded because the findings could not be written, and the raw results can
// be reprocessed later (§8). The failure is loud rather than silent.
func (r *Runner) persistFindings(
	ctx context.Context, log *slog.Logger, job queue.Job,
	scan *scans.Scan, normalized []normalization.Result,
) *scored {
	if r.opts.Findings == nil || len(normalized) == 0 {
		return nil
	}

	combined := normalization.Combine(normalized)
	for _, e := range combined.Errors {
		// Per-entry parse failures are already safe to store: the mappers name
		// the field at fault and never quote the value.
		log.Warn("finding could not be normalized",
			slog.String("scan_id", job.ScanID), slog.String("detail", e))
	}

	// Which scanners are entitled to resolve a finding they did not report.
	//
	// This is the important half. A scan that ran only gitleaks says nothing
	// about semgrep's findings, and marking them resolved would be a false
	// "fixed" -- the same error as reporting a PARTIAL scan as clean (§13,
	// ADR 010). Only scanners that succeeded with no degradation count.
	var complete []string
	for _, res := range scan.Results {
		if res.Succeeded() {
			complete = append(complete, res.Scanner)
		}
	}

	if err := r.opts.Findings.RecordScan(
		ctx, job.ProjectID, job.ScanID, combined, complete, r.now(),
	); err != nil {
		log.Error("could not persist findings",
			slog.String("scan_id", job.ScanID), slog.String("error", err.Error()))
		return nil
	}

	log.Info("findings recorded",
		slog.String("scan_id", job.ScanID),
		slog.Int("findings", len(combined.Findings)),
		slog.Int("occurrences", len(combined.Occurrences)),
		slog.Int("parse_errors", len(combined.Errors)),
		slog.Any("resolving_scanners", complete),
	)

	r.correlate(ctx, log, job.ProjectID, job.ScanID)
	return r.score(ctx, log, job.ProjectID, job.ScanID)
}

// correlate recomputes the project's issues from its live findings.
//
// It runs after persistence rather than on the in-memory result, because
// correlation is project-wide: a finding this scan did not report still
// correlates with one it did, and the store is the only place that knows about
// both (ADR 017).
//
// Not fatal, for the same reason persistFindings is not. Findings that are
// stored but uncorrelated are still findings; a scan discarded because the
// derived view could not be rebuilt would lose the observations too.
func (r *Runner) correlate(ctx context.Context, log *slog.Logger, projectID, scanID string) {
	subjects, err := r.opts.Findings.ListLiveForCorrelation(ctx, projectID)
	if err != nil {
		log.Error("could not load findings for correlation",
			slog.String("scan_id", scanID), slog.String("error", err.Error()))
		return
	}

	// The built artifact, when there is one. Read here and passed in rather
	// than fetched by the engine, which stays pure (§8): correlation takes
	// findings and facts, never a database.
	//
	// Best-effort. A project with no image scan is the common case and yields
	// an empty inventory, which the engine reports as `unknown` -- the correct
	// answer, not a gap. A failure to read one costs deployment evidence and
	// must not cost the correlation that does not depend on it.
	var artifact correlation.Inventory
	if r.opts.Components != nil {
		if art, err := r.opts.Components.ArtifactFor(ctx, projectID); err != nil {
			log.Error("could not read the artifact inventory",
				slog.String("project_id", projectID), slog.String("error", err.Error()))
		} else if art.Found {
			artifact = correlation.NewInventory(art.ScanID, art.ScannedAt, art.PURLs, art.Complete)
		}
	}

	result := correlation.CorrelateWith(subjects, correlation.Options{Artifact: artifact})
	if err := r.opts.Findings.ReplaceCorrelation(ctx, projectID, result); err != nil {
		log.Error("could not persist correlation",
			slog.String("scan_id", scanID), slog.String("error", err.Error()))
		return
	}

	if len(result.Truncated) > 0 {
		// A truncated bucket means correlation is incomplete for that key.
		// Logged at warn rather than swallowed: silence here would look
		// identical to "nothing correlated", which is a different fact
		// (ADR 010's rule applied to this engine).
		log.Warn("correlation truncated an oversized bucket",
			slog.String("scan_id", scanID),
			slog.Any("keys", result.Truncated),
			slog.Int("limit", correlation.DefaultMaxBucketSize),
		)
	}

	log.Info("correlation recomputed",
		slog.String("scan_id", scanID),
		slog.Int("subjects", len(subjects)),
		slog.Int("issues", len(result.Issues)),
		slog.Int("links", len(result.Links)),
	)
}

// score recomputes the project's risk from its findings and issues (§10).
//
// After correlation, deliberately: a finding that correlation escalated is
// scored at the issue's severity, and running the two in the other order would
// score yesterday's classification of today's findings.
//
// Not fatal, for the same reason correlate is not. A stored finding with no
// score is still a finding; discarding the scan because a derived number could
// not be computed would lose the observations that produced it.
func (r *Runner) score(ctx context.Context, log *slog.Logger, projectID, scanID string) *scored {
	subjects, projectCtx, err := r.opts.Findings.LoadRiskInputs(ctx, projectID)
	if err != nil {
		log.Error("could not load inputs for risk scoring",
			slog.String("scan_id", scanID), slog.String("error", err.Error()))
		return nil
	}

	assessment := risk.Assess(subjects, projectCtx)
	weights := risk.DefaultWeights()
	if err := r.opts.Findings.SaveRiskScore(
		ctx, projectID, scanID, assessment, weights.Digest(), time.Now().UTC(),
	); err != nil {
		log.Error("could not persist risk score",
			slog.String("scan_id", scanID), slog.String("error", err.Error()))
		return nil
	}

	log.Info("risk recomputed",
		slog.String("scan_id", scanID),
		slog.Float64("score", assessment.Score),
		slog.Float64("total", assessment.Total),
		slog.Int("live", assessment.Live),
		slog.Int("dismissed", assessment.Dismissed),
		// The configuration the number was computed under. Without it a score
		// in a log line cannot be compared with one from before a re-tuning.
		slog.String("weights", weights.Digest()[:12]),
	)
	return &scored{subjects: subjects, projectCtx: projectCtx, assessment: assessment}
}

// scored is what the risk stage hands to the gate.
//
// Passed forward rather than reloaded, so the gate evaluates the same picture
// the score was computed from. Reloading would leave a window in which a
// concurrent change makes the verdict describe findings the score did not.
type scored struct {
	subjects   []risk.Subject
	projectCtx risk.Context
	assessment risk.Assessment
}

// gate evaluates the project's security policy against this scan (§12).
//
// Runs last, and after the terminal status is known, because the verdict
// depends on whether the scan actually completed: a scanner that crashed
// reported nothing, fewer findings breach fewer rules, and without this a
// broken scan would pass the gate precisely because it broke.
//
// Not fatal, like every derived stage before it. A scan whose gate could not be
// evaluated is still a scan that produced findings; discarding it would lose
// the observations to save the conclusion.
func (r *Runner) gate(
	ctx context.Context, log *slog.Logger, job queue.Job,
	sc *scored, status scans.Status,
) {
	if r.opts.Policies == nil || sc == nil {
		return
	}

	policy, err := r.opts.Policies.Get(ctx, job.ProjectID)
	if err != nil {
		log.Error("could not load security policy",
			slog.String("scan_id", job.ScanID), slog.String("error", err.Error()))
		return
	}

	in := policies.InputFrom(sc.subjects, sc.assessment.Score,
		string(status), status == scans.StatusCompleted)

	result, err := policies.Evaluate(policy, in)
	if err != nil {
		// An unusable policy is a configuration problem, and inventing a
		// verdict from one would hide it behind a confident answer.
		log.Error("could not evaluate security policy",
			slog.String("scan_id", job.ScanID), slog.String("error", err.Error()))
		return
	}

	if err := r.opts.Policies.SaveResult(
		ctx, job.ProjectID, job.ScanID, policy, result, r.now(),
	); err != nil {
		log.Error("could not persist policy result",
			slog.String("scan_id", job.ScanID), slog.String("error", err.Error()))
		return
	}

	log.Info("security gate evaluated",
		slog.String("scan_id", job.ScanID),
		slog.String("verdict", string(result.Verdict)),
		slog.Bool("scan_complete", result.Coverage.Complete),
		slog.Bool("coverage_downgrade", result.Coverage.Downgraded),
	)
}
