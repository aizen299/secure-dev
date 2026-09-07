package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/aizen299/secure-dev/internal/fetch"
	"github.com/aizen299/secure-dev/internal/sbom"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// InProcess runs a scan inside the worker's own process, in an ephemeral
// workspace directory.
//
// This is what `docker-compose` runs and what every test exercises. ADR 039
// keeps it rather than replacing it: a cluster can create a Job per scan and a
// developer's laptop cannot, and a change that improves production by breaking
// `make up` is not a good trade for a project this size. The cost is two
// execution paths for one thing, and it is a real cost.
//
// The isolation here is what it always was -- non-root, read-only root
// filesystem, a tmpfs workspace destroyed after the job, hard timeouts. What it
// cannot do is vary any of that per scan, which is the whole of ADR 039.
type InProcess struct {
	WorkspaceRoot  string
	Fetcher        Fetcher
	Fetch          fetch.Options
	ScannerTimeout time.Duration
	Logger         *slog.Logger
	Now            func() time.Time
}

// Execute implements Executor.
func (e *InProcess) Execute(ctx context.Context, req Request, ev Events) error {
	log := e.Logger.With(
		slog.String("scan_id", req.ScanID),
		slog.String("project_id", req.ProjectID),
		slog.String("target_kind", string(req.Target.Kind)),
	)

	workspace, err := scanners.NewWorkspace(e.WorkspaceRoot, req.ScanID)
	if err != nil {
		return fatal(scans.FailureWorkspaceUnavailable, err)
	}
	// Untrusted content never outlives the job that fetched it (§14.3).
	defer func() {
		if err := workspace.Remove(); err != nil {
			log.Error("could not remove workspace", slog.String("error", err.Error()))
		}
	}()

	scanTarget, err := e.fetchIfNeeded(ctx, log, req, workspace, ev)
	if err != nil {
		return err
	}

	for _, scanner := range req.Scanners {
		ev.Scanner(e.runScanner(ctx, log, scanner, scanTarget))

		// Stop dispatching further scanners once the job is cancelled. The
		// Runner still finalizes, so the scan reaches a terminal state.
		if ctx.Err() != nil {
			break
		}
	}
	return nil
}

// fetchIfNeeded turns a remote into bytes on disk, and reports what it got.
//
// This is where SecureOps pulls attacker-controlled content onto a machine it
// owns, so a failure here is recorded distinctly from a scanner failure: "we
// could not get the code" must never read as "we scanned it and found nothing".
func (e *InProcess) fetchIfNeeded(
	ctx context.Context, log *slog.Logger, req Request,
	workspace *scanners.Workspace, ev Events,
) (scanners.Target, error) {
	if req.Target.Kind != scanners.KindRepository {
		return req.Target, nil
	}

	fetched, err := e.Fetcher(ctx, e.Fetch, workspace.Path, req.Target)
	if err != nil {
		reason := scans.FailureFetchFailed
		if errors.Is(err, fetch.ErrTooLarge) {
			reason = scans.FailureTargetTooLarge
		}
		// git's stderr quotes the remote's response, so the detail is logged
		// and the stored reason stays fixed (§15.3).
		log.Error("could not fetch the repository", slog.String("error", err.Error()))
		return scanners.Target{}, fatal(reason, err)
	}

	log.Info("fetched repository",
		slog.Int64("bytes", fetched.Bytes),
		slog.Int("files", fetched.Files),
		slog.String("commit", fetched.CommitSHA),
		slog.Duration("duration", fetched.Duration),
	)

	// Prefer what was checked out over what was asked for. A request with no
	// ref still lands on a branch -- the remote's default -- and that name
	// cannot be recovered later, because branches move and are deleted.
	branch := fetched.Branch
	if branch == "" {
		branch = req.Target.Ref
	}
	if ev.Checkout != nil {
		ev.Checkout(fetched.CommitSHA, branch)
	}

	// Adapters see a local path and nothing else.
	return scanners.Target{Kind: scanners.KindFilesystem, Path: fetched.Path}, nil
}

// runScanner executes one scanner and converts every outcome -- success,
// failure, missing binary, timeout, oversized output -- into a structured
// result. It never returns an error: a broken scanner degrades its own result,
// nothing more (§13).
func (e *InProcess) runScanner(
	ctx context.Context, log *slog.Logger,
	scanner scanners.Scanner, target scanners.Target,
) Execution {
	name := scanner.Name()
	started := e.Now()
	out := Execution{
		Result: scans.ScannerResult{
			Scanner: name, Status: scans.ScannerRunning, StartedAt: &started,
		},
	}

	version, err := scanner.Version(ctx)
	if err != nil {
		// A missing binary is absent coverage, not a broken scan. It must be
		// visibly distinct from a scanner that ran and failed (§4).
		if errors.Is(err, scanners.ErrBinaryMissing) {
			log.Warn("scanner is not installed; skipping", slog.String("scanner", name))
			out.Result.Status = scans.ScannerSkipped
			out.Result.Error = "scanner binary is not installed"
			return out
		}
		log.Error("could not determine scanner version",
			slog.String("scanner", name), slog.String("error", err.Error()))
	}
	out.Result.Version = version

	scanCtx, cancel := context.WithTimeout(ctx, e.ScannerTimeout)
	defer cancel()

	raw, err := scanner.Scan(scanCtx, target)
	out.Raw = raw
	out.Result.Duration = e.Now().Sub(started)
	out.Result.ExitCode = raw.ExitCode
	// Reasons travel from the adapter unchanged. The worker records what the
	// adapter reported and never interprets it, which is how a scanner-specific
	// cause reaches the API without any core code branching on scanner name.
	out.Result.Degradations = raw.Degradations

	switch {
	case err == nil:
		out.Result.Status = scans.ScannerSucceeded
		// A degraded result stays succeeded: its findings are real, merely an
		// under-count. Succeeded() is false while any reason is present, so the
		// scan still settles at PARTIAL. No Error is set -- the reason is
		// structured, and prose duplicating it would be a second source of
		// truth (ADR 010).

		// An adapter whose bill of materials is a separate run produces it
		// here, because that is another subprocess and subprocesses are this
		// side of the seam. Whether it HAS one is asked of the adapter, never
		// inferred from its name (§7 rule 2).
		if runner, ok := scanner.(sbom.ArtifactInventorier); ok {
			out.Inventory = e.inventoryOutput(scanCtx, log, runner, name, target)
		}

	case errors.Is(err, scanners.ErrBinaryMissing):
		out.Result.Status = scans.ScannerSkipped
		out.Result.Error = "scanner binary is not installed"

	case errors.Is(err, scanners.ErrExecTimeout):
		out.Result.Status = scans.ScannerFailed
		out.Result.Error = "scanner exceeded its execution timeout"

	case errors.Is(err, scanners.ErrOutputTooLarge):
		out.Result.Status = scans.ScannerFailed
		out.Result.Degradations = []scanners.Degradation{scanners.DegradedOutputTruncated}
		out.Result.Error = "scanner output exceeded the size limit"

	case errors.Is(err, context.Canceled):
		out.Result.Status = scans.ScannerFailed
		out.Result.Error = "scan was cancelled"

	default:
		out.Result.Status = scans.ScannerFailed
		// The message is a fixed summary. The underlying error can quote
		// repository content or a detected secret, so it is logged, not stored.
		out.Result.Error = "scanner execution failed"
		log.Error("scanner failed",
			slog.String("scanner", name), slog.String("error", err.Error()))
	}

	return out
}

// inventoryOutput asks an adapter for a bill of materials it produces
// separately from its findings.
//
// A second subprocess, which is why it is on this side of the seam: syft's scan
// output IS an SBOM, while trivy's is a vulnerability report and its inventory
// needs another run asking for a different format (ADR 037).
func (e *InProcess) inventoryOutput(
	ctx context.Context, log *slog.Logger,
	runner sbom.ArtifactInventorier, scanner string, target scanners.Target,
) []byte {
	raw, err := runner.ScanInventory(ctx, target)
	switch {
	case errors.Is(err, scanners.ErrUnsupportedTarget):
		// Not a failure. This adapter simply has no inventory for this kind.
		return nil
	case err != nil:
		log.Warn("could not produce a bill of materials",
			slog.String("scanner", scanner), slog.String("error", err.Error()))
		return nil
	}
	return raw.Output
}
