package scanjob

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aizen299/secure-dev/internal/fetch"
	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Config is everything a Job is told.
//
// Every value arrives through the environment, never a flag: a flag is visible
// in `ps` and in a pod's spec, and the token is a credential. That is the same
// rule the CI client follows (ADR 036), for the same reason.
type Config struct {
	ScanID    string
	ProjectID string
	// CallbackURL is the controller. The Job talks to exactly this and nothing
	// else in the cluster.
	CallbackURL string
	Token       string

	Target   scanners.Target
	Scanners []string

	// Phase is which half of a repository scan this pod is: the fetch, which
	// has egress, or the scan, which has none (ADR 039 §5). Empty runs both,
	// which is what a single-Job image or endpoint scan does.
	Phase scanexec.Phase
	// WorkspacePath is the volume the two phases share.
	WorkspacePath string

	WorkspaceRoot  string
	ScannerTimeout time.Duration
	Fetch          fetch.Options
}

// Run executes one scan and reports it.
//
// It returns an error when the scan could not be run at all, or when a result
// could not be reported. The second is deliberate: a Job that scanned
// successfully and failed to deliver must not exit zero, because the controller
// would then see a completed scan with a scanner silently missing from it.
func Run(ctx context.Context, cfg Config, registry *scanners.Registry, log *slog.Logger) error {
	if cfg.ScanID == "" || cfg.CallbackURL == "" || cfg.Token == "" {
		return fmt.Errorf("scanjob: scan id, callback URL and token are all required")
	}

	// Selection is re-resolved here from names the controller chose. The Job
	// does not decide what to run -- it is told, and resolving a name it does
	// not have is an error rather than a quiet omission.
	selected, err := registry.Resolve(scanners.EffectiveKind(cfg.Target.Kind), cfg.Scanners)
	if err != nil {
		return fmt.Errorf("scanjob: resolving scanners: %w", err)
	}

	reporter := NewReporter(cfg.CallbackURL, cfg.Token, cfg.ScanID)

	// A reporting failure is captured rather than thrown, so the scan finishes
	// and every result gets its attempt. The first error is what the Job exits
	// with -- losing one result is a failure of the whole Job either way, and
	// stopping early would lose the rest too.
	var reportErr error
	events := reporter.Events(func(err error) {
		log.Error("could not report to the controller", slog.String("error", err.Error()))
		if reportErr == nil {
			reportErr = err
		}
	})

	exec := &scanexec.InProcess{
		Phase:          cfg.Phase,
		WorkspacePath:  cfg.WorkspacePath,
		WorkspaceRoot:  cfg.WorkspaceRoot,
		Fetcher:        fetch.Repository,
		Fetch:          cfg.Fetch,
		ScannerTimeout: cfg.ScannerTimeout,
		Logger:         log,
		Now:            func() time.Time { return time.Now().UTC() },
	}

	if err := exec.Execute(ctx, scanexec.Request{
		ScanID:    cfg.ScanID,
		ProjectID: cfg.ProjectID,
		Target:    cfg.Target,
		Scanners:  selected,
	}, events); err != nil {
		return err
	}
	return reportErr
}
