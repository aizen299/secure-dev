package scanexec

import (
	"context"
	"fmt"

	"github.com/aizen299/secure-dev/internal/fetch"

	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// Executor obtains a target's content and runs a scan's scanners against it.
//
// This is the seam ADR 039 cuts the worker along. Everything after execution --
// normalization, dedup, correlation, risk, the gate, and every write to the
// database -- is the same whatever produced the bytes, so it stays in the
// Runner. Everything that touches untrusted content is behind here.
//
// Two implementations follow: the in-process one below, which is what
// docker-compose runs, and a Kubernetes one that creates a Job per scan. The
// second is why this interface exists, and the reason is not packaging: a scan
// running in its own pod can be given a filesystem quota and a network policy
// derived from what its adapters declared, and it does not have to hold the
// database credential to do it.
type Executor interface {
	// Execute runs the request and reports progress through ev as it happens.
	//
	// It returns an error only for a failure of the whole job -- the content
	// could not be fetched, the workspace could not be made. A scanner that
	// fails, hangs, or is missing is reported through ev.Scanner as a degraded
	// result and is not an error here: one broken scanner degrades its own
	// result and nothing more (§13).
	Execute(ctx context.Context, req Request, ev Events) error
}

// Request is one scan's work, after the target has been re-validated and the
// adapters resolved. Both happen in the Runner, because both are decisions
// about what to run rather than the running of it.
type Request struct {
	ScanID    string
	ProjectID string
	// Target as submitted and validated. A repository target is still a remote
	// here; turning it into a checkout is the executor's job (ADR 008).
	Target   scanners.Target
	Scanners []scanners.Scanner
}

// Events reports progress while a scan is still running.
//
// Callbacks rather than a returned slice, and that is deliberate rather than
// stylistic: §13 requires progress reporting, and a scan runs six scanners over
// minutes. Collecting results and returning them at the end would make a scan
// look motionless until it finished, and would make the Kubernetes executor --
// which receives results one at a time as the Job posts them -- have to buffer
// for no reason.
type Events struct {
	// Checkout reports the revision that was actually fetched, as soon as it
	// is known. Only called for a target that was fetched.
	Checkout func(commitSHA, branch string)
	// Scanner reports one scanner's outcome as it finishes.
	Scanner func(Execution)
}

// Execution is what one scanner contributed.
type Execution struct {
	// Result is how the process behaved: status, version, exit code, duration,
	// degradation reasons. Classifying this belongs with execution, because it
	// is a statement about a subprocess rather than about findings.
	Result scans.ScannerResult
	// Raw is the verbatim output, stored as-is (§8).
	Raw scanners.RawResult
	// Inventory is a bill of materials the adapter produced separately from
	// its findings. Empty for adapters whose scan output IS the SBOM, and for
	// those that produce none at all -- the Runner asks the adapter which it
	// is rather than branching on a name (§7 rule 2).
	Inventory []byte
}

// FatalError is a failure of the whole job, carrying the reason to record.
//
// A typed error rather than a sentinel per case: the Runner needs the reason to
// persist, and mapping an opaque error back to one would put knowledge of the
// executor's failure modes in the caller.
type FatalError struct {
	Reason scans.FailureReason
	Err    error
}

func (e *FatalError) Error() string {
	return fmt.Sprintf("%s: %v", e.Reason, e.Err)
}

func (e *FatalError) Unwrap() error { return e.Err }

// Fatal builds a job-level failure carrying the reason to persist.
func Fatal(reason scans.FailureReason, err error) *FatalError {
	return &FatalError{Reason: reason, Err: err}
}

// Reason is the failure vocabulary, aliased so callers need not import scans
// only to name one.
type Reason = scans.FailureReason

// Fetcher obtains untrusted target content into a workspace.
//
// A function type rather than a direct call so an executor can be tested
// without a git remote.
type Fetcher func(
	ctx context.Context, opts fetch.Options, workspace string, target scanners.Target,
) (fetch.Result, error)
