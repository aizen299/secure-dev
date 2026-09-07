package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// fakeExecutor stands in for a Kubernetes Job: it produces results without
// running anything, which is the point of the seam.
type fakeExecutor struct {
	calls    int
	req      Request
	emit     []Execution
	checkout [2]string
	err      error
}

func (f *fakeExecutor) Execute(_ context.Context, req Request, ev Events) error {
	f.calls++
	f.req = req
	if f.checkout[0] != "" && ev.Checkout != nil {
		ev.Checkout(f.checkout[0], f.checkout[1])
	}
	for _, x := range f.emit {
		ev.Scanner(x)
	}
	return f.err
}

func succeededBy(scanner string, output []byte) Execution {
	started := time.Unix(0, 0).UTC()
	return Execution{
		Result: scans.ScannerResult{
			Scanner: scanner, Status: scans.ScannerSucceeded, StartedAt: &started,
		},
		Raw: scanners.RawResult{Scanner: scanner, Output: output},
	}
}

// TestAConfiguredExecutorReplacesInProcessExecution is the seam's contract.
//
// A Kubernetes deployment supplies an executor that creates a Job, and nothing
// else about the pipeline changes. If this stops holding, the split ADR 039
// describes has leaked back together.
func TestAConfiguredExecutorReplacesInProcessExecution(t *testing.T) {
	store := newFakeStore()
	fetcher := &fakeFetcher{makeDir: true}
	r := testRunnerWithFetcher(t, store, fetcher, &scriptedScanner{name: "gitleaks"})

	exec := &fakeExecutor{emit: []Execution{succeededBy("gitleaks", []byte(`{"findings":[]}`))}}
	r.opts.Executor = exec

	job := repoJob("s-exec-1")
	r.executeJob(context.Background(), job)

	if exec.calls != 1 {
		t.Fatalf("executor called %d times, want 1", exec.calls)
	}
	if fetcher.calls != 0 {
		t.Errorf("the in-process fetcher ran %d times; a configured executor owns fetching", fetcher.calls)
	}
	results := store.resultsFor(job.ScanID)
	if len(results) != 1 || results[0].Scanner != "gitleaks" {
		t.Fatalf("recorded %+v, want one gitleaks result from the executor", results)
	}
	if got := store.finalStatus(job.ScanID); got != scans.StatusCompleted {
		t.Errorf("status = %q, want completed", got)
	}
}

// TestTheExecutorIsHandedTheValidatedTargetAndTheResolvedScanners.
//
// Validation and selection stay in the Runner deliberately (ADR 039): they are
// decisions about what to run, and a Job that chose its own scanners would take
// a decision away from the component that holds the credential.
func TestTheExecutorIsHandedTheValidatedTargetAndTheResolvedScanners(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "gitleaks"}, &scriptedScanner{name: "semgrep"})
	exec := &fakeExecutor{}
	r.opts.Executor = exec

	job := repoJob("s-exec-2")
	r.executeJob(context.Background(), job)

	if exec.req.ScanID != job.ScanID || exec.req.ProjectID != job.ProjectID {
		t.Errorf("request identifies %q/%q, want %q/%q",
			exec.req.ScanID, exec.req.ProjectID, job.ScanID, job.ProjectID)
	}
	if exec.req.Target.Kind != scanners.KindRepository {
		t.Errorf("target kind = %q, want the submitted repository target", exec.req.Target.Kind)
	}
	if len(exec.req.Scanners) != 2 {
		t.Errorf("handed %d scanners, want both resolved adapters", len(exec.req.Scanners))
	}
}

// TestAFatalExecutorErrorCarriesItsReason.
//
// Typed rather than inferred, so a Kubernetes executor can report "the Job
// could not be scheduled" without the Runner guessing from an opaque error
// what to persist.
func TestAFatalExecutorErrorCarriesItsReason(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "gitleaks"})
	r.opts.Executor = &fakeExecutor{
		err: fatal(scans.FailureTargetTooLarge, errors.New("too big")),
	}

	job := repoJob("s-exec-3")
	r.executeJob(context.Background(), job)

	if got := store.finalStatus(job.ScanID); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if got := store.failureReason(job.ScanID); got != scans.FailureTargetTooLarge {
		t.Errorf("reason = %q, want the executor's own reason", got)
	}
}

// TestAnUntypedExecutorErrorStillTerminatesTheScan.
//
// A scan must reach a terminal state whatever went wrong. An executor that
// returns a bare error is a bug in that executor, and a scan must not be left
// RUNNING forever because of it.
func TestAnUntypedExecutorErrorStillTerminatesTheScan(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "gitleaks"})
	r.opts.Executor = &fakeExecutor{err: errors.New("something unclassified")}

	job := repoJob("s-exec-4")
	r.executeJob(context.Background(), job)

	if got := store.finalStatus(job.ScanID); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
}

// TestTheCheckoutCallbackRecordsTheRevisionAsItLands.
//
// A callback rather than a return value, because §13 wants progress while a
// scan runs -- and because a Kubernetes executor learns the revision from a Job
// that is still going.
func TestTheCheckoutCallbackRecordsTheRevisionAsItLands(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "gitleaks"})
	r.opts.Executor = &fakeExecutor{checkout: [2]string{"abc123", "release-9"}}

	job := repoJob("s-exec-5")
	r.executeJob(context.Background(), job)

	if got := store.checkoutFor(job.ScanID); got != [2]string{"abc123", "release-9"} {
		t.Errorf("recorded %v, want abc123/release-9", got)
	}
}

// TestTheDefaultExecutorIsInProcess.
//
// Compose has no way to create a Job, so a Runner built without an executor
// must still scan. This is the line that keeps `make up` working.
func TestTheDefaultExecutorIsInProcess(t *testing.T) {
	r := testRunner(t, newFakeStore(), &scriptedScanner{name: "gitleaks"})
	if _, ok := r.executor().(*InProcess); !ok {
		t.Fatalf("default executor is %T, want *InProcess", r.executor())
	}
}
