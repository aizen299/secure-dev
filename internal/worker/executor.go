package worker

import "github.com/aizen299/secure-dev/internal/scanexec"

// The scan execution seam moved to internal/scanexec in Phase 12b's second
// change, because both ends of it now need the types: the controller drives an
// Executor, and cmd/scanjob IS one, running inside a Job with no database
// credential (ADR 039).
//
// Aliases rather than a rename. The Runner and its tests speak in these names,
// they read correctly here -- a worker.Execution is what a worker ingests --
// and a rename would have churned a hundred call sites to say the same thing.
type (
	// Executor obtains a target's content and runs a scan's scanners.
	Executor = scanexec.Executor
	// Request is one scan's work, after validation and scanner selection.
	Request = scanexec.Request
	// Events reports progress while a scan is still running.
	Events = scanexec.Events
	// Execution is what one scanner contributed.
	Execution = scanexec.Execution
	// FatalError is a failure of the whole job, carrying the reason to record.
	FatalError = scanexec.FatalError
	// InProcess runs a scan inside this process, which is what compose gets.
	InProcess = scanexec.InProcess
	// Fetcher obtains untrusted target content into a workspace.
	Fetcher = scanexec.Fetcher
)

// fatal is re-exported for tests that assert the reason survives the seam.
func fatal(reason scanexec.Reason, err error) *FatalError {
	return scanexec.Fatal(reason, err)
}
