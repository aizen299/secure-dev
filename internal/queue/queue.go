// Package queue defines the scan job queue.
//
// The queue is a trust boundary. The API enqueues; workers consume and are the
// only component that touches untrusted target content (CLAUDE.md §14). Job
// payloads are therefore plain data -- a scan ID, a validated target, a list of
// scanner names. A payload never carries a command line, a script, or anything
// else a worker would execute directly (ADR 003).
package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// ErrEmpty reports that no job was available before the poll deadline.
var ErrEmpty = errors.New("queue is empty")

// Job is one unit of scan work.
type Job struct {
	ScanID    string          `json:"scan_id"`
	ProjectID string          `json:"project_id"`
	Target    scanners.Target `json:"target"`
	// Scanners names the adapters to run. Empty means "every scanner that
	// supports this target kind", resolved by the registry at execution time.
	Scanners   []string  `json:"scanners,omitempty"`
	EnqueuedAt time.Time `json:"enqueued_at"`
	// Attempt counts delivery attempts, starting at 1, so a poison job can be
	// retired instead of cycling forever.
	Attempt int `json:"attempt"`
}

// Validate checks that a job is structurally usable.
//
// Payloads are re-validated on the consuming side: anything crossing the queue
// is treated as untrusted, even though this system wrote it (§15.7).
func (j Job) Validate() error {
	if j.ScanID == "" {
		return fmt.Errorf("job: scan_id is required")
	}
	if j.ProjectID == "" {
		return fmt.Errorf("job: project_id is required")
	}
	if !j.Target.Kind.Valid() {
		return fmt.Errorf("job: target kind %q is not valid", j.Target.Kind)
	}
	if j.Attempt < 1 {
		return fmt.Errorf("job: attempt must be at least 1")
	}
	return nil
}

// Queue transports scan jobs from the API to workers.
type Queue interface {
	// Enqueue submits a job.
	Enqueue(ctx context.Context, job Job) error

	// Dequeue blocks for up to timeout waiting for a job, returning ErrEmpty
	// if none arrives.
	Dequeue(ctx context.Context, timeout time.Duration) (Job, error)

	// Len reports the number of waiting jobs.
	Len(ctx context.Context) (int64, error)
}
