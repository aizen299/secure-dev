// Package scans models the scan lifecycle.
//
// A scan is a durable entity with an explicit state machine. The rule that
// shapes this package: a scan in which any scanner failed must never be
// reported as a clean, complete scan (CLAUDE.md §13). Degraded coverage has to
// stay visible all the way through to the security gate, because a gate that
// passes on incomplete evidence is worse than no gate.
package scans

import (
	"errors"
	"fmt"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// Status is a scan's lifecycle state.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusPartial   Status = "partial"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// ErrInvalidTransition reports an illegal lifecycle move.
var ErrInvalidTransition = errors.New("invalid scan status transition")

// allowedTransitions is the whole state machine, in one place so it can be read
// and tested as a unit.
var allowedTransitions = map[Status][]Status{
	StatusQueued:  {StatusRunning, StatusCancelled, StatusFailed},
	StatusRunning: {StatusPartial, StatusCompleted, StatusFailed, StatusCancelled},
	// Terminal states.
	StatusPartial:   {},
	StatusCompleted: {},
	StatusFailed:    {},
	StatusCancelled: {},
}

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	_, ok := allowedTransitions[s]
	return ok
}

// Terminal reports whether s is an end state.
func (s Status) Terminal() bool {
	switch s {
	case StatusPartial, StatusCompleted, StatusFailed, StatusCancelled:
		return true
	default:
		return false
	}
}

// CanTransitionTo reports whether s may move to next.
func (s Status) CanTransitionTo(next Status) bool {
	for _, allowed := range allowedTransitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}

// ScannerStatus is the outcome of one scanner within a scan.
type ScannerStatus string

const (
	ScannerPending   ScannerStatus = "pending"
	ScannerRunning   ScannerStatus = "running"
	ScannerSucceeded ScannerStatus = "succeeded"
	ScannerFailed    ScannerStatus = "failed"
	// ScannerSkipped means the scanner was not run at all, most often because
	// its binary is not installed. It is distinct from failure: absent
	// coverage and broken coverage need different operator responses.
	ScannerSkipped ScannerStatus = "skipped"
)

// ScannerResult records how one scanner fared. Per-scanner detail is what makes
// a PARTIAL scan actionable instead of merely alarming.
type ScannerResult struct {
	Scanner   string        `json:"scanner"`
	Status    ScannerStatus `json:"status"`
	Version   string        `json:"version,omitempty"`
	ExitCode  int           `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
	StartedAt *time.Time    `json:"started_at,omitempty"`
	// Error is a structured, non-sensitive summary. Raw scanner stderr is not
	// stored here: it can contain repository content and detected secrets.
	Error string `json:"error,omitempty"`
	// Truncated reports that output hit the size cap, so the result is
	// incomplete and must not be normalized as if it were whole.
	Truncated bool `json:"truncated,omitempty"`
}

// Succeeded reports whether this scanner produced usable, complete output.
func (r ScannerResult) Succeeded() bool {
	return r.Status == ScannerSucceeded && !r.Truncated
}

// Scan is the durable record of one scan.
type Scan struct {
	ID           string          `json:"id"`
	ProjectID    string          `json:"project_id"`
	RepositoryID *string         `json:"repository_id,omitempty"`
	Status       Status          `json:"status"`
	Target       scanners.Target `json:"target"`
	CommitSHA    string          `json:"commit_sha,omitempty"`
	Branch       string          `json:"branch,omitempty"`

	// RequestedScanners is the explicit selection the client asked for. Empty
	// means "every scanner that supports this target kind". It is kept
	// separate from Results so that "what was asked for" stays
	// distinguishable from "what actually ran".
	RequestedScanners []string `json:"requested_scanners,omitempty"`

	// FailureReason explains a terminal state reached without usable results.
	// Always one of the fixed FailureReason constants, never a raw error.
	FailureReason string `json:"failure_reason,omitempty"`

	Results []ScannerResult `json:"results"`

	QueuedAt    time.Time  `json:"queued_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Transition moves the scan to next, rejecting illegal moves.
func (s *Scan) Transition(next Status, at time.Time) error {
	if !next.Valid() {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidTransition, next)
	}
	if !s.Status.CanTransitionTo(next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, s.Status, next)
	}

	s.Status = next
	switch {
	case next == StatusRunning:
		t := at
		s.StartedAt = &t
	case next.Terminal():
		t := at
		s.CompletedAt = &t
	}
	return nil
}

// TerminalStatus computes the end state implied by the per-scanner results.
//
// This is the heart of §13. The rules, in order:
//   - no results at all           -> failed (nothing ran; not a clean scan)
//   - every scanner failed/skipped -> failed
//   - some succeeded, some did not -> partial
//   - all succeeded                -> completed
//
// A truncated result counts as not-succeeded: partial output would silently
// under-report findings, which is exactly the false reassurance a security gate
// must never give.
func (s *Scan) TerminalStatus() Status {
	if len(s.Results) == 0 {
		return StatusFailed
	}

	var succeeded, degraded int
	for _, r := range s.Results {
		if r.Succeeded() {
			succeeded++
		} else {
			degraded++
		}
	}

	switch {
	case succeeded == 0:
		return StatusFailed
	case degraded > 0:
		return StatusPartial
	default:
		return StatusCompleted
	}
}

// Complete moves the scan to the terminal state its results imply.
func (s *Scan) Complete(at time.Time) error {
	return s.Transition(s.TerminalStatus(), at)
}

// HasCompleteCoverage reports whether every selected scanner produced whole
// output. Policy evaluation must consult this: a gate result computed from
// degraded coverage has to be labelled as such (§12).
func (s *Scan) HasCompleteCoverage() bool {
	if len(s.Results) == 0 {
		return false
	}
	for _, r := range s.Results {
		if !r.Succeeded() {
			return false
		}
	}
	return true
}

// DegradedScanners lists the scanners that did not produce complete output.
func (s *Scan) DegradedScanners() []string {
	var out []string
	for _, r := range s.Results {
		if !r.Succeeded() {
			out = append(out, r.Scanner)
		}
	}
	return out
}

// RecordResult stores a scanner outcome, replacing any earlier entry for the
// same scanner (a retry supersedes its previous attempt).
func (s *Scan) RecordResult(result ScannerResult) {
	for i, existing := range s.Results {
		if existing.Scanner == result.Scanner {
			s.Results[i] = result
			return
		}
	}
	s.Results = append(s.Results, result)
}
