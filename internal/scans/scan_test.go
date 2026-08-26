package scans

import (
	"errors"
	"testing"
	"time"
)

func now() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) }

func TestStatusValidity(t *testing.T) {
	for _, s := range []Status{StatusQueued, StatusRunning, StatusPartial, StatusCompleted, StatusFailed, StatusCancelled} {
		if !s.Valid() {
			t.Errorf("%q reported invalid", s)
		}
	}
	for _, s := range []Status{"", "done", "QUEUED", "success"} {
		if s.Valid() {
			t.Errorf("%q reported valid", s)
		}
	}
}

func TestTerminalStates(t *testing.T) {
	terminal := []Status{StatusPartial, StatusCompleted, StatusFailed, StatusCancelled}
	for _, s := range terminal {
		if !s.Terminal() {
			t.Errorf("%q should be terminal", s)
		}
	}
	for _, s := range []Status{StatusQueued, StatusRunning} {
		if s.Terminal() {
			t.Errorf("%q should not be terminal", s)
		}
	}
}

func TestLegalTransitions(t *testing.T) {
	legal := []struct{ from, to Status }{
		{StatusQueued, StatusRunning},
		{StatusQueued, StatusCancelled},
		{StatusQueued, StatusFailed},
		{StatusRunning, StatusCompleted},
		{StatusRunning, StatusPartial},
		{StatusRunning, StatusFailed},
		{StatusRunning, StatusCancelled},
	}
	for _, tc := range legal {
		t.Run(string(tc.from)+"->"+string(tc.to), func(t *testing.T) {
			s := &Scan{Status: tc.from}
			if err := s.Transition(tc.to, now()); err != nil {
				t.Errorf("legal transition rejected: %v", err)
			}
			if s.Status != tc.to {
				t.Errorf("status = %q, want %q", s.Status, tc.to)
			}
		})
	}
}

// Terminal states are final. Re-opening a finished scan would let a failed run
// be quietly rewritten as a clean one.
func TestIllegalTransitions(t *testing.T) {
	illegal := []struct{ from, to Status }{
		{StatusQueued, StatusCompleted},  // must run first
		{StatusQueued, StatusPartial},    // must run first
		{StatusCompleted, StatusRunning}, // terminal
		{StatusFailed, StatusCompleted},  // terminal: would erase the failure
		{StatusPartial, StatusCompleted}, // terminal: would erase degradation
		{StatusCancelled, StatusRunning}, // terminal
		{StatusRunning, StatusQueued},    // backwards
		{StatusRunning, StatusRunning},   // no self-loop
	}
	for _, tc := range illegal {
		t.Run(string(tc.from)+"->"+string(tc.to), func(t *testing.T) {
			s := &Scan{Status: tc.from}
			if err := s.Transition(tc.to, now()); !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("illegal transition allowed: err = %v", err)
			}
			if s.Status != tc.from {
				t.Errorf("status changed to %q on a rejected transition", s.Status)
			}
		})
	}
}

func TestTransitionRejectsUnknownStatus(t *testing.T) {
	s := &Scan{Status: StatusRunning}
	if err := s.Transition("finished", now()); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("err = %v, want ErrInvalidTransition", err)
	}
}

func TestTransitionStampsTimes(t *testing.T) {
	s := &Scan{Status: StatusQueued}

	if err := s.Transition(StatusRunning, now()); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if s.StartedAt == nil || !s.StartedAt.Equal(now()) {
		t.Errorf("StartedAt = %v, want %v", s.StartedAt, now())
	}
	if s.CompletedAt != nil {
		t.Error("CompletedAt set while still running")
	}

	end := now().Add(time.Minute)
	if err := s.Transition(StatusCompleted, end); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if s.CompletedAt == nil || !s.CompletedAt.Equal(end) {
		t.Errorf("CompletedAt = %v, want %v", s.CompletedAt, end)
	}
}

func result(name string, status ScannerStatus) ScannerResult {
	return ScannerResult{Scanner: name, Status: status}
}

// The central §13 rule: a scan with any failed scanner is never "completed".
func TestTerminalStatusFromResults(t *testing.T) {
	tests := []struct {
		name    string
		results []ScannerResult
		want    Status
	}{
		{
			name: "all succeeded",
			results: []ScannerResult{
				result("gitleaks", ScannerSucceeded), result("semgrep", ScannerSucceeded),
			},
			want: StatusCompleted,
		},
		{
			name: "one failed is partial, never completed",
			results: []ScannerResult{
				result("gitleaks", ScannerSucceeded), result("semgrep", ScannerFailed),
			},
			want: StatusPartial,
		},
		{
			name: "a skipped scanner also degrades the scan",
			results: []ScannerResult{
				result("gitleaks", ScannerSucceeded), result("zap", ScannerSkipped),
			},
			want: StatusPartial,
		},
		{
			name: "every scanner failed",
			results: []ScannerResult{
				result("gitleaks", ScannerFailed), result("semgrep", ScannerFailed),
			},
			want: StatusFailed,
		},
		{
			name:    "all skipped means nothing was actually scanned",
			results: []ScannerResult{result("zap", ScannerSkipped)},
			want:    StatusFailed,
		},
		{
			name:    "no results at all is a failure, not a clean scan",
			results: nil,
			want:    StatusFailed,
		},
		{
			name: "still-pending scanner degrades the scan",
			results: []ScannerResult{
				result("gitleaks", ScannerSucceeded), result("semgrep", ScannerPending),
			},
			want: StatusPartial,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Scan{Status: StatusRunning, Results: tc.results}
			if got := s.TerminalStatus(); got != tc.want {
				t.Errorf("TerminalStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Truncated output is incomplete evidence. Treating it as success would let a
// gate pass on findings that were never seen.
func TestTruncatedResultDegradesScan(t *testing.T) {
	s := &Scan{Status: StatusRunning, Results: []ScannerResult{
		{Scanner: "gitleaks", Status: ScannerSucceeded},
		{Scanner: "trivy", Status: ScannerSucceeded, Truncated: true},
	}}

	if got := s.TerminalStatus(); got != StatusPartial {
		t.Errorf("TerminalStatus() = %q, want partial for truncated output", got)
	}
	if s.HasCompleteCoverage() {
		t.Error("HasCompleteCoverage() = true despite truncated output")
	}
	degraded := s.DegradedScanners()
	if len(degraded) != 1 || degraded[0] != "trivy" {
		t.Errorf("DegradedScanners() = %v, want [trivy]", degraded)
	}
}

func TestCompleteAppliesTerminalStatus(t *testing.T) {
	s := &Scan{Status: StatusRunning, Results: []ScannerResult{
		result("gitleaks", ScannerSucceeded), result("semgrep", ScannerFailed),
	}}

	if err := s.Complete(now()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if s.Status != StatusPartial {
		t.Errorf("status = %q, want partial", s.Status)
	}
	if s.CompletedAt == nil {
		t.Error("CompletedAt was not stamped")
	}
}

func TestHasCompleteCoverage(t *testing.T) {
	full := &Scan{Results: []ScannerResult{
		result("a", ScannerSucceeded), result("b", ScannerSucceeded),
	}}
	if !full.HasCompleteCoverage() {
		t.Error("HasCompleteCoverage() = false for an all-succeeded scan")
	}

	// An empty scan has no coverage at all; it must not read as complete.
	if (&Scan{}).HasCompleteCoverage() {
		t.Error("HasCompleteCoverage() = true for a scan with no results")
	}

	partial := &Scan{Results: []ScannerResult{
		result("a", ScannerSucceeded), result("b", ScannerFailed),
	}}
	if partial.HasCompleteCoverage() {
		t.Error("HasCompleteCoverage() = true despite a failed scanner")
	}
	if got := partial.DegradedScanners(); len(got) != 1 || got[0] != "b" {
		t.Errorf("DegradedScanners() = %v, want [b]", got)
	}
}

func TestRecordResultReplacesRetry(t *testing.T) {
	s := &Scan{}
	s.RecordResult(ScannerResult{Scanner: "trivy", Status: ScannerFailed, ExitCode: 2})
	s.RecordResult(ScannerResult{Scanner: "gitleaks", Status: ScannerSucceeded})
	// A retry supersedes the earlier attempt rather than appending.
	s.RecordResult(ScannerResult{Scanner: "trivy", Status: ScannerSucceeded})

	if len(s.Results) != 2 {
		t.Fatalf("results = %d, want 2 (retry should replace)", len(s.Results))
	}
	for _, r := range s.Results {
		if r.Scanner == "trivy" && r.Status != ScannerSucceeded {
			t.Errorf("trivy status = %q, want succeeded after retry", r.Status)
		}
	}
	if s.TerminalStatus() != StatusCompleted {
		t.Errorf("TerminalStatus() = %q, want completed", s.TerminalStatus())
	}
}

func TestScannerResultSucceeded(t *testing.T) {
	if !(ScannerResult{Status: ScannerSucceeded}).Succeeded() {
		t.Error("succeeded result reported as not succeeded")
	}
	for _, r := range []ScannerResult{
		{Status: ScannerFailed},
		{Status: ScannerSkipped},
		{Status: ScannerPending},
		{Status: ScannerRunning},
		{Status: ScannerSucceeded, Truncated: true},
	} {
		if r.Succeeded() {
			t.Errorf("%+v reported as succeeded", r)
		}
	}
}
