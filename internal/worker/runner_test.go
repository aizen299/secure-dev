package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

// --- fakes -----------------------------------------------------------------

type fakeStore struct {
	mu       sync.Mutex
	running  []string
	results  map[string][]scans.ScannerResult
	final    map[string]scans.Status
	reasons  map[string]scans.FailureReason
	failCall string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		results: map[string][]scans.ScannerResult{},
		final:   map[string]scans.Status{},
		reasons: map[string]scans.FailureReason{},
	}
}

func (f *fakeStore) MarkRunning(_ context.Context, id string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCall == "running" {
		return errors.New("store unavailable")
	}
	f.running = append(f.running, id)
	return nil
}

func (f *fakeStore) RecordScannerResult(_ context.Context, id string, r scans.ScannerResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[id] = append(f.results[id], r)
	return nil
}

func (f *fakeStore) Finalize(
	_ context.Context, id string, st scans.Status, reason scans.FailureReason, _ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.final[id] = st
	f.reasons[id] = reason
	return nil
}

func (f *fakeStore) finalStatus(id string) scans.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.final[id]
}

func (f *fakeStore) failureReason(id string) scans.FailureReason {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reasons[id]
}

func (f *fakeStore) resultsFor(id string) []scans.ScannerResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]scans.ScannerResult(nil), f.results[id]...)
}

type scriptedScanner struct {
	name     string
	kinds    []scanners.Kind
	scanErr  error
	versErr  error
	delay    time.Duration
	truncate bool
	started  atomic.Int32
}

func (s *scriptedScanner) Name() string { return s.name }
func (s *scriptedScanner) Capabilities() scanners.Capabilities {
	kinds := s.kinds
	if kinds == nil {
		kinds = []scanners.Kind{scanners.KindRepository}
	}
	return scanners.Capabilities{Kinds: kinds, Category: scanners.CategorySAST}
}
func (s *scriptedScanner) Version(context.Context) (string, error) {
	if s.versErr != nil {
		return "", s.versErr
	}
	return "1.2.3", nil
}
func (s *scriptedScanner) Scan(ctx context.Context, t scanners.Target) (scanners.RawResult, error) {
	s.started.Add(1)
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return scanners.RawResult{}, ctx.Err()
		}
	}
	if s.scanErr != nil {
		return scanners.RawResult{Scanner: s.name, ExitCode: 1}, s.scanErr
	}
	return scanners.RawResult{
		Scanner: s.name, Version: "1.2.3", Target: t,
		Output: []byte(`{"findings":[]}`), Truncated: s.truncate,
	}, nil
}

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func testRunner(t *testing.T, store ScanStore, sc ...scanners.Scanner) *Runner {
	t.Helper()
	reg := scanners.NewRegistry()
	for _, s := range sc {
		if err := reg.Register(s); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	r, err := New(Options{
		Registry:       reg,
		Queue:          queue.NewMemory(),
		Store:          store,
		Validator:      scanners.Validator{WorkspaceRoot: t.TempDir(), Resolver: fixedResolver{}},
		WorkspaceRoot:  t.TempDir(),
		Logger:         discard(),
		ScannerTimeout: 2 * time.Second,
		JobTimeout:     10 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

type fixedResolver struct{}

func (fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

func repoJob(id string) queue.Job {
	return queue.Job{
		ScanID: id, ProjectID: "p1", Attempt: 1,
		Target: scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://github.com/x/y"},
	}
}

// --- tests -----------------------------------------------------------------

func TestNewValidatesOptions(t *testing.T) {
	base := func() Options {
		return Options{
			Registry: scanners.NewRegistry(), Queue: queue.NewMemory(),
			Store: newFakeStore(), WorkspaceRoot: t.TempDir(), Logger: discard(),
		}
	}
	if _, err := New(base()); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	for name, mut := range map[string]func(*Options){
		"no registry":  func(o *Options) { o.Registry = nil },
		"no queue":     func(o *Options) { o.Queue = nil },
		"no store":     func(o *Options) { o.Store = nil },
		"no workspace": func(o *Options) { o.WorkspaceRoot = "" },
	} {
		t.Run(name, func(t *testing.T) {
			o := base()
			mut(&o)
			if _, err := New(o); err == nil {
				t.Error("invalid options accepted")
			}
		})
	}
}

func TestDefaultsAreApplied(t *testing.T) {
	r := testRunner(t, newFakeStore(), &scriptedScanner{name: "a"})
	if r.opts.Concurrency < 1 || r.opts.MaxAttempts < 1 || r.opts.PollTimeout <= 0 {
		t.Errorf("defaults not applied: %+v", r.opts)
	}
}

func TestAllScannersSucceedCompletesScan(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"}, &scriptedScanner{name: "bravo"})

	r.executeJob(t.Context(), repoJob("scan-ok"))

	if got := store.finalStatus("scan-ok"); got != scans.StatusCompleted {
		t.Errorf("status = %q, want completed", got)
	}
	if len(store.resultsFor("scan-ok")) != 2 {
		t.Errorf("recorded %d results, want 2", len(store.resultsFor("scan-ok")))
	}
}

// The §13 rule end to end: one broken scanner must yield PARTIAL, and the
// working scanner must still have run.
func TestOneFailingScannerYieldsPartial(t *testing.T) {
	store := newFakeStore()
	good := &scriptedScanner{name: "alpha"}
	bad := &scriptedScanner{name: "bravo", scanErr: errors.New("boom")}
	r := testRunner(t, store, good, bad)

	r.executeJob(t.Context(), repoJob("scan-partial"))

	if got := store.finalStatus("scan-partial"); got != scans.StatusPartial {
		t.Errorf("status = %q, want partial", got)
	}
	if good.started.Load() != 1 {
		t.Error("a failing scanner prevented the others from running")
	}

	var sawFailure bool
	for _, res := range store.resultsFor("scan-partial") {
		if res.Scanner == "bravo" {
			sawFailure = res.Status == scans.ScannerFailed
		}
	}
	if !sawFailure {
		t.Error("the failing scanner was not recorded as failed")
	}
}

func TestAllScannersFailYieldsFailed(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store,
		&scriptedScanner{name: "alpha", scanErr: errors.New("boom")},
		&scriptedScanner{name: "bravo", scanErr: errors.New("boom")},
	)

	r.executeJob(t.Context(), repoJob("scan-failed"))

	if got := store.finalStatus("scan-failed"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
}

// A missing binary is absent coverage, not a broken scanner, and must be
// visibly distinct in the results.
func TestMissingBinaryIsSkippedNotFailed(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store,
		&scriptedScanner{name: "installed"},
		&scriptedScanner{name: "absent", versErr: scanners.ErrBinaryMissing},
	)

	r.executeJob(t.Context(), repoJob("scan-skip"))

	var skipped bool
	for _, res := range store.resultsFor("scan-skip") {
		if res.Scanner == "absent" {
			skipped = res.Status == scans.ScannerSkipped
		}
	}
	if !skipped {
		t.Error("missing binary was not recorded as skipped")
	}
	// Absent coverage still degrades the scan.
	if got := store.finalStatus("scan-skip"); got != scans.StatusPartial {
		t.Errorf("status = %q, want partial", got)
	}
}

func TestTruncatedOutputDegradesScan(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "flood", truncate: true})

	r.executeJob(t.Context(), repoJob("scan-trunc"))

	if got := store.finalStatus("scan-trunc"); got != scans.StatusFailed {
		// A single truncated scanner means zero complete results.
		t.Errorf("status = %q, want failed (no complete coverage)", got)
	}
	for _, res := range store.resultsFor("scan-trunc") {
		if !res.Truncated {
			t.Error("result was not marked truncated")
		}
	}
}

func TestScannerTimeoutIsRecordedAsFailure(t *testing.T) {
	store := newFakeStore()
	slow := &scriptedScanner{name: "slow", delay: 5 * time.Second}
	r := testRunner(t, store, slow)
	r.opts.ScannerTimeout = 150 * time.Millisecond

	start := time.Now()
	r.executeJob(t.Context(), repoJob("scan-timeout"))

	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("scanner timeout was not enforced: took %s", elapsed)
	}
	if got := store.finalStatus("scan-timeout"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
}

// A hostile target must be refused at the worker, not just at the API.
func TestInvalidTargetIsRejectedOnArrival(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"})

	job := repoJob("scan-bad")
	job.Target.RepositoryURL = "file:///etc/passwd"
	r.executeJob(t.Context(), job)

	if got := store.finalStatus("scan-bad"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if len(store.resultsFor("scan-bad")) != 0 {
		t.Error("a scanner ran despite an invalid target")
	}
}

func TestUnknownScannerNameFailsScan(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"})

	job := repoJob("scan-unknown")
	job.Scanners = []string{"nonexistent"}
	r.executeJob(t.Context(), job)

	if got := store.finalStatus("scan-unknown"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
}

// A job that keeps killing its handler must be retired, not cycled forever.
func TestJobExceedingMaxAttemptsIsRetired(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"})
	r.opts.MaxAttempts = 2

	job := repoJob("scan-poison")
	job.Attempt = 5
	r.executeJob(t.Context(), job)

	if got := store.finalStatus("scan-poison"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if len(store.resultsFor("scan-poison")) != 0 {
		t.Error("a retired job still executed scanners")
	}
}

// The workspace holds untrusted repository content and must not survive.
func TestWorkspaceIsDestroyedAfterJob(t *testing.T) {
	root := t.TempDir()
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"})
	r.opts.WorkspaceRoot = root

	r.executeJob(t.Context(), repoJob("scan-ws"))

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("workspace survived the job: %d entries remain", len(entries))
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	var live, peak atomic.Int32
	blocker := make(chan struct{})

	gate := &gatedScanner{name: "gate", live: &live, peak: &peak, release: blocker}
	reg := scanners.NewRegistry()
	reg.MustRegister(gate)

	q := queue.NewMemory()
	store := newFakeStore()
	r, err := New(Options{
		Registry: reg, Queue: q, Store: store,
		Validator:     scanners.Validator{WorkspaceRoot: t.TempDir(), Resolver: fixedResolver{}},
		WorkspaceRoot: t.TempDir(), Logger: discard(),
		Concurrency: 2, PollTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := range 6 {
		if err := q.Enqueue(t.Context(), repoJob("scan-"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()

	time.Sleep(300 * time.Millisecond)
	close(blocker)
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	if got := peak.Load(); got > 2 {
		t.Errorf("peak concurrent jobs = %d, want at most 2", got)
	}
}

type gatedScanner struct {
	name    string
	live    *atomic.Int32
	peak    *atomic.Int32
	release chan struct{}
}

func (g *gatedScanner) Name() string { return g.name }
func (g *gatedScanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{Kinds: []scanners.Kind{scanners.KindRepository}}
}
func (g *gatedScanner) Version(context.Context) (string, error) { return "1", nil }
func (g *gatedScanner) Scan(ctx context.Context, _ scanners.Target) (scanners.RawResult, error) {
	n := g.live.Add(1)
	for {
		p := g.peak.Load()
		if n <= p || g.peak.CompareAndSwap(p, n) {
			break
		}
	}
	defer g.live.Add(-1)

	select {
	case <-g.release:
	case <-ctx.Done():
		return scanners.RawResult{}, ctx.Err()
	case <-time.After(3 * time.Second):
	}
	return scanners.RawResult{Scanner: g.name}, nil
}

func TestRunStopsOnContextCancel(t *testing.T) {
	r := testRunner(t, newFakeStore(), &scriptedScanner{name: "alpha"})
	r.opts.PollTimeout = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

// A panicking scanner must degrade one job, not kill the worker.
func TestPanicInJobDoesNotKillWorker(t *testing.T) {
	reg := scanners.NewRegistry()
	reg.MustRegister(&panicScanner{})
	q := queue.NewMemory()

	r, err := New(Options{
		Registry: reg, Queue: q, Store: newFakeStore(),
		Validator:     scanners.Validator{WorkspaceRoot: t.TempDir(), Resolver: fixedResolver{}},
		WorkspaceRoot: t.TempDir(), Logger: discard(), PollTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := q.Enqueue(t.Context(), repoJob("scan-panic")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker died on a panicking scanner")
	}
}

type panicScanner struct{}

func (panicScanner) Name() string { return "panic" }
func (panicScanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{Kinds: []scanners.Kind{scanners.KindRepository}}
}
func (panicScanner) Version(context.Context) (string, error) { return "1", nil }
func (panicScanner) Scan(context.Context, scanners.Target) (scanners.RawResult, error) {
	panic("scanner exploded")
}

// --- failure reasons -------------------------------------------------------
//
// A scan that fails before any scanner runs used to reach FAILED with no
// explanation anywhere. Once POST /scans exists, that is a status a user
// cannot act on, so each pre-execution failure records a fixed reason.

// Until Phase 3 registers adapters this is the outcome of every scan, so it is
// the reason a first-time user is most likely to meet.
func TestNoRegisteredScannerRecordsAReason(t *testing.T) {
	store := newFakeStore()
	// A registry holding only an image scanner cannot serve a repository job.
	r := testRunner(t, store, &scriptedScanner{
		name: "image-only", kinds: []scanners.Kind{scanners.KindImage},
	})

	r.executeJob(context.Background(), repoJob("scan-no-scanner"))

	if got := store.finalStatus("scan-no-scanner"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if got := store.failureReason("scan-no-scanner"); got != scans.FailureNoScannerAvailable {
		t.Errorf("reason = %q, want %q", got, scans.FailureNoScannerAvailable)
	}
}

// An explicit selection naming something unregistered is a different operator
// problem from having no adapter at all, and must read differently.
func TestUnknownRequestedScannerRecordsADistinctReason(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"})

	job := repoJob("scan-unknown-scanner")
	job.Scanners = []string{"nosuchscanner"}
	r.executeJob(context.Background(), job)

	if got := store.finalStatus("scan-unknown-scanner"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if got := store.failureReason("scan-unknown-scanner"); got != scans.FailureScannerNotRegistered {
		t.Errorf("reason = %q, want %q", got, scans.FailureScannerNotRegistered)
	}
}

func TestTargetValidationFailureRecordsAReason(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"})

	job := repoJob("scan-bad-target")
	// file:// would read the worker's own filesystem, so the validator rejects
	// it on arrival even though this system wrote the payload (§15.7).
	job.Target.RepositoryURL = "file:///etc/passwd"
	r.executeJob(context.Background(), job)

	if got := store.finalStatus("scan-bad-target"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if got := store.failureReason("scan-bad-target"); got != scans.FailureTargetInvalid {
		t.Errorf("reason = %q, want %q", got, scans.FailureTargetInvalid)
	}
}

func TestRetiredJobRecordsAReason(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store, &scriptedScanner{name: "alpha"})

	job := repoJob("scan-retired")
	job.Attempt = r.opts.MaxAttempts + 1
	r.executeJob(context.Background(), job)

	if got := store.failureReason("scan-retired"); got != scans.FailureMaxAttemptsExceeded {
		t.Errorf("reason = %q, want %q", got, scans.FailureMaxAttemptsExceeded)
	}
}

func TestEveryScannerFailingRecordsAReason(t *testing.T) {
	store := newFakeStore()
	r := testRunner(t, store,
		&scriptedScanner{name: "alpha", scanErr: errors.New("boom")},
		&scriptedScanner{name: "bravo", scanErr: errors.New("boom")})

	r.executeJob(context.Background(), repoJob("scan-all-failed"))

	if got := store.finalStatus("scan-all-failed"); got != scans.StatusFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if got := store.failureReason("scan-all-failed"); got != scans.FailureAllScannersDegraded {
		t.Errorf("reason = %q, want %q", got, scans.FailureAllScannersDegraded)
	}
}

// A PARTIAL scan already explains itself through its per-scanner results.
// Stamping a failure reason on it would misreport partial coverage as none.
func TestPartialAndCompletedScansRecordNoReason(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		store := newFakeStore()
		r := testRunner(t, store,
			&scriptedScanner{name: "alpha"},
			&scriptedScanner{name: "bravo", scanErr: errors.New("boom")})

		r.executeJob(context.Background(), repoJob("scan-partial-reason"))

		if got := store.finalStatus("scan-partial-reason"); got != scans.StatusPartial {
			t.Fatalf("status = %q, want partial", got)
		}
		if got := store.failureReason("scan-partial-reason"); got != "" {
			t.Errorf("reason = %q, want empty", got)
		}
	})

	t.Run("completed", func(t *testing.T) {
		store := newFakeStore()
		r := testRunner(t, store, &scriptedScanner{name: "alpha"})

		r.executeJob(context.Background(), repoJob("scan-clean-reason"))

		if got := store.failureReason("scan-clean-reason"); got != "" {
			t.Errorf("reason = %q, want empty", got)
		}
	})
}
