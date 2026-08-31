package httpapi

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scans"
)

// Synthetic credentials. Fixtures containing real secrets are forbidden (§19).
// Deliberately word-shaped rather than random hex: see internal/auth/auth_test.go.
const (
	testToken      = "secureops-test-token-not-a-secret"
	testTokenLabel = "test-client"
	// A valid UUID that no fake is seeded with.
	unknownUUID = "00000000-0000-4000-8000-000000000999"
)

func testAuthenticator(t interface{ Fatalf(string, ...any) }) *auth.Authenticator {
	a, err := auth.New([]string{testTokenLabel + ":" + testToken})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

// fakeProjectStore is an in-memory ProjectStore.
//
// Errors are injectable so the handlers' failure paths -- which is where
// information disclosure happens -- can be exercised without a database.
type fakeProjectStore struct {
	mu    sync.Mutex
	items map[string]projects.Project

	createErr error
	getErr    error
	existsErr error
	listErr   error
}

func newFakeProjectStore() *fakeProjectStore {
	return &fakeProjectStore{items: map[string]projects.Project{}}
}

// seed inserts a project directly, bypassing validation.
func (f *fakeProjectStore) seed(p projects.Project) projects.Project {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[p.ID] = p
	return p
}

func (f *fakeProjectStore) Create(_ context.Context, input projects.NewProject) (projects.Project, error) {
	if f.createErr != nil {
		return projects.Project{}, f.createErr
	}
	// The real store validates through Normalize, so the fake must too, or the
	// tests would pass against behaviour production does not have.
	normalized, err := input.Normalize()
	if err != nil {
		return projects.Project{}, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, existing := range f.items {
		if existing.Slug == normalized.Slug {
			return projects.Project{}, projects.ErrSlugTaken
		}
	}

	now := time.Now().UTC()
	p := projects.Project{
		ID:             newTestUUID(len(f.items) + 1),
		Name:           normalized.Name,
		Slug:           normalized.Slug,
		Description:    normalized.Description,
		Environment:    normalized.Environment,
		Criticality:    normalized.Criticality,
		InternetFacing: normalized.InternetFacing,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	f.items[p.ID] = p
	return p, nil
}

func (f *fakeProjectStore) Get(_ context.Context, id string) (projects.Project, error) {
	if f.getErr != nil {
		return projects.Project{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.items[id]
	if !ok {
		return projects.Project{}, projects.ErrNotFound
	}
	return p, nil
}

func (f *fakeProjectStore) Exists(_ context.Context, id string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.items[id]
	return ok, nil
}

func (f *fakeProjectStore) List(_ context.Context, page projects.Page) ([]projects.Project, bool, error) {
	if f.listErr != nil {
		return nil, false, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	all := make([]projects.Project, 0, len(f.items))
	for _, p := range f.items {
		all = append(all, p)
	}
	return paginate(all, page.Limit, page.Offset)
}

// fakeScanStore is an in-memory ScanStore.
type fakeScanStore struct {
	mu    sync.Mutex
	items map[string]scans.Scan
	// finalized records what Finalize was called with, so the unqueued-scan
	// path can be asserted rather than assumed.
	finalized map[string]scans.FailureReason

	createErr   error
	getErr      error
	listErr     error
	finalizeErr error
}

func newFakeScanStore() *fakeScanStore {
	return &fakeScanStore{
		items:     map[string]scans.Scan{},
		finalized: map[string]scans.FailureReason{},
	}
}

func (f *fakeScanStore) seed(s scans.Scan) scans.Scan {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[s.ID] = s
	return s
}

func (f *fakeScanStore) Create(_ context.Context, input scans.NewScan) (scans.Scan, error) {
	if f.createErr != nil {
		return scans.Scan{}, f.createErr
	}
	normalized, err := input.Normalize()
	if err != nil {
		return scans.Scan{}, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	s := scans.Scan{
		ID:                newTestUUID(len(f.items) + 100),
		ProjectID:         normalized.ProjectID,
		RepositoryID:      normalized.RepositoryID,
		Status:            scans.StatusQueued,
		Target:            normalized.Target,
		CommitSHA:         normalized.CommitSHA,
		Branch:            normalized.Branch,
		RequestedScanners: normalized.Scanners,
		QueuedAt:          time.Now().UTC(),
	}
	f.items[s.ID] = s
	return s, nil
}

func (f *fakeScanStore) Get(_ context.Context, id string) (scans.Scan, error) {
	if f.getErr != nil {
		return scans.Scan{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.items[id]
	if !ok {
		return scans.Scan{}, scans.ErrNotFound
	}
	return s, nil
}

func (f *fakeScanStore) ListByProject(
	_ context.Context, projectID string, page scans.Page,
) ([]scans.Scan, bool, error) {
	if f.listErr != nil {
		return nil, false, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	var all []scans.Scan
	for _, s := range f.items {
		if s.ProjectID == projectID {
			all = append(all, s)
		}
	}
	return paginate(all, page.Limit, page.Offset)
}

func (f *fakeScanStore) Finalize(
	_ context.Context, scanID string, status scans.Status,
	reason scans.FailureReason, _ time.Time,
) error {
	if f.finalizeErr != nil {
		return f.finalizeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	s, ok := f.items[scanID]
	if !ok {
		return errors.New("no such scan")
	}
	s.Status = status
	s.FailureReason = string(reason)
	f.items[scanID] = s
	f.finalized[scanID] = reason
	return nil
}

// paginate applies limit/offset with the same has-more semantics the real
// stores use, so pagination assertions mean the same thing in both.
func paginate[T any](all []T, limit, offset int) ([]T, bool, error) {
	if offset >= len(all) {
		return nil, false, nil
	}
	rest := all[offset:]
	if len(rest) > limit {
		return rest[:limit], true, nil
	}
	return rest, false, nil
}

// failingQueue rejects every enqueue, to exercise the path where a scan is
// persisted but its job never reaches a worker.
type failingQueue struct{ err error }

func (q failingQueue) Enqueue(context.Context, queue.Job) error { return q.err }
func (q failingQueue) Dequeue(context.Context, time.Duration) (queue.Job, error) {
	return queue.Job{}, queue.ErrEmpty
}
func (q failingQueue) Len(context.Context) (int64, error) { return 0, nil }

// newTestUUID builds a deterministic, syntactically valid UUID.
func newTestUUID(n int) string {
	const hex = "0123456789abcdef"
	suffix := []byte("000000000000")
	for i := len(suffix) - 1; i >= 0 && n > 0; i-- {
		suffix[i] = hex[n%16]
		n /= 16
	}
	// Version 4, variant 8: shape matters, randomness does not.
	return "11111111-2222-4333-8444-" + string(suffix)
}
