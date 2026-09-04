package httpapi

import (
	"context"
	"errors"
	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/policies"
	"github.com/aizen299/secure-dev/internal/risk"
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
	// Lower-privileged credentials, so the role checks (ADR 023) can be
	// exercised rather than assumed. The default testToken is admin, which is
	// why every other test still passes unchanged.
	serviceToken = "secureops-service-token-not-a-secret"
	viewerToken  = "secureops-viewer-token-not-a-secret1"
	// A valid UUID that no fake is seeded with.
	unknownUUID = "00000000-0000-4000-8000-000000000999"
)

func testAuthenticator(t interface{ Fatalf(string, ...any) }) *auth.Authenticator {
	a, err := auth.New([]string{
		testTokenLabel + ":admin:" + testToken,
		"ci-runner:service:" + serviceToken,
		"dashboard:viewer:" + viewerToken,
	})
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
	createdBy []audit.Actor
	mu        sync.Mutex
	items     map[string]projects.Project

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

func (f *fakeProjectStore) Create(
	_ context.Context, input projects.NewProject, actor audit.Actor,
) (projects.Project, error) {
	f.createdBy = append(f.createdBy, actor)
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
	createdBy []audit.Actor
	mu        sync.Mutex
	items     map[string]scans.Scan
	// finalized records what Finalize was called with, so the unqueued-scan
	// path can be asserted rather than assumed.
	finalized map[string]scans.FailureReason

	createErr   error
	getErr      error
	listErr     error
	finalizeErr error
}

// count reports how many scans were created, for assertions that a request
// must NOT have created one.
func (f *fakeScanStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.items)
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

func (f *fakeScanStore) Create(
	_ context.Context, input scans.NewScan, actor audit.Actor,
) (scans.Scan, error) {
	f.createdBy = append(f.createdBy, actor)
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

// fakeFindingStore serves findings from memory.
type fakeFindingStore struct {
	byProject map[string][]findings.Record
	byScan    map[string][]findings.Record
	issues    map[string][]findings.IssueRecord
	risk      map[string][]findings.RiskRecord
	subjects  map[string][]risk.Subject
	riskCtx   risk.Context
	history   map[string][]findings.TransitionRecord
	statuses  map[string]normalization.Status
	err       error
}

func newFakeFindingStore() *fakeFindingStore {
	return &fakeFindingStore{
		byProject: map[string][]findings.Record{},
		byScan:    map[string][]findings.Record{},
		issues:    map[string][]findings.IssueRecord{},
	}
}

func (f *fakeFindingStore) ListByProject(
	_ context.Context, projectID string, filter findings.Filter, page findings.Page,
) ([]findings.Record, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	var out []findings.Record
	for _, r := range f.byProject[projectID] {
		if filter.Status != "" && string(r.Status) != filter.Status {
			continue
		}
		if filter.Severity != "" && string(r.Severity) != filter.Severity {
			continue
		}
		if filter.Scanner != "" && r.Scanner != filter.Scanner {
			continue
		}
		out = append(out, r)
	}
	return paginateRecords(out, page)
}

func (f *fakeFindingStore) ListByScan(
	_ context.Context, scanID string, page findings.Page,
) ([]findings.Record, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	return paginateRecords(f.byScan[scanID], page)
}

func (f *fakeFindingStore) ListIssues(
	_ context.Context, projectID string, page findings.Page,
) ([]findings.IssueRecord, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	in := f.issues[projectID]
	limit := page.Limit
	if limit <= 0 {
		limit = 50
	}
	if page.Offset >= len(in) {
		return []findings.IssueRecord{}, false, nil
	}
	out := in[page.Offset:]
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func paginateRecords(in []findings.Record, page findings.Page) ([]findings.Record, bool, error) {
	limit := page.Limit
	if limit <= 0 {
		limit = 50
	}
	if page.Offset >= len(in) {
		return []findings.Record{}, false, nil
	}
	rest := in[page.Offset:]
	if len(rest) > limit {
		return rest[:limit], true, nil
	}
	return rest, false, nil
}

// seedFinding adds one finding visible on both the project and the scan.
func (f *fakeFindingStore) LatestRiskScore(
	_ context.Context, projectID string,
) (findings.RiskRecord, error) {
	if f.err != nil {
		return findings.RiskRecord{}, f.err
	}
	records := f.risk[projectID]
	if len(records) == 0 {
		return findings.RiskRecord{}, findings.ErrNoRiskScore
	}
	return records[0], nil
}

func (f *fakeFindingStore) RiskHistory(
	_ context.Context, projectID string, limit int,
) ([]findings.RiskRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	records := f.risk[projectID]
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func (f *fakeFindingStore) LoadRiskInputs(
	_ context.Context, projectID string,
) ([]risk.Subject, risk.Context, error) {
	if f.err != nil {
		return nil, risk.Context{}, f.err
	}
	return f.subjects[projectID], f.riskCtx, nil
}

func (f *fakeFindingStore) Transition(
	_ context.Context, findingID string, req findings.TransitionRequest, actor audit.Actor,
) (findings.TransitionRecord, error) {
	if f.err != nil {
		return findings.TransitionRecord{}, f.err
	}
	// The real validation, not a second copy of it. A fake that enforces
	// weaker rules than the store makes handler tests agree with nothing.
	if err := req.Validate(); err != nil {
		return findings.TransitionRecord{}, err
	}
	if f.statuses == nil {
		f.statuses = map[string]normalization.Status{}
	}
	from := f.statuses[findingID]
	if from == "" {
		from = normalization.StatusOpen
	}
	f.statuses[findingID] = req.To

	rec := findings.TransitionRecord{
		FindingID: findingID, From: from, To: req.To,
		Actor: actor.Label, Reason: req.Reason, Note: req.Note,
		ChangedAt: time.Now().UTC(),
	}
	if f.history == nil {
		f.history = map[string][]findings.TransitionRecord{}
	}
	f.history[findingID] = append(f.history[findingID], rec)
	return rec, nil
}

func (f *fakeFindingStore) History(
	_ context.Context, findingID string,
) ([]findings.TransitionRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.history[findingID], nil
}

func (f *fakeFindingStore) seedSubjects(projectID string, subjects ...risk.Subject) {
	if f.subjects == nil {
		f.subjects = map[string][]risk.Subject{}
	}
	f.subjects[projectID] = append(f.subjects[projectID], subjects...)
}

func (f *fakeFindingStore) seedRisk(projectID string, records ...findings.RiskRecord) {
	if f.risk == nil {
		f.risk = map[string][]findings.RiskRecord{}
	}
	f.risk[projectID] = append(f.risk[projectID], records...)
}

func (f *fakeFindingStore) seed(projectID, scanID string, r findings.Record) {
	f.byProject[projectID] = append(f.byProject[projectID], r)
	f.byScan[scanID] = append(f.byScan[scanID], r)
}

// fakePolicyStore is an in-memory gate configuration store.
type fakePolicyStore struct {
	policies map[string]policies.Policy
	results  map[string]policies.ResultRecord
	audited  []audit.Entry
	err      error
}

func (f *fakePolicyStore) Get(_ context.Context, projectID string) (policies.Policy, error) {
	if f.err != nil {
		return policies.Policy{}, f.err
	}
	if p, ok := f.policies[projectID]; ok {
		return p, nil
	}
	return policies.DefaultPolicy(), nil
}

func (f *fakePolicyStore) Set(
	_ context.Context, projectID string, p policies.Policy, actor audit.Actor,
) error {
	if f.err != nil {
		return f.err
	}
	if f.policies == nil {
		f.policies = map[string]policies.Policy{}
	}
	f.policies[projectID] = p
	// Recorded here so a handler test can assert the actor reached the store;
	// atomicity itself is a database property and is tested against Postgres.
	f.audited = append(f.audited, audit.Entry{
		Actor: actor, Action: "policy.update",
		ResourceType: "security_policy", ResourceID: projectID, After: p,
	})
	return nil
}

func (f *fakePolicyStore) GetResult(_ context.Context, scanID string) (policies.ResultRecord, error) {
	if f.err != nil {
		return policies.ResultRecord{}, f.err
	}
	rec, ok := f.results[scanID]
	if !ok {
		return policies.ResultRecord{}, policies.ErrNoResult
	}
	return rec, nil
}

func (f *fakePolicyStore) seedResult(scanID string, rec policies.ResultRecord) {
	if f.results == nil {
		f.results = map[string]policies.ResultRecord{}
	}
	f.results[scanID] = rec
}
