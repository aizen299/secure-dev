package httpapi

import (
	"context"
	"errors"
	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/policies"
	"github.com/aizen299/secure-dev/internal/risk"
	"sort"
	"sync"
	"time"

	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scans"
	"github.com/aizen299/secure-dev/internal/users"
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
	// An admin credential confined to one project (ADR 033). Admin on purpose:
	// it makes the tests show that role and scope are independent, and that the
	// most powerful role is still confined by scope.
	scopedToken = "secureops-scoped-token-not-a-secret1"
	scopedSlug  = "team-a-project"
	// A valid UUID that no fake is seeded with.
	unknownUUID = "00000000-0000-4000-8000-000000000999"
)

func testAuthenticator(t interface{ Fatalf(string, ...any) }) *auth.Authenticator {
	a, err := auth.New([]string{
		testTokenLabel + ":admin:*:" + testToken,
		"ci-runner:service:*:" + serviceToken,
		"dashboard:viewer:*:" + viewerToken,
		// Scoped to one project, so the scoping tests have a credential that
		// is genuinely confined rather than one that happens not to ask.
		"team-a:admin:" + scopedSlug + ":" + scopedToken,
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
	// archived records what SetArchived was called with, so the archive path
	// can be asserted rather than assumed.
	archived map[string]bool

	createdBy []audit.Actor
	mu        sync.Mutex
	items     map[string]projects.Project

	createErr error
	getErr    error
	existsErr error
	listErr   error
}

func newFakeProjectStore() *fakeProjectStore {
	return &fakeProjectStore{
		items:    map[string]projects.Project{},
		archived: map[string]bool{},
	}
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

// Get filters archived projects out, as the real store's `archived_at IS NULL`
// does. A fake that returned them would make an archived project readable here
// and 404 in production -- and that is not hypothetical: a handler reading
// through Get instead of the resolved project was found by hand, in a browser,
// because this fake was permissive enough to let its test pass.
func (f *fakeProjectStore) Get(_ context.Context, id string) (projects.Project, error) {
	if f.getErr != nil {
		return projects.Project{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.items[id]
	if !ok || f.archived[id] {
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
	// An archived project does not exist for the purpose of accepting work,
	// mirroring the real store's `archived_at IS NULL` filter.
	return ok && !f.archived[id], nil
}

// The fake filters by scope before paginating, mirroring what the real store
// does in SQL. A fake that ignored the scope would make every scoping test pass
// against a store that leaks.
func (f *fakeProjectStore) List(
	_ context.Context, page projects.Page, scope auth.Scope,
) ([]projects.Project, bool, error) {
	if f.listErr != nil {
		return nil, false, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	all := make([]projects.Project, 0, len(f.items))
	for _, p := range f.items {
		if scope.Allows(p.Slug) {
			all = append(all, p)
		}
	}
	// Deterministic order, so pagination assertions do not depend on map
	// iteration.
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return paginate(all, page.Limit, page.Offset)
}

// GetAny finds a project whether or not it is archived, mirroring the real
// store. A fake that filtered archived ones would make the unarchive path
// untestable in exactly the way the real bug was untested.
func (f *fakeProjectStore) GetAny(_ context.Context, id string) (projects.Project, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	project, ok := f.items[id]
	if !ok {
		return projects.Project{}, projects.ErrNotFound
	}
	project.Archived = f.archived[id]
	return project, nil
}

func (f *fakeProjectStore) SetArchived(
	_ context.Context, id string, archived bool, _ audit.Actor,
) (projects.Project, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	project, ok := f.items[id]
	if !ok {
		return projects.Project{}, projects.ErrNotFound
	}
	f.archived[id] = archived
	return project, nil
}

// fakeUserStore is an in-memory UserStore.
//
// It mirrors the real store's last-admin guard rather than omitting it. A fake
// without that check would let the handler tests pass against a store that
// permits locking every administrator out.
type fakeUserStore struct {
	mu         sync.Mutex
	items      map[string]users.User
	membership map[string][]string
	scope      auth.Scope
	err        error
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{
		items:      map[string]users.User{},
		membership: map[string][]string{},
		scope:      auth.GlobalScope(),
	}
}

func (f *fakeUserStore) seed(u users.User) users.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[u.ID] = u
	return u
}

func (f *fakeUserStore) Authenticate(_ context.Context, email, password string) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.items {
		if u.Email == email && password == "correct-password-value" && !u.Disabled {
			return u, nil
		}
	}
	return users.User{}, users.ErrNotFound
}

func (f *fakeUserStore) ByID(_ context.Context, id string) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.items[id]; ok {
		return u, nil
	}
	return users.User{}, users.ErrNotFound
}

func (f *fakeUserStore) ScopeOf(_ context.Context, _ users.User) (auth.Scope, error) {
	return f.scope, nil
}

func (f *fakeUserStore) RecordLogin(context.Context, string) error { return nil }

func (f *fakeUserStore) Create(
	_ context.Context, input users.NewUser, _ audit.Actor,
) (users.User, error) {
	if err := input.Validate(); err != nil {
		return users.User{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.items {
		if u.Email == input.Email {
			return users.User{}, users.ErrEmailTaken
		}
	}
	user := users.User{
		ID: newTestUUID(len(f.items) + 80), Email: input.Email,
		DisplayName: input.DisplayName, Role: input.Role,
	}
	f.items[user.ID] = user
	return user, nil
}

func (f *fakeUserStore) List(context.Context) ([]users.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]users.User, 0, len(f.items))
	for _, u := range f.items {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// enabledAdminsExcluding mirrors the real store's guard, so a handler test
// exercising the refusal exercises the same rule.
func (f *fakeUserStore) enabledAdminsExcluding(id string) int {
	n := 0
	for _, u := range f.items {
		if u.ID != id && u.Role == users.RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

func (f *fakeUserStore) SetRole(
	_ context.Context, id string, role users.Role, _ audit.Actor,
) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.items[id]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	if u.Role == users.RoleAdmin && role != users.RoleAdmin && f.enabledAdminsExcluding(id) == 0 {
		return users.User{}, users.ErrLastAdmin
	}
	u.Role = role
	f.items[id] = u
	return u, nil
}

func (f *fakeUserStore) SetDisabled(
	_ context.Context, id string, disabled bool, _ audit.Actor,
) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.items[id]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	if disabled && u.Role == users.RoleAdmin && f.enabledAdminsExcluding(id) == 0 {
		return users.User{}, users.ErrLastAdmin
	}
	u.Disabled = disabled
	f.items[id] = u
	return u, nil
}

func (f *fakeUserStore) SetMembership(
	_ context.Context, userID string, projectIDs []string, _ audit.Actor,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.items[userID]; !ok {
		return users.ErrNotFound
	}
	f.membership[userID] = projectIDs
	return nil
}

func (f *fakeUserStore) MembershipOf(_ context.Context, userID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.membership[userID]
	if out == nil {
		return []string{}, nil
	}
	return out, nil
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
	// projectOf maps a finding id to its owning project, so the scope check on
	// the finding-addressed endpoints can be exercised (ADR 033).
	projectOf map[string]string
	mu        sync.Mutex
	err       error
}

func newFakeFindingStore() *fakeFindingStore {
	return &fakeFindingStore{
		byProject: map[string][]findings.Record{},
		byScan:    map[string][]findings.Record{},
		issues:    map[string][]findings.IssueRecord{},
		projectOf: map[string]string{},
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

// The fake resolves a finding to whichever project the test seeded it under,
// falling back to the seeded project id. A fake that returned "in scope" for
// everything would make the scoping tests pass against handlers that do not
// check.
func (f *fakeFindingStore) ProjectOf(_ context.Context, findingID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if projectID, ok := f.projectOf[findingID]; ok {
		return projectID, nil
	}
	return "", findings.ErrNotFound
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
