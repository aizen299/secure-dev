//go:build integration

package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/policies"
)

func actor() audit.Actor { return audit.TokenActor("itest-token") }

func strictPolicy() policies.Policy {
	return policies.Policy{
		Rules: []policies.Rule{{
			Kind:     policies.KindSeverityCount,
			Selector: string(normalization.SeverityCritical),
			Max:      0,
			Level:    policies.LevelFail,
		}},
		IncompleteScan: policies.LevelFail,
	}
}

// A project with no stored policy is gated by the default, not by nothing.
// An absent policy meaning "everything passes" would make deleting a row a way
// to silently disable the gate.
func TestAnUnconfiguredProjectIsGatedByTheDefault(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)
	_, projectID := seedScan(t, pool)

	got, err := store.Get(t.Context(), projectID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(got.Rules) == 0 {
		t.Fatal("an unconfigured project has no rules, so nothing gates it")
	}
	if got.IncompleteScan == "" {
		t.Error("no incomplete-scan treatment")
	}
}

func TestPolicySurvivesTheRoundTrip(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)
	_, projectID := seedScan(t, pool)

	want := strictPolicy()
	if err := store.Set(t.Context(), projectID, want, actor()); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	got, err := store.Get(t.Context(), projectID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Selector != "critical" || got.Rules[0].Max != 0 {
		t.Errorf("rules = %+v, want the stored rule", got.Rules)
	}
	if got.IncompleteScan != policies.LevelFail {
		t.Errorf("incomplete_scan = %q, want fail", got.IncompleteScan)
	}
}

// The property ADR 022 exists for. The audit record is written in the change's
// own transaction, so a policy change and the record of it are atomic.
func TestAPolicyChangeIsAuditedWithItsBeforeAndAfter(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)
	_, projectID := seedScan(t, pool)

	// Create, then edit, so both actions are exercised.
	if err := store.Set(t.Context(), projectID, policies.DefaultPolicy(), actor()); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := store.Set(t.Context(), projectID, strictPolicy(), actor()); err != nil {
		t.Fatalf("update policy: %v", err)
	}

	rows, err := pool.Query(t.Context(), `
		SELECT action, actor_kind, actor_label, resource_type,
		       before_value IS NULL, after_value IS NULL
		  FROM audit_logs
		 WHERE project_id = $1
		 ORDER BY id`, projectID)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	defer rows.Close()

	type entry struct {
		action, kind, label, resource string
		beforeNull, afterNull         bool
	}
	var got []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.action, &e.kind, &e.label, &e.resource, &e.beforeNull, &e.afterNull); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		got = append(got, e)
	}
	if len(got) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(got))
	}

	// Creating has no previous value; editing does. That distinction is what
	// makes "what exactly changed" answerable.
	if got[0].action != "policy.create" || !got[0].beforeNull {
		t.Errorf("first entry = %+v, want policy.create with a null before value", got[0])
	}
	if got[1].action != "policy.update" || got[1].beforeNull {
		t.Errorf("second entry = %+v, want policy.update carrying the previous policy", got[1])
	}
	for _, e := range got {
		if e.kind != string(audit.ActorTokenLabel) {
			t.Errorf("actor kind = %q, want a token label: SecureOps cannot name a person yet", e.kind)
		}
		if e.label != "itest-token" {
			t.Errorf("actor label = %q, want the token's label", e.label)
		}
		if e.afterNull {
			t.Errorf("entry %+v has no after value", e)
		}
	}
}

// A rejected policy must leave no trace. An audit entry for a change that did
// not happen is worse than none: it is a false record.
func TestARejectedPolicyChangeIsNotAudited(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)
	_, projectID := seedScan(t, pool)

	bad := policies.Policy{IncompleteScan: "pass"}
	if err := store.Set(t.Context(), projectID, bad, actor()); err == nil {
		t.Fatal("a policy letting an incomplete scan pass was accepted")
	} else if !errors.Is(err, policies.ErrInvalidPolicy) {
		t.Errorf("error = %v, want ErrInvalidPolicy", err)
	}

	var count int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE project_id = $1`, projectID).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 0 {
		t.Errorf("audit entries = %d, want 0 for a rejected change", count)
	}
}

// Append-only enforced by the database, not by convention. "We only ever
// insert" is a claim about the code written so far, not about the code written
// next (§15.13).
func TestTheAuditLogRefusesUpdatesAndDeletes(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)
	_, projectID := seedScan(t, pool)

	if err := store.Set(t.Context(), projectID, strictPolicy(), actor()); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	if _, err := pool.Exec(t.Context(),
		`UPDATE audit_logs SET actor_label = 'somebody else' WHERE project_id = $1`, projectID); err == nil {
		t.Error("an audit record was rewritten")
	} else if !containsText(err.Error(), "append-only") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}

	if _, err := pool.Exec(t.Context(),
		`DELETE FROM audit_logs WHERE project_id = $1`, projectID); err == nil {
		t.Error("an audit record was deleted")
	} else if !containsText(err.Error(), "append-only") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}
}

func TestGateResultSurvivesTheRoundTrip(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)
	scanID, projectID := seedScan(t, pool)

	policy := policies.DefaultPolicy()
	result, err := policies.Evaluate(policy, policies.Input{
		SeverityCounts: map[normalization.Severity]int{normalization.SeverityCritical: 2},
		RiskScore:      88,
		ScanStatus:     "completed",
		ScanComplete:   true,
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Verdict != policies.VerdictFail {
		t.Fatalf("verdict = %q, want fail", result.Verdict)
	}

	if err := store.SaveResult(t.Context(), projectID, scanID, policy, result, time.Now().UTC()); err != nil {
		t.Fatalf("save result: %v", err)
	}

	got, err := store.GetResult(t.Context(), scanID)
	if err != nil {
		t.Fatalf("get result: %v", err)
	}
	if got.Result.Verdict != policies.VerdictFail {
		t.Errorf("verdict = %q, want fail", got.Result.Verdict)
	}
	// Every rule, not only the breached ones: §12 forbids a bare verdict, and
	// a stored result with no conditions is exactly that.
	if len(got.Result.Conditions) != len(policy.Rules) {
		t.Errorf("conditions = %d, want all %d rules", len(got.Result.Conditions), len(policy.Rules))
	}
	if got.Result.Summary == "" {
		t.Error("no stored summary")
	}
}

// A gate outcome is a decision made at a moment. Editing the policy afterwards
// must not rewrite what was decided.
func TestEditingAPolicyDoesNotRewriteAPastVerdict(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)
	scanID, projectID := seedScan(t, pool)

	original := policies.DefaultPolicy()
	result, err := policies.Evaluate(original, policies.Input{
		SeverityCounts: map[normalization.Severity]int{normalization.SeverityCritical: 1},
		ScanStatus:     "completed", ScanComplete: true,
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if err := store.SaveResult(t.Context(), projectID, scanID, original, result, time.Now().UTC()); err != nil {
		t.Fatalf("save result: %v", err)
	}

	// Somebody turns the gate off afterwards.
	lax := policies.Policy{Rules: nil, IncompleteScan: policies.LevelWarn}
	if err := store.Set(t.Context(), projectID, lax, actor()); err != nil {
		t.Fatalf("relax policy: %v", err)
	}

	got, err := store.GetResult(t.Context(), scanID)
	if err != nil {
		t.Fatalf("get result: %v", err)
	}
	if got.Result.Verdict != policies.VerdictFail {
		t.Errorf("verdict = %q, want the fail that was recorded at the time", got.Result.Verdict)
	}
	if len(got.Result.Conditions) == 0 {
		t.Error("the conditions behind the past verdict were lost")
	}
}

// The schema's own statement of the rule, independent of the Go model.
func TestTheDatabaseRefusesAPassingIncompleteScan(t *testing.T) {
	pool := testPool(t)
	scanID, projectID := seedScan(t, pool)

	_, err := pool.Exec(t.Context(), `
		INSERT INTO policy_results
		    (scan_id, project_id, verdict, scan_complete, summary)
		VALUES ($1, $2, 'pass', false, 'x')`, scanID, projectID)
	if err == nil {
		t.Fatal("an incomplete scan was recorded as passing")
	}
	if !containsText(err.Error(), "policy_results_incomplete_never_passes") {
		t.Errorf("rejected by the wrong constraint: %v", err)
	}
}

// ADR 022's central claim, tested directly: an audit entry joins the caller's
// transaction rather than being written beside it.
//
// If Write used its own connection, this row would survive the rollback. The
// gap that produces is worse than no audit at all -- a record of a change that
// was undone, indistinguishable from a change that stuck.
func TestAnAuditEntryRollsBackWithItsTransaction(t *testing.T) {
	pool := testPool(t)
	_, projectID := seedScan(t, pool)

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := audit.Write(t.Context(), tx, audit.Entry{
		Actor:        actor(),
		Action:       "policy.update",
		ResourceType: "security_policy",
		ResourceID:   projectID,
		ProjectID:    projectID,
		After:        strictPolicy(),
	}); err != nil {
		t.Fatalf("write audit entry: %v", err)
	}

	// Visible inside the transaction...
	var inTx int
	if err := tx.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE project_id = $1`, projectID).Scan(&inTx); err != nil {
		t.Fatalf("count inside tx: %v", err)
	}
	if inTx != 1 {
		t.Fatalf("entries inside the transaction = %d, want 1", inTx)
	}

	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// ...and gone once the change it described was undone.
	var after int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE project_id = $1`, projectID).Scan(&after); err != nil {
		t.Fatalf("count after rollback: %v", err)
	}
	if after != 0 {
		t.Errorf("entries after rollback = %d, want 0: the audit record outlived the change it recorded", after)
	}
}

// The other direction: a policy write that fails must leave no audit record
// claiming it succeeded.
func TestAFailedPolicyWriteLeavesNoAuditRecord(t *testing.T) {
	pool := testPool(t)
	store := policies.NewStore(pool)

	// A project that does not exist; the foreign key rejects the write.
	missing := "00000000-0000-0000-0000-0000000000ff"
	if err := store.Set(t.Context(), missing, strictPolicy(), actor()); err == nil {
		t.Fatal("a policy was stored for a project that does not exist")
	}

	var count int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE resource_id = $1`, missing).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 0 {
		t.Errorf("audit entries = %d for a change that failed", count)
	}
}
