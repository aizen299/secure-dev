//go:build integration

package integration

import (
	"errors"
	"testing"
	"time"

	"context"
	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
	"github.com/google/uuid"
)

func seedOpenFinding(t *testing.T, store *findings.Store, projectID, scanID, fp string) string {
	t.Helper()
	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings: []normalization.MergedFinding{{
			Finding: normalization.Finding{
				Fingerprint: fp, Scanner: "grype", Title: "Vulnerable component",
				Category: scanners.CategoryDependency, Severity: normalization.SeverityCritical,
				Confidence: normalization.ConfidenceHigh, Status: normalization.StatusOpen,
			},
			Sources: []string{"grype"},
		}},
		Occurrences: []normalization.Occurrence{occurrenceIn(fp, scanID, "grype", "go.mod")},
	}, []string{"grype"}, time.Now().UTC()); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	records, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{})
	if err != nil || len(records) == 0 {
		t.Fatalf("list findings: %v (%d records)", err, len(records))
	}
	return records[0].ID
}

// The change the three previous phases were waiting on: a human can finally
// dismiss a finding, and the engines that already honour dismissal see it.
func TestAFindingCanBeDismissedAndItStopsCounting(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	scanID, projectID := seedScan(t, pool)
	id := seedOpenFinding(t, store, projectID, scanID, fingerprintOf("1"))

	rec, err := store.Transition(t.Context(), id, findings.TransitionRequest{
		To:     normalization.StatusFalsePositive,
		Reason: findings.ReasonFalsePositive,
		Note:   "matches our test fixtures, not production code",
	}, audit.TokenActor("triager"))
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if rec.From != normalization.StatusOpen || rec.To != normalization.StatusFalsePositive {
		t.Errorf("transition %+v, want open -> false_positive", rec)
	}

	// The risk engine's own inputs must now report it dismissed, or the three
	// engines that honour dismissal still will not see it.
	subjects, _, err := store.LoadRiskInputs(t.Context(), projectID)
	if err != nil {
		t.Fatalf("load risk inputs: %v", err)
	}
	if len(subjects) != 1 {
		t.Fatalf("subjects = %d, want 1", len(subjects))
	}
	if subjects[0].Status != normalization.StatusFalsePositive {
		t.Errorf("status = %q, want false_positive: the dismissal did not reach the engines", subjects[0].Status)
	}
}

// ADR 024's central rule. Refused at the store, not only at the handler, so it
// holds for every caller.
func TestAPersonCannotDeclareAFindingResolved(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	scanID, projectID := seedScan(t, pool)
	id := seedOpenFinding(t, store, projectID, scanID, fingerprintOf("2"))

	for _, status := range []normalization.Status{
		normalization.StatusResolved, normalization.StatusReopened,
	} {
		_, err := store.Transition(t.Context(), id, findings.TransitionRequest{
			To: status, Reason: findings.ReasonTriaged,
		}, audit.TokenActor("triager"))
		if !errors.Is(err, findings.ErrTransitionNotAllowed) {
			t.Errorf("setting %q gave %v, want ErrTransitionNotAllowed", status, err)
		}
	}

	// And nothing changed: a refused transition must not have taken effect.
	records, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if records[0].Status != normalization.StatusOpen {
		t.Errorf("status = %q, want open", records[0].Status)
	}
}

// §15.6: a dismissal is security-sensitive. It lowers the risk score, removes
// remediation work, and can turn a failing gate green, so the record and the
// change are atomic.
func TestADismissalIsAuditedWithBothStates(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	scanID, projectID := seedScan(t, pool)
	id := seedOpenFinding(t, store, projectID, scanID, fingerprintOf("3"))

	if _, err := store.Transition(t.Context(), id, findings.TransitionRequest{
		To: normalization.StatusIgnored, Reason: findings.ReasonAcceptedRisk,
		Note: "compensating control in the WAF",
	}, audit.TokenActor("triager")); err != nil {
		t.Fatalf("transition: %v", err)
	}

	var (
		action, actorLabel string
		before, after      []byte
	)
	if err := pool.QueryRow(t.Context(), `
		SELECT action, actor_label, before_value, after_value
		  FROM audit_logs
		 WHERE resource_type = 'finding' AND resource_id = $1`, id).Scan(
		&action, &actorLabel, &before, &after); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if action != "finding.status_change" {
		t.Errorf("action = %q", action)
	}
	if actorLabel != "triager" {
		t.Errorf("actor = %q, want the token label", actorLabel)
	}
	if !containsText(string(before), "open") {
		t.Errorf("before = %s, want the previous status", before)
	}
	if !containsText(string(after), "ignored") || !containsText(string(after), "accepted_risk") {
		t.Errorf("after = %s, want the new status and the reason", after)
	}
}

// A refused transition must leave neither a status change nor an audit record
// claiming one happened.
func TestARefusedTransitionLeavesNoTrace(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	scanID, projectID := seedScan(t, pool)
	id := seedOpenFinding(t, store, projectID, scanID, fingerprintOf("4"))

	if _, err := store.Transition(t.Context(), id, findings.TransitionRequest{
		To: normalization.StatusResolved, Reason: findings.ReasonTriaged,
	}, audit.TokenActor("triager")); err == nil {
		t.Fatal("a hand-set resolved was accepted")
	}

	var count int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE resource_id = $1`, id).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 0 {
		t.Errorf("audit entries = %d for a refused transition", count)
	}
}

// A dismissal is a judgement, and judgements are revisited. Without a way back,
// a mistaken false positive is permanent.
func TestADismissalCanBeUndone(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	scanID, projectID := seedScan(t, pool)
	id := seedOpenFinding(t, store, projectID, scanID, fingerprintOf("5"))

	if _, err := store.Transition(t.Context(), id, findings.TransitionRequest{
		To: normalization.StatusFalsePositive, Reason: findings.ReasonFalsePositive,
	}, audit.TokenActor("triager")); err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	if _, err := store.Transition(t.Context(), id, findings.TransitionRequest{
		To: normalization.StatusOpen, Reason: findings.ReasonReinstated,
		Note: "the rule does fire on production code after all",
	}, audit.TokenActor("reviewer")); err != nil {
		t.Fatalf("reinstate: %v", err)
	}

	history, err := store.History(t.Context(), id)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	// Newest first: reinstated, dismissed, and the scan-driven first_seen.
	if len(history) < 3 {
		t.Fatalf("history = %d entries, want the two human changes plus first_seen", len(history))
	}
	if history[0].To != normalization.StatusOpen || history[0].Actor != "reviewer" {
		t.Errorf("newest entry = %+v, want the reinstatement by reviewer", history[0])
	}
	// The scan-driven transition is attributed to the system, not to a person.
	oldest := history[len(history)-1]
	if oldest.Actor != findings.ActorSystem {
		t.Errorf("oldest actor = %q, want %q: a scan-driven transition is nobody's judgement",
			oldest.Actor, findings.ActorSystem)
	}
}

// The schema refuses a self-transition, and so does the store, before it writes
// a second identical history row for no change.
func TestTransitioningToTheCurrentStatusIsRefused(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	scanID, projectID := seedScan(t, pool)
	id := seedOpenFinding(t, store, projectID, scanID, fingerprintOf("6"))

	_, err := store.Transition(t.Context(), id, findings.TransitionRequest{
		To: normalization.StatusOpen, Reason: findings.ReasonReinstated,
	}, audit.TokenActor("triager"))
	if !errors.Is(err, findings.ErrInvalidTransition) {
		t.Errorf("error = %v, want ErrInvalidTransition", err)
	}
}

// §15.6 lists scan creation and project changes alongside policy changes.
// Until now only policy changes reached the table, so T-24 stayed Partial for
// a reason rather than by oversight.
func TestScanAndProjectCreationAreAudited(t *testing.T) {
	pool := testPool(t)
	projectStore := projects.NewStore(pool)
	scanStore := scans.NewStore(pool)
	actor := audit.TokenActor("itest-creator")

	project, err := projectStore.Create(t.Context(), projects.NewProject{
		Name:           "Audited Project",
		Slug:           "itest-audited-" + uuid.NewString()[:8],
		Environment:    projects.EnvProduction,
		Criticality:    projects.CriticalityHigh,
		InternetFacing: true,
	}, actor)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	scan, err := scanStore.Create(t.Context(), scans.NewScan{
		ProjectID: project.ID,
		Target: scanners.Target{
			Kind:          scanners.KindRepository,
			RepositoryURL: "https://github.com/example/repo",
		},
	}, actor)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}

	rows, err := pool.Query(t.Context(), `
		SELECT action, resource_type, resource_id, actor_label,
		       before_value IS NULL, after_value IS NULL
		  FROM audit_logs WHERE project_id = $1 ORDER BY id`, project.ID)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	defer rows.Close()

	type entry struct {
		action, resourceType, resourceID, actorLabel string
		beforeNull, afterNull                        bool
	}
	var got []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.action, &e.resourceType, &e.resourceID, &e.actorLabel,
			&e.beforeNull, &e.afterNull); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		got = append(got, e)
	}
	if len(got) != 2 {
		t.Fatalf("audit entries = %d, want one per creation: %+v", len(got), got)
	}

	if got[0].action != "project.create" || got[0].resourceID != project.ID {
		t.Errorf("first entry = %+v, want project.create for %s", got[0], project.ID)
	}
	if got[1].action != "scan.create" || got[1].resourceID != scan.ID {
		t.Errorf("second entry = %+v, want scan.create for %s", got[1], scan.ID)
	}
	for _, e := range got {
		if e.actorLabel != "itest-creator" {
			t.Errorf("actor = %q, want the token label", e.actorLabel)
		}
		// A creation has no previous value; that is what distinguishes it from
		// an edit, and a typed nil marshalling to JSON null would break it.
		if !e.beforeNull {
			t.Errorf("%s carries a before value; a creation has no previous state", e.action)
		}
		if e.afterNull {
			t.Errorf("%s has no after value", e.action)
		}
	}
}

// A failed creation must leave no audit record claiming it happened.
func TestAFailedProjectCreateLeavesNoAuditRecord(t *testing.T) {
	pool := testPool(t)
	store := projects.NewStore(pool)
	// A label unique to this test: audit_logs is append-only and shared across
	// the suite, so counting by a fixed label would count other tests' rows.
	label := "itest-dup-" + uuid.NewString()[:8]
	actor := audit.TokenActor(label)

	slug := label
	first, err := store.Create(t.Context(), projects.NewProject{Name: "First", Slug: slug}, actor)
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, first.ID)
	})

	if _, err := store.Create(t.Context(), projects.NewProject{Name: "Second", Slug: slug}, actor); err == nil {
		t.Fatal("a duplicate slug was accepted")
	}

	var count int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_logs WHERE action = 'project.create' AND actor_label = $1`,
		label).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("project.create entries = %d, want 1: the rejected creation was audited", count)
	}
}
