package policies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/audit"
)

// ErrNoResult reports that a scan has not been evaluated against a policy.
//
// Distinct from a PASS. "No gate ran" and "the gate passed" are different
// claims, and only one of them means a change is cleared to ship.
var ErrNoResult = errors.New("no policy result recorded")

// Store persists policies and the decisions made with them.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Get reads a project's policy, falling back to the default.
//
// A project with no stored policy is gated by DefaultPolicy rather than by
// nothing. An absent policy meaning "everything passes" would make deleting a
// row a way to silently disable the gate.
func (s *Store) Get(ctx context.Context, projectID string) (Policy, error) {
	var (
		rulesJSON []byte
		level     string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT rules, incomplete_scan::text
		  FROM security_policies WHERE project_id = $1`, projectID).Scan(&rulesJSON, &level)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DefaultPolicy(), nil
		}
		return Policy{}, fmt.Errorf("get policy: %w", err)
	}

	p := Policy{IncompleteScan: Level(level)}
	if err := json.Unmarshal(rulesJSON, &p.Rules); err != nil {
		return Policy{}, fmt.Errorf("decode policy rules: %w", err)
	}
	return p, nil
}

// Set replaces a project's policy and records the change, atomically.
//
// The audit entry is written in this transaction, not after it. A policy is the
// control deciding whether insecure code ships: someone who raises
// max_critical from 0 to 50 turns the gate off, and a record that can be lost
// while the change survives is worse than none, because its gaps look exactly
// like inaction (ADR 022).
func (s *Store) Set(ctx context.Context, projectID string, p Policy, actor audit.Actor) error {
	if err := p.Validate(); err != nil {
		return err
	}

	// A policy with no rules is legitimate -- it passes everything and says so
	// -- but a nil slice marshals to `null`, which the schema rejects because
	// it is not an array. Normalised here so "no rules" is storable rather
	// than a write that fails at the database.
	ruleList := p.Rules
	if ruleList == nil {
		ruleList = []Rule{}
	}
	rules, err := json.Marshal(ruleList)
	if err != nil {
		return fmt.Errorf("encode policy rules: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin policy update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Read the previous value inside the transaction, so the before/after pair
	// describes one atomic step rather than two observations of a moving
	// target.
	previous, err := s.previousWithin(ctx, tx, projectID)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO security_policies (project_id, rules, incomplete_scan)
		VALUES ($1, $2, $3)
		ON CONFLICT (project_id) DO UPDATE SET
		    rules = EXCLUDED.rules,
		    incomplete_scan = EXCLUDED.incomplete_scan`,
		projectID, rules, string(p.IncompleteScan)); err != nil {
		return fmt.Errorf("set policy: %w", err)
	}

	action := "policy.update"
	if previous == nil {
		action = "policy.create"
	}
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor:        actor,
		Action:       action,
		ResourceType: "security_policy",
		ResourceID:   projectID,
		ProjectID:    projectID,
		Before:       previous,
		After:        p,
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy update: %w", err)
	}
	return nil
}

// previousWithin reads the stored policy inside a transaction, returning nil
// when there is none. Nil is meaningful in the audit record: it distinguishes
// creating a policy from editing one.
func (s *Store) previousWithin(ctx context.Context, tx pgx.Tx, projectID string) (*Policy, error) {
	var (
		rulesJSON []byte
		level     string
	)
	err := tx.QueryRow(ctx, `
		SELECT rules, incomplete_scan::text
		  FROM security_policies WHERE project_id = $1`, projectID).Scan(&rulesJSON, &level)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read previous policy: %w", err)
	}

	prev := Policy{IncompleteScan: Level(level)}
	if err := json.Unmarshal(rulesJSON, &prev.Rules); err != nil {
		return nil, fmt.Errorf("decode previous policy: %w", err)
	}
	return &prev, nil
}

// ResultRecord is a stored gate decision.
type ResultRecord struct {
	ScanID      string
	ProjectID   string
	Result      Result
	EvaluatedAt time.Time
}

// SaveResult records a gate decision for one scan.
func (s *Store) SaveResult(
	ctx context.Context, projectID, scanID string, p Policy, res Result, at time.Time,
) error {
	conditions, err := json.Marshal(res.Conditions)
	if err != nil {
		return fmt.Errorf("encode conditions: %w", err)
	}
	policyJSON, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode evaluated policy: %w", err)
	}

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO policy_results
		    (scan_id, project_id, verdict, conditions, evaluated_policy,
		     scan_complete, coverage_downgrade, summary, evaluated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (scan_id) DO UPDATE SET
		    verdict = EXCLUDED.verdict,
		    conditions = EXCLUDED.conditions,
		    evaluated_policy = EXCLUDED.evaluated_policy,
		    scan_complete = EXCLUDED.scan_complete,
		    coverage_downgrade = EXCLUDED.coverage_downgrade,
		    summary = EXCLUDED.summary,
		    evaluated_at = EXCLUDED.evaluated_at`,
		scanID, projectID, string(res.Verdict), conditions, policyJSON,
		res.Coverage.Complete, res.Coverage.Downgraded, res.Summary, at.UTC()); err != nil {
		return fmt.Errorf("save policy result: %w", err)
	}
	return nil
}

// GetResult reads the gate decision for one scan.
func (s *Store) GetResult(ctx context.Context, scanID string) (ResultRecord, error) {
	var (
		rec            ResultRecord
		verdict        string
		conditionsJSON []byte
		policyJSON     []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT scan_id, project_id, verdict::text, conditions, evaluated_policy,
		       scan_complete, coverage_downgrade, summary, evaluated_at
		  FROM policy_results WHERE scan_id = $1`, scanID).Scan(
		&rec.ScanID, &rec.ProjectID, &verdict, &conditionsJSON, &policyJSON,
		&rec.Result.Coverage.Complete, &rec.Result.Coverage.Downgraded,
		&rec.Result.Summary, &rec.EvaluatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResultRecord{}, ErrNoResult
		}
		return ResultRecord{}, fmt.Errorf("get policy result: %w", err)
	}

	rec.Result.Verdict = Verdict(verdict)
	if err := json.Unmarshal(conditionsJSON, &rec.Result.Conditions); err != nil {
		return ResultRecord{}, fmt.Errorf("decode conditions: %w", err)
	}
	var evaluated Policy
	if err := json.Unmarshal(policyJSON, &evaluated); err != nil {
		return ResultRecord{}, fmt.Errorf("decode evaluated policy: %w", err)
	}
	rec.Result.Coverage.Level = evaluated.IncompleteScan
	return rec, nil
}
