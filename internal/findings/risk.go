package findings

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// ErrNoRiskScore reports that a project has never been scored.
//
// Distinct from a score of zero, which is a real assessment meaning "we looked
// and found nothing". Collapsing the two would let an unscanned project display
// as secure, which is the most dangerous wrong answer this system could give.
var ErrNoRiskScore = errors.New("no risk score recorded")

// RiskRecord is one stored project score.
type RiskRecord struct {
	ScanID            string
	ProjectID         string
	Score             float64
	Total             float64
	LiveFindings      int
	DismissedFindings int
	// WeightsDigest identifies the configuration the score was computed under.
	// Two records with different digests are not comparable.
	WeightsDigest string
	ComputedAt    time.Time

	// ScanStatus is the status of the scan this score was computed for, joined
	// rather than copied so it cannot go stale. A score from a PARTIAL scan
	// rests on incomplete coverage and §12 forbids treating it as a complete
	// one: a scanner that failed produces no findings, and fewer findings look
	// exactly like an improvement.
	ScanStatus string
}

// LoadRiskInputs reads everything the risk engine needs for one project.
//
// One call rather than three because the engine is pure and must be given a
// consistent picture: findings, the scanners that reported them, the issues
// correlation placed them in, and the project's declared context. Assembling
// those from separate round trips would let them disagree.
func (s *Store) LoadRiskInputs(
	ctx context.Context, projectID string,
) ([]risk.Subject, risk.Context, error) {
	var rc risk.Context
	var env, crit string
	err := s.pool.QueryRow(ctx, `
		SELECT environment, criticality, internet_facing
		  FROM projects WHERE id = $1`, projectID).Scan(&env, &crit, &rc.InternetFacing)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, risk.Context{}, fmt.Errorf("load risk context: %w", projects.ErrNotFound)
		}
		return nil, risk.Context{}, fmt.Errorf("load risk context: %w", err)
	}
	rc.Environment = projects.Environment(env)
	rc.Criticality = projects.Criticality(crit)

	// Every finding, live or not. Dismissed ones are scored at zero rather
	// than filtered away here, so the assessment can report how many a human
	// has taken out of scope -- a project at 12 with forty dismissed findings
	// is a different situation from one at 12 with none.
	rows, err := s.pool.Query(ctx, `
		SELECT f.fingerprint, f.scanner, f.category, f.severity, f.confidence,
		       f.status::text, f.title,
		       coalesce(f.cve, ''), coalesce(f.package, ''),
		       f.epss_probability, f.epss_percentile,
		       coalesce(f.epss_source, ''), f.epss_observed_at,
		       (SELECT coalesce(array_agg(DISTINCT o.scanner), '{}')
		          FROM finding_occurrences o WHERE o.finding_id = f.id),
		       worst.severity, worst.key
		  FROM findings f
		  -- The worst issue this finding belongs to. Correlation may place one
		  -- finding in several issues (a CVE issue and a file issue); the worst
		  -- is the one whose escalation stands. Lateral rather than two
		  -- correlated subqueries so the ordering is evaluated once.
		  --
		  -- The CASE mirrors normalization.Severity.Rank(). It is duplicated
		  -- here because SQL cannot call it, which is a known and deliberate
		  -- drift risk shared with the other ordered queries in this package.
		  LEFT JOIN LATERAL (
		      SELECT i.severity::text AS severity,
		             i.key_kind || ':' || i.key_value AS key
		        FROM correlated_issue_members m
		        JOIN correlated_issues i ON i.id = m.issue_id
		       WHERE m.finding_id = f.id
		       ORDER BY CASE i.severity::text
		                  WHEN 'critical' THEN 5 WHEN 'high' THEN 4
		                  WHEN 'medium' THEN 3 WHEN 'unknown' THEN 2
		                  WHEN 'low' THEN 1 ELSE 0 END DESC
		       LIMIT 1
		  ) worst ON true
		 WHERE f.project_id = $1
		 ORDER BY f.fingerprint`, projectID)
	if err != nil {
		return nil, risk.Context{}, fmt.Errorf("list findings for risk: %w", err)
	}
	defer rows.Close()

	var out []risk.Subject
	for rows.Next() {
		var (
			sub                                risk.Subject
			category, severity, confid, status string
			prob, pct                          *float64
			epssSource                         string
			observedAt                         *time.Time
			issueSeverity, issueKey            *string
		)
		if err := rows.Scan(
			&sub.Fingerprint, &sub.Scanner, &category, &severity, &confid, &status,
			&sub.Title, &sub.CVE, &sub.Package,
			&prob, &pct, &epssSource, &observedAt,
			&sub.Sources, &issueSeverity, &issueKey,
		); err != nil {
			return nil, risk.Context{}, fmt.Errorf("scan risk subject: %w", err)
		}

		sub.ProjectID = projectID
		sub.Category = scanners.Category(category)
		sub.Severity = normalization.Severity(severity)
		sub.Confidence = normalization.Confidence(confid)
		sub.Status = normalization.Status(status)

		// All four or nothing, matching the schema constraint and ADR 018: a
		// half-populated value is a number of unknown origin.
		if prob != nil && pct != nil && observedAt != nil && epssSource != "" {
			sub.Threat = normalization.ThreatIntel{EPSS: &normalization.EPSS{
				Probability: *prob,
				Percentile:  *pct,
				Source:      epssSource,
				ObservedAt:  *observedAt,
			}}
		}
		if issueSeverity != nil {
			sub.IssueSeverity = normalization.Severity(*issueSeverity)
		}
		if issueKey != nil {
			sub.IssueKey = *issueKey
		}
		out = append(out, sub)
	}
	if err := rows.Err(); err != nil {
		return nil, risk.Context{}, fmt.Errorf("scan risk subjects: %w", err)
	}
	return out, rc, nil
}

// SaveRiskScore records a project's score for one scan.
//
// Upsert rather than insert: a scan that is re-run replaces its score, so the
// history stays one point per scan instead of accumulating attempts.
func (s *Store) SaveRiskScore(
	ctx context.Context, projectID, scanID string,
	a risk.Assessment, weightsDigest string, at time.Time,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_risk_scores
		    (scan_id, project_id, score, total, live_findings,
		     dismissed_findings, weights_digest, computed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (scan_id) DO UPDATE SET
		    score = EXCLUDED.score,
		    total = EXCLUDED.total,
		    live_findings = EXCLUDED.live_findings,
		    dismissed_findings = EXCLUDED.dismissed_findings,
		    weights_digest = EXCLUDED.weights_digest,
		    computed_at = EXCLUDED.computed_at`,
		scanID, projectID, a.Score, a.Total, a.Live, a.Dismissed,
		weightsDigest, at.UTC())
	if err != nil {
		return fmt.Errorf("save risk score: %w", err)
	}
	return nil
}

// LatestRiskScore reads a project's most recent score.
func (s *Store) LatestRiskScore(ctx context.Context, projectID string) (RiskRecord, error) {
	var r RiskRecord
	err := s.pool.QueryRow(ctx, `
		SELECT rs.scan_id, rs.project_id, rs.score, rs.total, rs.live_findings,
		       rs.dismissed_findings, rs.weights_digest, rs.computed_at,
		       s.status::text
		  FROM scan_risk_scores rs
		  JOIN scans s ON s.id = rs.scan_id
		 WHERE rs.project_id = $1
		 ORDER BY rs.computed_at DESC
		 LIMIT 1`, projectID).Scan(
		&r.ScanID, &r.ProjectID, &r.Score, &r.Total, &r.LiveFindings,
		&r.DismissedFindings, &r.WeightsDigest, &r.ComputedAt, &r.ScanStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RiskRecord{}, ErrNoRiskScore
		}
		return RiskRecord{}, fmt.Errorf("latest risk score: %w", err)
	}
	return r, nil
}

// RiskHistory reads a project's recent scores, newest first.
//
// The trend §18 asks for. Bounded by limit rather than returning everything:
// an unbounded history query is a denial-of-service vector on a project that
// has been scanned for years.
func (s *Store) RiskHistory(
	ctx context.Context, projectID string, limit int,
) ([]RiskRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT rs.scan_id, rs.project_id, rs.score, rs.total, rs.live_findings,
		       rs.dismissed_findings, rs.weights_digest, rs.computed_at,
		       s.status::text
		  FROM scan_risk_scores rs
		  JOIN scans s ON s.id = rs.scan_id
		 WHERE rs.project_id = $1
		 ORDER BY rs.computed_at DESC
		 LIMIT $2`, projectID, limit)
	if err != nil {
		return nil, fmt.Errorf("risk history: %w", err)
	}
	defer rows.Close()

	out := make([]RiskRecord, 0, limit)
	for rows.Next() {
		var r RiskRecord
		if err := rows.Scan(
			&r.ScanID, &r.ProjectID, &r.Score, &r.Total, &r.LiveFindings,
			&r.DismissedFindings, &r.WeightsDigest, &r.ComputedAt, &r.ScanStatus,
		); err != nil {
			return nil, fmt.Errorf("scan risk history: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan risk history: %w", err)
	}
	return out, nil
}
