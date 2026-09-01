package findings

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aizen299/secure-dev/internal/correlation"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// liveStatuses are the statuses correlation considers.
//
// A dismissed finding must not be pulled into a live issue: correlating a
// false positive or an ignored finding would resurrect a decision somebody
// already made, and put it back in front of them under a new name.
var liveStatuses = []string{"open", "reopened", "acknowledged", "in_progress"}

// ListLiveForCorrelation returns a project's live findings as correlation
// subjects.
//
// Project-wide rather than scan-scoped, per ADR 017: a Grype finding recorded
// on Monday and a Semgrep finding recorded on Tuesday describe one problem or
// they do not, and which scan produced them is irrelevant.
//
// The file list is assembled here rather than in the engine, which is what
// keeps internal/correlation free of a database.
func (s *Store) ListLiveForCorrelation(
	ctx context.Context, projectID string,
) ([]correlation.Subject, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT f.fingerprint, f.scanner, f.category, f.severity, f.confidence,
		       f.title, coalesce(f.package, ''), coalesce(f.purl, ''),
		       coalesce(f.cve, ''), coalesce(f.cwe, ''),
		       (SELECT coalesce(array_agg(DISTINCT o.file), '{}')
		          FROM finding_occurrences o
		         WHERE o.finding_id = f.id AND o.file IS NOT NULL)
		  FROM findings f
		 WHERE f.project_id = $1
		   AND f.status::text = ANY($2)
		 ORDER BY f.fingerprint`,
		projectID, liveStatuses)
	if err != nil {
		return nil, fmt.Errorf("list findings for correlation: %w", err)
	}
	defer rows.Close()

	var out []correlation.Subject
	for rows.Next() {
		var (
			sub                        correlation.Subject
			category, severity, confid string
		)
		if err := rows.Scan(
			&sub.Fingerprint, &sub.Scanner, &category, &severity, &confid,
			&sub.Title, &sub.Package, &sub.PURL, &sub.CVE, &sub.CWE, &sub.Files,
		); err != nil {
			return nil, fmt.Errorf("scan correlation subject: %w", err)
		}
		sub.ProjectID = projectID
		sub.Category = scanners.Category(category)
		sub.Severity = normalization.Severity(severity)
		sub.Confidence = normalization.Confidence(confid)
		out = append(out, sub)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan correlation subjects: %w", err)
	}
	return out, nil
}

// ReplaceCorrelation writes a project's correlation, replacing what was there.
//
// Replace rather than merge, per ADR 017: an issue whose members have since
// been resolved, dismissed, or re-fingerprinted must not linger, and the number
// of ways a stale issue can survive an incremental update is larger than the
// cost of recomputing. The engine is deterministic and its input is the current
// findings, so nothing here is irreproducible state.
//
// One transaction. A project observed mid-write would otherwise show the old
// issues and the new links, which is a view that was never true.
func (s *Store) ReplaceCorrelation(
	ctx context.Context, projectID string, result correlation.Result,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("replace correlation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	idByFingerprint, err := findingIDs(ctx, tx, projectID)
	if err != nil {
		return err
	}

	if err := clearCorrelation(ctx, tx, projectID); err != nil {
		return err
	}

	for _, link := range result.Links {
		from, okFrom := idByFingerprint[link.From]
		to, okTo := idByFingerprint[link.To]
		if !okFrom || !okTo {
			// A finding that changed status between the read and this write.
			// Dropping the link is correct: the alternative is a foreign key
			// error that fails the whole scan over a race with no consequence.
			continue
		}
		if err := insertLink(ctx, tx, from, to, link); err != nil {
			return err
		}
	}

	for _, issue := range result.Issues {
		if err := insertIssue(ctx, tx, projectID, issue, idByFingerprint); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func findingIDs(ctx context.Context, tx pgx.Tx, projectID string) (map[string]string, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, fingerprint FROM findings WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, fmt.Errorf("load finding ids: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var id, fingerprint string
		if err := rows.Scan(&id, &fingerprint); err != nil {
			return nil, fmt.Errorf("scan finding id: %w", err)
		}
		out[fingerprint] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load finding ids: %w", err)
	}
	return out, nil
}

// clearCorrelation removes the project's derived correlation.
//
// Only correlation output is touched. Findings, occurrences, and lifecycle
// history are untouched by design: those are observations, and this is an
// opinion about them.
func clearCorrelation(ctx context.Context, tx pgx.Tx, projectID string) error {
	// Members cascade from the issue.
	if _, err := tx.Exec(ctx,
		`DELETE FROM correlated_issues WHERE project_id = $1`, projectID); err != nil {
		return fmt.Errorf("clear correlated issues: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM finding_links
		 WHERE from_finding_id IN (SELECT id FROM findings WHERE project_id = $1)`,
		projectID); err != nil {
		return fmt.Errorf("clear finding links: %w", err)
	}
	return nil
}

func insertIssue(
	ctx context.Context, tx pgx.Tx, projectID string,
	issue correlation.Issue, idByFingerprint map[string]string,
) error {
	var issueID string
	err := tx.QueryRow(ctx, `
		INSERT INTO correlated_issues
		    (project_id, key_kind, key_value, severity, escalated, categories, explanation)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id`,
		projectID, string(issue.Key.Kind), issue.Key.Value,
		string(issue.Severity), issue.Escalated, issue.Categories, issue.Explanation,
	).Scan(&issueID)
	if err != nil {
		return fmt.Errorf("insert correlated issue: %w", err)
	}

	for _, m := range issue.Members {
		findingID, ok := idByFingerprint[m.Fingerprint]
		if !ok {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO correlated_issue_members (issue_id, finding_id, evidence)
			VALUES ($1,$2,$3)
			ON CONFLICT (issue_id, finding_id) DO NOTHING`,
			issueID, findingID, m.Evidence); err != nil {
			return fmt.Errorf("insert issue member: %w", err)
		}
	}
	return nil
}

func insertLink(ctx context.Context, tx pgx.Tx, from, to string, l correlation.Link) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO finding_links
		    (from_finding_id, to_finding_id, relationship, confidence, evidence)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (from_finding_id, to_finding_id, relationship) DO NOTHING`,
		from, to, string(l.Relationship), string(l.Confidence), l.Evidence)
	if err != nil {
		return fmt.Errorf("insert finding link: %w", err)
	}
	return nil
}

// IssueRecord is a correlated issue as read back, with its members.
type IssueRecord struct {
	ID          string
	Key         correlation.Key
	Severity    normalization.Severity
	Escalated   bool
	Categories  []string
	Explanation string
	Members     []IssueMemberRecord
}

// IssueMemberRecord is one finding's participation, as read back.
type IssueMemberRecord struct {
	FindingID   string
	Fingerprint string
	Scanner     string
	Severity    normalization.Severity
	Title       string
	Evidence    string
}

// ListIssues returns a project's correlated issues, most severe first.
//
// Members are loaded in a second query rather than a join, so the page limit
// bounds issues rather than issue-member rows. A join would make a page size of
// 50 mean "50 rows", which for one issue with 40 members is one issue.
func (s *Store) ListIssues(
	ctx context.Context, projectID string, page Page,
) ([]IssueRecord, bool, error) {
	page = page.normalize()

	rows, err := s.pool.Query(ctx, `
		SELECT id, key_kind, key_value, severity, escalated, categories, explanation
		  FROM correlated_issues
		 WHERE project_id = $1
		 ORDER BY
		     CASE severity
		         WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		         WHEN 'unknown' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
		     key_kind, key_value
		 LIMIT $2 OFFSET $3`,
		projectID, page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list issues: %w", err)
	}

	var (
		issues []IssueRecord
		ids    []string
	)
	for rows.Next() {
		var (
			r        IssueRecord
			kind     string
			severity string
		)
		if err := rows.Scan(&r.ID, &kind, &r.Key.Value, &severity,
			&r.Escalated, &r.Categories, &r.Explanation); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("scan issue row: %w", err)
		}
		r.Key.Kind = correlation.KeyKind(kind)
		r.Severity = normalization.Severity(severity)
		issues = append(issues, r)
		ids = append(ids, r.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("scan issue rows: %w", err)
	}

	hasMore := len(issues) > page.Limit
	if hasMore {
		issues = issues[:page.Limit]
		ids = ids[:page.Limit]
	}
	if len(issues) == 0 {
		return []IssueRecord{}, false, nil
	}

	members, err := s.issueMembers(ctx, ids)
	if err != nil {
		return nil, false, err
	}
	for i := range issues {
		issues[i].Members = members[issues[i].ID]
	}
	return issues, hasMore, nil
}

func (s *Store) issueMembers(
	ctx context.Context, issueIDs []string,
) (map[string][]IssueMemberRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT m.issue_id, m.finding_id, f.fingerprint, f.scanner, f.severity,
		       f.title, m.evidence
		  FROM correlated_issue_members m
		  JOIN findings f ON f.id = m.finding_id
		 WHERE m.issue_id = ANY($1)
		 ORDER BY f.fingerprint`, issueIDs)
	if err != nil {
		return nil, fmt.Errorf("list issue members: %w", err)
	}
	defer rows.Close()

	out := map[string][]IssueMemberRecord{}
	for rows.Next() {
		var (
			issueID  string
			m        IssueMemberRecord
			severity string
		)
		if err := rows.Scan(&issueID, &m.FindingID, &m.Fingerprint, &m.Scanner,
			&severity, &m.Title, &m.Evidence); err != nil {
			return nil, fmt.Errorf("scan issue member: %w", err)
		}
		m.Severity = normalization.Severity(severity)
		out[issueID] = append(out[issueID], m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan issue members: %w", err)
	}
	return out, nil
}
