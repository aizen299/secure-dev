// Package findings persists the canonical findings that normalization produces.
//
// Split from internal/normalization deliberately: that package is pure by
// contract, and a database handle in it would make the claim untrue. This one
// owns storage and the lifecycle state machine; that one owns the
// transformation.
package findings

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Reasons recorded on a lifecycle transition. A fixed vocabulary rather than
// free text, so "why did this become resolved?" is a query rather than a search.
const (
	ReasonFirstSeen   = "first_seen"
	ReasonReopened    = "reopened"
	ReasonNotReported = "not_reported"
)

// ActorSystem is the actor for scan-driven transitions, which is most of them:
// a finding becomes resolved because a scan stopped reporting it, not because
// anyone decided anything. Phase 11 adds named principals.
const ActorSystem = "system"

// Store persists findings, their occurrences, their links, and their history.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// RecordScan persists one scan's normalized results.
//
// Everything happens in one transaction. A half-written scan would leave
// findings whose occurrences are missing, which reads as "seen but nowhere",
// and lifecycle transitions that no scan explains.
func (s *Store) RecordScan(
	ctx context.Context, projectID, scanID string, result normalization.DedupResult,
	completeScanners []string, at time.Time,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("record findings: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	idByFingerprint := make(map[string]string, len(result.Findings))
	for _, f := range result.Findings {
		id, err := upsertFinding(ctx, tx, projectID, scanID, f, at)
		if err != nil {
			return err
		}
		idByFingerprint[f.Fingerprint] = id
	}

	for _, occ := range result.Occurrences {
		findingID, ok := idByFingerprint[occ.Fingerprint]
		if !ok {
			// An occurrence for a finding that was not stored means the two
			// halves of one result disagree, which is a bug rather than data.
			return fmt.Errorf("record findings: occurrence for unknown fingerprint %s", occ.Fingerprint)
		}
		if err := insertOccurrence(ctx, tx, findingID, scanID, occ); err != nil {
			return err
		}
	}

	if err := resolveUnreported(ctx, tx, projectID, scanID, completeScanners, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// upsertFinding inserts a finding or advances an existing one, and records any
// lifecycle transition that results.
func upsertFinding(
	ctx context.Context, tx pgx.Tx, projectID, scanID string,
	f normalization.MergedFinding, at time.Time,
) (string, error) {
	var (
		id        string
		prevState *string
	)

	// The upsert returns the status as it was BEFORE this statement, so the
	// transition can be recorded accurately. Reading it afterwards would see
	// the new value and report every finding as unchanged.
	err := tx.QueryRow(ctx, `
		WITH previous AS (
		    SELECT id, status FROM findings
		     WHERE project_id = $1 AND fingerprint = $2
		)
		INSERT INTO findings (
		    project_id, fingerprint, scanner, scanner_finding_id, scanner_severity,
		    category, severity, confidence, title, description, remediation,
		    package, package_version, purl, cve, cwe, cvss,
		    status, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'open',$18,$18)
		ON CONFLICT (project_id, fingerprint) DO UPDATE SET
		    last_seen = EXCLUDED.last_seen,
		    -- Severity can move: a vendor rescoring a CVE, or a second scanner
		    -- reporting it worse. Prose is refreshed for the same reason.
		    severity    = EXCLUDED.severity,
		    title       = EXCLUDED.title,
		    description = EXCLUDED.description,
		    remediation = EXCLUDED.remediation,
		    -- A finding that was resolved and is reported again has come back.
		    -- Anything a person set -- acknowledged, ignored, false_positive --
		    -- is left alone: a scan must not overrule a human judgement.
		    status = CASE
		        WHEN findings.status = 'resolved' THEN 'reopened'::finding_status
		        ELSE findings.status
		    END
		RETURNING id, (SELECT status::text FROM previous)`,
		projectID, f.Fingerprint, f.Scanner, nullIfEmpty(f.ScannerFindingID),
		nullIfEmpty(f.ScannerSeverity), string(f.Category), string(f.Severity),
		string(f.Confidence), f.Title, nullIfEmpty(f.Description), nullIfEmpty(f.Remediation),
		nullIfEmpty(f.Package), nullIfEmpty(f.PackageVersion), nullIfEmpty(f.PURL),
		nullIfEmpty(f.CVE), nullIfEmpty(f.CWE), nullIfZero(f.CVSS),
		at.UTC(),
	).Scan(&id, &prevState)
	if err != nil {
		return "", fmt.Errorf("upsert finding: %w", err)
	}

	switch {
	case prevState == nil:
		// Newly discovered.
		if err := recordTransition(ctx, tx, id, nil, "open", ReasonFirstSeen, scanID, at); err != nil {
			return "", err
		}
	case *prevState == "resolved":
		// It came back. Distinct from never having been fixed.
		from := "resolved"
		if err := recordTransition(ctx, tx, id, &from, "reopened", ReasonReopened, scanID, at); err != nil {
			return "", err
		}
	}
	return id, nil
}

// resolveUnreported closes findings this scan did not report.
//
// The correctness question here is which findings a scan is entitled to
// resolve. A scan that ran only gitleaks says nothing about semgrep's findings,
// and marking them resolved would be a false "fixed" -- the same class of error
// as a PARTIAL scan reported as clean (§13, ADR 010).
//
// So a finding is eligible only when EVERY scanner that has ever reported it
// completed successfully in this scan. "Every", not "the first one": findings
// carry a single scanner column recording who saw it first, and a finding both
// grype and trivy report would otherwise resolve the moment grype came back
// clean, even though trivy failed and was never asked.
//
// The conservative direction is deliberate. A finding stays open until every
// scanner that vouched for it has had its say, which means dropping a scanner
// from a project's selection leaves that scanner's old findings open rather
// than silently declaring them fixed. Stale-but-open is a visible state; a
// false "resolved" is not.
func resolveUnreported(
	ctx context.Context, tx pgx.Tx, projectID, scanID string,
	completeScanners []string, at time.Time,
) error {
	if len(completeScanners) == 0 {
		return nil
	}

	rows, err := tx.Query(ctx, `
		UPDATE findings f
		   SET status = 'resolved'
		 WHERE f.project_id = $1
		   AND f.scanner = ANY($2)
		   AND f.status IN ('open', 'reopened')
		   -- Not reported by THIS scan.
		   AND NOT EXISTS (
		       SELECT 1 FROM finding_occurrences o
		        WHERE o.finding_id = f.id AND o.scan_id = $3
		   )
		   -- And no scanner that has ever reported it is missing from the
		   -- completed set. A single failed reporter blocks the resolve.
		   AND NOT EXISTS (
		       SELECT 1 FROM finding_occurrences o
		        WHERE o.finding_id = f.id AND NOT (o.scanner = ANY($2))
		   )
		RETURNING f.id, f.status`,
		projectID, completeScanners, scanID)
	if err != nil {
		return fmt.Errorf("resolve unreported findings: %w", err)
	}

	var ids []string
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			rows.Close()
			return fmt.Errorf("resolve unreported findings: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("resolve unreported findings: %w", err)
	}

	for _, id := range ids {
		// from_status is not read back per row: both 'open' and 'reopened'
		// transition to 'resolved' for the same reason, and the history's
		// value is in the reason and the timestamp.
		if err := recordTransition(ctx, tx, id, nil, "resolved", ReasonNotReported, scanID, at); err != nil {
			return err
		}
	}
	return nil
}

func recordTransition(
	ctx context.Context, tx pgx.Tx, findingID string, from *string,
	to, reason, scanID string, at time.Time,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO finding_status_history
		    (finding_id, from_status, to_status, actor, reason, scan_id, changed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		findingID, from, to, ActorSystem, reason, nullIfEmpty(scanID), at.UTC())
	if err != nil {
		return fmt.Errorf("record status transition: %w", err)
	}
	return nil
}

func insertOccurrence(
	ctx context.Context, tx pgx.Tx, findingID, scanID string, o normalization.Occurrence,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO finding_occurrences
		    (finding_id, scan_id, scanner, file, start_line, end_line, seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,now())
		ON CONFLICT (finding_id, scan_id, scanner, file, start_line) DO NOTHING`,
		findingID, scanID, o.Scanner, nullIfEmpty(o.File),
		nullIfZero(float64(o.StartLine)), nullIfZero(float64(o.EndLine)))
	if err != nil {
		return fmt.Errorf("insert occurrence: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZero(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}

// Page bounds a listing. Mirrors scans.Page: every list endpoint paginates
// (§18), and an unbounded query over findings is the one most likely to hurt.
type Page struct {
	Limit  int
	Offset int
}

const (
	defaultLimit = 50
	maxLimit     = 200
)

func (p Page) normalize() Page {
	if p.Limit <= 0 {
		p.Limit = defaultLimit
	}
	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// Filter narrows a listing. Zero values mean "no constraint".
type Filter struct {
	Status   string
	Severity string
	Scanner  string
}

// Record is a stored finding as read back, with the sightings that support it.
type Record struct {
	normalization.Finding
	ID string
	// Sources are the distinct scanners that have reported this finding,
	// derived from its occurrences rather than stored: two scanners agreeing
	// is a fact about the sightings.
	Sources     []string
	Occurrences int
	FirstSeen   time.Time
	LastSeen    time.Time
}

const recordColumns = `
	f.id, f.fingerprint, f.scanner, f.scanner_finding_id, f.scanner_severity,
	f.category, f.severity, f.confidence, f.title, f.description, f.remediation,
	f.package, f.package_version, f.purl, f.cve, f.cwe, f.cvss,
	f.status, f.first_seen, f.last_seen,
	(SELECT count(*) FROM finding_occurrences o WHERE o.finding_id = f.id),
	(SELECT coalesce(array_agg(DISTINCT o.scanner), '{}')
	   FROM finding_occurrences o WHERE o.finding_id = f.id)`

// ListByProject returns a project's findings, most severe first.
//
// Ordered by severity then recency because a findings list is read to decide
// what to do next, and the answer is almost always "the worst thing most
// recently seen".
func (s *Store) ListByProject(
	ctx context.Context, projectID string, filter Filter, page Page,
) ([]Record, bool, error) {
	page = page.normalize()

	rows, err := s.pool.Query(ctx, `
		SELECT `+recordColumns+`
		  FROM findings f
		 WHERE f.project_id = $1
		   AND ($2 = '' OR f.status::text = $2)
		   AND ($3 = '' OR f.severity::text = $3)
		   AND ($4 = '' OR f.scanner = $4)
		 ORDER BY
		     CASE f.severity
		         WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		         WHEN 'unknown' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
		     f.last_seen DESC, f.id
		 LIMIT $5 OFFSET $6`,
		projectID, filter.Status, filter.Severity, filter.Scanner,
		page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	return collectRecords(rows, page.Limit)
}

// ListByScan returns the findings a specific scan reported.
func (s *Store) ListByScan(
	ctx context.Context, scanID string, page Page,
) ([]Record, bool, error) {
	page = page.normalize()

	rows, err := s.pool.Query(ctx, `
		SELECT `+recordColumns+`
		  FROM findings f
		 WHERE EXISTS (
		     SELECT 1 FROM finding_occurrences o
		      WHERE o.finding_id = f.id AND o.scan_id = $1
		 )
		 ORDER BY
		     CASE f.severity
		         WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		         WHEN 'unknown' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
		     f.last_seen DESC, f.id
		 LIMIT $2 OFFSET $3`,
		scanID, page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list scan findings: %w", err)
	}
	defer rows.Close()

	return collectRecords(rows, page.Limit)
}

func collectRecords(rows pgx.Rows, limit int) ([]Record, bool, error) {
	out := make([]Record, 0, limit)
	for rows.Next() {
		var (
			r                     Record
			findingID, sevStr     string
			catStr, confStr       string
			statusStr             string
			scannerFindingID      *string
			scannerSeverity       *string
			description, remedy   *string
			pkg, pkgVersion, purl *string
			cve, cwe              *string
			cvss                  *float64
		)
		if err := rows.Scan(
			&findingID, &r.Fingerprint, &r.Scanner, &scannerFindingID, &scannerSeverity,
			&catStr, &sevStr, &confStr, &r.Title, &description, &remedy,
			&pkg, &pkgVersion, &purl, &cve, &cwe, &cvss,
			&statusStr, &r.FirstSeen, &r.LastSeen, &r.Occurrences, &r.Sources,
		); err != nil {
			return nil, false, fmt.Errorf("scan finding row: %w", err)
		}

		r.ID = findingID
		r.Category = scanners.Category(catStr)
		r.Severity = normalization.Severity(sevStr)
		r.Confidence = normalization.Confidence(confStr)
		r.Status = normalization.Status(statusStr)
		assignIfPresent(&r.ScannerFindingID, scannerFindingID)
		assignIfPresent(&r.ScannerSeverity, scannerSeverity)
		assignIfPresent(&r.Description, description)
		assignIfPresent(&r.Remediation, remedy)
		assignIfPresent(&r.Package, pkg)
		assignIfPresent(&r.PackageVersion, pkgVersion)
		assignIfPresent(&r.PURL, purl)
		assignIfPresent(&r.CVE, cve)
		assignIfPresent(&r.CWE, cwe)
		if cvss != nil {
			r.CVSS = *cvss
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("scan finding rows: %w", err)
	}

	// One row beyond the limit was requested, so "is there more?" is answered
	// without a second count query.
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func assignIfPresent(dst *string, v *string) {
	if v != nil {
		*dst = *v
	}
}
