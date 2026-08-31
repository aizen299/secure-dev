package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// maxStoredOutputBytes caps how much raw scanner output is persisted per
// scanner. Raw output is kept for audit and reprocessing (§8), but it comes
// from an untrusted process, so it is bounded like any other input (§15.8).
const maxStoredOutputBytes = 16 << 20 // 16 MiB

// Store persists scans and their per-scanner results in PostgreSQL.
//
// Every statement uses parameter placeholders; no query in this file is built
// by string concatenation (§15.9).
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// scanColumns is the shared select list, so every read returns the same shape.
const scanColumns = `id, project_id, repository_id, status, target,
	commit_sha, branch, requested_scanners, failure_reason,
	queued_at, started_at, completed_at`

// Create inserts a scan in the queued state and returns the stored record.
//
// The scan row is written before the job is enqueued, so a scan always exists
// to report on. The reverse order would allow a worker to dequeue a job whose
// scan row is not there yet.
func (s *Store) Create(ctx context.Context, input NewScan) (Scan, error) {
	normalized, err := input.Normalize()
	if err != nil {
		return Scan{}, err
	}

	target, err := json.Marshal(normalized.Target)
	if err != nil {
		return Scan{}, fmt.Errorf("create scan: encode target: %w", err)
	}

	// A nil slice would be written as NULL, and the column is NOT NULL.
	requested := normalized.Scanners
	if requested == nil {
		requested = []string{}
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO scans
			(project_id, repository_id, status, target, commit_sha, branch, requested_scanners)
		VALUES ($1, $2, 'queued', $3, $4, $5, $6)
		RETURNING `+scanColumns,
		normalized.ProjectID, normalized.RepositoryID, target,
		nullIfEmpty(normalized.CommitSHA), nullIfEmpty(normalized.Branch), requested)

	scan, err := scanRow(row)
	if err != nil {
		return Scan{}, fmt.Errorf("create scan: %w", err)
	}
	return scan, nil
}

// Get returns one scan with its per-scanner results.
//
// The results are always loaded: a scan status without the per-scanner detail
// is exactly the "clean scan" illusion §13 exists to prevent.
func (s *Store) Get(ctx context.Context, id string) (Scan, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scanColumns+` FROM scans WHERE id = $1`, id)

	scan, err := scanRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Scan{}, ErrNotFound
		}
		return Scan{}, fmt.Errorf("get scan: %w", err)
	}

	results, err := s.scannerResults(ctx, id)
	if err != nil {
		return Scan{}, err
	}
	scan.Results = results
	return scan, nil
}

// ListByProject returns a page of a project's scans, newest first.
//
// Per-scanner results are deliberately not loaded: a list view shows status
// and timing, and fetching results for every row would be N+1 queries for data
// the list does not display. GET /scans/{id} is where the detail lives.
func (s *Store) ListByProject(ctx context.Context, projectID string, page Page) ([]Scan, bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+scanColumns+`
		  FROM scans
		 WHERE project_id = $1
		 ORDER BY queued_at DESC, id DESC
		 LIMIT $2 OFFSET $3`,
		projectID, page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	out := make([]Scan, 0, page.Limit)
	for rows.Next() {
		scan, err := scanRow(rows)
		if err != nil {
			return nil, false, fmt.Errorf("list scans: %w", err)
		}
		out = append(out, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list scans: %w", err)
	}

	hasMore := len(out) > page.Limit
	if hasMore {
		out = out[:page.Limit]
	}
	return out, hasMore, nil
}

// scannerResults loads the per-scanner outcomes for one scan.
func (s *Store) scannerResults(ctx context.Context, scanID string) ([]ScannerResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT scanner, status, scanner_version, exit_code, duration_ms,
		       error, truncated, started_at
		  FROM scan_scanner_results
		 WHERE scan_id = $1
		 ORDER BY scanner`, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scanner results: %w", err)
	}
	defer rows.Close()

	var out []ScannerResult
	for rows.Next() {
		var (
			r          ScannerResult
			version    *string
			exitCode   *int
			durationMS *int64
			errMsg     *string
		)
		if err := rows.Scan(&r.Scanner, &r.Status, &version, &exitCode,
			&durationMS, &errMsg, &r.Truncated, &r.StartedAt); err != nil {
			return nil, fmt.Errorf("get scanner results: %w", err)
		}
		if version != nil {
			r.Version = *version
		}
		if exitCode != nil {
			r.ExitCode = *exitCode
		}
		if durationMS != nil {
			r.Duration = time.Duration(*durationMS) * time.Millisecond
		}
		if errMsg != nil {
			r.Error = *errMsg
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get scanner results: %w", err)
	}
	return out, nil
}

// Page bounds a list query.
type Page struct {
	Limit  int
	Offset int
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRow(rs rowScanner) (Scan, error) {
	var (
		s          Scan
		rawTarget  []byte
		commitSHA  *string
		branch     *string
		failReason *string
	)

	err := rs.Scan(
		&s.ID, &s.ProjectID, &s.RepositoryID, &s.Status, &rawTarget,
		&commitSHA, &branch, &s.RequestedScanners, &failReason,
		&s.QueuedAt, &s.StartedAt, &s.CompletedAt,
	)
	if err != nil {
		return Scan{}, err
	}

	if len(rawTarget) > 0 {
		if err := json.Unmarshal(rawTarget, &s.Target); err != nil {
			return Scan{}, fmt.Errorf("decode stored target: %w", err)
		}
	}
	if commitSHA != nil {
		s.CommitSHA = *commitSHA
	}
	if branch != nil {
		s.Branch = *branch
	}
	if failReason != nil {
		s.FailureReason = *failReason
	}
	return s, nil
}

// MarkRunning moves a queued scan into the running state.
//
// The WHERE clause enforces the state machine in the database: a scan that is
// already terminal cannot be dragged back to running by a duplicate delivery.
func (s *Store) MarkRunning(ctx context.Context, scanID string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE scans
		   SET status = 'running', started_at = COALESCE(started_at, $2)
		 WHERE id = $1
		   AND status = 'queued'`,
		scanID, at.UTC())
	if err != nil {
		return fmt.Errorf("mark scan running: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the scan is gone or it is not queued. Both mean this delivery
		// should not proceed as if it owned the scan.
		return fmt.Errorf("mark scan running: scan %s is not in the queued state", scanID)
	}
	return nil
}

// RecordScannerResult upserts one scanner's outcome.
func (s *Store) RecordScannerResult(ctx context.Context, scanID string, r ScannerResult) error {
	var startedAt any
	if r.StartedAt != nil {
		startedAt = r.StartedAt.UTC()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_scanner_results
			(scan_id, scanner, status, scanner_version, exit_code,
			 duration_ms, error, truncated, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (scan_id, scanner) DO UPDATE SET
			status          = EXCLUDED.status,
			scanner_version = EXCLUDED.scanner_version,
			exit_code       = EXCLUDED.exit_code,
			duration_ms     = EXCLUDED.duration_ms,
			error           = EXCLUDED.error,
			truncated       = EXCLUDED.truncated,
			started_at      = EXCLUDED.started_at,
			finished_at     = EXCLUDED.finished_at`,
		scanID, r.Scanner, string(r.Status), nullIfEmpty(r.Version), r.ExitCode,
		r.Duration.Milliseconds(), nullIfEmpty(r.Error), r.Truncated,
		startedAt, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("record scanner result: %w", err)
	}
	return nil
}

// Finalize moves a running scan to a terminal state.
//
// reason explains a failure and must be one of the FailureReason constants; it
// is empty for a scan that produced results. Passing the underlying error here
// would leak repository content into a client-visible field (§15.3).
func (s *Store) Finalize(
	ctx context.Context, scanID string, status Status, reason FailureReason, at time.Time,
) error {
	if !status.Terminal() {
		return fmt.Errorf("finalize scan: %q is not a terminal status", status)
	}

	// Only a non-terminal scan may be finalized, so a late or duplicated
	// worker cannot rewrite an outcome that is already recorded.
	tag, err := s.pool.Exec(ctx, `
		UPDATE scans
		   SET status = $2, completed_at = $3, failure_reason = $4
		 WHERE id = $1
		   AND status IN ('queued', 'running')`,
		scanID, string(status), at.UTC(), nullIfEmpty(string(reason)))
	if err != nil {
		return fmt.Errorf("finalize scan: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("finalize scan: scan %s is not in a finalizable state", scanID)
	}
	return nil
}

// StoreRaw persists a scanner's verbatim output.
func (s *Store) StoreRaw(ctx context.Context, scanID string, raw scanners.RawResult) error {
	output := raw.Output
	truncated := raw.Truncated
	if len(output) > maxStoredOutputBytes {
		output = output[:maxStoredOutputBytes]
		truncated = true
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_raw_results
			(scan_id, scanner, scanner_version, output, output_bytes, truncated)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (scan_id, scanner) DO UPDATE SET
			scanner_version = EXCLUDED.scanner_version,
			output          = EXCLUDED.output,
			output_bytes    = EXCLUDED.output_bytes,
			truncated       = EXCLUDED.truncated,
			collected_at    = now()`,
		scanID, raw.Scanner, nullIfEmpty(raw.Version), output, len(output), truncated)
	if err != nil {
		return fmt.Errorf("store raw result: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
