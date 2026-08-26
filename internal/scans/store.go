package scans

import (
	"context"
	"fmt"
	"time"

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
func (s *Store) Finalize(ctx context.Context, scanID string, status Status, at time.Time) error {
	if !status.Terminal() {
		return fmt.Errorf("finalize scan: %q is not a terminal status", status)
	}

	// Only a non-terminal scan may be finalized, so a late or duplicated
	// worker cannot rewrite an outcome that is already recorded.
	tag, err := s.pool.Exec(ctx, `
		UPDATE scans
		   SET status = $2, completed_at = $3
		 WHERE id = $1
		   AND status IN ('queued', 'running')`,
		scanID, string(status), at.UTC())
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
