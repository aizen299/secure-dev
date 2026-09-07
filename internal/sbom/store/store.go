// Package store persists a scan's bill of materials.
//
// Split out of internal/sbom for the reason internal/scans/store was: a
// package's imports are the union of its files', so the pure CycloneDX parser
// sitting beside this pgx-backed store put a PostgreSQL driver into every
// binary that parsed an SBOM -- including cmd/scanjob, which must hold nothing
// (ADR 039).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/sbom"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// Store persists and reads component inventories.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// RecordScan replaces one scan's inventory.
//
// Replaces rather than appends, so a re-run of the same scan is idempotent: an
// inventory that grew every time a scan was reprocessed would describe a
// project that never existed. Nothing else references these rows, so a delete
// here cascades to nothing.
//
// One transaction. A half-written inventory is worse than none: it reads as a
// complete list of what a project contains, which is exactly the claim it
// cannot support.
func (s *Store) RecordScan(
	ctx context.Context, scanID, projectID, scanner string, components []sbom.Component,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("record sbom: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM sbom_components WHERE scan_id = $1 AND scanner = $2`,
		scanID, scanner); err != nil {
		return fmt.Errorf("record sbom: clearing the previous inventory: %w", err)
	}

	if len(components) > 0 {
		// CopyFrom rather than a loop of INSERTs. A container image can carry
		// thousands of components, and a round trip each would make persisting
		// an inventory slower than producing it.
		rows := make([][]any, 0, len(components))
		for _, c := range components {
			rows = append(rows, []any{
				scanID, projectID, c.PURL, c.Name, c.Version,
				c.Type, c.CPE, c.Location, scanner,
			})
		}
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"sbom_components"},
			[]string{
				"scan_id", "project_id", "purl", "name", "version",
				"component_type", "cpe", "location", "scanner",
			},
			pgx.CopyFromRows(rows),
		); err != nil {
			return fmt.Errorf("record sbom: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("record sbom: %w", err)
	}
	return nil
}

const componentColumns = `scan_id::text, project_id::text, purl, name, version,
	component_type, cpe, location, scanner`

// ByScan returns one scan's inventory.
//
// Ordered by name so two reads of one scan agree, and so a caller comparing two
// scans is comparing lists in the same order rather than diffing noise.
func (s *Store) ByScan(ctx context.Context, scanID string, page sbom.Page) ([]sbom.Record, bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+componentColumns+`
		  FROM sbom_components
		 WHERE scan_id = $1
		 ORDER BY name, version, id
		 LIMIT $2 OFFSET $3`,
		scanID, page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list components: %w", err)
	}
	return collectComponents(rows, page.Limit)
}

// ByProject returns the components of a project's most recent scan that
// produced any.
//
// The most recent scan rather than every scan, because "what is in this
// project" is a question about now. A union across scans would list versions
// that were replaced months ago beside the current one, with nothing to
// distinguish them -- an inventory that grows monotonically and never
// describes any real build.
//
// A scan that produced no components does not become the answer: an endpoint
// scan runs only ZAP and has no SBOM, and letting it shadow the last repository
// scan would make a website scan erase a project's inventory.
func (s *Store) ByProject(ctx context.Context, projectID string, page sbom.Page) ([]sbom.Record, bool, error) {
	rows, err := s.pool.Query(ctx, `
		WITH latest AS (
			SELECT scan_id
			  FROM sbom_components
			 WHERE project_id = $1
			 ORDER BY id DESC
			 LIMIT 1
		)
		SELECT `+componentColumns+`
		  FROM sbom_components
		 WHERE scan_id = (SELECT scan_id FROM latest)
		 ORDER BY name, version, id
		 LIMIT $2 OFFSET $3`,
		projectID, page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list project components: %w", err)
	}
	return collectComponents(rows, page.Limit)
}

func collectComponents(rows pgx.Rows, limit int) ([]sbom.Record, bool, error) {
	defer rows.Close()

	out := make([]sbom.Record, 0, limit)
	for rows.Next() {
		var r sbom.Record
		if err := rows.Scan(
			&r.ScanID, &r.ProjectID, &r.PURL, &r.Name, &r.Version,
			&r.Type, &r.CPE, &r.Location, &r.Scanner,
		); err != nil {
			return nil, false, fmt.Errorf("scan component: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("scan components: %w", err)
	}

	// One more than asked for tells the caller there is a next page without a
	// second count query, matching how every other list in this codebase pages.
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ArtifactFor reads the inventory of a project's most recent image scan.
//
// Returns Found=false rather than an error when there is none: most projects
// have never been scanned as an image, and treating the common case as a
// failure would make every correlation run log one.
func (s *Store) ArtifactFor(ctx context.Context, projectID string) (sbom.Artifact, error) {
	// The scan first, so "which artifact" is decided once and the components
	// are read against that decision rather than assembled from whatever rows
	// happen to sort highest.
	var (
		art       sbom.Artifact
		scannedAt *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT s.id::text,
		       coalesce(s.completed_at, s.started_at, s.queued_at),
		       NOT EXISTS (
		           SELECT 1 FROM scan_scanner_results r
		            WHERE r.scan_id = s.id
		              AND $2 = ANY(r.degradations)
		       )
		  FROM scans s
		 WHERE s.project_id = $1
		   AND s.target->>'kind' = 'image'
		   AND EXISTS (SELECT 1 FROM sbom_components c WHERE c.scan_id = s.id)
		 ORDER BY coalesce(s.completed_at, s.queued_at) DESC, s.id DESC
		 LIMIT 1`,
		projectID, string(scanners.DegradedSBOMTruncated),
	).Scan(&art.ScanID, &scannedAt, &art.Complete)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sbom.Artifact{}, nil
		}
		return sbom.Artifact{}, fmt.Errorf("artifact scan: %w", err)
	}
	if scannedAt != nil {
		art.ScannedAt = *scannedAt
	}
	art.Found = true

	rows, err := s.pool.Query(ctx,
		`SELECT purl FROM sbom_components WHERE scan_id = $1 AND purl <> ''`, art.ScanID)
	if err != nil {
		return sbom.Artifact{}, fmt.Errorf("artifact components: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var purl string
		if err := rows.Scan(&purl); err != nil {
			return sbom.Artifact{}, fmt.Errorf("scan artifact component: %w", err)
		}
		art.PURLs = append(art.PURLs, purl)
	}
	if err := rows.Err(); err != nil {
		return sbom.Artifact{}, fmt.Errorf("artifact components: %w", err)
	}
	return art, nil
}
