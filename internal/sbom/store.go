package sbom

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists and reads component inventories.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Record is one component as stored, with the scan that observed it.
type Record struct {
	Component
	ScanID    string `json:"scan_id"`
	ProjectID string `json:"project_id"`
	// Scanner names what produced this row. Syft today; trivy also emits
	// CycloneDX, and an inventory that cannot say where a component came from
	// cannot be reconciled when two disagree.
	Scanner string `json:"scanner"`
}

// Page bounds a read.
type Page struct {
	Limit  int
	Offset int
}

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
	ctx context.Context, scanID, projectID, scanner string, components []Component,
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
func (s *Store) ByScan(ctx context.Context, scanID string, page Page) ([]Record, bool, error) {
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
func (s *Store) ByProject(ctx context.Context, projectID string, page Page) ([]Record, bool, error) {
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

func collectComponents(rows pgx.Rows, limit int) ([]Record, bool, error) {
	defer rows.Close()

	out := make([]Record, 0, limit)
	for rows.Next() {
		var r Record
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
