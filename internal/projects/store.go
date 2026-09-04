package projects

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/auth"
)

// uniqueViolation is the PostgreSQL SQLSTATE for a unique constraint breach.
const uniqueViolation = "23505"

// Store persists projects in PostgreSQL.
//
// Every statement uses parameter placeholders; no query here is assembled by
// string concatenation (§15.9).
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// projectColumns is the shared select list, so every read returns the same
// shape and scanProject stays valid for all of them.
const projectColumns = `id, name, slug, description, environment, criticality,
	internet_facing, archived_at IS NOT NULL, created_at, updated_at`

// Create inserts a project.
//
// It returns ErrSlugTaken on a slug collision so the API can answer 409 rather
// than surfacing a driver error.
func (s *Store) Create(ctx context.Context, input NewProject, actor audit.Actor) (Project, error) {
	normalized, err := input.Normalize()
	if err != nil {
		return Project{}, err
	}

	// A transaction, because the audit record must land with the project
	// rather than beside it (§15.6, ADR 022). A project is the unit of
	// security context -- its environment, criticality, and internet exposure
	// are risk multipliers -- so creating one is a security-sensitive act even
	// though it creates nothing dangerous by itself.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Project{}, fmt.Errorf("begin project create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		INSERT INTO projects (name, slug, description, environment, criticality, internet_facing)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+projectColumns,
		normalized.Name, normalized.Slug, normalized.Description,
		string(normalized.Environment), string(normalized.Criticality), normalized.InternetFacing)

	project, err := scanProject(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return Project{}, fmt.Errorf("%w: %s", ErrSlugTaken, normalized.Slug)
		}
		return Project{}, fmt.Errorf("create project: %w", err)
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		Actor:        actor,
		Action:       "project.create",
		ResourceType: "project",
		ResourceID:   project.ID,
		ProjectID:    project.ID,
		// No previous value: the resource did not exist, which is what
		// distinguishes a creation from an edit.
		After: map[string]any{
			"name":            project.Name,
			"slug":            project.Slug,
			"environment":     string(project.Environment),
			"criticality":     string(project.Criticality),
			"internet_facing": project.InternetFacing,
		},
	}); err != nil {
		return Project{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Project{}, fmt.Errorf("commit project create: %w", err)
	}
	return project, nil
}

// Get returns one project by ID. Archived projects are excluded: they are
// soft-deleted, and a soft-deleted record must not read as live (§17).
func (s *Store) Get(ctx context.Context, id string) (Project, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+projectColumns+`
		  FROM projects
		 WHERE id = $1
		   AND archived_at IS NULL`, id)

	project, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Project{}, ErrNotFound
		}
		return Project{}, fmt.Errorf("get project: %w", err)
	}
	return project, nil
}

// Exists reports whether a live project has this ID.
//
// Used on the scan-creation path, where the project is a foreign key rather
// than something to return, so there is no reason to read every column.
func (s *Store) Exists(ctx context.Context, id string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM projects WHERE id = $1 AND archived_at IS NULL
		)`, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check project exists: %w", err)
	}
	return exists, nil
}

// List returns a page of projects, newest first.
//
// The caller passes limit+1 semantics through Page: List fetches one extra row
// to determine whether another page exists, without a second COUNT query.
// List returns a page of projects the scope reaches (ADR 033).
//
// The filter is in the query and not in the caller, and that is not a
// preference. Filtering a fetched page would corrupt pagination: a page of
// twenty rows containing two in-scope projects would return two items and a
// `has_more` computed from twenty, so a client paging through would see a
// truncated estate and no indication of it. Worse, the count itself leaks --
// "there are more projects you cannot see" is the disclosure T-38 describes.
//
// A zero Scope reaches nothing and returns an empty page, which is what makes
// forgetting to pass one fail closed.
func (s *Store) List(ctx context.Context, page Page, scope auth.Scope) ([]Project, bool, error) {
	// The scope filter stays in SQL alongside the archived one. Filtering a
	// fetched page would return the right rows and the wrong `has_more`, which
	// leaks the size of what the caller cannot see (T-38).
	rows, err := s.pool.Query(ctx, `
		SELECT `+projectColumns+`
		  FROM projects
		 WHERE (archived_at IS NOT NULL) = $5::boolean
		   AND ($3::boolean OR slug = ANY($4::text[]))
		 ORDER BY created_at DESC, id DESC
		 LIMIT $1 OFFSET $2`,
		page.Limit+1, page.Offset, scope.IsGlobal(), scope.Slugs(), page.Archived)
	if err != nil {
		return nil, false, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	out := make([]Project, 0, page.Limit)
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			return nil, false, fmt.Errorf("list projects: %w", err)
		}
		out = append(out, project)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list projects: %w", err)
	}

	hasMore := len(out) > page.Limit
	if hasMore {
		out = out[:page.Limit]
	}
	return out, hasMore, nil
}

// Page bounds a list query.
type Page struct {
	Limit  int
	Offset int

	// Archived selects the archived projects INSTEAD of the live ones, rather
	// than in addition to them.
	//
	// Two disjoint lists rather than one flag that widens a list, because they
	// answer different questions: "what am I working on" and "what did we put
	// away". Mixing them would put a project that accepts no scans beside ones
	// that do, in a list read to decide what to look at next.
	//
	// This exists because archiving a project made it unreachable from the UI:
	// the list hides it, and the control that restores it lives on its page.
	// The page worked; nothing could navigate to it (ADR 033 §6).
	Archived bool
}

// scanner is satisfied by both pgx.Row and pgx.Rows, so one scan function
// serves single-row and multi-row reads.
type scanner interface {
	Scan(dest ...any) error
}

func scanProject(s scanner) (Project, error) {
	var p Project
	err := s.Scan(
		&p.ID, &p.Name, &p.Slug, &p.Description,
		&p.Environment, &p.Criticality, &p.InternetFacing, &p.Archived,
		&p.CreatedAt, &p.UpdatedAt,
	)
	return p, err
}

// GetAny returns a project whether or not it is archived.
//
// Get filters archived projects out, which is right for a caller asking "show
// me this project" and wrong for the middleware that resolves one before a
// handler runs. Archiving hid a project so completely that `/unarchive` could
// never find it — a one-way door, found by running it rather than by reading
// it.
//
// Archiving hides from lists; it does not revoke access to what was already
// gathered. The handler decides what an archived project may still be used
// for, which is everything except accepting a new scan.
func (s *Store) GetAny(ctx context.Context, id string) (Project, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+projectColumns+` FROM projects WHERE id = $1`, id)
	project, err := scanProject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("get project: %w", err)
	}
	return project, nil
}

// SetArchived hides a project from lists, or brings it back (ADR 033 §6).
//
// Not a delete, and the distinction is §17's: security-relevant records are
// soft-deleted or archived, never destroyed. Every scan, finding, correlated
// issue and risk score stays exactly where it was, and every query in this
// package already filters `archived_at IS NULL` -- the column has existed since
// migration 0001 and only the write path was ever missing.
//
// The reason it lands now rather than earlier: a hiding operation needs an
// actor with a name, and until identity existed there was none. An archive
// recorded against "the dashboard" tells an investigator that a project
// vanished and not who removed it, which is the shape of problem this whole
// change set exists to fix.
func (s *Store) SetArchived(ctx context.Context, id string, archived bool, actor audit.Actor) (Project, error) {
	action := "project.unarchive"
	if archived {
		action = "project.archive"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Project{}, fmt.Errorf("%s: %w", action, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Read the current state INSIDE the transaction, and without the
	// archived_at filter every other query here applies -- an archived project
	// still has to be findable, or it could never be brought back.
	var wasArchived bool
	err = tx.QueryRow(ctx,
		`SELECT archived_at IS NOT NULL FROM projects WHERE id = $1 FOR UPDATE`, id).Scan(&wasArchived)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("%s: %w", action, err)
	}

	row := tx.QueryRow(ctx, `
		UPDATE projects
		   SET archived_at = CASE WHEN $2 THEN now() ELSE NULL END
		 WHERE id = $1
		 RETURNING `+projectColumns, id, archived)
	project, err := scanProject(row)
	if err != nil {
		return Project{}, fmt.Errorf("%s: %w", action, err)
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		Actor:        actor,
		Action:       action,
		ResourceType: "project",
		ResourceID:   id,
		ProjectID:    id,
		Before:       map[string]any{"archived": wasArchived},
		After:        map[string]any{"archived": archived},
	}); err != nil {
		return Project{}, fmt.Errorf("%s: %w", action, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Project{}, fmt.Errorf("%s: %w", action, err)
	}
	return project, nil
}
