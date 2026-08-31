package projects

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
	internet_facing, created_at, updated_at`

// Create inserts a project.
//
// It returns ErrSlugTaken on a slug collision so the API can answer 409 rather
// than surfacing a driver error.
func (s *Store) Create(ctx context.Context, input NewProject) (Project, error) {
	normalized, err := input.Normalize()
	if err != nil {
		return Project{}, err
	}

	row := s.pool.QueryRow(ctx, `
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
func (s *Store) List(ctx context.Context, page Page) ([]Project, bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+projectColumns+`
		  FROM projects
		 WHERE archived_at IS NULL
		 ORDER BY created_at DESC, id DESC
		 LIMIT $1 OFFSET $2`,
		page.Limit+1, page.Offset)
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
		&p.Environment, &p.Criticality, &p.InternetFacing,
		&p.CreatedAt, &p.UpdatedAt,
	)
	return p, err
}
