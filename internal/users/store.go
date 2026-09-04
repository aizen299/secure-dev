package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/auth"
)

// uniqueViolation is the PostgreSQL SQLSTATE for a unique constraint breach.
const uniqueViolation = "23505"

// userColumns is every column that may travel.
//
// Written out rather than `SELECT *`, and password_hash is deliberately absent:
// a read path that never selects the hash cannot accidentally return it. The
// one place that needs it asks for it by name.
const userColumns = `id, email, display_name, role::text, disabled_at, last_login_at, created_at, updated_at`

// Store persists users and their project membership.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Create adds a user, hashing the password on the way in.
//
// The plaintext never reaches this type's caller and never reaches the
// database: it is hashed here, and the NewUser value goes out of scope with the
// function. Audited in the same transaction as the insert, so a created account
// and the record of its creation cannot disagree (ADR 022).
func (s *Store) Create(ctx context.Context, input NewUser, actor audit.Actor) (User, error) {
	if err := input.Validate(); err != nil {
		return User{}, err
	}

	hash, err := HashPassword(input.Password)
	if err != nil {
		return User{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var user User
	var role string
	var disabledAt, lastLogin *time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, display_name, role)
		VALUES ($1, $2, $3, $4::user_role)
		RETURNING `+userColumns,
		input.Email, hash, input.DisplayName, string(input.Role),
	).Scan(&user.ID, &user.Email, &user.DisplayName, &role,
		&disabledAt, &lastLogin, &user.CreatedAt, &user.UpdatedAt)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return User{}, ErrEmailTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	user.Role = Role(role)
	user.Disabled = disabledAt != nil
	if lastLogin != nil {
		user.LastLoginAt = *lastLogin
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		Actor:        actor,
		Action:       "user.create",
		ResourceType: "user",
		ResourceID:   user.ID,
		// The email and the role, never the password and never a hash. An
		// audit record is read by people who must not learn a credential from
		// it (§15.3).
		After: map[string]any{"email": user.Email, "role": string(user.Role)},
	}); err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

// Authenticate verifies an email and password, and returns the user.
//
// Returns ErrNotFound for an unknown email, a wrong password, AND a disabled
// account. One error for three causes, deliberately: distinguishing them tells
// an attacker which addresses are registered, which is an enumeration oracle on
// the one endpoint that is reachable without credentials.
//
// The work is done in every case. An unknown email still runs a verification
// against a decoy hash, so the response time does not separate "no such user"
// from "wrong password" -- without that, the timing says what the error refuses
// to.
func (s *Store) Authenticate(ctx context.Context, email, password string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	var (
		user       User
		role       string
		hash       string
		disabledAt *time.Time
		lastLogin  *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT `+userColumns+`, password_hash
		  FROM users
		 WHERE lower(email) = $1`, email,
	).Scan(&user.ID, &user.Email, &user.DisplayName, &role,
		&disabledAt, &lastLogin, &user.CreatedAt, &user.UpdatedAt, &hash)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Verify against a decoy so an unknown address costs the same as a
		// known one. The result is discarded; only the time it took matters.
		_, _ = VerifyPassword(password, decoyHash)
		return User{}, ErrNotFound
	case err != nil:
		return User{}, fmt.Errorf("authenticate: %w", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		// A hash this package cannot read is an operator's problem, not the
		// person's. Surfaced as an error so it reaches the logs, and the caller
		// must still answer the request as a plain failure.
		return User{}, fmt.Errorf("authenticate %s: %w", user.ID, err)
	}
	if !ok || disabledAt != nil {
		return User{}, ErrNotFound
	}

	user.Role = Role(role)
	user.Disabled = false
	if lastLogin != nil {
		user.LastLoginAt = *lastLogin
	}
	return user, nil
}

// decoyHash is a real Argon2id hash of a value nobody knows.
//
// Its only purpose is to be verified against when no user matched, so the cost
// of a failed lookup matches the cost of a failed password. Generated at
// startup rather than hardcoded: a constant in the source would be a hash an
// attacker could recognise, and recognising it is the same signal as the timing
// it exists to hide.
var decoyHash = mustDecoy()

func mustDecoy() string {
	h, err := HashPassword("decoy-value-nobody-signs-in-with")
	if err != nil {
		panic("users: building the decoy hash: " + err.Error())
	}
	return h
}

// RecordLogin stamps a successful sign-in.
//
// Best-effort and separate from Authenticate: a failure to record the time must
// not fail the sign-in, because the timestamp is observability and the sign-in
// is the security decision.
func (s *Store) RecordLogin(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("record login: %w", err)
	}
	return nil
}

// ByID returns one user.
func (s *Store) ByID(ctx context.Context, id string) (User, error) {
	var user User
	var role string
	var disabledAt, lastLogin *time.Time

	err := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id,
	).Scan(&user.ID, &user.Email, &user.DisplayName, &role,
		&disabledAt, &lastLogin, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user: %w", err)
	}

	user.Role = Role(role)
	user.Disabled = disabledAt != nil
	if lastLogin != nil {
		user.LastLoginAt = *lastLogin
	}
	return user, nil
}

// Count returns how many users exist.
//
// For the bootstrap command, which refuses to create a second admin
// unattended: the first account is a chicken-and-egg exception, and every one
// after it goes through the audited API.
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// ScopeOf returns the projects a user reaches (ADR 033).
//
// An admin gets the global scope from their ROLE rather than from rows, because
// enumerating every project into project_members would mean a project created
// later silently failing to appear for them.
//
// Everyone else gets exactly their memberships, and a user with none gets the
// zero Scope -- which reaches nothing. That is the correct answer for somebody
// who has been granted nothing, and it is what auth.Scope's zero value is for.
func (s *Store) ScopeOf(ctx context.Context, user User) (auth.Scope, error) {
	if user.Role == RoleAdmin {
		return auth.GlobalScope(), nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT p.slug
		  FROM project_members m
		  JOIN projects p ON p.id = m.project_id
		 WHERE m.user_id = $1`, user.ID)
	if err != nil {
		return auth.Scope{}, fmt.Errorf("user scope: %w", err)
	}
	defer rows.Close()

	var slugs []string
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return auth.Scope{}, fmt.Errorf("user scope: %w", err)
		}
		slugs = append(slugs, slug)
	}
	if err := rows.Err(); err != nil {
		return auth.Scope{}, fmt.Errorf("user scope: %w", err)
	}
	return auth.ScopeTo(slugs...), nil
}
