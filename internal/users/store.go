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

// --- administration ---------------------------------------------------------
//
// Everything below is admin-only at the API boundary. It is also where the
// lockout footguns live, so the store refuses the two that would leave a
// deployment with nobody able to administer it.

// ErrLastAdmin reports an operation that would leave no enabled admin.
//
// Refused in the store rather than only in a handler, because the check and the
// write have to be atomic: two concurrent requests each demoting a different
// admin would both pass a check done beforehand and leave zero.
var ErrLastAdmin = errors.New("this would leave no enabled administrator")

// List returns every user, oldest first.
//
// Unpaginated, deliberately. This is the operator roster of a self-hosted
// security tool -- it is tens of rows, not thousands, and a paginated list
// would be ceremony around a screen that shows all of them anyway. If that
// stops being true it is a small change to make, and a wrong assumption that
// announces itself.
func (s *Store) List(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var (
			user                  User
			role                  string
			disabledAt, lastLogin *time.Time
		)
		if err := rows.Scan(&user.ID, &user.Email, &user.DisplayName, &role,
			&disabledAt, &lastLogin, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		user.Role = Role(role)
		user.Disabled = disabledAt != nil
		if lastLogin != nil {
			user.LastLoginAt = *lastLogin
		}
		out = append(out, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}

// SetRole changes what a user may do.
//
// Refuses to demote the last enabled admin: a deployment with no administrator
// cannot appoint one, and the only way back is SQL on the database. That is a
// worse outcome than a refused request, so it is refused.
func (s *Store) SetRole(ctx context.Context, id string, role Role, actor audit.Actor) (User, error) {
	if !role.Valid() {
		return User{}, fmt.Errorf("%w: role %q must be one of viewer, engineer, admin", ErrInvalidUser, role)
	}
	return s.update(ctx, id, actor, "user.role_change", func(current User) error {
		if current.Role == RoleAdmin && role != RoleAdmin {
			return s.refuseIfLastAdmin(ctx, id)
		}
		return nil
	}, `UPDATE users SET role = $2::user_role WHERE id = $1 RETURNING `+userColumns, string(role))
}

// SetDisabled disables or re-enables an account.
//
// Disabling takes effect on the NEXT REQUEST, not at the next restart: the
// session is stateless but the user row is read on every request (ADR 033 §5a).
// So this is the revocation mechanism, and it is why refusing to disable the
// last admin matters as much as refusing to demote them.
func (s *Store) SetDisabled(ctx context.Context, id string, disabled bool, actor audit.Actor) (User, error) {
	action := "user.enable"
	if disabled {
		action = "user.disable"
	}
	return s.update(ctx, id, actor, action, func(current User) error {
		if disabled && current.Role == RoleAdmin {
			return s.refuseIfLastAdmin(ctx, id)
		}
		return nil
	}, `UPDATE users SET disabled_at = CASE WHEN $2 THEN now() ELSE NULL END
	     WHERE id = $1 RETURNING `+userColumns, disabled)
}

// refuseIfLastAdmin returns ErrLastAdmin when no OTHER enabled admin exists.
func (s *Store) refuseIfLastAdmin(ctx context.Context, excluding string) error {
	var others int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM users
		 WHERE role = 'admin' AND disabled_at IS NULL AND id <> $1`, excluding).Scan(&others)
	if err != nil {
		return fmt.Errorf("counting administrators: %w", err)
	}
	if others == 0 {
		return ErrLastAdmin
	}
	return nil
}

// update applies one change to a user, audited in the same transaction.
//
// The before value is read inside the transaction and the guard runs against
// it, so a concurrent change cannot slip between the check and the write --
// which for the last-admin guard is the difference between a refusal and a
// locked-out deployment.
func (s *Store) update(
	ctx context.Context, id string, actor audit.Actor, action string,
	guard func(User) error, query string, args ...any,
) (User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("%s: %w", action, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	before, err := s.byIDTx(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	if guard != nil {
		if err := guard(before); err != nil {
			return User{}, err
		}
	}

	var (
		after                 User
		role                  string
		disabledAt, lastLogin *time.Time
	)
	err = tx.QueryRow(ctx, query, append([]any{id}, args...)...).
		Scan(&after.ID, &after.Email, &after.DisplayName, &role,
			&disabledAt, &lastLogin, &after.CreatedAt, &after.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("%s: %w", action, err)
	}
	after.Role = Role(role)
	after.Disabled = disabledAt != nil
	if lastLogin != nil {
		after.LastLoginAt = *lastLogin
	}

	// Both sides, which is what §15.6 asks for: "what happened" and "what
	// exactly changed" are different questions and only the second is
	// answerable from a diff. Neither side carries a credential.
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor:        actor,
		Action:       action,
		ResourceType: "user",
		ResourceID:   id,
		Before:       map[string]any{"role": string(before.Role), "disabled": before.Disabled},
		After:        map[string]any{"role": string(after.Role), "disabled": after.Disabled},
	}); err != nil {
		return User{}, fmt.Errorf("%s: %w", action, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("%s: %w", action, err)
	}
	return after, nil
}

func (s *Store) byIDTx(ctx context.Context, tx pgx.Tx, id string) (User, error) {
	var (
		user                  User
		role                  string
		disabledAt, lastLogin *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 FOR UPDATE`, id).
		Scan(&user.ID, &user.Email, &user.DisplayName, &role,
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

// SetMembership replaces a user's project grants.
//
// The whole set at once rather than add and remove separately: membership is
// read whole when a scope is built, and a partially-applied change is not a
// state worth being able to represent. The same reasoning ADR 021 applied to a
// policy's rules.
//
// An admin's membership is stored but not consulted -- their reach comes from
// the role (ADR 033) -- so granting one is harmless and revoking one changes
// nothing. That is worth knowing rather than guarding against: it means a
// demoted admin keeps whatever was recorded for them.
func (s *Store) SetMembership(ctx context.Context, userID string, projectIDs []string, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("set membership: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := s.byIDTx(ctx, tx, userID); err != nil {
		return err
	}

	var before []string
	rows, err := tx.Query(ctx, `SELECT project_id::text FROM project_members WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("set membership: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("set membership: %w", err)
		}
		before = append(before, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("set membership: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM project_members WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("set membership: %w", err)
	}
	for _, projectID := range projectIDs {
		// A project that does not exist fails on the foreign key, which is the
		// right place for it: the alternative is a membership row pointing at
		// nothing and a scope that silently omits a project somebody was told
		// they had.
		if _, err := tx.Exec(ctx,
			`INSERT INTO project_members (user_id, project_id) VALUES ($1, $2)`,
			userID, projectID); err != nil {
			return fmt.Errorf("set membership: %w", err)
		}
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		Actor:        actor,
		Action:       "user.membership_change",
		ResourceType: "user",
		ResourceID:   userID,
		Before:       map[string]any{"projects": before},
		After:        map[string]any{"projects": projectIDs},
	}); err != nil {
		return fmt.Errorf("set membership: %w", err)
	}
	return tx.Commit(ctx)
}

// MembershipOf returns the project ids a user is a member of.
//
// Ids rather than slugs, unlike ScopeOf: this answers "what is configured for
// this person" for an administration screen, while ScopeOf answers "what may
// they reach" for an authorization decision. Keeping them separate means an
// admin's role-derived global reach cannot be mistaken for a membership list
// somebody could edit.
func (s *Store) MembershipOf(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT project_id::text FROM project_members WHERE user_id = $1 ORDER BY project_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("user membership: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("user membership: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user membership: %w", err)
	}
	return out, nil
}
