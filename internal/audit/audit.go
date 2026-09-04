// Package audit records security-sensitive changes durably (§15.6).
//
// The one property that makes this worth having: the record is written in the
// same transaction as the change it describes. An audit row written after a
// successful commit can be lost -- the process dies, the write fails, the
// connection drops -- and the resulting gap is indistinguishable from a change
// nobody made. Atomic, either the change happened and the log says so, or
// neither did.
//
// See docs/adr/022-durable-audit-log.md.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrInvalidEntry reports an audit record that would be useless if stored.
var ErrInvalidEntry = errors.New("invalid audit entry")

// ActorKind describes what sort of identity an entry names.
//
// Explicit because SecureOps cannot currently name a person. The interim
// bearer token labels a client (ADR 006), and storing that label in a field
// called "user" would claim an attribution the authentication model does not
// support.
type ActorKind string

const (
	// ActorTokenLabel is an interim bearer token's label. It identifies a
	// credential, not a human.
	ActorTokenLabel ActorKind = "token_label"
	// ActorSystem is SecureOps acting on its own behalf, such as a worker
	// recording an automatic transition.
	ActorSystem ActorKind = "system"
	// ActorUser is a person, identified by their user id (ADR 033).
	//
	// The kind ADR 006, ADR 022, ADR 024 and ADR 029 each said was missing.
	// Until it existed, "who dismissed this finding?" was answerable only to
	// the granularity of a credential label -- and an action taken through the
	// dashboard was recorded against the dashboard.
	//
	// Records written before this stay 'token_label'. Nothing is backfilled:
	// an audit log that invents an attribution it never had is worse than one
	// that admits its limit.
	ActorUser ActorKind = "user"
)

// Actor is who did something, as precisely as the system can honestly say.
type Actor struct {
	Kind  ActorKind
	Label string
}

// TokenActor builds an actor from an authenticated token label.
func TokenActor(label string) Actor {
	if strings.TrimSpace(label) == "" {
		label = "unknown"
	}
	return Actor{Kind: ActorTokenLabel, Label: label}
}

// UserActor builds an actor from an authenticated person (ADR 033).
//
// The label is the id, not the email. An audit record outlives the account it
// names -- a person can be renamed, and a person can leave -- and a record that
// points at a mutable value is a record whose subject can be changed after the
// fact. The id is stable and resolvable; the email is display, and belongs in
// whatever renders the trail rather than in the trail itself.
//
// An empty id is refused rather than defaulted, because "user" with no user is
// a claim of attribution that is not true.
func UserActor(userID string) (Actor, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return Actor{}, fmt.Errorf("%w: a user actor needs a user id", ErrInvalidEntry)
	}
	return Actor{Kind: ActorUser, Label: userID}, nil
}

// Entry is one recorded change.
type Entry struct {
	Actor        Actor
	Action       string
	ResourceType string
	ResourceID   string
	ProjectID    string
	// Before and After are the values either side of the change. §15.6 asks
	// for both: "what happened" and "what exactly changed" are different
	// questions, and only the second is answerable from a diff.
	Before any
	After  any
	// OccurredAt defaults to now when zero. A parameter rather than a clock
	// read inside the store, so a caller recording several changes in one
	// transaction can stamp them identically.
	OccurredAt time.Time
}

func (e Entry) validate() error {
	if strings.TrimSpace(string(e.Actor.Kind)) == "" || strings.TrimSpace(e.Actor.Label) == "" {
		return fmt.Errorf("%w: an entry with no actor records that something happened but not who did it", ErrInvalidEntry)
	}
	if strings.TrimSpace(e.Action) == "" {
		return fmt.Errorf("%w: action is required", ErrInvalidEntry)
	}
	if strings.TrimSpace(e.ResourceType) == "" {
		return fmt.Errorf("%w: resource type is required", ErrInvalidEntry)
	}
	return nil
}

// Write takes a pgx.Tx and not a broader interface, deliberately.
//
// An earlier version accepted anything with an Exec method, which a connection
// pool also satisfies -- so "pass the transaction, never a bare pool" was a
// rule in a comment that nothing enforced, and the failure it guards against
// only becomes observable when a commit fails, which is exactly when nobody is
// watching. Requiring the transaction type makes a pool a compile error rather
// than a latent gap in the audit trail.

// Write appends one entry using the given querier.
//
// Pass the transaction that is making the change, never a bare pool: an audit
// record that can outlive a rolled-back change, or be lost after a committed
// one, is worse than none because its gaps look like inaction.
func Write(ctx context.Context, tx pgx.Tx, e Entry) error {
	if err := e.validate(); err != nil {
		return err
	}
	at := e.OccurredAt
	if at.IsZero() {
		at = time.Now()
	}

	before, err := encode(e.Before)
	if err != nil {
		return fmt.Errorf("encode before value: %w", err)
	}
	after, err := encode(e.After)
	if err != nil {
		return fmt.Errorf("encode after value: %w", err)
	}

	// The project's slug, resolved here rather than required from callers.
	//
	// project_id lost its foreign key in 0015 (ADR 028), so an id can outlive
	// its project -- and an id alone degrades badly: `project 38150c6b-...`
	// proves something happened and tells an investigation nothing about what.
	//
	// Resolved in the caller's transaction, which matters twice. A project
	// created and audited in one transaction can see its own row. And three of
	// the four call sites hold only an id, so requiring the slug as a
	// parameter would mean the same lookup written three times, each able to
	// drift.
	//
	// A miss is not an error. Auditing an action against a project that no
	// longer exists is a real situation, and refusing to record it would lose
	// the entry rather than the name.
	slug, err := projectSlug(ctx, tx, e.ProjectID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs
		    (occurred_at, actor_kind, actor_label, action, resource_type,
		     resource_id, project_id, project_slug, before_value, after_value)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		at.UTC(), string(e.Actor.Kind), e.Actor.Label, e.Action, e.ResourceType,
		nullIfEmpty(e.ResourceID), nullIfEmpty(e.ProjectID), nullIfEmpty(slug),
		before, after)
	if err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}

// encode renders a value as JSON, or NULL when there was none.
//
// A nil Before is meaningful: it says the resource did not exist, which is what
// distinguishes a creation from an edit.
//
// The reflection is not decoration. A typed nil pointer -- (*Policy)(nil)
// handed to an `any` parameter -- is not equal to nil, and json.Marshal turns
// it into the four bytes `null`, which Postgres stores as JSON null rather than
// SQL NULL. The record would then say a creation had a previous value, which is
// a false audit record: the one thing this table exists to prevent.
func encode(v any) (any, error) {
	if v == nil || isNilPointer(v) {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// isNilPointer reports whether v is a nil pointer, map, or slice wrapped in a
// non-nil interface.
func isNilPointer(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// projectSlug reads a project's slug inside the caller's transaction.
//
// Returns empty when there is no project id, or when no project has that id.
// Both are ordinary: not every audited action concerns a project, and an
// action against a since-deleted one is exactly what ADR 028 made possible.
func projectSlug(ctx context.Context, tx pgx.Tx, projectID string) (string, error) {
	if strings.TrimSpace(projectID) == "" {
		return "", nil
	}
	var slug string
	err := tx.QueryRow(ctx, `SELECT slug FROM projects WHERE id = $1`, projectID).Scan(&slug)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("resolve project slug for audit entry: %w", err)
	}
	return slug, nil
}
