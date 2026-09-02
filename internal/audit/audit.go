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

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs
		    (occurred_at, actor_kind, actor_label, action, resource_type,
		     resource_id, project_id, before_value, after_value)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		at.UTC(), string(e.Actor.Kind), e.Actor.Label, e.Action, e.ResourceType,
		nullIfEmpty(e.ResourceID), nullIfEmpty(e.ProjectID), before, after)
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
