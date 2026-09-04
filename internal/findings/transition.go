package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aizen299/secure-dev/internal/audit"
	"github.com/aizen299/secure-dev/internal/normalization"
)

// ErrTransitionNotAllowed reports a status change a person may not make.
var ErrTransitionNotAllowed = errors.New("transition not allowed")

// ErrNotFound reports that no such finding exists.
var ErrNotFound = errors.New("finding not found")

// ErrInvalidTransition reports a malformed transition request.
var ErrInvalidTransition = errors.New("invalid transition")

// Human reasons for a status change (ADR 024 §3).
//
// A fixed vocabulary rather than free text, so "everything dismissed as an
// accepted risk this quarter" is answerable. The argument behind the judgement
// goes in the note.
const (
	ReasonFalsePositive = "false_positive"
	ReasonAcceptedRisk  = "accepted_risk"
	ReasonTriaged       = "triaged"
	ReasonWorkStarted   = "work_started"
	ReasonReinstated    = "reinstated"
)

// humanReasons is the vocabulary a person may use.
func humanReasons() map[string]struct{} {
	return map[string]struct{}{
		ReasonFalsePositive: {},
		ReasonAcceptedRisk:  {},
		ReasonTriaged:       {},
		ReasonWorkStarted:   {},
		ReasonReinstated:    {},
	}
}

// maxNoteLength mirrors the schema. Bounded because it is client-supplied
// (§15.8), and checked here so an oversized note is a 400 rather than a
// constraint violation surfacing as a 500.
const maxNoteLength = 2000

// humanSettable is the set of states a person may move a finding into
// (ADR 024 §1 and §2).
//
// `resolved` and `reopened` are deliberately absent. They mean "a scanner
// stopped reporting this" and "a scanner saw it again" -- observations, not
// judgements. Allowing a person to write them would make a hand-typed
// assurance indistinguishable from a verified one, which is the false comfort
// this platform exists to remove.
func humanSettable(s normalization.Status) bool {
	switch s {
	case normalization.StatusAcknowledged, normalization.StatusInProgress,
		normalization.StatusFalsePositive, normalization.StatusIgnored,
		normalization.StatusOpen:
		return true
	default:
		return false
	}
}

// TransitionRequest is one human status change.
type TransitionRequest struct {
	To     normalization.Status
	Reason string
	// Note is the argument behind the judgement. Optional: `accepted_risk`
	// alone does not tell the next reader what was accepted or on whose
	// authority.
	Note string
}

// Validate reports whether this is a transition a person may make.
//
// Exported so the API can refuse an impossible request without a database
// round trip, and so tests exercise the same rules the store enforces rather
// than a second copy that can drift from them.
func (r TransitionRequest) Validate() error {
	if !r.To.Valid() {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidTransition, r.To)
	}
	if !humanSettable(r.To) {
		// Named explicitly rather than reported as a generic refusal: a caller
		// trying to set `resolved` is making a reasonable-seeming request and
		// deserves to know why it is refused.
		return fmt.Errorf(
			"%w: %q is set by scans, not by people -- it means a scanner stopped reporting the finding; use `ignored` with a note to record a fix a scanner cannot see",
			ErrTransitionNotAllowed, r.To)
	}
	if _, ok := humanReasons()[r.Reason]; !ok {
		return fmt.Errorf("%w: reason %q is not one of false_positive, accepted_risk, triaged, work_started, reinstated",
			ErrInvalidTransition, r.Reason)
	}
	if len(r.Note) > maxNoteLength {
		return fmt.Errorf("%w: note is %d characters, the limit is %d",
			ErrInvalidTransition, len(r.Note), maxNoteLength)
	}
	return nil
}

// TransitionRecord is a status change as stored.
type TransitionRecord struct {
	FindingID string
	From      normalization.Status
	To        normalization.Status
	Actor     string
	Reason    string
	Note      string
	ChangedAt time.Time
}

// Transition changes a finding's status on a person's authority (ADR 024).
//
// The history row, the finding update, and the audit record are written in one
// transaction. A dismissal is security-sensitive under §15.6: it lowers the
// risk score, removes remediation work, and can turn a failing gate green, so a
// record that could be lost while the change survived would leave a gap looking
// exactly like nobody having acted.
func (s *Store) Transition(
	ctx context.Context, findingID string, req TransitionRequest, actor audit.Actor,
) (TransitionRecord, error) {
	if err := req.Validate(); err != nil {
		return TransitionRecord{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TransitionRecord{}, fmt.Errorf("begin transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Locked for the duration, so two concurrent dismissals cannot each read
	// the same previous state and record contradictory histories.
	var (
		from      string
		projectID string
	)
	err = tx.QueryRow(ctx, `
		SELECT status::text, project_id FROM findings WHERE id = $1 FOR UPDATE`,
		findingID).Scan(&from, &projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TransitionRecord{}, ErrNotFound
		}
		return TransitionRecord{}, fmt.Errorf("read finding for transition: %w", err)
	}

	if normalization.Status(from) == req.To {
		// Not an error worth failing on, but not a transition either: the
		// schema refuses a self-transition, and recording one would put a
		// second identical row in the history for no change.
		return TransitionRecord{}, fmt.Errorf("%w: the finding is already %q", ErrInvalidTransition, req.To)
	}

	at := time.Now().UTC()
	if _, err := tx.Exec(ctx,
		`UPDATE findings SET status = $2 WHERE id = $1`, findingID, string(req.To)); err != nil {
		return TransitionRecord{}, fmt.Errorf("update finding status: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_status_history
		    (finding_id, from_status, to_status, actor, reason, note, changed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		findingID, from, string(req.To), actor.Label, req.Reason,
		nullIfEmpty(strings.TrimSpace(req.Note)), at); err != nil {
		return TransitionRecord{}, fmt.Errorf("record transition: %w", err)
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		Actor:        actor,
		Action:       "finding.status_change",
		ResourceType: "finding",
		ResourceID:   findingID,
		ProjectID:    projectID,
		Before:       map[string]any{"status": from},
		After:        map[string]any{"status": string(req.To), "reason": req.Reason, "note": req.Note},
		OccurredAt:   at,
	}); err != nil {
		return TransitionRecord{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return TransitionRecord{}, fmt.Errorf("commit transition: %w", err)
	}

	return TransitionRecord{
		FindingID: findingID,
		From:      normalization.Status(from),
		To:        req.To,
		Actor:     actor.Label,
		Reason:    req.Reason,
		Note:      req.Note,
		ChangedAt: at,
	}, nil
}

// History reads a finding's status changes, newest first.
//
// §17 requires every transition to record who, when, why, and both states.
// Storing that and never serving it would satisfy the letter and none of the
// point: the history exists to be read when somebody asks why a finding is in
// the state it is in.
// ProjectOf returns the project a finding belongs to.
//
// Exists so an endpoint addressed by finding id can be scope-checked (ADR 033):
// `/findings/{id}/history` and `/findings/{id}/status` have no project in the
// URL, so there is nothing to check until the owner is known.
//
// Returns ErrNotFound for a finding that does not exist, which the caller must
// answer identically to one it may not see -- a distinct answer would confirm
// the id is real (T-38).
func (s *Store) ProjectOf(ctx context.Context, findingID string) (string, error) {
	var projectID string
	err := s.pool.QueryRow(ctx,
		`SELECT project_id FROM findings WHERE id = $1`, findingID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("finding project: %w", err)
	}
	return projectID, nil
}

func (s *Store) History(ctx context.Context, findingID string) ([]TransitionRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT from_status::text, to_status::text, actor, reason, note, changed_at
		  FROM finding_status_history
		 WHERE finding_id = $1
		 ORDER BY changed_at DESC, id DESC`, findingID)
	if err != nil {
		return nil, fmt.Errorf("read finding history: %w", err)
	}
	defer rows.Close()

	var out []TransitionRecord
	for rows.Next() {
		var (
			rec        TransitionRecord
			from, note *string
			to         string
		)
		if err := rows.Scan(&from, &to, &rec.Actor, &rec.Reason, &note, &rec.ChangedAt); err != nil {
			return nil, fmt.Errorf("scan history row: %w", err)
		}
		rec.FindingID = findingID
		rec.To = normalization.Status(to)
		if from != nil {
			rec.From = normalization.Status(*from)
		}
		if note != nil {
			rec.Note = *note
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan finding history: %w", err)
	}
	return out, nil
}
