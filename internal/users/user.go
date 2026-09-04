// Package users holds people, their roles, and the projects they reach.
//
// This is what ADR 006 called Phase 11's replacement for interim bearer tokens,
// and what ADR 033 designed. A credential already carries a scope (change A);
// this carries a person, which is the half that lets the audit trail answer
// "who" rather than "which token".
//
// The distinction that governs the package: a `service` role exists for tokens
// and cannot exist here. A CI credential is not a junior person, and modelling
// it as one would put a password on something that has none.
package users

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound reports that no such user exists.
var ErrNotFound = errors.New("user not found")

// ErrEmailTaken reports a collision on the case-insensitive email index.
var ErrEmailTaken = errors.New("email is already registered")

// ErrInvalidUser reports input that cannot become a user.
var ErrInvalidUser = errors.New("invalid user")

// ErrUnknownProject reports a membership change naming a project that is not
// there -- a malformed id, or a well-formed one for a project that does not
// exist.
//
// Its own sentinel rather than ErrInvalidUser, because the message reaches an
// administrator: "invalid user: no project with id ..." blames the person being
// edited for a mistake about a project, and the first three words are the ones
// somebody reads.
var ErrUnknownProject = errors.New("unknown project")

// Role is what a person may do (ADR 033).
//
// Three, not §15.5's four. Developer and Security Engineer differ in which
// projects they can see, and membership expresses that -- encoding it twice
// would let the two disagree about the same person.
type Role string

const (
	// RoleViewer may read what they are a member of.
	RoleViewer Role = "viewer"
	// RoleEngineer may additionally triage findings, edit a policy, and submit
	// scans for the projects they are a member of.
	RoleEngineer Role = "engineer"
	// RoleAdmin manages users, roles and membership, and reaches every
	// project.
	//
	// Global reach is a property of this role rather than rows in
	// project_members, deliberately: enumerating every project for an admin
	// would mean a project created later silently failing to appear.
	RoleAdmin Role = "admin"
)

// Roles lists every valid role.
func Roles() []Role { return []Role{RoleViewer, RoleEngineer, RoleAdmin} }

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	for _, known := range Roles() {
		if r == known {
			return true
		}
	}
	return false
}

// ParseRole reads a role from configuration or a request.
//
// Unrecognised input is not a role and the caller must reject it. Defaulting an
// unknown value -- to viewer or anything else -- would mean a typo silently
// changing what somebody can do, which is the same refusal auth.ParseRole makes
// for credentials.
func ParseRole(raw string) (Role, bool) {
	r := Role(strings.ToLower(strings.TrimSpace(raw)))
	return r, r.Valid()
}

// MaxEmailLength bounds the address, so a hostile value cannot become an
// unbounded insert.
const MaxEmailLength = 254

// MaxDisplayNameLength bounds the name shown in an audit trail.
const MaxDisplayNameLength = 128

// User is a person.
//
// The password hash is deliberately NOT a field. Nothing that reads a user
// needs it, and a struct that carries it will eventually be serialised into a
// response by someone who did not know it was there. Verification takes the
// hash directly from the store and never puts it in a value that travels.
type User struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        Role      `json:"role"`
	Disabled    bool      `json:"disabled"`
	LastLoginAt time.Time `json:"last_login_at,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewUser is the validated input for creating one.
type NewUser struct {
	Email       string
	Password    string
	DisplayName string
	Role        Role
}

// Validate normalises and checks the input.
//
// Email is lowercased here as well as in the database's unique index, so the
// value stored matches the value compared. Two places, one rule -- but the
// index is the one that actually enforces it, because two concurrent inserts
// cannot both check first.
func (n *NewUser) Validate() error {
	n.Email = strings.ToLower(strings.TrimSpace(n.Email))
	n.DisplayName = strings.TrimSpace(n.DisplayName)

	switch {
	case n.Email == "":
		return fmt.Errorf("%w: email is required", ErrInvalidUser)
	case len(n.Email) > MaxEmailLength:
		return fmt.Errorf("%w: email must be at most %d characters", ErrInvalidUser, MaxEmailLength)
	case !strings.Contains(n.Email[1:], "@"):
		// Deliberately loose, matching the database's own check. Email
		// validation by regex is a well-known way to reject valid addresses;
		// whether a person can be reached is not something this can decide.
		return fmt.Errorf("%w: email must contain @", ErrInvalidUser)
	case len(n.DisplayName) > MaxDisplayNameLength:
		return fmt.Errorf("%w: display name must be at most %d characters",
			ErrInvalidUser, MaxDisplayNameLength)
	}

	if n.Role == "" {
		// The safe default, and the only default. An unspecified role must not
		// become admin, and refusing outright would make creating an ordinary
		// account require a field nobody thinks about.
		n.Role = RoleViewer
	}
	if !n.Role.Valid() {
		return fmt.Errorf("%w: role %q must be one of viewer, engineer, admin", ErrInvalidUser, n.Role)
	}
	if len(n.Password) < MinPasswordLength {
		return fmt.Errorf("%w: password must be at least %d characters", ErrInvalidUser, MinPasswordLength)
	}
	return nil
}

// CanTriage reports whether the role may change a finding's status or edit a
// policy. Reading is everyone; writing is engineer and above.
func (r Role) CanTriage() bool { return r == RoleEngineer || r == RoleAdmin }

// CanAdminister reports whether the role may manage users and membership.
func (r Role) CanAdminister() bool { return r == RoleAdmin }
