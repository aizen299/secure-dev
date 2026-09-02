package auth

import "strings"

// Role is what a credential is permitted to do (ADR 023).
//
// Interim, and named so it cannot be mistaken for §15.5's model. These are
// route-level checks against a static token, not identities with project
// scoping: an admin token can edit any project's policy, because there is no
// tenancy for it to be scoped to. Phase 11 replaces this with real roles and a
// real identity, and using different names now keeps that replacement visible
// rather than a silent redefinition.
type Role string

const (
	// RoleViewer reads. It performs no mutation at all.
	RoleViewer Role = "viewer"
	// RoleService submits scans and creates projects. This is what CI holds,
	// and the reason this ADR exists: it is the most widely distributed
	// credential in the system, and it must not be able to disable the gate
	// that judges it.
	RoleService Role = "service"
	// RoleAdmin additionally changes security-relevant configuration --
	// today, security policy.
	RoleAdmin Role = "admin"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleService, RoleAdmin:
		return true
	default:
		return false
	}
}

// rank orders roles so a requirement can be expressed as a minimum.
//
// An unknown role ranks below viewer rather than panicking, so a value that
// somehow escaped validation grants nothing. It is the safe direction to be
// wrong in.
func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleService:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// Allows reports whether this role satisfies a required minimum.
func (r Role) Allows(required Role) bool {
	return r.Valid() && r.rank() >= required.rank()
}

// ParseRole converts configured text into a Role.
//
// Unrecognised input is not a role, and the caller must reject it. Defaulting
// an unknown value to anything -- viewer included -- would mean a typo in
// configuration silently changes what a credential can do.
func ParseRole(raw string) (Role, bool) {
	r := Role(strings.ToLower(strings.TrimSpace(raw)))
	return r, r.Valid()
}
