package auth

import (
	"fmt"
	"sort"
	"strings"
)

// Scope is the set of projects a credential may reach (ADR 033).
//
// The zero value reaches nothing. That is the whole design: a store method
// handed a Scope nobody set returns no rows, rather than every row. The
// permissive default is the failure this type exists to make impossible, so it
// is impossible by construction rather than by discipline.
//
// Global is a value somebody assigned, never the absence of one. `*` in
// configuration is a decision with a name on it; an empty field is an accident,
// and the two must not produce the same behaviour.
type Scope struct {
	global bool
	// projects holds slugs, sorted and deduplicated. Slugs rather than ids
	// because configuration is written by a person, and a person cannot write
	// a UUID they have not looked up.
	projects []string
}

// GlobalScope reaches every project.
//
// Used by credentials that genuinely need the whole estate: the dashboard
// renders a fleet view, and an operator's own credential is not usefully
// scoped. It is deliberately verbose at every call site.
func GlobalScope() Scope { return Scope{global: true} }

// ScopeTo builds a scope over the named project slugs.
//
// Empty input yields the zero value, which reaches nothing. A caller that
// wanted "everything" has to say GlobalScope.
func ScopeTo(slugs ...string) Scope {
	seen := make(map[string]struct{}, len(slugs))
	out := make([]string, 0, len(slugs))
	for _, s := range slugs {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return Scope{projects: out}
}

// ParseScope reads the scope field of a token specification.
//
// `*` is global. Anything else is a comma-separated list of project slugs. An
// empty field is an error rather than a default, for the reason on Scope: the
// two possible defaults are "everything", which is the permissive behaviour
// this replaces, and "nothing", which would break every deployment in a way
// that looks like the API being broken.
func ParseScope(raw string) (Scope, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Scope{}, fmt.Errorf("scope is empty; use * for every project, or a comma-separated list of project slugs")
	}
	if trimmed == "*" {
		return GlobalScope(), nil
	}
	scope := ScopeTo(strings.Split(trimmed, ",")...)
	if len(scope.projects) == 0 {
		return Scope{}, fmt.Errorf("scope %q names no project", raw)
	}
	return scope, nil
}

// IsGlobal reports whether this scope reaches every project.
func (s Scope) IsGlobal() bool { return s.global }

// IsEmpty reports whether this scope reaches nothing.
//
// A distinct question from IsGlobal, and worth asking separately: an empty
// scope is almost always a construction bug, and a caller that wants to refuse
// one should be able to say so.
func (s Scope) IsEmpty() bool { return !s.global && len(s.projects) == 0 }

// Slugs returns the project slugs in scope, sorted. Empty for a global scope,
// which reaches every project rather than a listed set -- callers must check
// IsGlobal rather than treating an empty list as "none".
func (s Scope) Slugs() []string {
	out := make([]string, len(s.projects))
	copy(out, s.projects)
	return out
}

// Allows reports whether a project slug is in scope.
func (s Scope) Allows(slug string) bool {
	if s.global {
		return true
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	for _, p := range s.projects {
		if p == slug {
			return true
		}
	}
	return false
}

// String renders the scope the way it is configured, for logs and errors.
//
// Never used to reconstruct a Scope: this is for a human reading a startup
// line, and a round trip through text would be a second parser to keep in step.
func (s Scope) String() string {
	switch {
	case s.global:
		return "*"
	case len(s.projects) == 0:
		return "(none)"
	default:
		return strings.Join(s.projects, ",")
	}
}
