package auth

import (
	"slices"
	"testing"
)

// The zero value must reach nothing.
//
// This is the property the whole type exists for: a Scope nobody set returns no
// rows rather than every row. If this test ever fails, every store method that
// takes a Scope has silently become a full-table read.
func TestTheZeroScopeReachesNothing(t *testing.T) {
	var zero Scope

	if zero.IsGlobal() {
		t.Fatal("the zero scope is global; an unset scope would read every project")
	}
	if !zero.IsEmpty() {
		t.Error("the zero scope is not empty")
	}
	for _, slug := range []string{"anything", "", "*", "some-project"} {
		if zero.Allows(slug) {
			t.Errorf("the zero scope allows %q", slug)
		}
	}
}

func TestGlobalScopeReachesEverything(t *testing.T) {
	g := GlobalScope()

	if !g.IsGlobal() || g.IsEmpty() {
		t.Fatalf("GlobalScope: global=%v empty=%v", g.IsGlobal(), g.IsEmpty())
	}
	for _, slug := range []string{"a", "b", "any-project-at-all"} {
		if !g.Allows(slug) {
			t.Errorf("global scope refuses %q", slug)
		}
	}
}

func TestScopeToAllowsOnlyWhatItNames(t *testing.T) {
	s := ScopeTo("payments-api", "checkout-edge")

	if s.IsGlobal() {
		t.Fatal("a listed scope is global")
	}
	if !s.Allows("payments-api") || !s.Allows("checkout-edge") {
		t.Error("a listed scope refuses a project it names")
	}
	if s.Allows("self-healing-iot") {
		t.Error("a listed scope allows a project it does not name")
	}
}

// Configuration is written by a person, so the comparison is case- and
// whitespace-insensitive. It is not a security-relevant normalisation -- slugs
// are already lowercase everywhere -- but a scope that silently fails to match
// because someone typed a capital is a lockout that looks like a bug.
func TestScopeIgnoresCaseAndSurroundingSpace(t *testing.T) {
	s := ScopeTo("  Payments-API  ")

	if !s.Allows("payments-api") || !s.Allows("  PAYMENTS-API ") {
		t.Errorf("scope %v did not match across case and space", s.Slugs())
	}
}

func TestScopeToDeduplicatesAndSorts(t *testing.T) {
	s := ScopeTo("b", "a", "b", "", "  ", "a")

	if got := s.Slugs(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("Slugs() = %v, want [a b]", got)
	}
}

// Slugs must not hand out the internal slice: a caller that sorted or truncated
// the result would be editing the credential's authorization.
func TestSlugsCannotBeMutatedThroughTheReturnedSlice(t *testing.T) {
	s := ScopeTo("a", "b")
	got := s.Slugs()
	got[0] = "everything"

	if !s.Allows("a") || s.Allows("everything") {
		t.Error("mutating the returned slice changed the scope")
	}
}

func TestParseScope(t *testing.T) {
	global, err := ParseScope("*")
	if err != nil || !global.IsGlobal() {
		t.Errorf("ParseScope(*) = %v, %v; want a global scope", global, err)
	}

	listed, err := ParseScope("payments-api, checkout-edge")
	if err != nil {
		t.Fatalf("ParseScope(list): %v", err)
	}
	if !listed.Allows("checkout-edge") || listed.Allows("other") {
		t.Errorf("ParseScope(list) = %v", listed.Slugs())
	}
}

// An empty scope field must be an error, never a default.
//
// Both possible defaults are wrong. "Everything" is the permissive behaviour
// ADR 033 exists to remove, and it would fail silently -- the deployment would
// keep working and keep T-23 open. "Nothing" would break every deployment in a
// way that reads as the API being broken rather than as configuration needing a
// field.
func TestParseScopeRefusesAnEmptyField(t *testing.T) {
	for _, raw := range []string{"", "   ", ",", " , , "} {
		got, err := ParseScope(raw)
		if err == nil {
			t.Errorf("ParseScope(%q) = %v, want an error: an unspecified scope must not default", raw, got)
		}
	}
}
