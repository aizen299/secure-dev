package normalization

import (
	"fmt"
	"strings"
)

// FixState says whether a fix exists, which is a different question from what
// the fix is.
//
// Four values rather than a boolean, because "there is no fix yet", "there will
// never be a fix", and "nobody told us" are three different facts that lead to
// three different decisions. Collapsing them is how a platform ends up telling
// someone to upgrade to a version that does not exist.
type FixState string

const (
	// FixStateUnknown is the zero value: no scanner reported a fix state. It is
	// never a synonym for "no fix exists" -- the same rule ADR 018 applies to
	// EPSS, applied to the field §11 calls authoritative.
	FixStateUnknown FixState = ""
	// FixStateFixed means a version exists that resolves this.
	FixStateFixed FixState = "fixed"
	// FixStateNotFixed means no fix is available yet. A fix may still come.
	FixStateNotFixed FixState = "not-fixed"
	// FixStateWontFix means the maintainer has declined to fix it. No upgrade
	// will ever resolve this finding, so remediation must not suggest one.
	FixStateWontFix FixState = "wont-fix"
)

// Valid reports whether s is a known fix state.
func (s FixState) Valid() bool {
	switch s {
	case FixStateUnknown, FixStateFixed, FixStateNotFixed, FixStateWontFix:
		return true
	default:
		return false
	}
}

// MapFixState converts a scanner's fix state onto the SecureOps scale.
//
// Unrecognised input becomes Unknown rather than an error, for the same reason
// MapSeverity refuses to guess: a scanner adding a state is not a reason to
// discard its findings, and Unknown is visible in a way a wrong guess is not.
func MapFixState(raw string) FixState {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "fixed":
		return FixStateFixed
	case "not-fixed", "not_fixed":
		return FixStateNotFixed
	case "wont-fix", "wont_fix", "will-not-fix":
		return FixStateWontFix
	default:
		return FixStateUnknown
	}
}

// Fix is the authoritative account of what to do about a finding (§11).
//
// Every field comes from a scanner or a vendor advisory. Nothing here is
// inferred: §11 makes this data the source of truth precisely because it is not
// SecureOps' opinion, and §25.6 forbids presenting a generated fix as verified.
type Fix struct {
	State FixState
	// FixedVersions are the versions reported to resolve this, verbatim and
	// unordered. SecureOps does not choose between them -- see
	// docs/architecture/remediation.md, "Why not a single upgrade target".
	FixedVersions []string
	// References are advisory or documentation URLs the scanner supplied.
	References []string
}

// Available reports whether an upgrade target is actually known.
//
// Both conditions are required. A `fixed` state with no versions is a scanner
// asserting a fix it did not name, which cannot be acted on, and treating it as
// actionable would produce an upgrade action with nothing to upgrade to.
func (f Fix) Available() bool {
	return f.State == FixStateFixed && len(f.FixedVersions) > 0
}

// Validate checks a fix is internally consistent.
func (f Fix) Validate() error {
	if !f.State.Valid() {
		return fmt.Errorf("%w: unknown fix state %q", ErrInvalidFinding, f.State)
	}
	for _, v := range f.FixedVersions {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: fix carries a blank version", ErrInvalidFinding)
		}
	}
	// Versions on a state that says there is no fix is a contradiction, and one
	// that would surface as an upgrade suggestion for something unfixable.
	if len(f.FixedVersions) > 0 && (f.State == FixStateWontFix || f.State == FixStateNotFixed) {
		return fmt.Errorf("%w: fix state %q carries %d fixed versions",
			ErrInvalidFinding, f.State, len(f.FixedVersions))
	}
	for _, r := range f.References {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("%w: fix carries a blank reference", ErrInvalidFinding)
		}
	}
	return nil
}
