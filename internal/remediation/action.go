package remediation

import (
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Kind is what a person actually does.
//
// Derived from a finding's category and its fix state, never from the scanner
// that reported it. §7.2 and §25.3 forbid branching on a scanner's name outside
// its adapter, and this is the last engine that could have leaked it: two
// scanners reporting the same vulnerable package must produce the same action.
type Kind string

const (
	// KindUpgrade is the only kind that names a version, and it is raised only
	// when a vendor actually supplied one.
	KindUpgrade Kind = "upgrade"
	// KindNoFixAvailable is a first-class action, not an omission. "There is
	// no upgrade for this, mitigate or accept it" is a decision somebody has
	// to make, and hiding those findings would drop exactly the ones most
	// likely to need a compensating control.
	KindNoFixAvailable Kind = "no_fix_available"
	// gosec reads the name and the literal together and sees a hardcoded
	// credential. It is an action kind. Suppressed at this line only:
	// G101 stays active everywhere else, because finding real hardcoded
	// credentials is what this product does, and disabling the rule
	// repo-wide to get a green build is what §15.12 forbids.
	KindRotateCredential Kind = "rotate_credential" // #nosec G101 -- an action kind, not a credential
	KindReconfigure      Kind = "reconfigure"
	KindChangeCode       Kind = "change_code"
	KindReviewLicense    Kind = "review_license"
)

// Source says where a statement came from (§11).
//
// On each statement rather than on the action, because one action mixes vendor
// facts with SecureOps' own derivation and a reader has to be able to tell
// which is which.
type Source string

const (
	// SourceVendor is an advisory or vendor claim -- a fixed version, a
	// published resolution. §11 makes this authoritative.
	SourceVendor Source = "vendor"
	// SourceScanner is the scanner speaking without vendor backing.
	SourceScanner Source = "scanner"
	// SourceDerived is SecureOps computing deterministically from the above.
	// Deterministic rules are labelled this, never "AI" (§25.6).
	SourceDerived Source = "derived"
	// SourceAIExplanation is declared and never produced.
	//
	// §11 requires AI-derived content to be structurally distinguishable from
	// verified data. The value exists so that such content would be visible if
	// it were ever added, and so that its absence is testable. Nothing in
	// SecureOps generates it: §25.15 forbids treating Claude Code or MCP as a
	// runtime dependency, and no model integration exists.
	SourceAIExplanation Source = "ai_explanation"
)

// Statement is one claim in an action, with its provenance.
type Statement struct {
	Source Source
	Text   string
}

// Member is one finding an action would resolve.
type Member struct {
	Fingerprint string
	Scanner     string
	Severity    normalization.Severity
	Title       string
	// Risk is the finding's own score, kept so a reader can see which member
	// dominates an action without recomputing it.
	Risk float64
}

// Action is one distinct piece of work, and every finding it would close.
//
// One action may resolve findings from several scanners: that consolidation is
// §11's requirement and the fragmentation §2 says the product exists to remove.
type Action struct {
	Kind Kind
	// Key is the action's stable identity, derived from what is being acted on
	// rather than from any finding's id.
	Key string
	// Component is what the work is done to -- a package, a file, a location.
	// §11 requires every recommendation to identify it.
	Component string

	// FixedVersions are every version the members' vendors reported as
	// fixing them, deduplicated. SecureOps does not choose between them: see
	// docs/architecture/remediation.md.
	FixedVersions []string
	References    []string

	// Statements are what to do and why, each carrying its source.
	Statements []Statement
	Members    []Member

	// RiskRemoved is how far the project score would fall if this action were
	// taken -- the ranking signal, computed by running the Phase 6 engine
	// without this action's members (ADR 020 §3).
	RiskRemoved float64
	// ScoreAfter is the project score that would remain.
	ScoreAfter float64
}

// kindFor derives the action kind from a finding's category and fix state.
//
// Category, never scanner. The mapping is total: an unrecognised category
// yields KindChangeCode rather than dropping the finding, because a finding
// nobody can act on is still a finding somebody must see (§8).
func kindFor(f normalization.Finding) Kind {
	switch f.Category {
	case scanners.CategoryDependency, scanners.CategoryContainer:
		if f.Fix.Available() {
			return KindUpgrade
		}
		// Covers wont-fix, not-fixed, and unknown alike. All three mean "no
		// upgrade target is known", which is what the action says; the
		// distinction between them is carried in the statements rather than
		// flattened into a claim that no fix exists.
		return KindNoFixAvailable
	case scanners.CategorySecrets:
		return KindRotateCredential
	case scanners.CategoryIaC:
		return KindReconfigure
	case scanners.CategoryLicense:
		return KindReviewLicense
	default:
		return KindChangeCode
	}
}
