// Package policies turns a scan's results into a decision (§12).
//
// Four engines produce a picture of a project. This one answers the question
// that picture exists for: may this change ship?
//
// Pure and deterministic like the engines before it -- same inputs, same
// verdict, always. Unlike them its output stops a build, which raises the cost
// of every ambiguity: that is why every rule reports itself whether or not it
// breached, and why a scan that did not complete can never pass.
//
// See docs/architecture/policy.md, ADR 021, and ADR 022.
package policies

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// ErrInvalidPolicy reports a policy that cannot be evaluated meaningfully.
var ErrInvalidPolicy = errors.New("invalid policy")

// Verdict is the gate's answer.
type Verdict string

const (
	VerdictPass Verdict = "pass"
	VerdictWarn Verdict = "warn"
	VerdictFail Verdict = "fail"
)

// rank orders verdicts so the worst wins.
func (v Verdict) rank() int {
	switch v {
	case VerdictFail:
		return 2
	case VerdictWarn:
		return 1
	default:
		return 0
	}
}

// Level is how hard a rule bites when it breaches.
//
// Configured per rule rather than derived from the metric, because "no
// criticals" should block one team's build and merely warn another's. Deriving
// it from the metric would be the hardcoded thresholds §12 forbids, wearing a
// different name.
type Level string

const (
	LevelWarn Level = "warn"
	LevelFail Level = "fail"
)

// Valid reports whether l is a known level. `pass` is deliberately absent: a
// rule that cannot affect the verdict is not a rule.
func (l Level) Valid() bool { return l == LevelWarn || l == LevelFail }

func (l Level) verdict() Verdict {
	if l == LevelFail {
		return VerdictFail
	}
	return VerdictWarn
}

// Kind is what a rule measures.
//
// Kind plus Selector rather than one constant per metric, so a new severity or
// category needs no code here. The vocabulary is the canonical model's own --
// never a scanner name, which §7.2 and §25.3 forbid in this package as in every
// other outside internal/scanners.
type Kind string

const (
	KindSeverityCount Kind = "severity_count"
	KindCategoryCount Kind = "category_count"
	KindRiskScore     Kind = "risk_score"
)

// Rule is one threshold a project has chosen to enforce.
type Rule struct {
	Kind Kind
	// Selector is the severity or category being counted. Empty for
	// KindRiskScore, which measures the project rather than a subset of it.
	Selector string
	// Max is the ceiling. A rule breaches when the observed value exceeds it,
	// so a Max of 0 means "none allowed" rather than "unlimited".
	Max float64
	// Level is what a breach produces.
	Level Level
}

// Policy is a project's gate configuration.
type Policy struct {
	Rules []Rule
	// IncompleteScan is how to treat a scan that did not complete. Constrained
	// to warn or fail: §12 and §13 both forbid reading a partial scan as a
	// clean one, and a crashed scanner reporting nothing must never look like
	// an improvement.
	IncompleteScan Level
}

// DefaultPolicy is §25's example, expressed in this model and with the risk
// rule corrected to a ceiling (ADR 021 §1).
//
// A default rather than a hardcoded policy: it is what a project starts with,
// and every value is editable per project.
func DefaultPolicy() Policy {
	return Policy{
		Rules: []Rule{
			{Kind: KindSeverityCount, Selector: string(normalization.SeverityCritical), Max: 0, Level: LevelFail},
			{Kind: KindSeverityCount, Selector: string(normalization.SeverityHigh), Max: 5, Level: LevelFail},
			{Kind: KindCategoryCount, Selector: string(scanners.CategorySecrets), Max: 0, Level: LevelFail},
			{Kind: KindRiskScore, Max: 70, Level: LevelFail},
		},
		IncompleteScan: LevelWarn,
	}
}

// Validate reports whether a policy can be evaluated as written.
func (p Policy) Validate() error {
	if !p.IncompleteScan.Valid() {
		return fmt.Errorf("%w: incomplete-scan treatment is %q, must be warn or fail: a partial scan can never pass (§12, §13)",
			ErrInvalidPolicy, p.IncompleteScan)
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for i, r := range p.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("%w: rule %d: %w", ErrInvalidPolicy, i, err)
		}
		// Two rules on one metric would make the verdict depend on evaluation
		// order, which a deterministic gate cannot have.
		key := string(r.Kind) + "/" + r.Selector
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: rule %d duplicates the metric %s", ErrInvalidPolicy, i, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (r Rule) validate() error {
	if !r.Level.Valid() {
		return fmt.Errorf("level %q must be warn or fail", r.Level)
	}
	if r.Max < 0 {
		return fmt.Errorf("max %v is negative; a threshold below zero can never be satisfied", r.Max)
	}
	switch r.Kind {
	case KindSeverityCount:
		if !normalization.Severity(r.Selector).Valid() {
			return fmt.Errorf("unknown severity %q", r.Selector)
		}
	case KindCategoryCount:
		if !validCategory(r.Selector) {
			return fmt.Errorf("unknown category %q", r.Selector)
		}
	case KindRiskScore:
		if strings.TrimSpace(r.Selector) != "" {
			return fmt.Errorf("risk_score takes no selector, got %q", r.Selector)
		}
		if r.Max > 100 {
			// A ceiling above the top of the scale can never breach, which is
			// a rule that silently does nothing.
			return fmt.Errorf("max %v is above the 0-100 risk scale", r.Max)
		}
	default:
		return fmt.Errorf("unknown rule kind %q", r.Kind)
	}
	return nil
}

// validCategory mirrors the canonical category set. Kept here rather than
// imported as a helper so an unknown category in stored policy data is rejected
// at the boundary rather than silently never matching.
func validCategory(c string) bool {
	switch scanners.Category(c) {
	case scanners.CategorySAST, scanners.CategorySecrets, scanners.CategoryDependency,
		scanners.CategoryContainer, scanners.CategoryIaC, scanners.CategoryDAST,
		scanners.CategoryLicense:
		return true
	default:
		return false
	}
}

// sortedRules returns the rules in a stable order, so two evaluations of the
// same policy list their conditions identically.
func sortedRules(in []Rule) []Rule {
	out := append([]Rule(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Selector < out[j].Selector
	})
	return out
}
