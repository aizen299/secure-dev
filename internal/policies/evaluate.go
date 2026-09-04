package policies

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Input is what a gate decision is made from.
//
// Counts rather than findings, so the engine stays a pure function of numbers
// and cannot accidentally depend on a finding's scanner. Build it with
// InputFrom.
type Input struct {
	SeverityCounts map[normalization.Severity]int
	CategoryCounts map[scanners.Category]int
	RiskScore      float64
	// ScanStatus is the scan's own status, carried so the result can say why
	// coverage was degraded rather than only that it was.
	ScanStatus string
	// ScanComplete is whether the scan finished with full scanner coverage.
	// A crashed scanner reports nothing, and fewer findings look exactly like
	// an improvement -- this is the flag that stops that reading (§12, §13).
	ScanComplete bool
}

// InputFrom counts a scan's live findings.
//
// Dismissed findings are excluded, matching correlation, risk, and remediation
// exactly. A gate that failed on a finding somebody already marked a false
// positive would be a gate teams learn to route around.
func InputFrom(subjects []risk.Subject, score float64, scanStatus string, complete bool) Input {
	in := Input{
		SeverityCounts: map[normalization.Severity]int{},
		CategoryCounts: map[scanners.Category]int{},
		RiskScore:      score,
		ScanStatus:     scanStatus,
		ScanComplete:   complete,
	}
	for _, s := range subjects {
		if dismissed(s.Status) {
			continue
		}
		in.SeverityCounts[s.Severity]++
		in.CategoryCounts[s.Category]++
	}
	return in
}

func dismissed(s normalization.Status) bool {
	switch s {
	case normalization.StatusResolved, normalization.StatusFalsePositive, normalization.StatusIgnored:
		return true
	default:
		return false
	}
}

// Condition is one rule's outcome, reported whether or not it breached.
//
// Satisfied rules are included deliberately. A pass that lists only its
// breaches lists nothing, and "the project is clean" then looks identical to
// "the policy checks nothing" -- the bare verdict §12 forbids, wearing a
// friendlier face.
type Condition struct {
	Rule     Rule
	Observed float64
	Breached bool
	// Explanation states the comparison in words, so a CI comment does not
	// have to reconstruct it from the numbers.
	Explanation string
}

// Result is a gate decision and the whole of its reasoning.
type Result struct {
	Verdict Verdict
	// Conditions covers every rule evaluated, in stable order.
	Conditions []Condition
	// Coverage records whether the scan was complete, and what that did to the
	// verdict. Present on every result, not only degraded ones.
	Coverage Coverage
	// Summary is the human-readable rendering. Derived from the same
	// conditions as the machine-readable form, so the two cannot disagree.
	Summary string
}

// Coverage is the gate's account of what the scan actually managed to do.
type Coverage struct {
	Complete   bool
	ScanStatus string
	// Downgraded records that incompleteness affected the verdict, so a WARN
	// caused by a crashed scanner is distinguishable from one caused by a
	// breached rule.
	Downgraded bool
	Level      Level
}

// Evaluate applies a policy to a scan's results.
//
// Returns an error only for an unusable policy. A policy that no scan can
// satisfy is a configuration problem, and producing a confident FAIL from one
// would hide it.
func Evaluate(p Policy, in Input) (Result, error) {
	if err := p.Validate(); err != nil {
		return Result{}, err
	}

	res := Result{
		Verdict:    VerdictPass,
		Conditions: make([]Condition, 0, len(p.Rules)),
		Coverage:   Coverage{Complete: in.ScanComplete, ScanStatus: in.ScanStatus, Level: p.IncompleteScan},
	}

	for _, r := range sortedRules(p.Rules) {
		observed := observe(r, in)
		// Strictly greater: Max is a ceiling the value may reach. "max
		// critical = 0" must pass with zero criticals and fail with one.
		breached := observed > r.Max

		res.Conditions = append(res.Conditions, Condition{
			Rule:        r,
			Observed:    observed,
			Breached:    breached,
			Explanation: explain(r, observed, breached),
		})
		if breached && r.Level.verdict().rank() > res.Verdict.rank() {
			res.Verdict = r.Level.verdict()
		}
	}

	// Coverage is applied last and can only make the verdict worse. §12 and
	// §13 both forbid reading a partial scan as a complete one, and the
	// failure is specific: the less a scan managed to do, the fewer rules can
	// breach, so a broken scan would pass precisely because it was broken.
	if !in.ScanComplete {
		if v := p.IncompleteScan.verdict(); v.rank() > res.Verdict.rank() {
			res.Verdict = v
			res.Coverage.Downgraded = true
		} else if res.Verdict.rank() >= v.rank() {
			// Already at least as bad for another reason; coverage did not
			// change the outcome, and claiming it did would misattribute it.
			res.Coverage.Downgraded = false
		}
	}

	res.Summary = summarize(res)
	return res, nil
}

// observe reads the value a rule measures.
func observe(r Rule, in Input) float64 {
	switch r.Kind {
	case KindSeverityCount:
		return float64(in.SeverityCounts[normalization.Severity(r.Selector)])
	case KindCategoryCount:
		return float64(in.CategoryCounts[scanners.Category(r.Selector)])
	case KindRiskScore:
		return in.RiskScore
	default:
		// Unreachable: Validate rejects unknown kinds before evaluation. A
		// zero here would silently satisfy any ceiling, so it is stated as
		// impossible rather than relied upon.
		return 0
	}
}

// explain states a condition in one sentence.
//
// The rule's level is named only when the condition is breached, because it is
// the consequence of a breach and not a property of the reading. Naming it
// unconditionally produced "secrets findings: 0 is within the limit of 0
// (fail)" -- a satisfied condition that reads, at a glance, as a failure, on
// exactly the screen somebody scans quickly to find out whether anything is
// wrong.
func explain(r Rule, observed float64, breached bool) string {
	if breached {
		return fmt.Sprintf("%s %s exceeds the limit of %s (%s)",
			metricName(r), number(observed), number(r.Max), r.Level)
	}
	return fmt.Sprintf("%s %s is within the limit of %s",
		metricName(r), number(observed), number(r.Max))
}

func metricName(r Rule) string {
	switch r.Kind {
	case KindSeverityCount:
		return r.Selector + " findings:"
	case KindCategoryCount:
		return r.Selector + " findings:"
	default:
		return "risk score:"
	}
}

// number formats a value for a person to read.
//
// Counts are whole and print without a decimal, so a rule reads "3 findings"
// rather than "3.0". Anything fractional -- in practice the risk score -- gets
// one decimal, which is the precision the score is quoted at everywhere else.
//
// Precision -1 was the original and it is what made a gate verdict read
// "risk score: 42.797864192072396 is within the limit of 70": it prints the
// shortest representation that round-trips a float64 exactly, which for a
// derived score is every digit it has. A security verdict quoting fifteen
// decimals is not more precise, only less readable.
func number(v float64) string {
	if v == math.Trunc(v) {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// summarize renders the result for a person -- a PR comment or a dashboard.
//
// Built from the same conditions the machine-readable form carries, so the two
// renderings cannot drift apart and tell a reviewer different things.
func summarize(res Result) string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(string(res.Verdict)))

	var breached []Condition
	for _, c := range res.Conditions {
		if c.Breached {
			breached = append(breached, c)
		}
	}

	switch {
	case len(breached) == 0 && len(res.Conditions) == 0:
		// An empty policy passing everything is worth saying out loud: it
		// looks identical to a clean project otherwise.
		b.WriteString(" — no policy rules are configured, so nothing was checked.")
	case len(breached) == 0:
		fmt.Fprintf(&b, " — all %d policy rules satisfied.", len(res.Conditions))
	default:
		fmt.Fprintf(&b, " — %d of %d policy rules breached:",
			len(breached), len(res.Conditions))
		for _, c := range breached {
			b.WriteString("\n  • ")
			b.WriteString(c.Explanation)
		}
	}

	if !res.Coverage.Complete {
		b.WriteString("\n\nCoverage: this scan is ")
		b.WriteString(res.Coverage.ScanStatus)
		b.WriteString(", not complete. A scanner that failed reported nothing, so this")
		b.WriteString(" result is computed over less than the whole project and fewer")
		b.WriteString(" findings do not mean fewer problems.")
		if res.Coverage.Downgraded {
			b.WriteString(" The verdict was downgraded for this reason.")
		}
	}
	return b.String()
}
