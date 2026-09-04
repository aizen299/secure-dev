package policies

import (
	"errors"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// --- helpers ---------------------------------------------------------------

func input(sev map[normalization.Severity]int, score float64) Input {
	return Input{
		SeverityCounts: sev,
		CategoryCounts: map[scanners.Category]int{},
		RiskScore:      score,
		ScanStatus:     "completed",
		ScanComplete:   true,
	}
}

func evaluate(t *testing.T, p Policy, in Input) Result {
	t.Helper()
	res, err := Evaluate(p, in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

func rule(kind Kind, selector string, max float64, level Level) Rule {
	return Rule{Kind: kind, Selector: selector, Max: max, Level: level}
}

// --- property 1: determinism ------------------------------------------------

func TestEvaluationIsDeterministic(t *testing.T) {
	p := DefaultPolicy()
	in := input(map[normalization.Severity]int{
		normalization.SeverityCritical: 1,
		normalization.SeverityHigh:     7,
	}, 55)

	first := evaluate(t, p, in)
	for range 30 {
		got := evaluate(t, p, in)
		if got.Verdict != first.Verdict || len(got.Conditions) != len(first.Conditions) {
			t.Fatalf("verdict varies: %+v vs %+v", first, got)
		}
		for i := range got.Conditions {
			if got.Conditions[i] != first.Conditions[i] {
				t.Fatalf("condition %d varies: %+v vs %+v", i, first.Conditions[i], got.Conditions[i])
			}
		}
	}
}

// --- property 2: policy is data ---------------------------------------------

// An empty policy checks nothing and must say so. Otherwise "clean project" and
// "policy that enforces nothing" produce an identical PASS.
func TestAnEmptyPolicyPassesAndAdmitsItCheckedNothing(t *testing.T) {
	res := evaluate(t, Policy{IncompleteScan: LevelWarn},
		input(map[normalization.Severity]int{normalization.SeverityCritical: 99}, 100))

	if res.Verdict != VerdictPass {
		t.Errorf("verdict = %q, want pass: no rules means nothing to breach", res.Verdict)
	}
	if !strings.Contains(res.Summary, "no policy rules are configured") {
		t.Errorf("an empty policy passed silently: %q", res.Summary)
	}
}

// Changing a threshold changes the verdict, with no code change. That is what
// §12 means by policy being data.
func TestAThresholdChangeAloneChangesTheVerdict(t *testing.T) {
	in := input(map[normalization.Severity]int{normalization.SeverityHigh: 5}, 0)

	strict := Policy{Rules: []Rule{rule(KindSeverityCount, "high", 4, LevelFail)}, IncompleteScan: LevelWarn}
	lenient := Policy{Rules: []Rule{rule(KindSeverityCount, "high", 5, LevelFail)}, IncompleteScan: LevelWarn}

	if got := evaluate(t, strict, in).Verdict; got != VerdictFail {
		t.Errorf("5 highs against a limit of 4 = %q, want fail", got)
	}
	if got := evaluate(t, lenient, in).Verdict; got != VerdictPass {
		t.Errorf("5 highs against a limit of 5 = %q, want pass: max is a ceiling the value may reach", got)
	}
}

// The same rule warns for one team and fails for another. If level were derived
// from the metric, this would be impossible.
func TestTheSameRuleCanWarnOrFailDependingOnConfiguration(t *testing.T) {
	in := input(map[normalization.Severity]int{normalization.SeverityCritical: 1}, 0)

	warns := Policy{Rules: []Rule{rule(KindSeverityCount, "critical", 0, LevelWarn)}, IncompleteScan: LevelWarn}
	fails := Policy{Rules: []Rule{rule(KindSeverityCount, "critical", 0, LevelFail)}, IncompleteScan: LevelWarn}

	if got := evaluate(t, warns, in).Verdict; got != VerdictWarn {
		t.Errorf("verdict = %q, want warn", got)
	}
	if got := evaluate(t, fails, in).Verdict; got != VerdictFail {
		t.Errorf("verdict = %q, want fail", got)
	}
}

// --- property 3: worst level wins -------------------------------------------

func TestOneFailOutranksAnyNumberOfWarnings(t *testing.T) {
	p := Policy{
		Rules: []Rule{
			rule(KindSeverityCount, "low", 0, LevelWarn),
			rule(KindSeverityCount, "medium", 0, LevelWarn),
			rule(KindSeverityCount, "critical", 0, LevelFail),
		},
		IncompleteScan: LevelWarn,
	}
	res := evaluate(t, p, input(map[normalization.Severity]int{
		normalization.SeverityLow:      9,
		normalization.SeverityMedium:   9,
		normalization.SeverityCritical: 1,
	}, 0))

	if res.Verdict != VerdictFail {
		t.Errorf("verdict = %q, want fail", res.Verdict)
	}
}

// --- property 4: an incomplete scan never passes ----------------------------

// The failure this exists to prevent: a scanner crashes, reports nothing, fewer
// findings breach fewer rules, and the broken scan passes *because* it broke.
func TestAnIncompleteScanNeverPassesEvenWithNoBreaches(t *testing.T) {
	in := input(map[normalization.Severity]int{}, 0)
	in.ScanComplete = false
	in.ScanStatus = "partial"

	for _, level := range []Level{LevelWarn, LevelFail} {
		p := DefaultPolicy()
		p.IncompleteScan = level

		res := evaluate(t, p, in)
		if res.Verdict == VerdictPass {
			t.Errorf("incomplete scan with no breaches returned pass at level %q", level)
		}
		if res.Verdict != level.verdict() {
			t.Errorf("verdict = %q, want %q", res.Verdict, level.verdict())
		}
		if !res.Coverage.Downgraded {
			t.Error("the coverage downgrade was not recorded")
		}
		if !strings.Contains(res.Summary, "not complete") {
			t.Errorf("the summary hides the degraded coverage: %q", res.Summary)
		}
	}
}

// A WARN caused by a crashed scanner must be distinguishable from a WARN caused
// by a breached rule, or the two get triaged the same way.
func TestCoverageDowngradeIsNotClaimedWhenARuleAlreadyCausedIt(t *testing.T) {
	p := Policy{Rules: []Rule{rule(KindSeverityCount, "critical", 0, LevelFail)}, IncompleteScan: LevelWarn}
	in := input(map[normalization.Severity]int{normalization.SeverityCritical: 1}, 0)
	in.ScanComplete = false
	in.ScanStatus = "partial"

	res := evaluate(t, p, in)
	if res.Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want fail", res.Verdict)
	}
	if res.Coverage.Downgraded {
		t.Error("coverage was credited with a downgrade the breached rule caused")
	}
	// The degraded coverage is still reported, just not blamed.
	if res.Coverage.Complete || !strings.Contains(res.Summary, "not complete") {
		t.Error("degraded coverage was hidden because a rule already failed")
	}
}

// A policy that lets a partial scan pass must be unrepresentable, not merely
// discouraged.
func TestAPolicyCannotAllowAnIncompleteScanToPass(t *testing.T) {
	for _, bad := range []Level{"pass", "", "ignore"} {
		p := DefaultPolicy()
		p.IncompleteScan = bad
		if _, err := Evaluate(p, input(nil, 0)); err == nil {
			t.Errorf("incomplete-scan treatment %q was accepted", bad)
		} else if !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("error = %v, want ErrInvalidPolicy", err)
		}
	}
}

// --- property 5: every rule is reported -------------------------------------

func TestSatisfiedRulesAreReportedToo(t *testing.T) {
	p := DefaultPolicy()
	res := evaluate(t, p, input(map[normalization.Severity]int{}, 0))

	if res.Verdict != VerdictPass {
		t.Fatalf("verdict = %q, want pass", res.Verdict)
	}
	if len(res.Conditions) != len(p.Rules) {
		t.Errorf("conditions = %d, want all %d rules reported on a pass",
			len(res.Conditions), len(p.Rules))
	}
	for _, c := range res.Conditions {
		if c.Breached {
			t.Errorf("rule %+v reported as breached on a clean project", c.Rule)
		}
		if c.Explanation == "" {
			t.Errorf("rule %+v has no explanation: §12 forbids a bare verdict", c.Rule)
		}
	}
	if !strings.Contains(res.Summary, "all 4 policy rules satisfied") {
		t.Errorf("the summary does not say what was checked: %q", res.Summary)
	}
}

func TestAFailureNamesTheExactConditions(t *testing.T) {
	res := evaluate(t, DefaultPolicy(), input(map[normalization.Severity]int{
		normalization.SeverityCritical: 2,
		normalization.SeverityHigh:     9,
	}, 80))

	if res.Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want fail", res.Verdict)
	}
	for _, want := range []string{"critical findings: 2", "high findings: 9", "risk score: 80", "exceeds"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("summary is missing %q:\n%s", want, res.Summary)
		}
	}
}

// --- property 6: risk is a ceiling ------------------------------------------

// §25's example says "minimum risk score: 70", which against §10's 0-secure to
// 100-critical scale would fail secure projects and pass catastrophic ones.
// SecureOps implements a ceiling; ADR 021 records the reinterpretation.
func TestRiskScoreIsACeilingNotAFloor(t *testing.T) {
	p := Policy{Rules: []Rule{rule(KindRiskScore, "", 70, LevelFail)}, IncompleteScan: LevelWarn}

	if got := evaluate(t, p, input(nil, 12)).Verdict; got != VerdictPass {
		t.Errorf("a secure project (risk 12) got %q, want pass", got)
	}
	if got := evaluate(t, p, input(nil, 71)).Verdict; got != VerdictFail {
		t.Errorf("a risky project (risk 71) got %q, want fail", got)
	}
	if got := evaluate(t, p, input(nil, 70)).Verdict; got != VerdictPass {
		t.Errorf("risk exactly at the ceiling got %q, want pass: max is inclusive", got)
	}
}

// --- property 7: no scanner branching ---------------------------------------

func TestTheVerdictDoesNotDependOnWhichScannerReported(t *testing.T) {
	build := func(scanner string) Input {
		return InputFrom([]risk.Subject{{
			Finding: normalization.Finding{
				Fingerprint: "a", Scanner: scanner, Title: "x",
				Category: scanners.CategorySecrets, Severity: normalization.SeverityCritical,
				Confidence: normalization.ConfidenceHigh, Status: normalization.StatusOpen,
			},
		}}, 40, "completed", true)
	}
	a := evaluate(t, DefaultPolicy(), build("gitleaks"))
	b := evaluate(t, DefaultPolicy(), build("some-future-scanner"))

	if a.Verdict != b.Verdict {
		t.Errorf("verdict changed with the scanner name: %q vs %q", a.Verdict, b.Verdict)
	}
}

// Dismissed findings must not fail a build. The gate has to agree with the
// other engines about which findings exist.
func TestDismissedFindingsDoNotBreachAGate(t *testing.T) {
	subject := func(status normalization.Status) risk.Subject {
		return risk.Subject{Finding: normalization.Finding{
			Fingerprint: "a", Scanner: "grype", Title: "x",
			Category: scanners.CategoryDependency, Severity: normalization.SeverityCritical,
			Confidence: normalization.ConfidenceHigh, Status: status,
		}}
	}
	for _, status := range []normalization.Status{
		normalization.StatusResolved, normalization.StatusFalsePositive, normalization.StatusIgnored,
	} {
		in := InputFrom([]risk.Subject{subject(status)}, 0, "completed", true)
		if got := evaluate(t, DefaultPolicy(), in).Verdict; got != VerdictPass {
			t.Errorf("a %s critical produced %q, want pass", status, got)
		}
	}
	in := InputFrom([]risk.Subject{subject(normalization.StatusOpen)}, 0, "completed", true)
	if got := evaluate(t, DefaultPolicy(), in).Verdict; got != VerdictFail {
		t.Errorf("an open critical produced %q, want fail: the test above would be vacuous", got)
	}
}

// --- validation -------------------------------------------------------------

func TestValidateRejectsPoliciesThatCannotMeanAnything(t *testing.T) {
	for name, p := range map[string]Policy{
		"unknown severity":         {Rules: []Rule{rule(KindSeverityCount, "catastrophic", 0, LevelFail)}, IncompleteScan: LevelWarn},
		"unknown category":         {Rules: []Rule{rule(KindCategoryCount, "vibes", 0, LevelFail)}, IncompleteScan: LevelWarn},
		"unknown kind":             {Rules: []Rule{rule("phase_of_moon", "", 0, LevelFail)}, IncompleteScan: LevelWarn},
		"negative max":             {Rules: []Rule{rule(KindSeverityCount, "high", -1, LevelFail)}, IncompleteScan: LevelWarn},
		"unreachable risk ceiling": {Rules: []Rule{rule(KindRiskScore, "", 140, LevelFail)}, IncompleteScan: LevelWarn},
		"selector on risk score":   {Rules: []Rule{rule(KindRiskScore, "high", 70, LevelFail)}, IncompleteScan: LevelWarn},
		"duplicate metric": {Rules: []Rule{
			rule(KindSeverityCount, "high", 5, LevelWarn),
			rule(KindSeverityCount, "high", 1, LevelFail),
		}, IncompleteScan: LevelWarn},
		"bad level": {Rules: []Rule{rule(KindSeverityCount, "high", 5, "shout")}, IncompleteScan: LevelWarn},
	} {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); err == nil {
				t.Fatal("accepted a policy that cannot be evaluated meaningfully")
			} else if !errors.Is(err, ErrInvalidPolicy) {
				t.Errorf("error = %v, want ErrInvalidPolicy", err)
			}
			if _, err := Evaluate(p, input(nil, 0)); err == nil {
				t.Error("Evaluate accepted it anyway")
			}
		})
	}
}

func TestTheDefaultPolicyIsValidAndMatchesTheSpecExample(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("the shipped default does not validate: %v", err)
	}
	if len(p.Rules) != 4 {
		t.Fatalf("rules = %d, want the four in §25's example", len(p.Rules))
	}
	// The risk rule is a ceiling, not the floor §25 literally writes.
	for _, r := range p.Rules {
		if r.Kind == KindRiskScore && r.Max != 70 {
			t.Errorf("risk ceiling = %v, want 70", r.Max)
		}
	}
	if p.IncompleteScan == "" {
		t.Error("the default has no incomplete-scan treatment")
	}
}

// A verdict is read by a person under time pressure, so its numbers are
// formatted for reading rather than for round-tripping a float64.
//
// The original used precision -1, which prints the shortest representation
// that survives a round trip -- for a derived risk score that is every digit
// it has, and a gate that says "risk score: 42.797864192072396" looks broken
// rather than precise.
func TestNumbersAreFormattedForReading(t *testing.T) {
	cases := map[float64]string{
		0:                  "0",
		3:                  "3",
		70:                 "70",
		42.797864192072396: "42.8",
		81.69420000000001:  "81.7",
		17.411500591706762: "17.4",
	}
	for value, want := range cases {
		if got := number(value); got != want {
			t.Errorf("number(%v) = %q, want %q", value, got, want)
		}
	}
}

// A satisfied condition must not name the rule's level.
//
// The level is what happens *if* a rule is breached. Printing it on a reading
// that is fine produced "secrets findings: 0 is within the limit of 0 (fail)",
// which on a quick scan reads as a failure -- on precisely the screen somebody
// reads quickly to find out whether anything is wrong.
func TestASatisfiedConditionDoesNotAnnounceAFailure(t *testing.T) {
	rule := Rule{Kind: KindCategoryCount, Selector: "secrets", Max: 0, Level: LevelFail}

	satisfied := explain(rule, 0, false)
	if strings.Contains(satisfied, string(LevelFail)) {
		t.Errorf("a satisfied condition names its level: %q", satisfied)
	}
	if want := "secrets findings: 0 is within the limit of 0"; satisfied != want {
		t.Errorf("explain(satisfied) = %q, want %q", satisfied, want)
	}

	// A breach still says what it costs, which is the whole point of the level.
	breached := explain(rule, 3, true)
	if !strings.Contains(breached, string(LevelFail)) {
		t.Errorf("a breached condition hides its level: %q", breached)
	}
	if want := "secrets findings: 3 exceeds the limit of 0 (fail)"; breached != want {
		t.Errorf("explain(breached) = %q, want %q", breached, want)
	}
}
