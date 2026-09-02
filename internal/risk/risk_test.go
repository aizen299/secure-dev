package risk

import (
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// --- helpers ---------------------------------------------------------------

// neutralContext is production, medium criticality, not internet-facing: the
// point where exposure and criticality both contribute exactly 1.0.
func neutralContext() Context {
	return Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityMedium}
}

func subject(fp string, sev normalization.Severity) Subject {
	return Subject{
		Finding: normalization.Finding{
			Fingerprint: fp,
			Scanner:     "grype",
			Title:       "Vulnerable component",
			Category:    scanners.CategoryDependency,
			Severity:    sev,
			Confidence:  normalization.ConfidenceHigh,
			Status:      normalization.StatusOpen,
		},
		Sources: []string{"grype"},
	}
}

func withEPSS(s Subject, percentile float64) Subject {
	s.Threat = normalization.ThreatIntel{EPSS: &normalization.EPSS{
		Probability: 0.07314,
		Percentile:  percentile,
		Source:      normalization.SourceGrype,
		ObservedAt:  time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}}
	return s
}

func many(n int, sev normalization.Severity) []Subject {
	out := make([]Subject, 0, n)
	for i := range n {
		out = append(out, subject("f"+strconv.Itoa(i), sev))
	}
	return out
}

func factor(t *testing.T, s Score, name string) Factor {
	t.Helper()
	for _, f := range s.Factors {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no %q factor in score", name)
	return Factor{}
}

const tolerance = 0.01

func closeTo(got, want float64) bool { return math.Abs(got-want) <= tolerance }

// --- property 1: determinism ------------------------------------------------

func TestScoringIsDeterministic(t *testing.T) {
	subjects := []Subject{
		withEPSS(subject("a", normalization.SeverityCritical), 0.9),
		subject("b", normalization.SeverityLow),
		subject("c", normalization.SeverityMedium),
	}
	first := Assess(subjects, neutralContext())
	for range 50 {
		if got := Assess(subjects, neutralContext()); got.Score != first.Score {
			t.Fatalf("score = %v then %v for identical input", first.Score, got.Score)
		}
	}
}

// Order is an accident of how findings came back from a query, and must not be
// an input to a security score.
func TestScoreIsIndependentOfFindingOrder(t *testing.T) {
	a := subject("a", normalization.SeverityCritical)
	b := subject("b", normalization.SeverityInfo)
	c := subject("c", normalization.SeverityHigh)

	forward := Assess([]Subject{a, b, c}, neutralContext()).Score
	reversed := Assess([]Subject{c, b, a}, neutralContext()).Score
	if !closeTo(forward, reversed) {
		t.Errorf("score depends on input order: %v vs %v", forward, reversed)
	}
}

// --- property 3: factor isolation -------------------------------------------

func TestEachFactorMovesTheScoreAloneAndInTheRightDirection(t *testing.T) {
	base := subject("a", normalization.SeverityMedium)
	baseline := Assess([]Subject{base}, neutralContext())

	tests := []struct {
		name    string
		subject Subject
		ctx     Context
		factor  string
		wantUp  bool
	}{
		{
			name:    "severity",
			subject: subject("a", normalization.SeverityCritical),
			ctx:     neutralContext(), factor: "severity", wantUp: true,
		},
		{
			name:    "exploitability rises with EPSS percentile",
			subject: withEPSS(base, 0.99),
			ctx:     neutralContext(), factor: "exploitability", wantUp: true,
		},
		{
			name:    "exploitability falls on measured low likelihood",
			subject: withEPSS(base, 0.0),
			ctx:     neutralContext(), factor: "exploitability", wantUp: false,
		},
		{
			name:    "exposure rises when internet-facing",
			subject: base,
			ctx:     Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityMedium, InternetFacing: true},
			factor:  "exposure", wantUp: true,
		},
		{
			name:    "exposure falls in development",
			subject: base,
			ctx:     Context{Environment: projects.EnvDevelopment, Criticality: projects.CriticalityMedium},
			factor:  "exposure", wantUp: false,
		},
		{
			name:    "criticality rises for a critical asset",
			subject: base,
			ctx:     Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityCritical},
			factor:  "criticality", wantUp: true,
		},
		{
			name: "confidence falls when the finding may not be real",
			subject: func() Subject {
				s := base
				s.Confidence = normalization.ConfidenceLow
				return s
			}(),
			ctx: neutralContext(), factor: "confidence", wantUp: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess([]Subject{tc.subject}, tc.ctx)

			if tc.wantUp && got.Score <= baseline.Score {
				t.Errorf("score = %v, want above the %v baseline", got.Score, baseline.Score)
			}
			if !tc.wantUp && got.Score >= baseline.Score {
				t.Errorf("score = %v, want below the %v baseline", got.Score, baseline.Score)
			}

			// And only that factor moved. This is what catches a factor
			// reading the wrong field -- a bug that would still produce a
			// score that moves in the right direction.
			for _, f := range got.Findings[0].Factors {
				was := factor(t, baseline.Findings[0], f.Name)
				changed := !closeTo(f.Value, was.Value)
				if f.Name == tc.factor && !changed {
					t.Errorf("%s did not change: still %v", f.Name, f.Value)
				}
				if f.Name != tc.factor && changed {
					t.Errorf("%s moved too: %v -> %v, but only %s should have",
						f.Name, was.Value, f.Value, tc.factor)
				}
			}
		})
	}
}

// --- property 4: boundaries -------------------------------------------------

func TestEmptyProjectScoresZero(t *testing.T) {
	got := Assess(nil, neutralContext())
	if got.Score != 0 || got.Total != 0 {
		t.Errorf("empty project scored %v (total %v), want 0", got.Score, got.Total)
	}
}

func TestScoreStaysWithinZeroAndOneHundred(t *testing.T) {
	// The worst input the model can express, many times over.
	ctx := Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityCritical, InternetFacing: true}
	subjects := many(2000, normalization.SeverityCritical)
	for i := range subjects {
		subjects[i] = withEPSS(subjects[i], 1.0)
	}

	got := Assess(subjects, ctx)
	if math.IsNaN(got.Score) || got.Score < 0 || got.Score > 100 {
		t.Fatalf("score = %v, want within [0, 100]", got.Score)
	}
}

// Saturation must be graceful across the range a real project occupies: bad and
// catastrophic stay distinguishable, and only genuinely extreme input reaches
// the ceiling.
func TestSaturationIsGradualNotACliff(t *testing.T) {
	ctx := Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityCritical, InternetFacing: true}
	worstCase := func(n int) []Subject {
		out := many(n, normalization.SeverityCritical)
		for i := range out {
			out[i] = withEPSS(out[i], 0.99)
		}
		return out
	}

	one := Assess(worstCase(1), ctx).Score
	ten := Assess(worstCase(10), ctx).Score
	if !(one < ten && ten < 100) {
		t.Errorf("scores %v then %v: want strictly increasing and below 100", one, ten)
	}
	if ten-one < 5 {
		t.Errorf("one critical scored %v and ten scored %v: the range is too compressed to be useful", one, ten)
	}
}

// Past saturation the score stops separating projects, which is why Total is
// carried alongside it. A gate reads Score; anyone asking "did this get worse?"
// at the top of the scale needs Total, and it must keep moving.
func TestTotalKeepsDistinguishingProjectsAfterTheScoreSaturates(t *testing.T) {
	ctx := Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityCritical, InternetFacing: true}

	smaller := Assess(many(2000, normalization.SeverityCritical), ctx)
	larger := Assess(many(4000, normalization.SeverityCritical), ctx)

	if smaller.Score != 100 || larger.Score != 100 {
		t.Skipf("neither project saturated (%v, %v); nothing to check here", smaller.Score, larger.Score)
	}
	if larger.Total <= smaller.Total {
		t.Errorf("total = %v for 4000 criticals against %v for 2000: saturation erased the difference",
			larger.Total, smaller.Total)
	}
}

// A missing project context is missing information, not evidence of safety.
func TestUndeclaredContextIsNeutralNotDiscounting(t *testing.T) {
	declared := Assess([]Subject{subject("a", normalization.SeverityHigh)}, neutralContext())
	absent := Assess([]Subject{subject("a", normalization.SeverityHigh)}, Context{})

	if !closeTo(declared.Score, absent.Score) {
		t.Errorf("undeclared context scored %v, want the neutral %v", absent.Score, declared.Score)
	}
	for _, name := range []string{"exposure", "criticality"} {
		if f := factor(t, absent.Findings[0], name); !f.Neutral {
			t.Errorf("%s is not marked neutral with no data: %+v", name, f)
		}
	}
}

// --- property 5: neutral absence --------------------------------------------

func TestAbsentThreatIntelligenceIsNeutralNotLow(t *testing.T) {
	s := subject("a", normalization.SeverityHigh)
	got := Assess([]Subject{s}, neutralContext())

	expl := factor(t, got.Findings[0], "exploitability")
	if expl.Value != 1.0 {
		t.Errorf("exploitability = %v with no signal, want exactly 1.0", expl.Value)
	}
	if !expl.Neutral {
		t.Error("the missing signal is not recorded as neutral, so a reader cannot tell it was absent")
	}

	// The score must equal the product of the other four factors exactly --
	// that is what "neutral" means, and it is the test that stops "unknown"
	// drifting into "low".
	want := DefaultWeights().Severity[normalization.SeverityHigh] * 1.0 * 1.0 * 1.0
	if got.Findings[0].Value != want {
		t.Errorf("risk = %v, want %v (severity alone, every other factor neutral)", got.Findings[0].Value, want)
	}

	// And it must score strictly above an identical finding that is measurably
	// unlikely to be exploited. Absence is not the bottom of the range.
	measured := Assess([]Subject{withEPSS(s, 0.0)}, neutralContext())
	if measured.Score >= got.Score {
		t.Errorf("a finding measured at percentile 0.0 scored %v, want below the %v of one with no data",
			measured.Score, got.Score)
	}
}

// --- property 6: dismissed findings score zero -------------------------------

func TestDismissedFindingsContributeNothing(t *testing.T) {
	live := subject("a", normalization.SeverityMedium)
	baseline := Assess([]Subject{live}, neutralContext())

	for _, status := range []normalization.Status{
		normalization.StatusResolved,
		normalization.StatusFalsePositive,
		normalization.StatusIgnored,
	} {
		t.Run(string(status), func(t *testing.T) {
			dead := subject("b", normalization.SeverityCritical)
			dead.Status = status

			got := Assess([]Subject{live, dead}, neutralContext())
			if !closeTo(got.Score, baseline.Score) {
				t.Errorf("a %s critical moved the score to %v, want the %v of the live finding alone",
					status, got.Score, baseline.Score)
			}
			if got.Dismissed != 1 || got.Live != 1 {
				t.Errorf("live/dismissed = %d/%d, want 1/1", got.Live, got.Dismissed)
			}
			// Explained, not discarded: the finding is still in the result.
			if len(got.Findings) != 2 {
				t.Fatalf("findings = %d, want both retained", len(got.Findings))
			}
			if got.Findings[1].Value != 0 {
				t.Errorf("dismissed finding scored %v, want 0", got.Findings[1].Value)
			}
		})
	}
}

// Every status a human has NOT dismissed still counts. Risk and correlation
// must agree on which findings exist, or a gate fails on something the
// dashboard does not show.
func TestLiveStatusesAllCount(t *testing.T) {
	for _, status := range []normalization.Status{
		normalization.StatusOpen, normalization.StatusReopened,
		normalization.StatusAcknowledged, normalization.StatusInProgress,
		"", // what a newly stored finding carries before the lifecycle assigns one
	} {
		s := subject("a", normalization.SeverityHigh)
		s.Status = status
		got := Assess([]Subject{s}, neutralContext())
		if got.Live != 1 || got.Score == 0 {
			t.Errorf("status %q scored %v with %d live, want it counted", status, got.Score, got.Live)
		}
	}
}

// --- property 7: no double counting -----------------------------------------

func TestAnEscalatedIssueRaisesSeverityOnceAndNothingElse(t *testing.T) {
	s := subject("a", normalization.SeverityHigh)
	s.IssueSeverity = normalization.SeverityCritical
	s.IssueKey = "cve:CVE-2026-0001"

	got := Assess([]Subject{s}, neutralContext()).Findings[0]

	if got.Severity != normalization.SeverityCritical || !got.Escalated {
		t.Fatalf("severity = %q (escalated %v), want critical and escalated", got.Severity, got.Escalated)
	}
	if w := factor(t, got, "severity"); w.Value != DefaultWeights().Severity[normalization.SeverityCritical] {
		t.Errorf("severity weight = %v, want the critical weight exactly", w.Value)
	}
	// The escalation must not also arrive as confidence. That would be the
	// same cross-domain evidence counted twice -- the seam ADR 017 reserved.
	if c := factor(t, got, "confidence"); c.Value != 1.0 {
		t.Errorf("confidence = %v, want the unchanged 1.0: escalation is severity only", c.Value)
	}
	// And it equals the score of a finding that was simply critical to begin
	// with: escalated-from-high is not worse than born-critical.
	plain := Assess([]Subject{subject("a", normalization.SeverityCritical)}, neutralContext())
	if got.Value != plain.Findings[0].Value {
		t.Errorf("escalated risk %v != plain critical risk %v", got.Value, plain.Findings[0].Value)
	}
}

// Correlation escalates; it never de-escalates. An issue severity below the
// finding's own must not quietly discount it.
func TestAnIssueNeverLowersAFindingsSeverity(t *testing.T) {
	s := subject("a", normalization.SeverityCritical)
	s.IssueSeverity = normalization.SeverityLow
	s.IssueKey = "file:server.ts"

	got := Assess([]Subject{s}, neutralContext()).Findings[0]
	if got.Severity != normalization.SeverityCritical {
		t.Errorf("severity = %q, want critical: an issue must not lower a finding", got.Severity)
	}
	if got.Escalated {
		t.Error("a downgrade was reported as an escalation")
	}
}

// --- corroboration ----------------------------------------------------------

func TestAgreementBetweenScannersRaisesConfidenceByOneStep(t *testing.T) {
	s := subject("a", normalization.SeverityHigh)
	s.Confidence = normalization.ConfidenceLow
	s.Sources = []string{"grype", "trivy"}

	got := Assess([]Subject{s}, neutralContext()).Findings[0]
	c := factor(t, got, "confidence")
	if c.Value != DefaultWeights().Confidence[normalization.ConfidenceMedium] {
		t.Errorf("confidence = %v, want the medium weight: one step up from low", c.Value)
	}

	// One step only. Three agreeing scanners are not three steps -- unbounded
	// corroboration would make every much-reported finding certain.
	s.Sources = []string{"grype", "trivy", "semgrep"}
	three := factor(t, Assess([]Subject{s}, neutralContext()).Findings[0], "confidence")
	if three.Value != c.Value {
		t.Errorf("three scanners gave %v, two gave %v: the raise must cap at one step", three.Value, c.Value)
	}
}

func TestConfidenceNeverExceedsOne(t *testing.T) {
	s := subject("a", normalization.SeverityHigh)
	s.Confidence = normalization.ConfidenceHigh
	s.Sources = []string{"grype", "trivy", "semgrep"}

	c := factor(t, Assess([]Subject{s}, neutralContext()).Findings[0], "confidence")
	if c.Value != 1.0 {
		t.Errorf("confidence = %v, want 1.0: corroboration cannot inflate above certainty", c.Value)
	}
}

// A duplicated scanner name is one reporter, not two. Otherwise a scanner
// listed twice by a bug upstream would manufacture agreement with itself.
func TestOneScannerListedTwiceIsNotAgreement(t *testing.T) {
	s := subject("a", normalization.SeverityHigh)
	s.Confidence = normalization.ConfidenceLow
	s.Sources = []string{"grype", "grype"}

	c := factor(t, Assess([]Subject{s}, neutralContext()).Findings[0], "confidence")
	if c.Value != DefaultWeights().Confidence[normalization.ConfidenceLow] {
		t.Errorf("confidence = %v, want the low weight unchanged", c.Value)
	}
}

// --- explainability ---------------------------------------------------------

func TestEveryScoreCarriesItsDerivation(t *testing.T) {
	s := withEPSS(subject("a", normalization.SeverityCritical), 0.99)
	s.Sources = []string{"grype", "trivy"}
	ctx := Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityCritical, InternetFacing: true}

	got := Assess([]Subject{s}, ctx).Findings[0]
	if len(got.Factors) != 5 {
		t.Fatalf("factors = %d, want all five named in §10", len(got.Factors))
	}

	explanation := got.Explain()
	for _, want := range []string{
		"severity", "exploitability", "exposure", "criticality", "confidence",
		"internet-facing", "EPSS percentile 0.99", "grype",
	} {
		if !contains(explanation, want) {
			t.Errorf("explanation is missing %q:\n%s", want, explanation)
		}
	}

	// The stated worked example in docs/architecture/risk-engine.md.
	if !closeTo(got.Value, 335.25) {
		t.Errorf("risk = %v, want 335.25 as the design document states", got.Value)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	}()
}
