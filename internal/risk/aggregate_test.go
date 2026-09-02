package risk

import (
	"math/rand/v2"
	"sort"
	"strconv"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
)

// --- property 2: monotonicity ------------------------------------------------

// The requirement §10 states outright: adding a finding must never reduce risk.
// It is the property an average would break, and the reason this engine sums
// rather than averages.
func TestAddingAnyFindingNeverLowersTheScore(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	severities := []normalization.Severity{
		normalization.SeverityCritical, normalization.SeverityHigh,
		normalization.SeverityMedium, normalization.SeverityUnknown,
		normalization.SeverityLow, normalization.SeverityInfo,
	}
	environments := projects.Environments()
	criticalities := projects.Criticalities()
	confidences := []normalization.Confidence{
		normalization.ConfidenceHigh, normalization.ConfidenceMedium, normalization.ConfidenceLow,
	}

	for run := range 20 {
		ctx := Context{
			Environment:    environments[r.IntN(len(environments))],
			Criticality:    criticalities[r.IntN(len(criticalities))],
			InternetFacing: r.IntN(2) == 0,
		}

		var subjects []Subject
		previous := 0.0
		for step := range 300 {
			s := subject("f"+strconv.Itoa(step), severities[r.IntN(len(severities))])
			s.Confidence = confidences[r.IntN(len(confidences))]
			if r.IntN(2) == 0 {
				s = withEPSS(s, r.Float64())
			}
			subjects = append(subjects, s)

			got := Assess(subjects, ctx).Score
			if got < previous {
				t.Fatalf("run %d step %d: score fell from %v to %v when a finding was added",
					run, step, previous, got)
			}
			previous = got
		}
	}
}

// The specific case the requirement is about: a trivial finding added to a
// project full of criticals. An average would drop here.
func TestAddingATrivialFindingToACriticalProjectDoesNotHelp(t *testing.T) {
	criticals := many(10, normalization.SeverityCritical)
	before := Assess(criticals, neutralContext()).Score

	after := Assess(append(criticals, subject("zz", normalization.SeverityInfo)), neutralContext()).Score
	if after < before {
		t.Errorf("score fell from %v to %v when an informational finding was added", before, after)
	}
}

// --- property 8: severity beats volume ---------------------------------------

// The regression test for the defect that produced this design. Under the
// rejected plain-sum aggregation, 500 informational findings scored 71.3 while
// the worst finding the model can express scored 56.7 -- volume outranking
// severity. See ADR 019, "Plain saturating sum".
//
// The claim is bounded, not absolute: max-dominance moves the crossover, it
// does not abolish one. Nothing short of λ = 0 would, and λ = 0 discards the
// density signal §10 asks for. What the design commits to is that the
// crossover sits far outside any plausible project, and this test holds it
// there -- raising λ enough to matter would fail it.
func TestTriviaDoesNotOutrankSeverityAtAnyPlausibleVolume(t *testing.T) {
	worstCtx := Context{
		Environment:    projects.EnvProduction,
		Criticality:    projects.CriticalityCritical,
		InternetFacing: true,
	}
	worst := Assess(
		[]Subject{withEPSS(subject("a", normalization.SeverityCritical), 0.99)},
		worstCtx,
	).Score

	for _, n := range []int{500, 5000, 20000} {
		trivia := Assess(many(n, normalization.SeverityInfo), neutralContext()).Score
		if trivia >= worst {
			t.Errorf("%d informational findings scored %v, at or above the %v of one worst-case critical",
				n, trivia, worst)
		}
	}

	// And the crossover itself stays where docs/architecture/risk-engine.md
	// publishes it. This is the guard on λ: the table in that document is a
	// claim about the exchange rate between volume and severity, and a tuning
	// change that moved it silently would make the document a lie.
	crossover := sort.Search(60000, func(n int) bool {
		return Assess(many(n, normalization.SeverityInfo), neutralContext()).Score >= worst
	})
	if crossover < 40000 {
		t.Errorf("informational crossover is at %d findings, want the ~44,700 the design document states",
			crossover)
	}
}

// The converse guard, so the test above cannot be satisfied by ignoring volume
// altogether: quantity must still matter. A pure maximum would pass the test
// above and fail this one.
func TestVolumeStillMovesTheScore(t *testing.T) {
	one := Assess(many(1, normalization.SeverityMedium), neutralContext()).Score
	hundred := Assess(many(100, normalization.SeverityMedium), neutralContext()).Score

	if hundred <= one*2 {
		t.Errorf("100 mediums scored %v against one at %v: density is not being reflected", hundred, one)
	}
}

// --- the design document's worked examples -----------------------------------

// Every row of the table in docs/architecture/risk-engine.md, recomputed by the
// engine. If the code and the document ever disagree about what a project
// scores, this is where it surfaces.
func TestTheWorkedExamplesInTheDesignDocument(t *testing.T) {
	worstCtx := Context{
		Environment:    projects.EnvProduction,
		Criticality:    projects.CriticalityCritical,
		InternetFacing: true,
	}
	devCtx := Context{Environment: projects.EnvDevelopment, Criticality: projects.CriticalityLow}

	worstCase := func(n int) []Subject {
		out := many(n, normalization.SeverityCritical)
		for i := range out {
			out[i] = withEPSS(out[i], 0.99)
		}
		return out
	}

	tests := []struct {
		name      string
		subjects  []Subject
		ctx       Context
		wantTotal float64
		wantScore float64
	}{
		{"one medium, neutral", many(1, normalization.SeverityMedium), neutralContext(), 8.0, 3.92},
		{"one critical, dev sandbox", many(1, normalization.SeverityCritical), devCtx, 21.0, 9.97},
		{"one worst-case critical", worstCase(1), worstCtx, 335.25, 81.29},
		{"ten worst-case criticals", worstCase(10), worstCtx, 787.84, 98.05},
		{"fifty lows, neutral", many(50, normalization.SeverityLow), neutralContext(), 8.35, 4.09},
		{"one hundred mediums, neutral", many(100, normalization.SeverityMedium), neutralContext(), 126.8, 46.95},
		{"five hundred info, neutral", many(500, normalization.SeverityInfo), neutralContext(), 3.79, 1.88},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(tc.subjects, tc.ctx)
			if !closeTo(got.Total, tc.wantTotal) {
				t.Errorf("total = %v, want %v", got.Total, tc.wantTotal)
			}
			if !closeTo(got.Score, tc.wantScore) {
				t.Errorf("score = %v, want %v", got.Score, tc.wantScore)
			}
		})
	}
}

// K is not a number someone liked; it is solved from a stated anchor. If the
// anchor is ever changed without K following, this fails.
func TestSaturationIsCalibratedToItsStatedAnchor(t *testing.T) {
	got := Assess(
		[]Subject{withEPSS(subject("a", normalization.SeverityCritical), 0.99)},
		Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityCritical, InternetFacing: true},
	).Score

	if got < 78 || got > 84 {
		t.Errorf("one worst-case finding scored %v, want ~80 as the anchor in ADR 019 §5 states", got)
	}
}

// --- aggregation arithmetic --------------------------------------------------

func TestAggregateIsMaxDominant(t *testing.T) {
	// total = max + λ(Σ − max) = 100 + 0.15 × 30 = 104.5
	total, _ := aggregate([]float64{100, 10, 20}, 0.15, 200)
	if !closeTo(total, 104.5) {
		t.Errorf("total = %v, want 104.5", total)
	}

	// λ = 0 is the pure maximum; λ = 1 is the plain sum. Both are reachable,
	// which is what makes the choice of 0.15 a dial rather than a hidden rule.
	if pureMax, _ := aggregate([]float64{100, 10, 20}, 0, 200); !closeTo(pureMax, 100) {
		t.Errorf("λ=0 gave %v, want the maximum 100", pureMax)
	}
	if plainSum, _ := aggregate([]float64{100, 10, 20}, 1, 200); !closeTo(plainSum, 130) {
		t.Errorf("λ=1 gave %v, want the sum 130", plainSum)
	}
}

func TestAggregateOfNothingIsZero(t *testing.T) {
	total, score := aggregate(nil, 0.15, 200)
	if total != 0 || score != 0 {
		t.Errorf("aggregate(nil) = (%v, %v), want (0, 0)", total, score)
	}
}
