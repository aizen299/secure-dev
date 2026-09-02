package risk

import (
	"errors"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
)

func TestDefaultWeightsAreValid(t *testing.T) {
	if err := DefaultWeights().Validate(); err != nil {
		t.Fatalf("the shipped defaults do not validate: %v", err)
	}
}

// The defaults are the design document's numbers, and this test is the tripwire
// that keeps them so. §21 names the risk formula as the part of the system most
// likely to drift; a weight changed in code without the document changing with
// it is precisely that drift, and it would otherwise be invisible.
func TestDefaultWeightsMatchTheDesignDocument(t *testing.T) {
	w := DefaultWeights()

	for sev, want := range map[normalization.Severity]float64{
		normalization.SeverityCritical: 100.0,
		normalization.SeverityHigh:     30.0,
		normalization.SeverityMedium:   8.0,
		normalization.SeverityUnknown:  5.0,
		normalization.SeverityLow:      1.0,
		normalization.SeverityInfo:     0.05,
	} {
		if got := w.Severity[sev]; got != want {
			t.Errorf("severity %q = %v, want %v (docs/architecture/risk-engine.md, factor 1)", sev, got, want)
		}
	}
	if w.TailWeight != 0.15 {
		t.Errorf("λ = %v, want 0.15", w.TailWeight)
	}
	if w.Saturation != 200 {
		t.Errorf("K = %v, want 200 (anchored on: one worst-case finding scores ~80)", w.Saturation)
	}

	// Unknown outranks low, matching Severity.Rank(). An unassessed finding
	// deserves more attention than one assessed as unimportant.
	if w.Severity[normalization.SeverityUnknown] <= w.Severity[normalization.SeverityLow] {
		t.Error("unknown must weigh more than low")
	}
	// The spread is geometric, not ordinal: §10 forbids a naive
	// severity-to-number mapping, and a near-linear table is that mapping.
	ratio := w.Severity[normalization.SeverityCritical] / w.Severity[normalization.SeverityInfo]
	if ratio < 1000 {
		t.Errorf("critical:info ratio is %v, want a geometric spread (>= 1000)", ratio)
	}
}

func TestValidateRejectsWeightsThatWouldBreakTheModel(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Weights)
	}{
		{"missing severity", func(w *Weights) { delete(w.Severity, normalization.SeverityHigh) }},
		{"zero severity makes a level invisible", func(w *Weights) {
			w.Severity[normalization.SeverityInfo] = 0
		}},
		{"missing environment", func(w *Weights) { delete(w.Environment, projects.EnvStaging) }},
		{"missing criticality", func(w *Weights) { delete(w.Criticality, projects.CriticalityLow) }},
		{"missing confidence", func(w *Weights) { delete(w.Confidence, normalization.ConfidenceMedium) }},
		{"confidence above 1 would inflate", func(w *Weights) {
			w.Confidence[normalization.ConfidenceHigh] = 1.25
		}},
		{"internet-facing discounts instead of amplifying", func(w *Weights) { w.InternetFacing = 0.8 }},
		{"exploitability floor puts neutral out of range", func(w *Weights) { w.ExploitabilityFloor = 1.4 }},
		{"tail weight outside the monotonicity proof", func(w *Weights) { w.TailWeight = 1.4 }},
		{"negative tail weight", func(w *Weights) { w.TailWeight = -0.1 }},
		{"zero saturation constant", func(w *Weights) { w.Saturation = 0 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := DefaultWeights()
			tc.mutate(&w)
			err := w.Validate()
			if err == nil {
				t.Fatal("accepted weights that break a documented invariant")
			}
			if !errors.Is(err, ErrInvalidWeights) {
				t.Errorf("error = %v, want it to wrap ErrInvalidWeights", err)
			}
			// And the engine must refuse to score at all, rather than
			// producing a plausible-looking number from broken configuration.
			if _, err := AssessWith(nil, neutralContext(), w); err == nil {
				t.Error("AssessWith scored with invalid weights")
			}
		})
	}
}
