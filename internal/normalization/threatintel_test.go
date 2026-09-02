package normalization

import (
	"errors"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func validEPSS() *EPSS {
	return &EPSS{
		Probability: 0.07314,
		Percentile:  0.93929,
		Source:      SourceGrype,
		ObservedAt:  time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}
}

func findingWith(t ThreatIntel) Finding {
	return Finding{
		Fingerprint: "fp", Scanner: "grype", Title: "t",
		Category: scanners.CategoryDependency, Severity: SeverityCritical,
		Confidence: ConfidenceHigh, Threat: t,
	}
}

// No signal is a valid state, and the common one. Most vulnerabilities have no
// EPSS score at all.
func TestNoThreatIntelIsValid(t *testing.T) {
	if err := (ThreatIntel{}).Validate(); err != nil {
		t.Errorf("empty threat intel rejected: %v", err)
	}
	if (ThreatIntel{}).Available() {
		t.Error("Available() is true for the zero value")
	}
}

func TestAvailableReportsAPresentSignal(t *testing.T) {
	if !(ThreatIntel{EPSS: validEPSS()}).Available() {
		t.Error("Available() is false with an EPSS present")
	}
}

// Provenance is mandatory (ADR 018). A number whose origin and age are unknown
// is worse than no value, because it looks like evidence.
func TestProvenanceIsRequired(t *testing.T) {
	for name, mutate := range map[string]func(*EPSS){
		"no source": func(e *EPSS) { e.Source = "" },
		"no date":   func(e *EPSS) { e.ObservedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			e := validEPSS()
			mutate(e)
			err := ThreatIntel{EPSS: e}.Validate()
			if err == nil {
				t.Fatal("accepted an EPSS with missing provenance")
			}
			if !errors.Is(err, ErrInvalidFinding) {
				t.Errorf("error = %v, want ErrInvalidFinding", err)
			}
		})
	}
}

// A probability is a probability. Values outside 0-1 mean the source is broken
// or hostile, and scanner output is untrusted (§15.7).
func TestOutOfRangeValuesAreRejected(t *testing.T) {
	for name, mutate := range map[string]func(*EPSS){
		"probability above 1": func(e *EPSS) { e.Probability = 1.5 },
		"probability below 0": func(e *EPSS) { e.Probability = -0.1 },
		"percentile above 1":  func(e *EPSS) { e.Percentile = 42 },
		"percentile below 0":  func(e *EPSS) { e.Percentile = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			e := validEPSS()
			mutate(e)
			if err := (ThreatIntel{EPSS: e}).Validate(); err == nil {
				t.Error("accepted an out-of-range value")
			}
		})
	}
}

// Zero is a legitimate EPSS value meaning "essentially nobody is exploiting
// this". It must validate, because rejecting it would push callers toward
// representing it as absent -- collapsing the very distinction the pointer
// exists to preserve.
func TestZeroProbabilityIsAValidValueNotAnAbsence(t *testing.T) {
	e := validEPSS()
	e.Probability = 0
	e.Percentile = 0
	if err := (ThreatIntel{EPSS: e}).Validate(); err != nil {
		t.Errorf("a genuine zero was rejected: %v", err)
	}
	if !(ThreatIntel{EPSS: e}).Available() {
		t.Error("a zero-probability signal reports as unavailable")
	}
}

// Threat intelligence is validated as part of the finding, not separately, so
// a bad value cannot reach storage through a path that forgot to check it.
func TestFindingValidationCoversThreatIntel(t *testing.T) {
	bad := validEPSS()
	bad.Source = ""
	if err := findingWith(ThreatIntel{EPSS: bad}).Validate(); err == nil {
		t.Error("Finding.Validate accepted an EPSS with no provenance")
	}
	if err := findingWith(ThreatIntel{EPSS: validEPSS()}).Validate(); err != nil {
		t.Errorf("a valid finding was rejected: %v", err)
	}
}
