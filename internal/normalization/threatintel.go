package normalization

import (
	"fmt"
	"time"
)

// ThreatIntel carries calibrated threat-likelihood signals about a finding's
// vulnerability.
//
// Deliberately separate from severity and CVSS, which answer a different
// question. Severity is how bad this would be if exploited; threat
// intelligence is how likely anyone is to exploit it. Collapsing the two is
// what makes a scoring function look contextual while ranking on severity
// twice (ADR 018).
//
// A container rather than a single field because the signals are known to be
// coming: CISA KEV (known-exploited) and CVSS v4 Exploit Maturity each arrive
// as a sibling, not as a reshaping.
type ThreatIntel struct {
	// EPSS is nil when no value is available. See EPSS.
	EPSS *EPSS
}

// Available reports whether any threat-likelihood signal is present.
//
// Consumers should ask this rather than testing a number, so "we have no
// data" never has to be inferred from a value.
func (t ThreatIntel) Available() bool { return t.EPSS != nil }

// EPSS is an Exploit Prediction Scoring System value.
//
// A pointer wherever it is held, and that is load-bearing rather than
// stylistic: EPSS probabilities are genuinely small -- 0.073 is a real value
// for a critical vulnerability -- so a float64 zero for "no data" would be
// indistinguishable from a real low score. "We do not know" and "essentially
// nobody is exploiting this" are opposite claims, and the same reason
// Severity keeps `unknown` as a distinct value (§8) applies here.
type EPSS struct {
	// Probability is the absolute likelihood of exploitation in the next 30
	// days, 0..1. Small even for dangerous vulnerabilities: it must never be
	// multiplied directly into a severity weight, which would erase the
	// findings that matter most (ADR 018).
	Probability float64
	// Percentile is the rank among all scored vulnerabilities, 0..1. Usually
	// the more legible of the two for a human: 0.939 says "worse than 94% of
	// everything scored" where 0.073 sounds like nothing.
	Percentile float64
	// Source is where this value reached us from, so a disputed or stale
	// value can be traced. "grype" means grype's vulnerability database
	// relayed FIRST.org's model output; a future direct client would record
	// its own origin. Required: a number with no provenance is not evidence.
	Source string
	// ObservedAt is the model date the value came from. EPSS is recomputed
	// daily, so a value without a date cannot be aged out or compared against
	// a newer one. Required.
	ObservedAt time.Time
}

// SourceGrype is the provenance value for EPSS relayed by grype's database.
//
// Named here rather than in the adapter because provenance is a fact about the
// canonical model, and the set of sources is something the platform reasons
// about. The adapter supplies it; it does not define it.
const SourceGrype = "grype"

// Validate checks a threat-intelligence value is complete enough to trust.
//
// Provenance is mandatory (ADR 018): an EPSS with no source or no observation
// date is a number of unknown origin and unknown age, which is worse than no
// value at all because it looks like evidence.
func (t ThreatIntel) Validate() error {
	if t.EPSS == nil {
		return nil
	}
	e := t.EPSS
	if e.Probability < 0 || e.Probability > 1 {
		return fmt.Errorf("%w: epss probability %v is outside 0-1", ErrInvalidFinding, e.Probability)
	}
	if e.Percentile < 0 || e.Percentile > 1 {
		return fmt.Errorf("%w: epss percentile %v is outside 0-1", ErrInvalidFinding, e.Percentile)
	}
	if e.Source == "" {
		return fmt.Errorf("%w: epss has no source; provenance is required", ErrInvalidFinding)
	}
	if e.ObservedAt.IsZero() {
		return fmt.Errorf("%w: epss has no observation date; provenance is required", ErrInvalidFinding)
	}
	return nil
}
