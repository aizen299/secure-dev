package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
)

// ErrInvalidWeights reports a configuration that would produce a meaningless
// score.
//
// Returned rather than tolerated. A weight table with a missing severity does
// not score those findings slightly wrong -- it scores them by a fallback
// nobody chose, and a security number nobody chose is worse than no number.
var ErrInvalidWeights = errors.New("invalid risk weights")

// Weights is every tunable number in the engine (§10: "weights are
// configuration, not magic numbers scattered in code").
//
// The neutral point of 1.0 is deliberately NOT in here. It is not a tuning
// knob; it is the definition that makes factor isolation testable -- a factor
// with no information must contribute exactly 1.0, or "we have no data" starts
// silently moving the score.
type Weights struct {
	// Severity is the base magnitude per level. Geometric, not ordinal: see
	// docs/architecture/risk-engine.md, factor 1.
	Severity map[normalization.Severity]float64

	// Environment and InternetFacing together form the exposure factor.
	Environment    map[projects.Environment]float64
	InternetFacing float64

	// Criticality is the declared importance of the project.
	Criticality map[projects.Criticality]float64

	// Confidence discounts findings that may not be real. Bounded at 1.0 by
	// Validate: uncertainty is not evidence, so confidence never inflates.
	Confidence map[normalization.Confidence]float64

	// ExploitabilityFloor is what a finding at EPSS percentile 0.0 scores.
	// Exploitability = ExploitabilityFloor + percentile, so the range is
	// [floor, floor+1] and the neutral 1.0 must lie inside it.
	ExploitabilityFloor float64

	// TailWeight is λ: how much everything below the worst finding counts.
	// Constrained to [0, 1], which is what the monotonicity proof assumes.
	TailWeight float64

	// Saturation is K, derived from a stated anchor rather than chosen. See
	// the aggregation section of docs/architecture/risk-engine.md.
	Saturation float64
}

// DefaultWeights returns the calibrated defaults documented in
// docs/architecture/risk-engine.md. Every value there is this value.
func DefaultWeights() Weights {
	return Weights{
		Severity: map[normalization.Severity]float64{
			normalization.SeverityCritical: 100.0,
			normalization.SeverityHigh:     30.0,
			normalization.SeverityMedium:   8.0,
			normalization.SeverityUnknown:  5.0,
			normalization.SeverityLow:      1.0,
			normalization.SeverityInfo:     0.05,
		},
		Environment: map[projects.Environment]float64{
			projects.EnvProduction:  1.0,
			projects.EnvStaging:     0.6,
			projects.EnvDevelopment: 0.3,
		},
		InternetFacing: 1.5,
		Criticality: map[projects.Criticality]float64{
			projects.CriticalityCritical: 1.5,
			projects.CriticalityHigh:     1.2,
			projects.CriticalityMedium:   1.0,
			projects.CriticalityLow:      0.7,
		},
		Confidence: map[normalization.Confidence]float64{
			normalization.ConfidenceHigh:   1.0,
			normalization.ConfidenceMedium: 0.75,
			normalization.ConfidenceLow:    0.5,
		},
		ExploitabilityFloor: 0.5,
		TailWeight:          0.15,
		Saturation:          200.0,
	}
}

// Validate reports whether these weights can produce a score worth reading.
//
// The checks are the invariants the design document states as rules, not
// defensive noise: each one, if violated, breaks a property §10 requires.
func (w Weights) Validate() error {
	// Completeness. A missing entry is the failure that would otherwise be
	// silent -- the finding still gets scored, by a number nobody configured.
	for _, s := range []normalization.Severity{
		normalization.SeverityCritical, normalization.SeverityHigh,
		normalization.SeverityMedium, normalization.SeverityUnknown,
		normalization.SeverityLow, normalization.SeverityInfo,
	} {
		v, ok := w.Severity[s]
		if !ok {
			return fmt.Errorf("%w: no weight for severity %q", ErrInvalidWeights, s)
		}
		// Never zero: a zero weight makes an entire severity invisible to
		// aggregation, which is the exact reason `info` is 0.05 and not 0.
		if v <= 0 {
			return fmt.Errorf("%w: severity %q weighs %v, must be > 0", ErrInvalidWeights, s, v)
		}
	}
	for _, e := range projects.Environments() {
		v, ok := w.Environment[e]
		if !ok {
			return fmt.Errorf("%w: no weight for environment %q", ErrInvalidWeights, e)
		}
		if v <= 0 {
			return fmt.Errorf("%w: environment %q weighs %v, must be > 0", ErrInvalidWeights, e, v)
		}
	}
	for _, c := range projects.Criticalities() {
		v, ok := w.Criticality[c]
		if !ok {
			return fmt.Errorf("%w: no weight for criticality %q", ErrInvalidWeights, c)
		}
		if v <= 0 {
			return fmt.Errorf("%w: criticality %q weighs %v, must be > 0", ErrInvalidWeights, c, v)
		}
	}

	// Confidence can only ever reduce (§ factor 5). A value above 1.0 would
	// let a "we are very sure" finding outscore what the other factors justify.
	for _, c := range []normalization.Confidence{
		normalization.ConfidenceHigh, normalization.ConfidenceMedium, normalization.ConfidenceLow,
	} {
		v, ok := w.Confidence[c]
		if !ok {
			return fmt.Errorf("%w: no weight for confidence %q", ErrInvalidWeights, c)
		}
		if v <= 0 || v > 1 {
			return fmt.Errorf("%w: confidence %q weighs %v, must be within (0, 1]", ErrInvalidWeights, c, v)
		}
	}

	if w.InternetFacing < 1 {
		return fmt.Errorf("%w: internet-facing multiplier is %v, must be >= 1: exposure amplifies, it does not discount",
			ErrInvalidWeights, w.InternetFacing)
	}

	// The neutral 1.0 must lie within [floor, floor+1], or "no EPSS signal"
	// would fall outside the range real signals can take -- making absence
	// systematically better or worse than every measurement.
	if w.ExploitabilityFloor < 0 || w.ExploitabilityFloor > 1 {
		return fmt.Errorf("%w: exploitability floor is %v, must be within [0, 1] so the neutral 1.0 stays in range",
			ErrInvalidWeights, w.ExploitabilityFloor)
	}

	// The monotonicity proof assumes λ ∈ [0, 1]. Outside it the guarantee §10
	// requires is no longer established, so the engine refuses rather than
	// scoring on an assumption it cannot back.
	if w.TailWeight < 0 || w.TailWeight > 1 {
		return fmt.Errorf("%w: tail weight is %v, must be within [0, 1]: monotonicity is only proved on that range",
			ErrInvalidWeights, w.TailWeight)
	}
	if w.Saturation <= 0 {
		return fmt.Errorf("%w: saturation constant is %v, must be > 0", ErrInvalidWeights, w.Saturation)
	}
	return nil
}

// Digest is a stable fingerprint of these weights.
//
// A stored score is only comparable with another if both were computed under
// the same configuration. Weights are deliberately tunable (§10), which means
// a re-tuning silently makes yesterday's 62 and today's 71 measurements of
// different things -- a trend line drawn across that change is fiction. The
// digest is what lets a reader tell the two apart, and it is stored beside
// every persisted score for that reason.
//
// Canonical by construction: keys sorted, floats formatted exactly, so the
// same weights always digest identically regardless of map iteration order.
func (w Weights) Digest() string {
	var b strings.Builder
	write := func(section string, keys []string, get func(string) float64) {
		b.WriteString(section)
		b.WriteByte('{')
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(strconv.FormatFloat(get(k), 'g', -1, 64))
			b.WriteByte(';')
		}
		b.WriteString("}")
	}

	sevKeys := make([]string, 0, len(w.Severity))
	for k := range w.Severity {
		sevKeys = append(sevKeys, string(k))
	}
	write("severity", sevKeys, func(k string) float64 { return w.Severity[normalization.Severity(k)] })

	envKeys := make([]string, 0, len(w.Environment))
	for k := range w.Environment {
		envKeys = append(envKeys, string(k))
	}
	write("environment", envKeys, func(k string) float64 { return w.Environment[projects.Environment(k)] })

	critKeys := make([]string, 0, len(w.Criticality))
	for k := range w.Criticality {
		critKeys = append(critKeys, string(k))
	}
	write("criticality", critKeys, func(k string) float64 { return w.Criticality[projects.Criticality(k)] })

	confKeys := make([]string, 0, len(w.Confidence))
	for k := range w.Confidence {
		confKeys = append(confKeys, string(k))
	}
	write("confidence", confKeys, func(k string) float64 { return w.Confidence[normalization.Confidence(k)] })

	write("scalar", []string{"internet_facing", "exploitability_floor", "tail_weight", "saturation"},
		func(k string) float64 {
			switch k {
			case "internet_facing":
				return w.InternetFacing
			case "exploitability_floor":
				return w.ExploitabilityFloor
			case "tail_weight":
				return w.TailWeight
			default:
				return w.Saturation
			}
		})

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
