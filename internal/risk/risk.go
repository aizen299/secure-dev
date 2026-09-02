// Package risk turns findings into one contextual number (§10).
//
// The engine is pure: given the same findings and the same project context it
// produces the same score, always -- no I/O, no network, no clock, no database.
// That is not a stylistic preference. It is what makes the monotonicity and
// factor-isolation properties §10 mandates testable at all, and what lets a
// gate result be re-derived months later from stored inputs.
//
// No AI, no LLM, and no heuristic model influences a score. §10 and §25.6 are
// explicit: AI may explain a score, never produce one.
//
// The formula, every weight, and the derivation of every constant are in
// docs/architecture/risk-engine.md and ADR 019. This package implements that
// document; where the two disagree the document is right and the code is a bug.
package risk

import (
	"math"
	"sort"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
)

// Context is the project-level input to scoring.
//
// Declared by an operator, never inferred. Exposure and criticality are the
// factors that separate "a critical in a sandbox" from "a critical on the
// internet", and only a human knows which one they are looking at.
type Context struct {
	Environment    projects.Environment
	Criticality    projects.Criticality
	InternetFacing bool
}

// Subject is one finding as the risk engine sees it.
//
// It carries the finding plus the two things scoring needs that the finding
// itself does not know: which scanners reported this identity, and whether
// correlation placed it in an issue whose severity was escalated.
type Subject struct {
	normalization.Finding

	// Sources are the scanner names that reported this fingerprint, as
	// deduplication recorded them. Two or more raises confidence -- never
	// severity, which is correlation's to raise (ADR 017).
	Sources []string

	// IssueSeverity is the severity of the correlated issue this finding
	// belongs to. Empty when it belongs to none. Used only when it is worse
	// than the finding's own: correlation may raise a finding's severity,
	// never lower it.
	IssueSeverity normalization.Severity
	// IssueKey names that issue, for the explanation.
	IssueKey string
}

// Factor is one multiplier in a score, with the reason it took that value.
//
// Neutral records that the factor contributed 1.0 for lack of data rather than
// because the data said "average". A score that cannot tell those apart cannot
// be argued with, and §12 has to explain gate results to people who will.
type Factor struct {
	Name    string
	Value   float64
	Reason  string
	Neutral bool
}

// Score is one finding's risk and the full derivation of it.
type Score struct {
	Fingerprint string
	Value       float64
	// Severity actually used, which is the issue's where correlation raised it.
	Severity normalization.Severity
	// Escalated records that Severity came from the issue rather than the
	// finding, so the claim is visible rather than folded into the number.
	Escalated bool
	// Dismissed findings score zero and are excluded from the project total.
	Dismissed bool
	Factors   []Factor
}

// Assessment is a project's risk, and every score that produced it.
type Assessment struct {
	// Score is 0 (secure) to 100 (critical).
	Score float64
	// Total is the aggregate before saturation, kept because it keeps
	// distinguishing projects after Score has saturated near 100.
	Total float64
	// Findings holds every subject in input order, dismissed ones included at
	// zero. Correlation's rule applies here too: explain, never discard.
	Findings  []Score
	Live      int
	Dismissed int
}

// Assess scores a project with the documented default weights.
func Assess(subjects []Subject, pc Context) Assessment {
	return assess(subjects, pc, DefaultWeights())
}

// AssessWith scores a project with caller-supplied weights.
//
// The weights are validated before anything is scored, so a misconfiguration
// is an error rather than a plausible-looking wrong number.
func AssessWith(subjects []Subject, pc Context, w Weights) (Assessment, error) {
	if err := w.Validate(); err != nil {
		return Assessment{}, err
	}
	return assess(subjects, pc, w), nil
}

// assess is the scoring core. Weights are assumed valid.
func assess(subjects []Subject, pc Context, w Weights) Assessment {
	out := Assessment{Findings: make([]Score, 0, len(subjects))}
	values := make([]float64, 0, len(subjects))

	for _, s := range subjects {
		sc := w.scoreOne(s, pc)
		out.Findings = append(out.Findings, sc)
		if sc.Dismissed {
			out.Dismissed++
			continue
		}
		out.Live++
		values = append(values, sc.Value)
	}

	out.Total, out.Score = aggregate(values, w.TailWeight, w.Saturation)
	return out
}

// scoreOne applies the five factors to one finding.
func (w Weights) scoreOne(s Subject, pc Context) Score {
	sc := Score{Fingerprint: s.Fingerprint}

	// A human decided this finding does not count. Honouring that is the whole
	// point of having a lifecycle: a dismissed finding that still moved the
	// score would mean the decision never took effect.
	if dismissed(s.Status) {
		sc.Dismissed = true
		sc.Severity = s.Severity
		sc.Factors = []Factor{{
			Name:   "status",
			Value:  0,
			Reason: "dismissed as " + string(s.Status),
		}}
		return sc
	}

	sc.Severity, sc.Escalated = effectiveSeverity(s)
	sevWeight, sevReason := w.severityFactor(sc, s)
	expl := w.exploitabilityFactor(s.Threat)
	exposure := w.exposureFactor(pc)
	crit := w.criticalityFactor(pc)
	conf := w.confidenceFactor(s)

	sc.Factors = []Factor{
		{Name: "severity", Value: sevWeight, Reason: sevReason},
		expl, exposure, crit, conf,
	}
	sc.Value = sevWeight * expl.Value * exposure.Value * crit.Value * conf.Value
	return sc
}

// effectiveSeverity picks the severity to score at.
//
// The issue's severity wins only when it is worse. Correlation escalates; it
// never de-escalates, and a lower issue severity would mean a bug upstream
// silently discounting a finding here.
func effectiveSeverity(s Subject) (normalization.Severity, bool) {
	if s.IssueSeverity == "" || !s.IssueSeverity.Valid() {
		return s.Severity, false
	}
	if s.IssueSeverity.Rank() > s.Severity.Rank() {
		return s.IssueSeverity, true
	}
	return s.Severity, false
}

func (w Weights) severityFactor(sc Score, s Subject) (float64, string) {
	v, ok := w.Severity[sc.Severity]
	if !ok {
		// A severity outside the enum means a finding that should not have
		// validated. Score it as `unknown` rather than dropping it: an
		// unreadable assessment is closer to "nobody assessed this" than to
		// "this does not matter", and a silently dropped finding is the worse
		// failure (§8).
		v = w.Severity[normalization.SeverityUnknown]
		return v, "unrecognised severity " + string(sc.Severity) + ", scored as unknown"
	}
	reason := string(sc.Severity)
	if sc.Escalated {
		reason += ", escalated from " + string(s.Severity) + " by issue " + s.IssueKey
	}
	return v, reason
}

// exploitabilityFactor derives how likely exploitation is, from threat
// intelligence (ADR 018).
//
// Percentile, never probability: EPSS probabilities are absolute and skewed
// toward zero, so multiplying a severity weight by one erases exactly the
// findings that matter most (ADR 018 §5).
func (w Weights) exploitabilityFactor(t normalization.ThreatIntel) Factor {
	if !t.Available() {
		// Neutral, never low. Scoring "we do not know" as "nobody is
		// exploiting this" is the error the *EPSS pointer exists to prevent.
		return Factor{
			Name:    "exploitability",
			Value:   1.0,
			Reason:  "no threat intelligence available",
			Neutral: true,
		}
	}
	e := t.EPSS
	return Factor{
		Name:   "exploitability",
		Value:  w.ExploitabilityFloor + e.Percentile,
		Reason: "EPSS percentile " + trim(e.Percentile) + " (" + e.Source + ", " + e.ObservedAt.Format("2006-01-02") + ")",
	}
}

func (w Weights) exposureFactor(pc Context) Factor {
	base, ok := w.Environment[pc.Environment]
	reason := string(pc.Environment)
	neutral := false
	if !ok {
		// An unset or unknown environment is missing context, not evidence of
		// safety. Neutral keeps it from discounting a real finding.
		base = 1.0
		reason = "environment not declared"
		neutral = true
	}
	if pc.InternetFacing {
		base *= w.InternetFacing
		reason += ", internet-facing"
	}
	return Factor{Name: "exposure", Value: base, Reason: reason, Neutral: neutral}
}

func (w Weights) criticalityFactor(pc Context) Factor {
	v, ok := w.Criticality[pc.Criticality]
	if !ok {
		return Factor{
			Name:    "criticality",
			Value:   1.0,
			Reason:  "criticality not declared",
			Neutral: true,
		}
	}
	return Factor{Name: "criticality", Value: v, Reason: string(pc.Criticality)}
}

// confidenceFactor discounts findings that may not be real, and applies the
// corroboration rule.
//
// Corroboration raises the *level* by one step before the table is read, rather
// than multiplying the result. This is the seam ADR 017 reserved: cross-domain
// agreement means "worse" and belongs to correlation, same-domain agreement
// means "more likely to be real" and belongs here. Counting either twice would
// inflate exactly the findings a security team is most likely to be looking at.
//
// KNOWN LIMIT: distinct scanner names are treated as distinct evidence, and
// they are not -- Grype and Trivy read overlapping advisory feeds. The one-step
// cap bounds the overstatement. Fixing it properly needs adapters to declare an
// evidence family (§7), never a scanner conditional here, which §7.2 and §25.3
// forbid. See docs/architecture/risk-engine.md.
func (w Weights) confidenceFactor(s Subject) Factor {
	level := s.Confidence
	if !level.Valid() {
		level = normalization.ConfidenceLow
	}

	reporters := distinct(s.Sources)
	reason := string(level)
	if len(reporters) >= 2 {
		if raised, ok := raiseConfidence(level); ok {
			level = raised
			reason = string(level) + ", raised by agreement between " + join(reporters)
		} else {
			reason = string(level) + ", corroborated by " + join(reporters)
		}
	}

	v, ok := w.Confidence[level]
	if !ok {
		v = w.Confidence[normalization.ConfidenceLow]
	}
	return Factor{Name: "confidence", Value: v, Reason: reason}
}

// raiseConfidence moves one step up: low → medium → high, capped at high.
func raiseConfidence(c normalization.Confidence) (normalization.Confidence, bool) {
	switch c {
	case normalization.ConfidenceLow:
		return normalization.ConfidenceMedium, true
	case normalization.ConfidenceMedium:
		return normalization.ConfidenceHigh, true
	default:
		return c, false
	}
}

// dismissed reports whether a human has taken this finding out of scope.
//
// The complement of correlation's live set, kept identical on purpose: the two
// engines must agree on which findings exist, or a gate can fail on a finding
// the dashboard does not show. An empty status is live -- it is what a newly
// stored finding carries before the lifecycle assigns one.
func dismissed(s normalization.Status) bool {
	switch s {
	case normalization.StatusResolved, normalization.StatusFalsePositive, normalization.StatusIgnored:
		return true
	default:
		return false
	}
}

// aggregate combines finding risks into a project total (ADR 019 §4).
//
//	total = max + λ × (Σ − max)
//	score = 100 × (1 − e^(−total ÷ K))
//
// The worst finding sets the floor and everything else is pressure above it.
// A plain sum would make volume and severity interchangeable -- 500
// informational findings outscoring the worst finding the model can express --
// and for a security score they are not.
//
// Monotonic for λ ∈ [0, 1], which Validate enforces: adding r ≤ max raises the
// total by exactly λr, and adding r > max raises it by r − max(1−λ) > 0.
func aggregate(values []float64, lambda, k float64) (total, score float64) {
	if len(values) == 0 {
		return 0, 0
	}

	sum, max := 0.0, values[0]
	for _, v := range values {
		sum += v
		if v > max {
			max = v
		}
	}

	total = max + lambda*(sum-max)
	score = 100 * (1 - math.Exp(-total/k))

	// Defensive only. The arithmetic above cannot leave [0, 100] for finite
	// non-negative inputs, but a score outside it would be read as fact by a
	// gate, so it is clamped rather than trusted.
	if math.IsNaN(score) || score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return total, score
}

// distinct returns the unique, sorted entries of in.
func distinct(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
