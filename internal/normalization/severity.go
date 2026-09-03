package normalization

import "strings"

// Severity is SecureOps' own scale. Every scanner's scale maps onto it, and the
// original is kept alongside (§8).
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	// SeverityUnknown means the scanner did not say. It is never guessed: a
	// finding whose severity is unknown must not be silently sorted as low,
	// because "we do not know" and "it does not matter" are different claims.
	SeverityUnknown Severity = "unknown"
)

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium,
		SeverityLow, SeverityInfo, SeverityUnknown:
		return true
	default:
		return false
	}
}

// Rank orders severities for sorting and comparison. Higher is worse.
//
// Note that Unknown ranks above Info: an unassessed finding deserves more
// attention than one assessed as informational.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityUnknown:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// MapSeverity converts a scanner's severity string onto the SecureOps scale.
//
// The mapping is shared rather than per-adapter because the vocabularies
// overlap almost entirely: grype and trivy agree on CRITICAL/HIGH/MEDIUM/LOW,
// and the disagreements are handled by name below. An adapter with a genuinely
// different scale maps it itself before calling this.
//
// Unrecognised input becomes Unknown rather than an error: a scanner adding a
// severity level is not a reason to discard its findings, and Unknown is
// visible in a way that a wrong guess would not be.
func MapSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "negligible", "info", "informational", "none":
		return SeverityInfo
	case "":
		return SeverityUnknown
	default:
		return SeverityUnknown
	}
}

// MapZAPRisk converts ZAP's numeric risk code onto the SecureOps scale.
//
// ZAP's scale is 0-3 and stops at High: it has no "critical". High maps to high
// rather than critical for the same reason semgrep's ERROR does -- it is the
// top of that tool's scale, not a claim that the finding is the worst kind of
// problem there is. Promoting it would fill the top of the risk scale with
// findings nobody assessed for exposure, and Phase 6's risk engine is the thing
// entitled to raise them.
//
// An unrecognised code becomes unknown rather than an error, the same way
// MapSeverity refuses to guess: a ZAP release adding a level is not a reason to
// discard its findings.
func MapZAPRisk(raw string) Severity {
	switch strings.TrimSpace(raw) {
	case "3":
		return SeverityHigh
	case "2":
		return SeverityMedium
	case "1":
		return SeverityLow
	case "0":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// MapZAPConfidence converts ZAP's numeric confidence onto the SecureOps scale.
//
// ZAP's 0 means "False Positive" -- a value a person sets in the GUI, which an
// automated scan never produces. It maps to low rather than being dropped:
// discarding a finding on the strength of a flag this pipeline cannot produce
// would be acting on a state that cannot occur, and low is visible in a way a
// silent drop is not.
//
// 4 is "User Confirmed", which is likewise a human act rather than a scanner
// output; it maps to high alongside 3.
func MapZAPConfidence(raw string) Confidence {
	switch strings.TrimSpace(raw) {
	case "3", "4":
		return ConfidenceHigh
	case "2":
		return ConfidenceMedium
	default:
		// 0 (false positive), 1 (low), and anything unrecognised. A confidence
		// SecureOps cannot interpret must not read as a confident finding.
		return ConfidenceLow
	}
}

// MapSemgrepSeverity converts semgrep's scale, which does not fit the shared
// mapping.
//
// ERROR becomes high rather than critical, deliberately. Semgrep's scale
// describes rule severity, not exploitability: ERROR is its top level and is
// applied liberally across its rulesets. Mapping it to critical would fill the
// top of the risk scale with findings nobody has assessed for exposure, and
// Phase 6's risk engine is the thing entitled to raise them.
func MapSemgrepSeverity(raw string) Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "ERROR":
		return SeverityHigh
	case "WARNING":
		return SeverityMedium
	case "INFO":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// Confidence is how much the platform trusts a finding to be real.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Valid reports whether c is a known confidence.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	default:
		return false
	}
}
