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
