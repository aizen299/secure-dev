package correlation

import "github.com/aizen299/secure-dev/internal/normalization"

// Issue is several findings that share one attribute, treated as one problem.
//
// It links; it does not destroy. Every member remains an individually
// queryable finding with its own severity, its own scanner, and its own
// remediation -- §9 requires it, and §11 depends on it, because each scanner's
// vendor data is the authoritative account of how to fix its own finding.
type Issue struct {
	// Key is what the members share, and the issue's identity.
	Key Key
	// Severity is derived: the worst member, possibly raised one step. It is
	// a classification on the severity enum and never a risk score -- see
	// issueSeverity and ADR 017.
	Severity normalization.Severity
	// Escalated records whether the derivation raised it, so the escalation is
	// visible as a claim rather than folded silently into the value.
	Escalated bool
	// Categories are the distinct domains present, sorted. Two or more is what
	// makes an issue cross-domain, which is the whole point of §9.
	Categories []string
	// Members are the findings, in fingerprint order.
	Members []Member
	// Explanation states the issue in one sentence a person can read.
	Explanation string
}

// Member is one finding's participation in an issue.
type Member struct {
	Fingerprint string
	Scanner     string
	// Severity as the scanner assessed it. Kept on the membership so the
	// issue's derived severity can be compared against what it was derived
	// from, without a second query.
	Severity normalization.Severity
	// Evidence is why this finding is in this issue.
	Evidence string
}

// issueSeverity derives an issue's severity from its members.
//
// The rule, in full: start at the worst member, and raise by one step when the
// members span two or more distinct categories.
//
// One step, because two scanners agreeing on a CVE is usually one vulnerability
// database being consulted twice rather than two independent confirmations.
// Unbounded escalation would turn every much-reported medium into a critical,
// and a scale on which everything is critical carries no information.
//
// Across categories, because that is the contextual signal §9 exists to
// surface: a vulnerable dependency that code demonstrably misuses is worse than
// either fact alone. Corroboration between two scanners in the same domain is
// real evidence too, but it speaks to confidence rather than to severity, and
// confidence is Phase 6's input.
func issueSeverity(members []Subject, categories []string) (normalization.Severity, bool) {
	worst := normalization.SeverityInfo
	for _, m := range members {
		if m.Severity.Rank() > worst.Rank() {
			worst = m.Severity
		}
	}

	if len(categories) < 2 {
		return worst, false
	}
	raised, ok := escalate(worst)
	if !ok {
		return worst, false
	}
	return raised, true
}

// escalate moves one step up the severity ladder.
//
// The ladder is info → low → medium → high → critical. `unknown` is not on it
// and never escalates: raising "the scanner did not say" to `low` would
// manufacture an assessment nobody made, which is the same reason MapSeverity
// refuses to guess. Critical is the top and stays there.
func escalate(s normalization.Severity) (normalization.Severity, bool) {
	switch s {
	case normalization.SeverityInfo:
		return normalization.SeverityLow, true
	case normalization.SeverityLow:
		return normalization.SeverityMedium, true
	case normalization.SeverityMedium:
		return normalization.SeverityHigh, true
	case normalization.SeverityHigh:
		return normalization.SeverityCritical, true
	default:
		// Critical is already the top; unknown is off the ladder entirely.
		return s, false
	}
}
