package remediation

import (
	"sort"
	"strconv"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/risk"
)

// maxVersions and maxReferences bound what one action may accumulate. Findings
// carry scanner-supplied content, which is untrusted (§15.7), and an action
// merging hundreds of them must not grow without limit (§15.8).
const (
	maxVersions   = 20
	maxReferences = 20
)

// group collects findings into actions.
//
// The grouping key is what a person acts on, which is why it differs by kind: a
// vulnerable package is fixed once no matter how many advisories name it, while
// two credentials in two files are two separate rotations.
func group(subjects []risk.Subject, perFinding map[string]float64) []Action {
	byKey := make(map[string]*Action)
	var order []string

	for _, s := range subjects {
		kind := kindFor(s.Finding)
		component := componentFor(s.Finding, kind)
		key := string(kind) + ":" + component

		a, seen := byKey[key]
		if !seen {
			a = &Action{Kind: kind, Key: key, Component: component}
			byKey[key] = a
			order = append(order, key)
		}

		a.Members = append(a.Members, Member{
			Fingerprint: s.Fingerprint,
			Scanner:     s.Scanner,
			Severity:    s.Severity,
			Title:       s.Title,
			Risk:        perFinding[s.Fingerprint],
		})
		// Vendor facts accumulate across members: one package with three
		// advisories has three sets of fixed versions, and the action carries
		// all of them rather than picking.
		a.FixedVersions = append(a.FixedVersions, s.Fix.FixedVersions...)
		a.References = append(a.References, s.Fix.References...)
	}

	out := make([]Action, 0, len(order))
	for _, key := range order {
		a := byKey[key]
		a.FixedVersions = dedupe(a.FixedVersions, maxVersions)
		a.References = dedupe(a.References, maxReferences)
		sort.SliceStable(a.Members, func(i, j int) bool {
			return a.Members[i].Fingerprint < a.Members[j].Fingerprint
		})
		a.Statements = statementsFor(*a, subjects)
		out = append(out, *a)
	}
	return out
}

// componentFor names the thing being acted on (§11: always identify the
// affected component).
//
// Derived from canonical fields only. A finding with nothing to name falls back
// to its own identity rather than being grouped with unrelated work -- merging
// on an empty string would collapse every unlocatable finding into one action.
func componentFor(f normalization.Finding, kind Kind) string {
	switch kind {
	case KindUpgrade, KindNoFixAvailable, KindReviewLicense:
		// The package is the unit of work: one upgrade closes every advisory
		// against it. PURL is preferred because it carries the ecosystem, so
		// two packages sharing a bare name are not merged.
		if p := strings.TrimSpace(f.PURL); p != "" {
			return p
		}
		if p := strings.TrimSpace(f.Package); p != "" {
			return p
		}
	case KindRotateCredential:
		// A credential is rotated where it lives. Location comes from the
		// occurrence rather than the finding, so the fingerprint is the stable
		// stand-in: two secrets are never one rotation.
		return f.Fingerprint
	case KindReconfigure, KindChangeCode:
		// One rule in one place. The scanner's own rule id identifies the
		// check; the fingerprint keeps two sites of the same rule distinct,
		// which is right -- each needs its own edit.
		if id := strings.TrimSpace(f.ScannerFindingID); id != "" {
			return id + "@" + f.Fingerprint[:min(12, len(f.Fingerprint))]
		}
	}
	return f.Fingerprint
}

// statementsFor builds the human account of an action, each claim tagged with
// where it came from (§11).
//
// Nothing here invents a fix. Vendor prose is passed through as `vendor`, the
// scanner's own words as `scanner`, and SecureOps' summary of them as
// `derived` -- never as AI, and never as a version nobody reported.
func statementsFor(a Action, subjects []risk.Subject) []Statement {
	out := make([]Statement, 0, 4)

	switch a.Kind {
	case KindUpgrade:
		out = append(out, Statement{
			Source: SourceDerived,
			Text: "Upgrade " + a.Component + " to a version that resolves " +
				plural(len(a.Members), "finding") + ". Versions reported as fixed: " +
				strings.Join(a.FixedVersions, ", ") + ".",
		})
		out = append(out, Statement{
			Source: SourceVendor,
			Text:   "Fixed versions are as published by the advisory source; SecureOps does not choose between them.",
		})
	case KindNoFixAvailable:
		out = append(out, Statement{
			Source: SourceDerived,
			Text: "No upgrade target is known for " + a.Component + ". " +
				fixStateAccount(a, subjects) +
				" Mitigate with a compensating control, or record an accepted risk.",
		})
	case KindRotateCredential:
		out = append(out, Statement{
			Source: SourceDerived,
			Text:   "Revoke this credential at its issuer first. Removing it from the file does not invalidate it, and it remains in git history.",
		})
	}

	// Whatever the scanners themselves said about fixing it, verbatim and
	// attributed. Trivy's Resolution is vendor guidance; Gitleaks' sentence is
	// the adapter's own. Both are the scanner's words, not ours.
	for _, s := range subjects {
		if !memberOf(a, s.Fingerprint) {
			continue
		}
		if r := strings.TrimSpace(s.Remediation); r != "" {
			out = appendUnique(out, Statement{Source: SourceScanner, Text: r})
		}
	}
	return out
}

// fixStateAccount says which flavour of "no fix" applies, because the three are
// genuinely different decisions.
func fixStateAccount(a Action, subjects []risk.Subject) string {
	var wontFix, notFixed, unknown bool
	for _, s := range subjects {
		if !memberOf(a, s.Fingerprint) {
			continue
		}
		switch s.Fix.State {
		case normalization.FixStateWontFix:
			wontFix = true
		case normalization.FixStateNotFixed:
			notFixed = true
		default:
			unknown = true
		}
	}
	switch {
	case wontFix:
		return "The maintainer has declined to fix at least one of these, so no upgrade will ever resolve it."
	case notFixed:
		return "A fix is not yet available."
	case unknown:
		return "No scanner reported whether a fix exists, which is not the same as there being none."
	default:
		return ""
	}
}

func memberOf(a Action, fingerprint string) bool {
	for _, m := range a.Members {
		if m.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

func appendUnique(in []Statement, s Statement) []Statement {
	for _, existing := range in {
		if existing.Text == s.Text && existing.Source == s.Source {
			return in
		}
	}
	return append(in, s)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
