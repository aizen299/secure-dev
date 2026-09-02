package grype

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Normalize converts grype output into canonical findings.
//
// Pure: bytes in, findings out, no I/O (§8). Everything grype-specific stops
// here.
//
// Grype findings carry no rule: their identity is the vulnerability plus the
// affected component. That is what makes two scanners reporting one CVE on one
// package produce a single fingerprint, which is the behaviour §9's correlation
// is built on.
func Normalize(data []byte, scanID string) (normalization.Result, error) {
	if err := validateReport(data); err != nil {
		return normalization.Result{}, err
	}

	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return normalization.Result{}, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	out := normalization.Result{}
	for i, m := range r.Matches {
		pkg := m.Artifact.PURL
		if pkg == "" && m.Artifact.Name != "" {
			pkg = m.Artifact.Name + "@" + m.Artifact.Version
		}

		fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
			Category: scanners.CategoryDependency,
			// No RuleID on purpose: a CVE on a package is the same problem
			// whichever scanner reports it.
			Package:         pkg,
			VulnerabilityID: m.Vulnerability.ID,
		})
		if err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("match %d: %v", i, err))
			continue
		}

		finding := normalization.Finding{
			Fingerprint:      fingerprint,
			Scanner:          Name,
			ScannerFindingID: m.Vulnerability.ID,
			ScannerSeverity:  m.Vulnerability.Severity,
			Category:         scanners.CategoryDependency,
			Severity:         normalization.MapSeverity(m.Vulnerability.Severity),
			Confidence:       normalization.ConfidenceHigh,
			Title:            vulnerabilityTitle(m),
			Package:          m.Artifact.Name,
			PackageVersion:   m.Artifact.Version,
			PURL:             m.Artifact.PURL,
			CVE:              m.Vulnerability.ID,
			Status:           normalization.StatusOpen,
		}

		// Threat intelligence is attached after the finding is built, because
		// a bad EPSS must not discard a real vulnerability. Scanner output is
		// untrusted (§15.7): the value is range-checked here and dropped with
		// a note if it fails, leaving the finding intact.
		epss, note := epssFor(m)
		if note != "" {
			out.Errors = append(out.Errors, fmt.Sprintf("match %d: %s", i, note))
		}
		finding.Threat.EPSS = epss
		if err := finding.Validate(); err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("match %d: %v", i, err))
			continue
		}

		out.Findings = append(out.Findings, finding)
		// A dependency finding has no line, and often no file that means
		// anything: it is about a component, not a place.
		out.Occurrences = append(out.Occurrences, normalization.Occurrence{
			Fingerprint: fingerprint,
			ScanID:      scanID,
			Scanner:     Name,
		})
	}
	return out, nil
}

func vulnerabilityTitle(m match) string {
	name := m.Artifact.Name
	if name == "" {
		name = "an unnamed component"
	}
	if m.Vulnerability.ID == "" {
		return "Known vulnerability in " + name
	}
	return m.Vulnerability.ID + " in " + name
}

// Normalize implements normalization.Normalizer, so the worker can normalize
// this adapter's output without knowing which adapter it is (§7 rule 2).
func (s *Scanner) Normalize(raw []byte, scanID string) (normalization.Result, error) {
	return Normalize(raw, scanID)
}

// epssFor resolves the one EPSS value that applies to this match, if any.
//
// Selection is a decision rather than a field read. Grype reports EPSS as an
// array keyed by CVE while the vulnerability itself is often a GHSA advisory,
// so the entry has to be associated through the advisory's aliases in
// relatedVulnerabilities.
//
// Returns nil whenever the value cannot be established. Nil means "no signal",
// which is deliberately different from a signal reporting a low probability
// (ADR 018) -- so guessing here would manufacture evidence.
func epssFor(m match) (*normalization.EPSS, string) {
	if len(m.Vulnerability.EPSS) == 0 {
		return nil, ""
	}

	// Every identifier this advisory is known by. EPSS entries are matched
	// against all of them, so a GHSA advisory picks up its CVE's score.
	ids := map[string]bool{m.Vulnerability.ID: true}
	for _, rel := range m.RelatedVulnerabilities {
		if rel.ID != "" {
			ids[rel.ID] = true
		}
	}

	// The most likely to be exploited governs. An advisory covering several
	// CVEs exposes the component to all of them, and under-reporting is the
	// dangerous direction -- the same reasoning that makes deduplication keep
	// the higher severity. Both numbers come from the one chosen entry:
	// probability and percentile rank differently, so mixing fields across
	// entries would describe a vulnerability that does not exist.
	var best *epssEntry
	for i := range m.Vulnerability.EPSS {
		e := &m.Vulnerability.EPSS[i]
		if !ids[e.CVE] {
			continue
		}
		if best == nil || e.Probability > best.Probability {
			best = e
		}
	}
	if best == nil {
		// Scores present, but none of them is for a vulnerability this finding
		// represents. Saying nothing is correct; picking one anyway would
		// attach another CVE's likelihood to this finding.
		return nil, ""
	}

	if best.Probability < 0 || best.Probability > 1 {
		return nil, fmt.Sprintf("epss probability %v is outside 0-1, dropped", best.Probability)
	}
	if best.Percentile < 0 || best.Percentile > 1 {
		return nil, fmt.Sprintf("epss percentile %v is outside 0-1, dropped", best.Percentile)
	}

	// Provenance is mandatory, so an unparseable date drops the value rather
	// than storing a number of unknown age (ADR 018).
	observed, err := time.Parse(time.DateOnly, best.Date)
	if err != nil {
		return nil, fmt.Sprintf("epss date %q is not a date, dropped", best.Date)
	}

	return &normalization.EPSS{
		Probability: best.Probability,
		Percentile:  best.Percentile,
		Source:      normalization.SourceGrype,
		ObservedAt:  observed.UTC(),
	}, ""
}
