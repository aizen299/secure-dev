package grype

import (
	"encoding/json"
	"fmt"

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
