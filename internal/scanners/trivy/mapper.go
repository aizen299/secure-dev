package trivy

import (
	"encoding/json"
	"fmt"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// resultBlock is the shape normalization reads. Kept separate from the
// validation types in parser.go, which deliberately keep Results opaque.
type resultBlock struct {
	Results []struct {
		Target            string `json:"Target"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Message       string `json:"Message"`
			Resolution    string `json:"Resolution"`
			Severity      string `json:"Severity"`
			Status        string `json:"Status"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

// Normalize converts trivy output into canonical findings.
//
// Pure: bytes in, findings out, no I/O (§8). Everything trivy-specific stops
// here.
//
// The input is the redacted document the adapter stored, not what trivy
// emitted, so no source content is available to leak into a finding even by
// accident (ADR 015).
func Normalize(data []byte, scanID string) (normalization.Result, error) {
	if err := validateReport(data); err != nil {
		return normalization.Result{}, err
	}
	// Checked again here, for the same reason the semgrep mapper checks its
	// own control: this is the last point before the database.
	if err := assertNoSourceContent(data); err != nil {
		return normalization.Result{}, err
	}

	var doc resultBlock
	if err := json.Unmarshal(data, &doc); err != nil {
		return normalization.Result{}, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	out := normalization.Result{}
	for _, r := range doc.Results {
		location := normalization.NormalizeLocation(r.Target)
		for i, m := range r.Misconfigurations {
			// Trivy reports passing checks too when asked; a finding is a
			// failure. Anything else would inflate every count downstream.
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}

			fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
				Category: scanners.CategoryIaC,
				RuleID:   m.ID,
				Location: location,
			})
			if err != nil {
				out.Errors = append(out.Errors, fmt.Sprintf("%s misconfiguration %d: %v", r.Target, i, err))
				continue
			}

			finding := normalization.Finding{
				Fingerprint:      fingerprint,
				Scanner:          Name,
				ScannerFindingID: m.ID,
				ScannerSeverity:  m.Severity,
				Category:         scanners.CategoryIaC,
				Severity:         normalization.MapSeverity(m.Severity),
				Confidence:       normalization.ConfidenceHigh,
				Title:            misconfigTitle(m.ID, m.Title),
				Description:      m.Description,
				Remediation:      m.Resolution,
				Status:           normalization.StatusOpen,
			}
			if err := finding.Validate(); err != nil {
				out.Errors = append(out.Errors, fmt.Sprintf("%s misconfiguration %d: %v", r.Target, i, err))
				continue
			}

			out.Findings = append(out.Findings, finding)
			out.Occurrences = append(out.Occurrences, normalization.Occurrence{
				Fingerprint: fingerprint,
				ScanID:      scanID,
				File:        location,
				StartLine:   m.CauseMetadata.StartLine,
				EndLine:     m.CauseMetadata.EndLine,
				Scanner:     Name,
			})
		}
	}
	return out, nil
}

func misconfigTitle(id, title string) string {
	if title != "" {
		return title
	}
	if id != "" {
		return "Misconfiguration " + id
	}
	return "Misconfiguration"
}
