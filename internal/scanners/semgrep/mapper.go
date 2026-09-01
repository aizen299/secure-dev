package semgrep

import (
	"encoding/json"
	"fmt"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Normalize converts semgrep output into canonical findings.
//
// Pure: bytes in, findings out, no I/O (§8). Everything semgrep-specific stops
// here -- nothing downstream knows what a check_id is.
func Normalize(data []byte, scanID string) (normalization.Result, error) {
	if err := validateReport(data); err != nil {
		return normalization.Result{}, err
	}
	// The last place matched source could enter the database. The adapter
	// already refuses to persist output carrying it, and this is checked again
	// because a control verified once is a control that quietly stops working
	// (ADR 014, T-34).
	if err := assertNoMatchedSource(data); err != nil {
		return normalization.Result{}, err
	}

	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return normalization.Result{}, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	out := normalization.Result{}
	for i, res := range r.Results {
		location := normalization.NormalizeLocation(res.Path)
		fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
			Category: scanners.CategorySAST,
			RuleID:   res.CheckID,
			Location: location,
		})
		if err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("result %d: %v", i, err))
			continue
		}

		finding := normalization.Finding{
			Fingerprint:      fingerprint,
			Scanner:          Name,
			ScannerFindingID: res.CheckID,
			ScannerSeverity:  res.Extra.Severity,
			Category:         scanners.CategorySAST,
			// Semgrep's ERROR becomes high rather than critical: its scale
			// describes rule severity, not exploitability, and Phase 6 is what
			// gets to raise a finding on exposure.
			Severity:    normalization.MapSemgrepSeverity(res.Extra.Severity),
			Confidence:  normalization.ConfidenceMedium,
			Title:       sastTitle(res.CheckID),
			Description: res.Extra.Message,
			Status:      normalization.StatusOpen,
		}
		if err := finding.Validate(); err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("result %d: %v", i, err))
			continue
		}

		out.Findings = append(out.Findings, finding)
		out.Occurrences = append(out.Occurrences, normalization.Occurrence{
			Fingerprint: fingerprint,
			ScanID:      scanID,
			File:        location,
			StartLine:   res.Start.Line,
			EndLine:     res.End.Line,
			Scanner:     Name,
		})
	}
	return out, nil
}

// sastTitle names the finding from its rule. Semgrep rule ids are dotted paths
// whose last segment is the human-meaningful part.
func sastTitle(checkID string) string {
	if checkID == "" {
		return "Static analysis finding"
	}
	last := checkID
	for i := len(checkID) - 1; i >= 0; i-- {
		if checkID[i] == '.' {
			last = checkID[i+1:]
			break
		}
	}
	return last
}
