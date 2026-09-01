package gitleaks

import (
	"fmt"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Normalize converts gitleaks output into canonical findings.
//
// Pure: bytes in, findings out, no I/O (§8). Everything gitleaks-specific stops
// here -- nothing downstream knows what a RuleID is.
func Normalize(data []byte, scanID string) (normalization.Result, error) {
	findings, err := parseReport(data)
	if err != nil {
		return normalization.Result{}, err
	}

	out := normalization.Result{}
	for i, f := range findings {
		// The redaction control runs before storage, so this should never
		// trigger. Asserted anyway: normalization is the last place a secret
		// could enter the database, and a control that is only checked once is
		// a control that quietly stops working (ADR 007).
		if !isRedactedSecret(f.Secret) || !isRedactedMatch(f.Match) {
			out.Errors = append(out.Errors,
				fmt.Sprintf("finding %d: unredacted secret material; discarded", i))
			continue
		}

		location := normalization.NormalizeLocation(f.File)
		fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
			Category: scanners.CategorySecrets,
			RuleID:   f.RuleID,
			Location: location,
		})
		if err != nil {
			// The value is not quoted: it came from untrusted content.
			out.Errors = append(out.Errors, fmt.Sprintf("finding %d: %v", i, err))
			continue
		}

		finding := normalization.Finding{
			Fingerprint:      fingerprint,
			Scanner:          Name,
			ScannerFindingID: f.Fingerprint,
			// Gitleaks reports no severity at all. SecureOps calls a committed
			// credential critical, and leaves ScannerSeverity empty so its
			// judgement is never mistaken for the scanner's.
			ScannerSeverity: "",
			Category:        scanners.CategorySecrets,
			Severity:        normalization.SeverityCritical,
			Confidence:      normalization.ConfidenceHigh,
			Title:           secretTitle(f.RuleID),
			Description:     f.Description,
			Remediation:     "Revoke the credential, then remove it from the file and from history.",
			Status:          normalization.StatusOpen,
		}
		if err := finding.Validate(); err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("finding %d: %v", i, err))
			continue
		}

		out.Findings = append(out.Findings, finding)
		out.Occurrences = append(out.Occurrences, normalization.Occurrence{
			Fingerprint: fingerprint,
			ScanID:      scanID,
			File:        location,
			StartLine:   f.StartLine,
			EndLine:     f.EndLine,
			Scanner:     Name,
		})
	}
	return out, nil
}

// secretTitle names the finding without repeating any part of the secret.
func secretTitle(ruleID string) string {
	if ruleID == "" {
		return "Exposed credential"
	}
	return "Exposed credential (" + ruleID + ")"
}
