//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func dastFinding(fingerprint, endpoint string) normalization.MergedFinding {
	return normalization.MergedFinding{
		Finding: normalization.Finding{
			Fingerprint: fingerprint,
			Scanner:     "zap",
			Title:       "Content Security Policy (CSP) Header Not Set",
			Category:    scanners.CategoryDAST,
			Severity:    normalization.SeverityMedium,
			Confidence:  normalization.ConfidenceHigh,
			Endpoint:    endpoint,
			CWE:         "CWE-693",
			Status:      normalization.StatusOpen,
		},
		Sources: []string{"zap"},
	}
}

// The endpoint survives the round trip, which is what makes "everything wrong
// with /login" a query rather than a correlation key (ADR 026).
func TestDASTFindingRetainsItsEndpoint(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("9")

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{dastFinding(fp, "GET /login")},
		Occurrences: []normalization.Occurrence{{Fingerprint: fp, ScanID: scanID, File: "login", Scanner: "zap"}},
	}, []string{"zap"}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	stored, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{Limit: 10})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("findings = %d, want 1", len(stored))
	}
	if stored[0].Endpoint != "GET /login" {
		t.Errorf("endpoint = %q, want GET /login", stored[0].Endpoint)
	}
	if stored[0].Category != scanners.CategoryDAST {
		t.Errorf("category = %q, want dast", stored[0].Category)
	}
	// The origin must never have been stored: it churns per deployment, and
	// what was scanned is recorded on the scan's target instead.
	if strings.Contains(stored[0].Endpoint, "://") {
		t.Errorf("endpoint %q carries an origin", stored[0].Endpoint)
	}
	// Image and endpoint are mutually exclusive in practice; neither may leak
	// into the other's findings.
	if stored[0].Image != "" {
		t.Errorf("image = %q on a DAST finding", stored[0].Image)
	}
}

// A finding that is not DAST has no endpoint, and NULL must read back as
// absence rather than as an endpoint named "".
func TestNonDASTFindingsHaveNoEndpoint(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)
	fp := fingerprintOf("8")

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, scanID, "gitleaks", 12)},
	}, []string{"gitleaks"}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	stored, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{Limit: 10})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("findings = %d, want 1", len(stored))
	}
	if stored[0].Endpoint != "" {
		t.Errorf("endpoint = %q, want empty for a secret finding", stored[0].Endpoint)
	}
}

// Two endpoints with the same rule are two findings: two places to fix.
func TestTwoEndpointsWithOneRuleAreTwoFindings(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)

	scanID, projectID := seedScan(t, pool)

	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{
		Findings: []normalization.MergedFinding{
			dastFinding(fingerprintOf("7"), "GET /login"),
			dastFinding(fingerprintOf("6"), "GET /admin"),
		},
		Occurrences: []normalization.Occurrence{
			{Fingerprint: fingerprintOf("7"), ScanID: scanID, File: "login", Scanner: "zap"},
			{Fingerprint: fingerprintOf("6"), ScanID: scanID, File: "admin", Scanner: "zap"},
		},
	}, []string{"zap"}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	stored, _, err := store.ListByProject(t.Context(), projectID, findings.Filter{}, findings.Page{Limit: 10})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("findings = %d, want 2: two endpoints are two places to fix", len(stored))
	}
	endpoints := map[string]bool{}
	for _, f := range stored {
		endpoints[f.Endpoint] = true
	}
	if !endpoints["GET /login"] || !endpoints["GET /admin"] {
		t.Errorf("endpoints = %v, want both", endpoints)
	}
}
