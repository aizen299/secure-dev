package httpapi

import (
	"net/http"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func vulnSubject(fp, scanner, purl string, sev normalization.Severity, fix normalization.Fix) risk.Subject {
	return risk.Subject{
		Finding: normalization.Finding{
			Fingerprint: fp, Scanner: scanner, Title: "Vulnerable component",
			Category: scanners.CategoryDependency, Severity: sev,
			Confidence: normalization.ConfidenceHigh, Status: normalization.StatusOpen,
			PURL: purl, Package: "express", Fix: fix,
		},
		Sources: []string{scanner},
	}
}

func TestGetProjectRemediation(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	fs := s.findings.(*fakeFindingStore)
	fs.riskCtx = risk.Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityHigh}
	fs.seedSubjects(project.ID,
		vulnSubject("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityCritical,
			normalization.Fix{State: normalization.FixStateFixed, FixedVersions: []string{"4.19.2"}}),
		vulnSubject("b", "trivy", "pkg:npm/express@4.17.1", normalization.SeverityMedium,
			normalization.Fix{State: normalization.FixStateFixed, FixedVersions: []string{"4.20.0"}}),
		vulnSubject("c", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityLow, normalization.Fix{}),
	)

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/remediation", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	got := decodeBody[remediationResponse](t, rec)
	if got.Addressable != 3 {
		t.Errorf("addressable = %d, want 3", got.Addressable)
	}
	// Two packages, so two actions -- the two express findings consolidate.
	if len(got.Actions) != 2 {
		t.Fatalf("actions = %d, want 2: one package is one action", len(got.Actions))
	}

	top := got.Actions[0]
	if top.Kind != "upgrade" || top.Component != "pkg:npm/express@4.17.1" {
		t.Errorf("top action = %s on %q, want the express upgrade", top.Kind, top.Component)
	}
	if len(top.Members) != 2 {
		t.Errorf("members = %d, want both scanners' findings", len(top.Members))
	}
	if len(top.FixedVersions) != 2 {
		t.Errorf("fixed_versions = %v, want both reported versions", top.FixedVersions)
	}
	if top.RiskRemoved <= 0 {
		t.Errorf("risk_removed = %v, want positive", top.RiskRemoved)
	}
	// Ranked, not merely listed.
	if top.RiskRemoved < got.Actions[1].RiskRemoved {
		t.Errorf("actions are not ranked: %v then %v", top.RiskRemoved, got.Actions[1].RiskRemoved)
	}
}

// §11: AI-derived content must be structurally distinguishable in the API, not
// only in the model. Nothing produces it, and this is where that is visible.
func TestNoRemediationStatementIsSourcedAI(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	fs := s.findings.(*fakeFindingStore)
	fs.seedSubjects(project.ID,
		vulnSubject("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh,
			normalization.Fix{State: normalization.FixStateFixed, FixedVersions: []string{"4.19.2"}}),
		vulnSubject("b", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityHigh,
			normalization.Fix{State: normalization.FixStateWontFix}),
	)

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/remediation", "")
	got := decodeBody[remediationResponse](t, rec)

	var statements int
	for _, a := range got.Actions {
		for _, st := range a.Statements {
			statements++
			if st.Source == "ai_explanation" {
				t.Errorf("action %s carries an AI statement: %q", a.Key, st.Text)
			}
			if st.Source == "" {
				t.Errorf("action %s carries an unattributed statement: %q", a.Key, st.Text)
			}
		}
	}
	if statements == 0 {
		t.Fatal("no statements at all; this test would pass vacuously")
	}
}

// A project with nothing wrong has no work, and says so with an empty list
// rather than a null a client has to guard against.
func TestACleanProjectHasAnEmptyPlan(t *testing.T) {
	s, projectStore, _ := newWiredServer(t, func(*Options) {})
	project := seedProject(t, projectStore)

	rec := authed(t, s, http.MethodGet, "/api/v1/projects/"+project.ID+"/remediation", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := decodeBody[remediationResponse](t, rec)
	if got.Actions == nil {
		t.Error("actions is null, want an empty array")
	}
	if len(got.Actions) != 0 || got.Addressable != 0 {
		t.Errorf("clean project produced %+v", got)
	}
}

func TestRemediationRejectsAMalformedProjectID(t *testing.T) {
	s, _, _ := newWiredServer(t, func(*Options) {})
	rec := authed(t, s, http.MethodGet, "/api/v1/projects/not-a-uuid/remediation", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
