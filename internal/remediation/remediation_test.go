package remediation

import (
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// --- helpers ---------------------------------------------------------------

func ctx() risk.Context {
	return risk.Context{Environment: projects.EnvProduction, Criticality: projects.CriticalityMedium}
}

func dep(fp, scanner, purl string, sev normalization.Severity, fix normalization.Fix) risk.Subject {
	return risk.Subject{
		Finding: normalization.Finding{
			Fingerprint: fp, Scanner: scanner,
			Title:      "Vulnerable component",
			Category:   scanners.CategoryDependency,
			Severity:   sev,
			Confidence: normalization.ConfidenceHigh,
			Status:     normalization.StatusOpen,
			PURL:       purl,
			Package:    "express",
			Fix:        fix,
		},
		Sources: []string{scanner},
	}
}

func fixedAt(versions ...string) normalization.Fix {
	return normalization.Fix{State: normalization.FixStateFixed, FixedVersions: versions}
}

func findAction(t *testing.T, p Plan, kind Kind, component string) Action {
	t.Helper()
	for _, a := range p.Actions {
		if a.Kind == kind && a.Component == component {
			return a
		}
	}
	t.Fatalf("no %s action for %q; got %d actions", kind, component, len(p.Actions))
	return Action{}
}

// --- property 1: determinism ------------------------------------------------

func TestPlansAreDeterministic(t *testing.T) {
	subjects := []risk.Subject{
		dep("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh, fixedAt("4.19.2")),
		dep("b", "trivy", "pkg:npm/express@4.17.1", normalization.SeverityMedium, fixedAt("4.20.0")),
		dep("c", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityCritical, normalization.Fix{}),
	}
	first := Build(subjects, ctx())
	for range 20 {
		got := Build(subjects, ctx())
		if len(got.Actions) != len(first.Actions) {
			t.Fatalf("action count varies: %d then %d", len(first.Actions), len(got.Actions))
		}
		for i := range got.Actions {
			if got.Actions[i].Key != first.Actions[i].Key ||
				got.Actions[i].RiskRemoved != first.Actions[i].RiskRemoved {
				t.Fatalf("plan varies at %d: %+v vs %+v", i, first.Actions[i], got.Actions[i])
			}
		}
	}
}

// --- property 2: consolidation ----------------------------------------------

// The fragmentation the product exists to remove. Two scanners reporting two
// advisories against one package is one upgrade, not two tasks.
func TestOneComponentIsOneUpgradeAcrossScanners(t *testing.T) {
	subjects := []risk.Subject{
		dep("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh, fixedAt("4.19.2")),
		dep("b", "trivy", "pkg:npm/express@4.17.1", normalization.SeverityMedium, fixedAt("4.20.0")),
	}
	p := Build(subjects, ctx())

	if len(p.Actions) != 1 {
		t.Fatalf("actions = %d, want 1: one package is one upgrade", len(p.Actions))
	}
	a := p.Actions[0]
	if len(a.Members) != 2 {
		t.Errorf("members = %d, want both findings retained", len(a.Members))
	}

	// Every reporting scanner survives the merge: an action consolidates work,
	// it does not discard evidence.
	seen := map[string]bool{}
	for _, m := range a.Members {
		seen[m.Scanner] = true
	}
	if !seen["grype"] || !seen["trivy"] {
		t.Errorf("scanners = %v, want both retained", seen)
	}

	// Both vendors' fixed versions are carried; neither is chosen over the other.
	if len(a.FixedVersions) != 2 {
		t.Errorf("fixed versions = %v, want both reported versions", a.FixedVersions)
	}
}

// --- property 3: never invent a fix -----------------------------------------

func TestNoActionNamesAVersionNoScannerReported(t *testing.T) {
	subjects := []risk.Subject{
		dep("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh, fixedAt("4.19.2")),
		dep("b", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityHigh, normalization.Fix{}),
	}
	reported := map[string]bool{"4.19.2": true}

	for _, a := range Build(subjects, ctx()).Actions {
		for _, v := range a.FixedVersions {
			if !reported[v] {
				t.Errorf("action %s names version %q that no scanner reported", a.Key, v)
			}
		}
		// And no statement smuggles a version in as prose.
		for _, st := range a.Statements {
			if strings.Contains(st.Text, "4.20") || strings.Contains(st.Text, "5.0.0") {
				t.Errorf("statement invents a version: %q", st.Text)
			}
		}
	}
}

// --- property 4: unknown is not wont-fix ------------------------------------

// The distinction the fix state exists for. A finding nobody has told us about
// must not produce an upgrade action, and must not be described as unfixable.
func TestUnknownFixStateProducesNoUpgrade(t *testing.T) {
	subjects := []risk.Subject{
		dep("a", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityHigh, normalization.Fix{}),
	}
	p := Build(subjects, ctx())

	a := findAction(t, p, KindNoFixAvailable, "pkg:npm/lodash@4.17.20")
	if len(a.FixedVersions) != 0 {
		t.Errorf("fixed versions = %v, want none", a.FixedVersions)
	}

	var text string
	for _, st := range a.Statements {
		text += st.Text
	}
	if !strings.Contains(text, "No scanner reported whether a fix exists") {
		t.Errorf("unknown was not described as unknown: %q", text)
	}
	if strings.Contains(text, "declined to fix") {
		t.Error("absent fix data was described as wont-fix")
	}
}

func TestWontFixIsDescribedAsPermanent(t *testing.T) {
	subjects := []risk.Subject{
		dep("a", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityHigh,
			normalization.Fix{State: normalization.FixStateWontFix}),
	}
	a := findAction(t, Build(subjects, ctx()), KindNoFixAvailable, "pkg:npm/lodash@4.17.20")

	var text string
	for _, st := range a.Statements {
		text += st.Text
	}
	if !strings.Contains(text, "declined to fix") {
		t.Errorf("wont-fix was not distinguished from unknown: %q", text)
	}
}

// --- property 5: ranking is by risk removed ---------------------------------

// The decision ADR 020 turns on. Under max-dominant aggregation, removing the
// single finding setting a project's floor can beat removing several lesser
// ones that sum higher -- so ranking must measure what an action removes, not
// what it contains.
func TestRankingMeasuresRiskRemovedNotRiskContained(t *testing.T) {
	worst := dep("a", "grype", "pkg:npm/critical@1.0.0", normalization.SeverityCritical, fixedAt("2.0.0"))
	subjects := []risk.Subject{worst}
	// Five mediums on one other package: they sum higher than one critical
	// under a naive sum, and must still rank below it.
	for _, fp := range []string{"b", "c", "d", "e", "f"} {
		subjects = append(subjects,
			dep(fp, "grype", "pkg:npm/medium@1.0.0", normalization.SeverityMedium, fixedAt("2.0.0")))
	}

	p := Build(subjects, ctx())
	if len(p.Actions) != 2 {
		t.Fatalf("actions = %d, want 2", len(p.Actions))
	}
	if p.Actions[0].Component != "pkg:npm/critical@1.0.0" {
		t.Errorf("top action is %q, want the critical: five mediums summing higher must not outrank it",
			p.Actions[0].Component)
	}

	// And the number is literally the score difference, not a proxy.
	top := p.Actions[0]
	if got := p.Score - top.ScoreAfter; got != top.RiskRemoved {
		t.Errorf("risk removed = %v, but score %v -> %v is %v", top.RiskRemoved, p.Score, top.ScoreAfter, got)
	}
	if top.RiskRemoved <= 0 {
		t.Errorf("risk removed = %v, want positive", top.RiskRemoved)
	}
}

// Taking every action must clear the board. If the actions do not collectively
// cover every live finding, the plan is telling someone they are done when they
// are not.
func TestEveryLiveFindingAppearsInSomeAction(t *testing.T) {
	subjects := []risk.Subject{
		dep("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh, fixedAt("4.19.2")),
		dep("b", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityLow, normalization.Fix{}),
		secret("c"), iac("d"), sast("e"),
	}
	p := Build(subjects, ctx())

	covered := map[string]bool{}
	for _, a := range p.Actions {
		for _, m := range a.Members {
			if covered[m.Fingerprint] {
				t.Errorf("%s appears in more than one action", m.Fingerprint)
			}
			covered[m.Fingerprint] = true
		}
	}
	for _, s := range subjects {
		if !covered[s.Fingerprint] {
			t.Errorf("%s (%s) produced no work", s.Fingerprint, s.Category)
		}
	}
	if p.Addressable != len(subjects) {
		t.Errorf("addressable = %d, want %d", p.Addressable, len(subjects))
	}
}

// --- property 6: dismissed findings produce no work -------------------------

func TestDismissedFindingsProduceNoWork(t *testing.T) {
	live := dep("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh, fixedAt("4.19.2"))
	for _, status := range []normalization.Status{
		normalization.StatusResolved,
		normalization.StatusFalsePositive,
		normalization.StatusIgnored,
	} {
		t.Run(string(status), func(t *testing.T) {
			dead := dep("b", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityCritical, fixedAt("5.0.0"))
			dead.Status = status

			p := Build([]risk.Subject{live, dead}, ctx())
			for _, a := range p.Actions {
				if a.Component == "pkg:npm/lodash@4.17.20" {
					t.Errorf("a %s finding produced work: %+v", status, a)
				}
			}
			if p.Addressable != 1 {
				t.Errorf("addressable = %d, want 1", p.Addressable)
			}
		})
	}
}

// --- property 7: no scanner branching ---------------------------------------

// §7.2 and §25.3: the same finding reported by a different scanner must produce
// the same action. Kind derives from category and fix state, never from a name.
func TestActionKindDoesNotDependOnWhichScannerReported(t *testing.T) {
	base := dep("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh, fixedAt("4.19.2"))
	other := base
	other.Scanner = "some-future-scanner"
	other.Sources = []string{"some-future-scanner"}

	a := Build([]risk.Subject{base}, ctx()).Actions[0]
	b := Build([]risk.Subject{other}, ctx()).Actions[0]

	if a.Kind != b.Kind || a.Key != b.Key || a.Component != b.Component {
		t.Errorf("action changed with the scanner name: %+v vs %+v", a, b)
	}
}

func TestCategoryDrivesTheKind(t *testing.T) {
	for _, tc := range []struct {
		subject risk.Subject
		want    Kind
	}{
		{dep("a", "grype", "pkg:npm/x@1", normalization.SeverityHigh, fixedAt("2")), KindUpgrade},
		{dep("b", "grype", "pkg:npm/y@1", normalization.SeverityHigh, normalization.Fix{}), KindNoFixAvailable},
		{secret("c"), KindRotateCredential},
		{iac("d"), KindReconfigure},
		{sast("e"), KindChangeCode},
	} {
		got := Build([]risk.Subject{tc.subject}, ctx()).Actions[0].Kind
		if got != tc.want {
			t.Errorf("category %s gave kind %q, want %q", tc.subject.Category, got, tc.want)
		}
	}
}

// --- property 8: nothing is AI ----------------------------------------------

// §11 requires AI content to be structurally distinguishable. The value exists
// so its absence is testable; nothing produces it, and §25.15 is why.
func TestNoStatementIsEverSourcedAI(t *testing.T) {
	subjects := []risk.Subject{
		dep("a", "grype", "pkg:npm/express@4.17.1", normalization.SeverityHigh, fixedAt("4.19.2")),
		dep("b", "grype", "pkg:npm/lodash@4.17.20", normalization.SeverityHigh, normalization.Fix{}),
		secret("c"), iac("d"), sast("e"),
	}
	for _, a := range Build(subjects, ctx()).Actions {
		for _, st := range a.Statements {
			if st.Source == SourceAIExplanation {
				t.Errorf("action %s carries an AI-sourced statement: %q", a.Key, st.Text)
			}
			if st.Source != SourceVendor && st.Source != SourceScanner && st.Source != SourceDerived {
				t.Errorf("action %s carries an unattributed statement: %+v", a.Key, st)
			}
		}
	}
}

// --- boundaries -------------------------------------------------------------

func TestAProjectWithNoFindingsHasNoWork(t *testing.T) {
	p := Build(nil, ctx())
	if len(p.Actions) != 0 || p.Score != 0 || p.Addressable != 0 {
		t.Errorf("empty project produced %+v", p)
	}
}

// Two credentials in two places are two rotations. Merging them on an empty
// component would tell someone one rotation clears both.
func TestSeparateSecretsAreSeparateRotations(t *testing.T) {
	p := Build([]risk.Subject{secret("c1"), secret("c2")}, ctx())
	if len(p.Actions) != 2 {
		t.Errorf("actions = %d, want 2: each credential is rotated where it lives", len(p.Actions))
	}
}

func secret(fp string) risk.Subject {
	return risk.Subject{
		Finding: normalization.Finding{
			Fingerprint: fp, Scanner: "gitleaks", Title: "Exposed credential",
			Category: scanners.CategorySecrets, Severity: normalization.SeverityCritical,
			Confidence: normalization.ConfidenceHigh, Status: normalization.StatusOpen,
			Remediation: "Revoke the credential, then remove it from the file and from history.",
		},
		Sources: []string{"gitleaks"},
	}
}

func iac(fp string) risk.Subject {
	return risk.Subject{
		Finding: normalization.Finding{
			Fingerprint: fp, Scanner: "trivy", Title: "Container runs as root",
			ScannerFindingID: "DS002",
			Category:         scanners.CategoryIaC, Severity: normalization.SeverityMedium,
			Confidence: normalization.ConfidenceHigh, Status: normalization.StatusOpen,
			Remediation: "Add a USER directive with a non-root user.",
		},
		Sources: []string{"trivy"},
	}
}

func sast(fp string) risk.Subject {
	return risk.Subject{
		Finding: normalization.Finding{
			Fingerprint: fp, Scanner: "semgrep", Title: "Unsafe deserialization",
			ScannerFindingID: "go.lang.security.audit",
			Category:         scanners.CategorySAST, Severity: normalization.SeverityHigh,
			Confidence: normalization.ConfidenceMedium, Status: normalization.StatusOpen,
		},
		Sources: []string{"semgrep"},
	}
}
