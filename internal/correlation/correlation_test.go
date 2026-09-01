package correlation

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func sub(
	fingerprint, scanner string, category scanners.Category,
	severity normalization.Severity, purl, cve string, files ...string,
) Subject {
	return Subject{
		Finding: normalization.Finding{
			Fingerprint: fingerprint, Scanner: scanner, Title: "t",
			Category: category, Severity: severity,
			Confidence: normalization.ConfidenceHigh,
			PURL:       purl, CVE: cve,
		},
		Files: files,
	}
}

func linkBetween(t *testing.T, r Result, a, b string) (Link, bool) {
	t.Helper()
	if a > b {
		a, b = b, a
	}
	for _, l := range r.Links {
		if l.From == a && l.To == b {
			return l, true
		}
	}
	return Link{}, false
}

func issueFor(t *testing.T, r Result, key string) (Issue, bool) {
	t.Helper()
	for _, i := range r.Issues {
		if i.Key.String() == key {
			return i, true
		}
	}
	return Issue{}, false
}

// --- linking rules ---------------------------------------------------------

// Two findings naming one CVE are related, not duplicates: both are real and
// both need action.
func TestSharedVulnerabilityIsRelated(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityHigh, "pkg:golang/a@1", "CVE-1"),
		sub("fp2", "grype", scanners.CategoryDependency, normalization.SeverityHigh, "pkg:golang/b@2", "CVE-1"),
	})

	l, ok := linkBetween(t, got, "fp1", "fp2")
	if !ok {
		t.Fatalf("no link; links = %+v", got.Links)
	}
	if l.Relationship != RelationRelated {
		t.Errorf("relationship = %q, want related", l.Relationship)
	}
	if l.Confidence != normalization.ConfidenceHigh {
		t.Errorf("confidence = %q, want high: a shared CVE is the strongest evidence we have", l.Confidence)
	}
	if !strings.Contains(l.Evidence, "CVE-1") {
		t.Errorf("evidence = %q, must name what is shared (§9)", l.Evidence)
	}
}

// §8 forbids merging things for looking similar. A likely duplicate is a claim
// with a confidence attached, and both findings survive.
func TestLikelyDuplicatesAreLinkedNotMerged(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "trivy", scanners.CategoryIaC, normalization.SeverityHigh, "pkg:golang/x@1", ""),
		sub("fp2", "semgrep", scanners.CategoryIaC, normalization.SeverityHigh, "pkg:golang/x@1", ""),
	})

	l, ok := linkBetween(t, got, "fp1", "fp2")
	if !ok {
		t.Fatalf("no link; links = %+v", got.Links)
	}
	if l.Relationship != RelationLikelyDuplicate {
		t.Errorf("relationship = %q, want likely_duplicate", l.Relationship)
	}
	if l.Confidence == "" {
		t.Error("a likely duplicate must carry a confidence: it is a claim, not a fact")
	}
}

// Co-location across domains is the cheapest cross-domain signal available
// before image and endpoint data exist -- and the weakest, so it is labelled
// low rather than presented as certainty.
func TestSameFileAcrossDomainsIsRelatedAtLowConfidence(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "gitleaks", scanners.CategorySecrets, normalization.SeverityCritical, "", "", "config/settings.py"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityMedium, "", "", "config/settings.py"),
	})

	l, ok := linkBetween(t, got, "fp1", "fp2")
	if !ok {
		t.Fatalf("no link; links = %+v", got.Links)
	}
	if l.Confidence != normalization.ConfidenceLow {
		t.Errorf("confidence = %q, want low: co-location is the weakest evidence in the rule set", l.Confidence)
	}
}

// The control for the rule above. Two findings of one kind in one file are two
// findings in one file; asserting a relationship adds nothing a path sort
// would not already show.
func TestSameFileSameCategoryIsNotLinked(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "", "server.ts"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityLow, "", "", "server.ts"),
	})
	if len(got.Links) != 0 {
		t.Errorf("links = %+v, want none: same file, same domain is not a relationship", got.Links)
	}
	if len(got.Issues) != 0 {
		t.Errorf("issues = %+v, want none: a busy file is not a contextual issue", got.Issues)
	}
}

// A wrong link sends somebody to investigate a relationship that does not
// exist, which is worse than a missing one.
func TestUnrelatedFindingsAreNotLinked(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "gitleaks", scanners.CategorySecrets, normalization.SeverityCritical, "", "", "a.py"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "", "b.ts"),
	})
	if len(got.Links) != 0 {
		t.Errorf("links = %+v, want none: these share nothing", got.Links)
	}
}

// Absence is not a shared attribute. Two findings that both lack a CVE have
// not been shown to have anything in common, and bucketing them on "" would
// relate every secret to every misconfiguration.
func TestEmptyFieldsAreNotACorrelationKey(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "gitleaks", scanners.CategorySecrets, normalization.SeverityHigh, "", ""),
		sub("fp2", "trivy", scanners.CategoryIaC, normalization.SeverityHigh, "", ""),
	})
	if len(got.Links) != 0 || len(got.Issues) != 0 {
		t.Errorf("links = %+v issues = %+v, want none from two empty fields", got.Links, got.Issues)
	}
}

// One pair sharing several keys must produce one link, not one per key: two
// rows saying the same thing at different confidences leaves a reader working
// out which to believe.
func TestOnePairProducesOneLinkKeepingTheStrongest(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityHigh, "pkg:npm/express@4", "CVE-1", "a.js"),
		sub("fp2", "trivy", scanners.CategoryContainer, normalization.SeverityHigh, "pkg:npm/express@4", "CVE-1", "a.js"),
	})

	if len(got.Links) != 1 {
		t.Fatalf("links = %+v, want exactly 1 for one pair", got.Links)
	}
	if got.Links[0].Confidence != normalization.ConfidenceHigh {
		t.Errorf("confidence = %q, want high: the CVE claim is stronger than the component or file claim",
			got.Links[0].Confidence)
	}
}

// --- issues ----------------------------------------------------------------

// The entity §9 asks for: several findings, one issue, members retained.
func TestFindingsSharingACVEBecomeOneIssue(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityHigh, "pkg:npm/a@1", "CVE-1"),
		sub("fp2", "trivy", scanners.CategoryIaC, normalization.SeverityMedium, "pkg:npm/b@2", "CVE-1"),
	})

	issue, ok := issueFor(t, got, "cve:CVE-1")
	if !ok {
		t.Fatalf("no cve issue; issues = %+v", got.Issues)
	}
	if len(issue.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(issue.Members))
	}
	for _, m := range issue.Members {
		if m.Evidence == "" {
			t.Errorf("member %s has no evidence: §9 requires every membership to be explainable", m.Fingerprint)
		}
	}
	if issue.Explanation == "" {
		t.Error("an issue with no explanation is an assertion")
	}
}

// A single-member issue would make the issue count and the finding count the
// same number, and an entity that adds no information costs a table, a join,
// and a concept to learn.
func TestALoneFindingIsNotAnIssue(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityCritical, "pkg:npm/a@1", "CVE-1"),
	})
	if len(got.Issues) != 0 {
		t.Errorf("issues = %+v, want none for a single finding", got.Issues)
	}
}

// A file issue requires two domains. Without that restriction every file with
// several findings becomes an "issue", which is a directory listing.
func TestFileIssuesRequireTwoDomains(t *testing.T) {
	oneDomain := Correlate([]Subject{
		sub("fp1", "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "", "app.py"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "", "app.py"),
	})
	if _, ok := issueFor(t, oneDomain, "file:app.py"); ok {
		t.Error("one domain in one file formed an issue")
	}

	twoDomains := Correlate([]Subject{
		sub("fp1", "gitleaks", scanners.CategorySecrets, normalization.SeverityHigh, "", "", "app.py"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "", "app.py"),
	})
	if _, ok := issueFor(t, twoDomains, "file:app.py"); !ok {
		t.Errorf("two domains in one file formed no issue; issues = %+v", twoDomains.Issues)
	}
}

// The property that keeps correlation honest. Transitive closure would put A
// and C in one issue on the strength of a chain no rule evaluated -- exactly
// the invention §9 forbids.
func TestIssuesDoNotChainTransitively(t *testing.T) {
	// A--B share a CVE. B--C share a file across domains. A and C share
	// nothing at all.
	got := Correlate([]Subject{
		sub("a", "grype", scanners.CategoryDependency, normalization.SeverityHigh, "", "CVE-1"),
		sub("b", "trivy", scanners.CategoryIaC, normalization.SeverityHigh, "", "CVE-1", "shared.tf"),
		sub("c", "gitleaks", scanners.CategorySecrets, normalization.SeverityHigh, "", "", "shared.tf"),
	})

	for _, issue := range got.Issues {
		var hasA, hasC bool
		for _, m := range issue.Members {
			hasA = hasA || m.Fingerprint == "a"
			hasC = hasC || m.Fingerprint == "c"
		}
		if hasA && hasC {
			t.Errorf("issue %s contains both a and c, which share no evidence: %s",
				issue.Key, issue.Explanation)
		}
	}
}

// --- severity --------------------------------------------------------------

// The §9 behaviour: corroboration across domains makes the combination worse
// than either part.
func TestCrossDomainCorroborationEscalatesOneStep(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityMedium, "pkg:npm/a@1", "CVE-1"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityMedium, "pkg:npm/a@1", "CVE-1"),
	})

	issue, ok := issueFor(t, got, "cve:CVE-1")
	if !ok {
		t.Fatal("no issue formed")
	}
	if issue.Severity != normalization.SeverityHigh {
		t.Errorf("severity = %q, want high: medium raised one step", issue.Severity)
	}
	if !issue.Escalated {
		t.Error("Escalated is false: the escalation must be visible as a claim, not folded into the value")
	}
	if !strings.Contains(issue.Explanation, "one step") {
		t.Errorf("explanation = %q, must say why the severity moved", issue.Explanation)
	}
}

// One domain is not corroboration. Two dependency scanners agreeing is usually
// one vulnerability database consulted twice.
func TestOneDomainDoesNotEscalate(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityMedium, "pkg:npm/a@1", "CVE-1"),
		sub("fp2", "trivy", scanners.CategoryDependency, normalization.SeverityMedium, "pkg:npm/b@2", "CVE-1"),
	})

	issue, ok := issueFor(t, got, "cve:CVE-1")
	if !ok {
		t.Fatal("no issue formed")
	}
	if issue.Severity != normalization.SeverityMedium || issue.Escalated {
		t.Errorf("severity = %q escalated = %v, want medium and not escalated",
			issue.Severity, issue.Escalated)
	}
}

// Escalating "the scanner did not say" to "low" would manufacture an
// assessment nobody made -- the same reason MapSeverity refuses to guess.
func TestUnknownSeverityNeverEscalates(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityUnknown, "", "CVE-1"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityUnknown, "", "CVE-1"),
	})

	issue, _ := issueFor(t, got, "cve:CVE-1")
	if issue.Severity != normalization.SeverityUnknown || issue.Escalated {
		t.Errorf("severity = %q escalated = %v, want unknown and not escalated",
			issue.Severity, issue.Escalated)
	}
}

// Critical is the top of the scale. A ceiling that leaks would make the enum
// meaningless.
func TestCriticalDoesNotEscalatePastCritical(t *testing.T) {
	got := Correlate([]Subject{
		sub("fp1", "gitleaks", scanners.CategorySecrets, normalization.SeverityCritical, "", "CVE-1"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "CVE-1"),
	})

	issue, _ := issueFor(t, got, "cve:CVE-1")
	if issue.Severity != normalization.SeverityCritical {
		t.Errorf("severity = %q, want critical", issue.Severity)
	}
	if issue.Escalated {
		t.Error("Escalated is true but the severity did not move")
	}
}

// Correlation links; it does not destroy (§9). An escalated issue must not
// rewrite the severities it was derived from.
func TestEscalationDoesNotMutateMembers(t *testing.T) {
	inputs := []Subject{
		sub("fp1", "grype", scanners.CategoryDependency, normalization.SeverityMedium, "", "CVE-1"),
		sub("fp2", "semgrep", scanners.CategorySAST, normalization.SeverityLow, "", "CVE-1"),
	}
	got := Correlate(inputs)

	if inputs[0].Severity != normalization.SeverityMedium || inputs[1].Severity != normalization.SeverityLow {
		t.Fatalf("input findings were mutated: %q, %q", inputs[0].Severity, inputs[1].Severity)
	}

	issue, _ := issueFor(t, got, "cve:CVE-1")
	want := map[string]normalization.Severity{
		"fp1": normalization.SeverityMedium,
		"fp2": normalization.SeverityLow,
	}
	for _, m := range issue.Members {
		if m.Severity != want[m.Fingerprint] {
			t.Errorf("member %s severity = %q, want %q: members keep what their scanner assigned",
				m.Fingerprint, m.Severity, want[m.Fingerprint])
		}
	}
}

// --- limits and determinism ------------------------------------------------

// A limit being reached is a structured, visible outcome, never a silent one
// (ADR 010 applied to this engine).
func TestAnOversizedBucketIsTruncatedAndReported(t *testing.T) {
	var subjects []Subject
	for i := 0; i < 12; i++ {
		subjects = append(subjects, sub(
			fmt.Sprintf("fp%02d", i), "grype", scanners.CategoryDependency,
			normalization.SeverityHigh, "", "CVE-1"))
	}

	got := CorrelateWith(subjects, Options{MaxBucketSize: 5})

	if len(got.Truncated) != 1 || got.Truncated[0] != "cve:CVE-1" {
		t.Fatalf("truncated = %v, want [cve:CVE-1]: silence would look like nothing correlated", got.Truncated)
	}
	issue, ok := issueFor(t, got, "cve:CVE-1")
	if !ok {
		t.Fatal("no issue formed")
	}
	if len(issue.Members) != 5 {
		t.Errorf("members = %d, want 5", len(issue.Members))
	}
}

// Truncation must be deterministic, or two runs over one project would
// correlate different subsets and the issue set would flap.
func TestTruncationIsDeterministic(t *testing.T) {
	var forward []Subject
	for i := 0; i < 10; i++ {
		forward = append(forward, sub(
			fmt.Sprintf("fp%02d", i), "grype", scanners.CategoryDependency,
			normalization.SeverityHigh, "", "CVE-1"))
	}
	reverse := make([]Subject, len(forward))
	for i, s := range forward {
		reverse[len(forward)-1-i] = s
	}

	a := CorrelateWith(forward, Options{MaxBucketSize: 4})
	b := CorrelateWith(reverse, Options{MaxBucketSize: 4})

	if !reflect.DeepEqual(a, b) {
		t.Errorf("truncated results differ by input order:\n%+v\n%+v", a, b)
	}
}

// Same findings in, same issues out. Without this the dashboard would show a
// different set of problems on every scan of an unchanged project.
func TestCorrelationIsOrderIndependent(t *testing.T) {
	subjects := []Subject{
		sub("fp3", "grype", scanners.CategoryDependency, normalization.SeverityHigh, "pkg:npm/a@1", "CVE-1", "a.js"),
		sub("fp1", "semgrep", scanners.CategorySAST, normalization.SeverityMedium, "", "", "a.js"),
		sub("fp2", "trivy", scanners.CategoryIaC, normalization.SeverityLow, "pkg:npm/a@1", "", "b.tf"),
	}
	reversed := []Subject{subjects[2], subjects[1], subjects[0]}

	if !reflect.DeepEqual(Correlate(subjects), Correlate(reversed)) {
		t.Error("correlation output depends on input order")
	}
}

func TestEmptyInputIsNotAnError(t *testing.T) {
	got := Correlate(nil)
	if len(got.Issues) != 0 || len(got.Links) != 0 || len(got.Truncated) != 0 {
		t.Errorf("empty input produced output: %+v", got)
	}
}

// A direct test on linkSet, because the engine currently sorts subjects by
// fingerprint before bucketing and so never hands it a reversed pair. That
// makes the normalization inside add() untestable end to end -- and it is
// exactly what stops a future key kind that emits links in another order from
// silently storing every relationship twice.
func TestLinkSetTreatsAReversedPairAsOnePair(t *testing.T) {
	set := newLinkSet()
	set.add(Link{From: "zzz", To: "aaa", Relationship: RelationRelated,
		Confidence: normalization.ConfidenceLow, Evidence: "same file x"})
	set.add(Link{From: "aaa", To: "zzz", Relationship: RelationRelated,
		Confidence: normalization.ConfidenceHigh, Evidence: "same vulnerability CVE-1"})

	got := set.sorted()
	if len(got) != 1 {
		t.Fatalf("links = %+v, want 1: the graph is undirected, so (a,b) and (b,a) are one pair", got)
	}
	if got[0].From != "aaa" || got[0].To != "zzz" {
		t.Errorf("link = %s -> %s, want the smaller fingerprint first", got[0].From, got[0].To)
	}
	if got[0].Confidence != normalization.ConfidenceHigh {
		t.Errorf("confidence = %q, want high: the stronger claim about the pair must win",
			got[0].Confidence)
	}
}

// The link graph is undirected -- "shares a CVE with" is symmetric -- so a
// pair must be one row regardless of which finding was seen first.
func TestLinkDirectionIsNormalized(t *testing.T) {
	got := Correlate([]Subject{
		sub("zzz", "grype", scanners.CategoryDependency, normalization.SeverityHigh, "", "CVE-1"),
		sub("aaa", "semgrep", scanners.CategorySAST, normalization.SeverityHigh, "", "CVE-1"),
	})
	if len(got.Links) != 1 {
		t.Fatalf("links = %+v, want 1", got.Links)
	}
	if got.Links[0].From != "aaa" || got.Links[0].To != "zzz" {
		t.Errorf("link = %s -> %s, want the smaller fingerprint first",
			got.Links[0].From, got.Links[0].To)
	}
}
