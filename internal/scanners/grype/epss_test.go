package grype

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/normalization"
)

func normalizeFixture(t *testing.T, name string) normalization.Result {
	t.Helper()
	res, err := (&Scanner{}).Normalize(fixture(t, name), "scan-1")
	if err != nil {
		t.Fatalf("Normalize(%s): %v", name, err)
	}
	return res
}

// The association that makes EPSS usable at all. Grype reports a GHSA advisory
// id while EPSS is keyed by CVE, so the score can only be attached through the
// advisory's aliases.
func TestEPSSIsAssociatedThroughTheAdvisoryAlias(t *testing.T) {
	res := normalizeFixture(t, "valid.json")
	if len(res.Findings) == 0 {
		t.Fatal("no findings")
	}

	var withEPSS int
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.CVE, "GHSA-") {
			continue
		}
		// The finding's own identifier is a GHSA. If association were done on
		// that id alone, nothing would ever match.
		if f.Threat.EPSS == nil {
			t.Errorf("%s has no EPSS: the CVE alias was not used for association", f.CVE)
			continue
		}
		withEPSS++
	}
	if withEPSS == 0 {
		t.Fatal("no GHSA finding carried EPSS; the fixture or the association is wrong")
	}
}

// Every field the model promises, populated from real captured output.
func TestEPSSCarriesValueAndProvenance(t *testing.T) {
	res := normalizeFixture(t, "valid.json")

	var found *normalization.EPSS
	for _, f := range res.Findings {
		if f.Threat.EPSS != nil {
			found = f.Threat.EPSS
			break
		}
	}
	if found == nil {
		t.Fatal("no finding carried EPSS")
	}

	if found.Probability <= 0 || found.Probability > 1 {
		t.Errorf("probability = %v, want a real value in 0-1", found.Probability)
	}
	if found.Percentile <= 0 || found.Percentile > 1 {
		t.Errorf("percentile = %v, want a real value in 0-1", found.Percentile)
	}
	// Provenance is mandatory: a number of unknown origin and unknown age
	// looks like evidence without being any (ADR 018).
	if found.Source != normalization.SourceGrype {
		t.Errorf("source = %q, want %q", found.Source, normalization.SourceGrype)
	}
	if found.ObservedAt.IsZero() {
		t.Error("no observation date: EPSS is recomputed daily and cannot be aged out without one")
	}
}

// The distinction the pointer exists for. Absent must not become zero, because
// zero is a real EPSS value meaning "essentially nobody is exploiting this" --
// the opposite of "we do not know".
func TestAbsentEPSSIsNilNotZero(t *testing.T) {
	res := normalizeFixture(t, "no-matches.json")
	for _, f := range res.Findings {
		if f.Threat.EPSS != nil {
			t.Errorf("%s invented an EPSS value", f.Fingerprint)
		}
		if f.Threat.Available() {
			t.Error("Available() is true with no signal present")
		}
	}
}

// --- the selection rules, on synthetic input -------------------------------

func matchWith(id string, related []string, entries ...epssEntry) match {
	m := match{
		Vulnerability: vulnerability{ID: id, Severity: "High", EPSS: entries},
		Artifact:      artifact{Name: "pkg", Version: "1.0.0", PURL: "pkg:golang/pkg@1.0.0"},
	}
	for _, r := range related {
		m.RelatedVulnerabilities = append(m.RelatedVulnerabilities, relatedVulnerability{ID: r})
	}
	return m
}

// An advisory covering several CVEs exposes the component to all of them, so
// the most likely to be exploited governs -- under-reporting is the dangerous
// direction, as it is for severity in deduplication.
func TestTheMostLikelyEntryWins(t *testing.T) {
	got, note := epssFor(matchWith("GHSA-x", []string{"CVE-1", "CVE-2"},
		epssEntry{CVE: "CVE-1", Probability: 0.01, Percentile: 0.50, Date: "2026-08-30"},
		epssEntry{CVE: "CVE-2", Probability: 0.40, Percentile: 0.99, Date: "2026-08-30"},
	))
	if note != "" {
		t.Fatalf("unexpected note: %s", note)
	}
	if got == nil {
		t.Fatal("no EPSS selected")
	}
	if got.Probability != 0.40 {
		t.Errorf("probability = %v, want 0.40", got.Probability)
	}
	// Both numbers must come from the one chosen entry. Probability and
	// percentile rank differently, so mixing fields across entries would
	// describe a vulnerability that does not exist.
	if got.Percentile != 0.99 {
		t.Errorf("percentile = %v, want 0.99: fields were mixed across entries", got.Percentile)
	}
}

// Scores present, but for a vulnerability this finding does not represent.
// Attaching one anyway would put another CVE's likelihood on this finding.
func TestUnrelatedEPSSEntryIsNotAttached(t *testing.T) {
	got, note := epssFor(matchWith("GHSA-x", []string{"CVE-1"},
		epssEntry{CVE: "CVE-999", Probability: 0.9, Percentile: 0.99, Date: "2026-08-30"},
	))
	if got != nil {
		t.Errorf("attached an unrelated CVE's score: %+v", got)
	}
	if note != "" {
		t.Errorf("unexpected note for a simple non-match: %s", note)
	}
}

// Scanner output is untrusted (§15.7). A hostile or broken value must not
// discard the vulnerability finding it is attached to.
func TestABadEPSSDropsTheValueNotTheFinding(t *testing.T) {
	for name, entry := range map[string]epssEntry{
		"probability above 1": {CVE: "CVE-1", Probability: 42, Percentile: 0.5, Date: "2026-08-30"},
		"negative percentile": {CVE: "CVE-1", Probability: 0.5, Percentile: -1, Date: "2026-08-30"},
		"unparseable date":    {CVE: "CVE-1", Probability: 0.5, Percentile: 0.5, Date: "not-a-date"},
		"missing date":        {CVE: "CVE-1", Probability: 0.5, Percentile: 0.5},
	} {
		t.Run(name, func(t *testing.T) {
			got, note := epssFor(matchWith("CVE-1", nil, entry))
			if got != nil {
				t.Errorf("kept a bad value: %+v", got)
			}
			if note == "" {
				t.Error("dropped the value silently; the anomaly must be recorded")
			}
		})
	}
}

// A date with no time zone must not drift by a day depending on where the
// worker runs.
func TestObservationDateIsUTC(t *testing.T) {
	got, _ := epssFor(matchWith("CVE-1", nil,
		epssEntry{CVE: "CVE-1", Probability: 0.5, Percentile: 0.5, Date: "2026-08-30"}))
	if got == nil {
		t.Fatal("no EPSS selected")
	}
	want := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	if !got.ObservedAt.Equal(want) {
		t.Errorf("observed_at = %v, want %v", got.ObservedAt, want)
	}
}

// Grype emits its own composite `risk` score. Using it would mean two
// different formulas producing two different numbers both called risk, when
// §10 makes SecureOps' risk one deterministic function (ADR 018).
//
// A structural assertion rather than a behavioural one, because there is no
// behaviour to observe: the guarantee is that the field is never modelled, and
// the failure mode is somebody adding it later without reading the ADR.
func TestGrypeRiskScoreIsNotConsumed(t *testing.T) {
	src, err := os.ReadFile("parser.go")
	if err != nil {
		t.Fatalf("read parser.go: %v", err)
	}
	if strings.Contains(string(src), `json:"risk"`) {
		t.Error("the parser models grype's own risk field; §10 owns risk scoring (ADR 018)")
	}
}

// EPSS is recomputed daily. If identity depended on it, every finding would
// become a new finding overnight and lifecycle continuity -- the entire point
// of fingerprinting -- would be destroyed. Tested through the real mapper
// rather than asserted about the struct, so it covers the path that runs.
func TestThreatIntelligenceDoesNotChangeIdentity(t *testing.T) {
	withEPSS, err := (&Scanner{}).Normalize(fixture(t, "valid.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	// The same report with every EPSS array stripped out.
	stripped := regexp.MustCompile(`"epss":\s*\[[^]]*\]`).
		ReplaceAll(fixture(t, "valid.json"), []byte(`"epss":[]`))
	withoutEPSS, err := (&Scanner{}).Normalize(stripped, "scan-1")
	if err != nil {
		t.Fatalf("Normalize(stripped): %v", err)
	}

	if len(withEPSS.Findings) != len(withoutEPSS.Findings) {
		t.Fatalf("finding counts differ: %d vs %d",
			len(withEPSS.Findings), len(withoutEPSS.Findings))
	}
	if len(withEPSS.Findings) == 0 {
		t.Fatal("no findings to compare")
	}

	var sawSignalDifference bool
	for i := range withEPSS.Findings {
		if withEPSS.Findings[i].Fingerprint != withoutEPSS.Findings[i].Fingerprint {
			t.Errorf("finding %d changed identity when EPSS was removed", i)
		}
		if withEPSS.Findings[i].Threat.Available() != withoutEPSS.Findings[i].Threat.Available() {
			sawSignalDifference = true
		}
	}
	// Guards the guard: if stripping EPSS changed nothing, the test proved
	// nothing about identity.
	if !sawSignalDifference {
		t.Fatal("stripping EPSS changed no finding's threat data; the comparison was vacuous")
	}
}
