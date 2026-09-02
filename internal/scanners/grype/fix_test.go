package grype

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
)

// The authoritative remediation fact §11 names first. It was in grype's output
// and on disk in these fixtures since Phase 3b, and the parser discarded it.
func TestFixVersionsReachTheCanonicalModel(t *testing.T) {
	res := normalizeFixture(t, "valid.json")
	if len(res.Findings) == 0 {
		t.Fatal("no findings")
	}

	var withFix int
	for _, f := range res.Findings {
		if !f.Fix.Available() {
			continue
		}
		withFix++
		if f.Fix.State != normalization.FixStateFixed {
			t.Errorf("%s: state = %q, want fixed", f.CVE, f.Fix.State)
		}
		for _, v := range f.Fix.FixedVersions {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: blank fixed version", f.CVE)
			}
		}
	}
	if withFix == 0 {
		t.Fatal("no finding carried a fixed version; the fix block is being discarded")
	}
}

// References are where to read about a finding, not what to do about it. They
// must not be mistaken for a fix.
func TestAdvisoryLinksAreReferencesNotFixes(t *testing.T) {
	res := normalizeFixture(t, "valid.json")

	var withRefs int
	for _, f := range res.Findings {
		if len(f.Fix.References) == 0 {
			continue
		}
		withRefs++
		if len(f.Fix.References) > maxReferences {
			t.Errorf("%s: %d references, want at most %d: untrusted output must be bounded",
				f.CVE, len(f.Fix.References), maxReferences)
		}
	}
	if withRefs == 0 {
		t.Fatal("no finding carried references")
	}
}

// normalizeRaw runs the mapper over hand-built output, so a state grype does
// not happen to emit in the captured fixtures can still be exercised.
func normalizeRaw(t *testing.T, vuln string) normalization.Finding {
	t.Helper()
	raw := `{"matches":[{"vulnerability":` + vuln +
		`,"artifact":{"name":"pkg","version":"1.0.0","purl":"pkg:golang/pkg@1.0.0"}}],` +
		`"descriptor":{"name":"grype","version":"0.117.0","db":{"built":"2026-08-30T00:00:00Z"}}}`

	// Guard against this test's own hand-built JSON being malformed, which
	// would make every assertion below vacuously pass through a parse error.
	if !json.Valid([]byte(raw)) {
		t.Fatal("the test's own input is not valid JSON")
	}
	res, err := (&Scanner{}).Normalize([]byte(raw), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (errors: %v)", len(res.Findings), res.Errors)
	}
	return res.Findings[0]
}

// The distinction the whole state exists for. A vulnerability nobody will fix
// must never produce an upgrade recommendation -- there is no version to
// upgrade to, and sending someone to look for one wastes the effort that should
// have gone into a compensating control.
func TestWontFixNeverCarriesAnUpgradeTarget(t *testing.T) {
	f := normalizeRaw(t, `{"id":"CVE-2026-1","severity":"High",
        "fix":{"state":"wont-fix","versions":["9.9.9"]}}`)

	if f.Fix.State != normalization.FixStateWontFix {
		t.Errorf("state = %q, want wont-fix", f.Fix.State)
	}
	if len(f.Fix.FixedVersions) != 0 {
		t.Errorf("fixed versions = %v, want none: a wont-fix vulnerability has no upgrade target",
			f.Fix.FixedVersions)
	}
	if f.Fix.Available() {
		t.Error("Available() is true for wont-fix")
	}
}

// "Nobody told us" is not "there is no fix". The same rule ADR 018 applies to
// EPSS, applied to the field §11 calls authoritative.
func TestAbsentFixDataIsUnknownNotUnfixable(t *testing.T) {
	f := normalizeRaw(t, `{"id":"CVE-2026-2","severity":"High"}`)

	if f.Fix.State != normalization.FixStateUnknown {
		t.Errorf("state = %q, want unknown", f.Fix.State)
	}
	if f.Fix.Available() {
		t.Error("Available() is true with no fix data")
	}
	// And it must not read as wont-fix, which would suppress the finding from
	// ever being offered an upgrade if one appears later.
	if f.Fix.State == normalization.FixStateWontFix {
		t.Error("absent fix data was recorded as wont-fix")
	}
}

// A scanner asserting a fix without naming a version cannot be acted on.
// Keeping the `fixed` state would produce an upgrade action with no target.
func TestFixedWithNoVersionDegradesToUnknown(t *testing.T) {
	f := normalizeRaw(t, `{"id":"CVE-2026-3","severity":"High",
        "fix":{"state":"fixed","versions":[]}}`)

	if f.Fix.State != normalization.FixStateUnknown {
		t.Errorf("state = %q, want unknown: a fix with no version names nothing to do", f.Fix.State)
	}
}

// Fix data is remediation, not identity. Capturing it must not re-fingerprint
// every stored finding -- a fix becoming available is not a new finding.
func TestFixDataDoesNotChangeIdentity(t *testing.T) {
	withFix := normalizeRaw(t, `{"id":"CVE-2026-4","severity":"High",
        "fix":{"state":"fixed","versions":["1.2.3"]}}`)
	without := normalizeRaw(t, `{"id":"CVE-2026-4","severity":"High"}`)

	if withFix.Fingerprint != without.Fingerprint {
		t.Errorf("fingerprint changed with fix data: %s vs %s",
			withFix.Fingerprint, without.Fingerprint)
	}
}

// Validation must reject the contradiction rather than store it.
func TestValidateRejectsVersionsOnAnUnfixableState(t *testing.T) {
	f := normalization.Finding{
		Fingerprint: strings.Repeat("a", 64), Scanner: "grype", Title: "x",
		Category: "dependency", Severity: normalization.SeverityHigh,
		Confidence: normalization.ConfidenceHigh,
		Fix: normalization.Fix{
			State:         normalization.FixStateWontFix,
			FixedVersions: []string{"1.0.0"},
		},
	}
	if err := f.Validate(); err == nil {
		t.Fatal("a wont-fix finding carrying a fixed version was accepted")
	}
}
