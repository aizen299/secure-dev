package trivy

import (
	"slices"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// The real thing: trivy 0.74.0 against alpine:3.9, captured verbatim.
func TestNormalizeImageFixture(t *testing.T) {
	res, err := Normalize(fixture(t, "image-vulnerable.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Errorf("errors = %v, want none for a well-formed report", res.Errors)
	}
	if got := len(res.Findings); got != 14 {
		t.Fatalf("findings = %d, want 14", got)
	}
	if len(res.Occurrences) != len(res.Findings) {
		t.Errorf("occurrences = %d, findings = %d: every finding needs a sighting",
			len(res.Occurrences), len(res.Findings))
	}

	for _, f := range res.Findings {
		if f.Category != scanners.CategoryContainer {
			t.Errorf("%s: category = %q, want container", f.CVE, f.Category)
		}
		// The tag is in the fixture's ArtifactName and must not survive.
		if f.Image != "alpine" {
			t.Errorf("%s: image = %q, want alpine", f.CVE, f.Image)
		}
		if strings.Contains(f.PURL, "?") {
			t.Errorf("%s: purl %q still carries qualifiers", f.CVE, f.PURL)
		}
		if f.Scanner != Name {
			t.Errorf("%s: scanner = %q", f.CVE, f.Scanner)
		}
	}

	// One finding checked in full, so the mapping is pinned rather than merely
	// shaped: this is the entry printed in ADR 025's measurements.
	// The fixture reports this CVE against two packages, libcrypto1.1 and
	// libssl1.1, which is correct and is why identity is the pair rather than
	// the CVE alone.
	var got *normalization.Finding
	for i := range res.Findings {
		if res.Findings[i].CVE == "CVE-2021-23840" && res.Findings[i].Package == "libcrypto1.1" {
			got = &res.Findings[i]
		}
	}
	if got == nil {
		t.Fatal("CVE-2021-23840 missing from the report")
	}
	if got.Severity != normalization.SeverityHigh {
		t.Errorf("severity = %q, want high", got.Severity)
	}
	if got.ScannerSeverity != "HIGH" {
		t.Errorf("scanner severity = %q, want the original verbatim", got.ScannerSeverity)
	}
	if got.Package != "libcrypto1.1" || got.PackageVersion != "1.1.1g-r0" {
		t.Errorf("component = %s@%s", got.Package, got.PackageVersion)
	}
	if got.PURL != "pkg:apk/alpine/libcrypto1.1@1.1.1g-r0" {
		t.Errorf("purl = %q", got.PURL)
	}
	if got.CWE != "CWE-190" {
		t.Errorf("cwe = %q, want CWE-190", got.CWE)
	}
	if got.CVSS != 7.5 {
		t.Errorf("cvss = %v, want nvd's 7.5", got.CVSS)
	}
	if got.Fix.State != normalization.FixStateFixed {
		t.Errorf("fix state = %q, want fixed", got.Fix.State)
	}
	if !slices.Equal(got.Fix.FixedVersions, []string{"1.1.1j-r0"}) {
		t.Errorf("fixed versions = %v", got.Fix.FixedVersions)
	}
	if !got.Fix.Available() {
		t.Error("a fixed state naming a version must be actionable (§11)")
	}
	if len(got.Fix.References) > maxCheckReferences {
		t.Errorf("references = %d, want at most %d (§15.8)",
			len(got.Fix.References), maxCheckReferences)
	}
}

// A clean image is not a failed scan, and the two must not read alike.
func TestNormalizeImageClean(t *testing.T) {
	res, err := Normalize(fixture(t, "image-clean.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(res.Findings) != 0 || len(res.Errors) != 0 {
		t.Errorf("findings = %d, errors = %v, want a clean report",
			len(res.Findings), res.Errors)
	}
}

// THE identity claim of ADR 025. A rebuild that only moves the tag or the
// digest must produce the same fingerprint, or every rebuild resolves every
// finding and opens an identical set of new ones.
func TestImageFingerprintSurvivesRebuild(t *testing.T) {
	report := func(ref string) []byte {
		return []byte(`{"SchemaVersion":2,"ArtifactType":"container_image",
		  "ArtifactName":"` + ref + `","Results":[{"Class":"os-pkgs","Vulnerabilities":[
		    {"VulnerabilityID":"CVE-2021-23840","PkgName":"libcrypto1.1",
		     "PkgIdentifier":{"PURL":"pkg:apk/alpine/libcrypto1.1@1.1.1g-r0?arch=x86_64&distro=3.9.6"},
		     "InstalledVersion":"1.1.1g-r0","Severity":"HIGH","Title":"x"}]}]}`)
	}
	fingerprintOf := func(t *testing.T, ref string) string {
		t.Helper()
		res, err := Normalize(report(ref), "scan-1")
		if err != nil {
			t.Fatalf("Normalize(%s): %v", ref, err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("Normalize(%s): findings = %d, want 1", ref, len(res.Findings))
		}
		return res.Findings[0].Fingerprint
	}

	base := fingerprintOf(t, "ghcr.io/org/app:1.2.3")
	same := []string{
		"ghcr.io/org/app:9.9.9",
		"ghcr.io/org/app@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/org/app:1.2.3@sha256:" + strings.Repeat("b", 64),
		"ghcr.io/org/app",
		"GHCR.io/Org/app:1.2.3",
	}
	for _, ref := range same {
		if got := fingerprintOf(t, ref); got != base {
			t.Errorf("%s: fingerprint changed; a rebuild must not re-identify a finding", ref)
		}
	}

	// The other half: different repositories are different assets, fixed
	// separately, and must not collapse into one finding.
	for _, ref := range []string{"ghcr.io/org/other:1.2.3", "docker.io/org/app:1.2.3", "app"} {
		if got := fingerprintOf(t, ref); got == base {
			t.Errorf("%s: fingerprint collided with ghcr.io/org/app", ref)
		}
	}
}

// The PURL qualifiers trivy adds to OS packages are what would otherwise churn
// identity when a base image is patched but the vulnerability is not.
func TestPURLQualifiersAreStripped(t *testing.T) {
	cases := map[string]string{
		"pkg:apk/alpine/libcrypto1.1@1.1.1g-r0?arch=x86_64&distro=3.9.6":  "pkg:apk/alpine/libcrypto1.1@1.1.1g-r0",
		"pkg:apk/alpine/libcrypto1.1@1.1.1g-r0?arch=aarch64&distro=3.9.7": "pkg:apk/alpine/libcrypto1.1@1.1.1g-r0",
		// A language package has no qualifiers and must be left exactly alone:
		// this is the string that has to match grype's byte for byte.
		"pkg:npm/express@4.17.1": "pkg:npm/express@4.17.1",
		"":                       "",
	}
	for in, want := range cases {
		if got := canonicalPURL(in); got != want {
			t.Errorf("canonicalPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImageRepository(t *testing.T) {
	cases := map[string]string{
		"alpine":                     "alpine",
		"alpine:3.9":                 "alpine",
		"library/alpine:3.9":         "library/alpine",
		"ghcr.io/org/app:1.2.3":      "ghcr.io/org/app",
		"ghcr.io/org/app@sha256:abc": "ghcr.io/org/app",
		// The colon here is a registry port, not a tag. Cutting at the last
		// colon regardless would leave "localhost", a different image.
		"localhost:5000/app":    "localhost:5000/app",
		"localhost:5000/app:2":  "localhost:5000/app",
		"  ghcr.io/Org/App:1  ": "ghcr.io/org/app",
		"":                      "",
	}
	for in, want := range cases {
		if got := imageRepository(in); got != want {
			t.Errorf("imageRepository(%q) = %q, want %q", in, got, want)
		}
	}
}

// Hostile output is in the threat model (§15.7). Every entry here is designed
// to be rejected or defanged, and the well-formed neighbours must survive.
func TestNormalizeImageHostile(t *testing.T) {
	res, err := Normalize(fixture(t, "image-hostile.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize must not fail the whole report over bad entries: %v", err)
	}

	byCVE := map[string]normalization.Finding{}
	for _, f := range res.Findings {
		byCVE[f.CVE] = f
	}

	// An impossible CVSS is dropped, not clamped, and must not take the
	// finding with it.
	if f, ok := byCVE["CVE-2026-0001"]; !ok {
		t.Error("CVE-2026-0001 dropped; an impossible CVSS must not discard a real vulnerability")
	} else if f.CVSS != 0 {
		t.Errorf("CVE-2026-0001: cvss = %v, want 0 (44.7 and -3 are both outside 0-10)", f.CVSS)
	}

	// A PURL carrying the fingerprint separator could forge a field boundary.
	if _, ok := byCVE["CVE-2026-0002"]; ok {
		t.Error("CVE-2026-0002 was accepted; a PURL containing the field separator must be refused")
	}

	// "fixed" naming no version cannot be acted on, so it must not read as
	// actionable to the remediation engine.
	if f, ok := byCVE["CVE-2026-0003"]; !ok {
		t.Error("CVE-2026-0003 dropped")
	} else {
		if f.Fix.State != normalization.FixStateUnknown {
			t.Errorf("CVE-2026-0003: fix state = %q, want unknown", f.Fix.State)
		}
		if f.Fix.Available() {
			t.Error("CVE-2026-0003: a fix with no version must not be actionable")
		}
	}

	// A version attached to wont-fix must never become an upgrade suggestion.
	if f, ok := byCVE["CVE-2026-0005"]; !ok {
		t.Error("CVE-2026-0005 dropped")
	} else {
		if f.Fix.State != normalization.FixStateWontFix {
			t.Errorf("CVE-2026-0005: fix state = %q, want wont-fix", f.Fix.State)
		}
		if len(f.Fix.FixedVersions) != 0 {
			t.Errorf("CVE-2026-0005: versions = %v on a wont-fix finding", f.Fix.FixedVersions)
		}
	}

	// The entry naming neither a component nor an identifier must be refused
	// rather than pinned to the image alone -- otherwise every such entry in
	// one image collapses onto a single identity.
	for _, f := range res.Findings {
		if f.CVE == "" && f.PURL == "" && f.Package == "" {
			t.Error("a vulnerability with nothing to identify it was accepted")
		}
	}
	if len(res.Errors) < 2 {
		t.Errorf("errors = %v, want both the unidentifiable and the forged entries recorded", res.Errors)
	}
}

// A report naming no artifact cannot be given an identity, and inventing one
// would put every such finding under the same repository.
func TestNormalizeImageWithoutArtifactName(t *testing.T) {
	_, err := Normalize([]byte(
		`{"SchemaVersion":2,"ArtifactType":"container_image","ArtifactName":"","Results":[]}`), "scan-1")
	if err == nil {
		t.Error("an image report with no artifact name must be refused")
	}
}

// The security-critical flag. Without it trivy tries the local docker daemon,
// containerd, and podman before the registry -- reading images it was never
// pointed at, and sidestepping the address policy that validated the reference.
func TestImageArgsForceRemoteRegistry(t *testing.T) {
	args := New("/var/cache/trivy").imageArgs("alpine:3.9")

	i := slices.Index(args, "--image-src")
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("--image-src missing from %v", args)
	}
	if args[i+1] != "remote" {
		t.Errorf("--image-src = %q, want remote: any other value reaches a local daemon", args[i+1])
	}
	if args[len(args)-1] != "alpine:3.9" {
		t.Errorf("image reference must be the final argument, got %v", args)
	}
	// §6: this mode asks for vulnerabilities and nothing else.
	j := slices.Index(args, "--scanners")
	if j < 0 || args[j+1] != "vuln" {
		t.Errorf("--scanners = %v, want vuln only", args)
	}
	if slices.Contains(args, "--skip-db-update") == false {
		t.Error("an image scan must not update the database mid-scan (ADR 012)")
	}
}

// The environment is an allow-list, and these are the variables trivy reads for
// registry authentication. None may reach it: §14.7 gives workers no registry
// credentials, and ADR 025 keeps image support to public registries.
func TestImageScanCarriesNoRegistryCredentials(t *testing.T) {
	env := New("/var/cache/trivy").env()

	forbidden := []string{
		"TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN",
		"DOCKER_CONFIG", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID",
	}
	for _, v := range env {
		name, _, _ := strings.Cut(v, "=")
		if slices.Contains(forbidden, name) {
			t.Errorf("%s reaches the trivy subprocess (§14.7)", name)
		}
	}
	if !slices.Contains(env, "HOME=/nonexistent") {
		t.Error("HOME must not resolve, or trivy reads ~/.docker/config.json")
	}
}

// The worker sits on the far side of a queue from the validator, so it
// re-applies the character rule rather than trusting the payload.
func TestScanRejectsUnsafeImageReferences(t *testing.T) {
	for _, ref := range []string{
		"--config=/etc/passwd", "-x", "alpine;id", "alpine|id",
		"alpine ../../etc", "a$(id)", "",
	} {
		if imageRefIsSafe(ref) && ref != "" {
			t.Errorf("imageRefIsSafe(%q) = true, want false", ref)
		}
	}
	for _, ref := range []string{"alpine", "alpine:3.9", "ghcr.io/org/app:1.2.3"} {
		if !imageRefIsSafe(ref) {
			t.Errorf("imageRefIsSafe(%q) = false, want true", ref)
		}
	}
}
