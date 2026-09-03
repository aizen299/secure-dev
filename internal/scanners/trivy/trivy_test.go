package trivy

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../tests/fixtures/trivy", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestCapabilities(t *testing.T) {
	c := New("/var/cache/trivy").Capabilities()

	if !c.Supports(scanners.KindFilesystem) {
		t.Error("trivy must accept filesystem targets")
	}
	if !c.Supports(scanners.KindImage) {
		t.Error("trivy must accept image targets (ADR 025)")
	}
	if !c.Covers(scanners.CategoryIaC) || !c.Covers(scanners.CategoryContainer) {
		t.Errorf("categories = %v, want both iac and container", c.Categories)
	}
	if c.Covers(scanners.CategorySecrets) || c.Covers(scanners.CategoryDependency) {
		t.Errorf("categories = %v: gitleaks owns secrets and grype owns dependencies (§6)", c.Categories)
	}
}

// Egress is per-kind, and the filesystem half is the half that must not have
// it: that scan runs over an untrusted checkout on disk, which is exactly the
// situation ADR 012 provisions ahead of time so the scan itself needs nothing.
func TestNetworkIsRequiredOnlyForImageTargets(t *testing.T) {
	c := New("/var/cache/trivy").Capabilities()

	if c.NeedsNetwork(scanners.KindFilesystem) {
		t.Error("a filesystem scan must run with no egress (ADR 012, §14.3)")
	}
	if !c.NeedsNetwork(scanners.KindImage) {
		t.Error("an image scan must declare the registry egress it needs")
	}
}

// The control this adapter exists for. Trivy embeds the source lines that
// caused each finding, and for infrastructure-as-code that source is routinely
// a credential (§15.3, ADR 015).
func TestRedactionRemovesSourceContent(t *testing.T) {
	before := fixture(t, "unredacted.json")

	// The fixture must actually carry source, or this test asserts nothing.
	if err := assertNoSourceContent(before); err == nil {
		t.Fatal("the unredacted fixture carries no source; the test is vacuous")
	}
	if !strings.Contains(string(before), "example-not-a-real-password") {
		t.Fatal("the unredacted fixture lost its planted value")
	}

	after, err := redactSourceContent(before)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if err := assertNoSourceContent(after); err != nil {
		t.Errorf("source survived redaction: %v", err)
	}
	if strings.Contains(string(after), "example-not-a-real-password") {
		t.Error("the planted value survived redaction")
	}
	if strings.Contains(string(after), "USER root") {
		t.Error("Dockerfile source survived redaction")
	}
}

// Redaction must not cost the report its usefulness: the location and the rule
// are what a person acts on, and Phase 4 fingerprints against them.
func TestRedactionKeepsWhatRemediationNeeds(t *testing.T) {
	after, err := redactSourceContent(fixture(t, "unredacted.json"))
	if err != nil {
		t.Fatalf("redact: %v", err)
	}

	n, err := misconfigurationCount(after)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n == 0 {
		t.Fatal("redaction removed the findings themselves")
	}

	var doc struct {
		Results []struct {
			Target            string `json:"Target"`
			Misconfigurations []struct {
				ID            string `json:"ID"`
				Severity      string `json:"Severity"`
				CauseMetadata struct {
					StartLine int `json:"StartLine"`
					Code      struct {
						Lines []struct {
							Number  int    `json:"Number"`
							Content string `json:"Content"`
							IsCause bool   `json:"IsCause"`
						} `json:"Lines"`
					} `json:"Code"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var checkedLines bool
	for _, r := range doc.Results {
		for _, m := range r.Misconfigurations {
			if m.ID == "" || m.Severity == "" {
				t.Error("a finding lost its rule or severity")
			}
			for _, ln := range m.CauseMetadata.Code.Lines {
				checkedLines = true
				if ln.Number == 0 {
					t.Error("a cause line lost its line number")
				}
				if ln.Content != redactedMarker {
					t.Errorf("Content = %q, want the marker", ln.Content)
				}
			}
		}
	}
	if !checkedLines {
		t.Error("no cause lines were examined; the assertion is vacuous")
	}
}

// The rewrite walks a decoded document, so a trivy schema change could move
// source somewhere it does not look. The assertion is what catches that.
func TestAssertionCatchesWhatTheRewriteMisses(t *testing.T) {
	err := assertNoSourceContent(fixture(t, "unredacted-after-rewrite.json"))
	if !errors.Is(err, ErrSourceLeak) {
		t.Errorf("err = %v, want ErrSourceLeak", err)
	}
	// The offending value must not travel in the error: it may be a credential.
	if err != nil && strings.Contains(err.Error(), "secret-source-line") {
		t.Error("the error message quotes the source it refused")
	}
}

// Highlighted is the same line with ANSI colour. Redacting only Content leaves
// the secret in the document -- measured, not assumed.
func TestHighlightedIsRedactedToo(t *testing.T) {
	if !slices.Contains(sourceBearingFields, "Content") {
		t.Error("Content is not redacted")
	}
	if !slices.Contains(sourceBearingFields, "Highlighted") {
		t.Error("Highlighted is not redacted; the secret survives in the coloured copy")
	}
	if !slices.Contains(sourceBearingFields, "Annotation") {
		t.Error("Annotation is not redacted")
	}
}

func TestValidateAcceptsRealReports(t *testing.T) {
	for _, name := range []string{"unredacted.json", "no-findings.json"} {
		if err := validateReport(fixture(t, name)); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
}

func TestValidateRejectsBadOutput(t *testing.T) {
	for _, name := range []string{"empty.json", "malformed.json", "truncated.json", "wrong-tool.json"} {
		t.Run(name, func(t *testing.T) {
			if err := validateReport(fixture(t, name)); err == nil {
				t.Error("accepted output that is not a usable trivy report")
			}
		})
	}
}

// An empty result set and a broken scan both contain zero findings. Conflating
// them is how a failed scan becomes a clean bill of health.
func TestNoFindingsIsNotAnError(t *testing.T) {
	data := fixture(t, "no-findings.json")
	if err := validateReport(data); err != nil {
		t.Fatalf("a clean project was rejected: %v", err)
	}
	n, err := misconfigurationCount(data)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("findings = %d, want 0", n)
	}
}

// §6: grype owns dependency vulnerabilities and gitleaks owns secrets. Asking
// trivy for either duplicates a domain another adapter already covers.
func TestArgsRequestOnlyMisconfiguration(t *testing.T) {
	got := New("/var/cache/trivy").fsArgs()

	i := slices.Index(got, "--scanners")
	if i < 0 || i+1 >= len(got) {
		t.Fatal("no --scanners flag; trivy would run its defaults, which include vuln and secret")
	}
	if got[i+1] != "misconfig" {
		t.Errorf("--scanners %q, want exactly misconfig (§6)", got[i+1])
	}
	for _, forbidden := range []string{"vuln", "secret", "license"} {
		if strings.Contains(got[i+1], forbidden) {
			t.Errorf("--scanners includes %q, which another adapter owns", forbidden)
		}
	}

	// No egress during a scan: the checks bundle is provisioned beforehand.
	for _, flag := range []string{"--skip-check-update", "--skip-db-update"} {
		if !slices.Contains(got, flag) {
			t.Errorf("%s missing; a scan would fetch with untrusted content on disk", flag)
		}
	}
	// A scan that found misconfigurations succeeded at its job.
	if j := slices.Index(got, "--exit-code"); j < 0 || got[j+1] != "0" {
		t.Error("findings must not make trivy exit non-zero")
	}
	if got[len(got)-1] != "." {
		t.Errorf("scan root = %q, want . so paths stay repository-relative", got[len(got)-1])
	}
}

// Trivy reads registry credentials from the environment. None can reach it,
// because nothing unlisted does.
func TestEnvIsAnAllowList(t *testing.T) {
	for _, name := range []string{"TRIVY_USERNAME", "TRIVY_PASSWORD", "GITHUB_TOKEN"} {
		t.Setenv(name, "should-never-be-inherited")
	}
	env := New("/var/cache/trivy").env()

	joined := strings.Join(env, "\n")
	for _, name := range []string{"TRIVY_USERNAME", "TRIVY_PASSWORD", "GITHUB_TOKEN"} {
		if strings.Contains(joined, name) {
			t.Errorf("%s reached the subprocess environment", name)
		}
	}
	if !strings.Contains(joined, "TMPDIR=") {
		t.Error("no TMPDIR; the worker's root filesystem is read-only")
	}
}

func TestCacheDirIsValidated(t *testing.T) {
	for _, bad := range []string{"", "  ", "relative/path", "./cache"} {
		if _, err := (&Scanner{CacheDir: bad}).baseDir(); err == nil {
			t.Errorf("baseDir accepted %q", bad)
		}
	}
	got, err := (&Scanner{CacheDir: "/var/cache/trivy/../trivy/"}).baseDir()
	if err != nil {
		t.Fatalf("a valid absolute path was rejected: %v", err)
	}
	if got != "/var/cache/trivy" {
		t.Errorf("baseDir = %q, want the cleaned path", got)
	}
}

func TestScanRejectsUnsupportedTargets(t *testing.T) {
	// A repository is fetched into the workspace before any adapter sees it
	// (ADR 008), so no adapter serves the kind directly. An endpoint needs
	// ZAP, which does not exist.
	for _, kind := range []scanners.Kind{scanners.KindRepository, scanners.KindEndpoint} {
		_, err := New("/var/cache/trivy").Scan(t.Context(), scanners.Target{Kind: kind})
		if !errors.Is(err, scanners.ErrUnsupportedTarget) {
			t.Errorf("%s target: err = %v, want ErrUnsupportedTarget", kind, err)
		}
	}
}

// A kind the adapter serves, with the field that kind requires left empty, is a
// different failure from a kind it does not serve -- and the two must not be
// reported as the same thing.
func TestScanRejectsIncompleteTargets(t *testing.T) {
	for _, target := range []scanners.Target{
		{Kind: scanners.KindFilesystem},
		{Kind: scanners.KindImage},
	} {
		_, err := New("/var/cache/trivy").Scan(t.Context(), target)
		if err == nil {
			t.Errorf("%s target with no value was accepted", target.Kind)
			continue
		}
		if errors.Is(err, scanners.ErrUnsupportedTarget) {
			t.Errorf("%s target: reported as unsupported, but the adapter does support it", target.Kind)
		}
	}
}

func TestParseVersion(t *testing.T) {
	if got := parseVersion([]byte(`{"Version":"0.74.0"}`)); got != "0.74.0" {
		t.Errorf("parseVersion = %q, want 0.74.0", got)
	}
	if got := parseVersion([]byte("not json")); got != "" {
		t.Errorf("parseVersion = %q, want empty for unparseable output", got)
	}
}

// The deterministic checks above are the real coverage (§19). This confirms the
// adapter drives the actual tool, which fixtures cannot.
func TestScanAgainstRealTrivy(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy is not installed; skipping live-binary test")
	}
	dir := os.Getenv("SECUREOPS_TRIVY_DIR")
	if dir == "" {
		t.Skip("SECUREOPS_TRIVY_DIR is not set; provisioning checks would need network")
	}

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "Dockerfile"),
		[]byte("FROM alpine:3.22\nUSER root\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := New(dir)
	raw, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: project})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := validateReport(raw.Output); err != nil {
		t.Fatalf("the adapter accepted output it should have rejected: %v", err)
	}
	if raw.Version == "" {
		t.Error("scanner version was not captured (§7 rule 6)")
	}
	// The real run must satisfy the same controls the fixtures assert.
	if err := assertNoSourceContent(raw.Output); err != nil {
		t.Errorf("real trivy output carried source: %v", err)
	}
	if strings.Contains(string(raw.Output), "USER root") {
		t.Error("real Dockerfile source reached the persisted output")
	}
	if err := assertNoWorkspacePaths(raw.Output, project); err != nil {
		t.Errorf("real trivy output embedded the workspace: %v", err)
	}
}

// The image half of the live check. Same reasoning as TestScanAgainstRealTrivy:
// the deterministic checks are the real coverage, and this confirms the adapter
// drives the actual tool.
//
// Doubly gated. It needs a provisioned vulnerability database, and it reaches a
// registry -- so it runs only when both are deliberately arranged, and never in
// the default local loop.
func TestImageScanAgainstRealTrivy(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy is not installed; skipping live-binary test")
	}
	dir := os.Getenv("SECUREOPS_TRIVY_DIR")
	if dir == "" {
		t.Skip("SECUREOPS_TRIVY_DIR is not set; the vulnerability database would need provisioning")
	}
	image := os.Getenv("SECUREOPS_TRIVY_TEST_IMAGE")
	if image == "" {
		t.Skip("SECUREOPS_TRIVY_TEST_IMAGE is not set; an image scan reaches a registry")
	}

	// Provisioning is part of the contract being checked: an image scan runs
	// --skip-db-update, so it works only if the database was fetched before the
	// job (ADR 012).
	sc := New(dir)
	if err := sc.Provision(t.Context()); err != nil {
		t.Fatalf("provision: %v", err)
	}

	raw, err := sc.Scan(t.Context(), scanners.Target{Kind: scanners.KindImage, Image: image})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := validateReport(raw.Output); err != nil {
		t.Fatalf("the adapter accepted output it should have rejected: %v", err)
	}
	if raw.Version == "" {
		t.Error("scanner version was not captured (§7 rule 6)")
	}

	res, err := Normalize(raw.Output, "scan-live")
	if err != nil {
		t.Fatalf("normalize live output: %v", err)
	}
	for _, f := range res.Findings {
		if f.Category != scanners.CategoryContainer {
			t.Errorf("%s: category = %q, want container", f.CVE, f.Category)
		}
		if f.Image == "" {
			t.Errorf("%s: no image recorded", f.CVE)
		}
		if strings.ContainsAny(f.Image, ":@") {
			t.Errorf("image %q carries a tag or digest; identity would churn on rebuild", f.Image)
		}
	}
}

// A scan of untrusted content must reach nothing.
//
// This is the flag that was missing. Trivy's Java post-analyzer resolves POM
// dependencies against Maven Central during a filesystem scan, which broke the
// posture every other adapter holds (ADR 012, §14.3) and made this adapter's
// own NetworkKinds declaration untrue -- it claims a filesystem scan needs no
// network.
//
// It surfaced as a reliability failure: Maven Central rate-limited the worker,
// trivy exited 1, and a real scan degraded to PARTIAL. The worse half is
// quieter -- scanning a private repository disclosed its dependency list to a
// third party simply by scanning it.
func TestScansNeverReachTheNetworkForDependencies(t *testing.T) {
	s := New("/var/cache/trivy")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"filesystem", s.fsArgs()},
		{"image", s.imageArgs("alpine:3.9")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !slices.Contains(tc.args, "--offline-scan") {
				t.Errorf("--offline-scan missing from %v: an analyzer may resolve "+
					"dependencies against a remote registry mid-scan", tc.args)
			}
			// The database and checks bundle are provisioned before a job is
			// claimed, so a scan must never fetch either.
			if !slices.Contains(tc.args, "--skip-db-update") {
				t.Error("--skip-db-update missing; the scan would fetch a database")
			}
		})
	}
}
