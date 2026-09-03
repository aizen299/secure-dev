package syft

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "fixtures", "syft", name)
	data, err := os.ReadFile(path) //nolint:gosec // G304: a fixed test fixture path.
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func requireSyft(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft is not installed; skipping live-binary test")
	}
}

// seedProject writes a directory with recognisable manifests.
func seedProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("go.mod", "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n")
	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}`)
	// A lockfile is required for the npm cataloger: syft does not resolve a
	// bare package.json, because a declared range is not a resolved version.
	// Without this the directory yields Go components only, and a test
	// asserting "at least two ecosystems" would be asserting nothing.
	write("package-lock.json", `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,`+
		`"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},`+
		`"node_modules/lodash":{"version":"4.17.21",`+
		`"resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}`)
	return dir
}

// --- contract --------------------------------------------------------------

func TestCapabilities(t *testing.T) {
	caps := New().Capabilities()

	if !caps.Supports(scanners.KindFilesystem) {
		t.Error("syft should support filesystem targets")
	}
	// The worker fetches repositories; adapters see a checkout (ADR 008).
	if caps.Supports(scanners.KindRepository) {
		t.Error("syft must not claim repository targets")
	}
	if !caps.Covers(scanners.CategorySBOM) {
		t.Errorf("categories = %v, want sbom", caps.Categories)
	}
	for _, k := range caps.Kinds {
		if caps.NeedsNetwork(k) {
			t.Error("syft catalogs local content and must not declare a network requirement")
		}
	}
}

func TestScanRejectsUnsupportedTargets(t *testing.T) {
	s := New()
	for _, target := range []scanners.Target{
		{Kind: scanners.KindRepository, RepositoryURL: "https://github.com/a/b"},
		{Kind: scanners.KindImage, Image: "alpine:3"},
		{Kind: scanners.KindEndpoint, EndpointURL: "https://api.example"},
	} {
		t.Run(string(target.Kind), func(t *testing.T) {
			if _, err := s.Scan(t.Context(), target); !errors.Is(err, scanners.ErrUnsupportedTarget) {
				t.Errorf("Scan(%s): error = %v, want ErrUnsupportedTarget", target.Kind, err)
			}
		})
	}
}

func TestScanRequiresAPath(t *testing.T) {
	if _, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem}); err == nil {
		t.Fatal("Scan with no path should fail")
	}
}

// The file cataloger is disabled deliberately, and dropping that flag silently
// reintroduces absolute workspace paths into every SBOM.
func TestArgsDisableTheFileCataloger(t *testing.T) {
	joined := strings.Join(args(), " ")

	if !strings.Contains(joined, "--select-catalogers -file") {
		t.Errorf("the file cataloger must be disabled; args are %q\n"+
			"it names components by absolute path, which embeds the ephemeral workspace", joined)
	}
	if !strings.Contains(joined, "cyclonedx-json") {
		t.Errorf("output format must be cyclonedx-json, got %q", joined)
	}
	if !strings.Contains(joined, "-q") {
		t.Errorf("syft must be quiet so stdout is the document and nothing else, got %q", joined)
	}
}

func TestEnvIsAnAllowList(t *testing.T) {
	got := env()
	if len(got) == 0 {
		t.Fatal("env() returned nothing; a nil environment makes the child inherit the worker's")
	}
	allowed := map[string]bool{"PATH": true, "HOME": true, "SYFT_CHECK_FOR_APP_UPDATE": true}
	for _, entry := range got {
		name, _, _ := strings.Cut(entry, "=")
		if !allowed[name] {
			t.Errorf("unexpected variable %q in the scanner environment", name)
		}
	}
	// A process handling untrusted content should not phone home.
	if !strings.Contains(strings.Join(got, " "), "SYFT_CHECK_FOR_APP_UPDATE=false") {
		t.Error("the update check should be disabled")
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"key-value block", "Application: syft\nVersion:     1.51.0\nBuildDate:   2026-01-01\n", "1.51.0"},
		{"lowercase key", "version: 1.51.0\n", "1.51.0"},
		{"bare string", "1.51.0", "1.51.0"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseVersion(tc.in); got != tc.want {
				t.Errorf("parseVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// --- SBOM validation -------------------------------------------------------

func TestValidateAcceptsARealDocument(t *testing.T) {
	if err := validateSBOM(fixture(t, "valid.json")); err != nil {
		t.Fatalf("validateSBOM rejected valid output: %v", err)
	}
	n, err := componentCount(fixture(t, "valid.json"))
	if err != nil {
		t.Fatalf("componentCount: %v", err)
	}
	if n != 2 {
		t.Errorf("componentCount = %d, want 2", n)
	}
}

// A repository with no recognised manifests legitimately has no components.
// Treating that as an error would fail every scan of such a repository.
func TestValidateAcceptsAnEmptyComponentList(t *testing.T) {
	if err := validateSBOM(fixture(t, "no-components.json")); err != nil {
		t.Fatalf("an empty component list is a valid result, got: %v", err)
	}
}

func TestValidateRejectsBadOutput(t *testing.T) {
	tests := []struct {
		fixture string
		why     string
	}{
		{"empty.json", "zero bytes means syft produced nothing"},
		{"malformed.json", "not JSON at all"},
		{"truncated.json", "cut mid-object, as a size cap would leave it"},
		{"spdx.json", "a realistic SPDX document, missing specVersion"},
		// Carries a specVersion, so the bomFormat check is the only thing that
		// can reject it. spdx.json alone left that check untested: it fails on
		// the missing specVersion first, so disabling the format check kept
		// every test green.
		{"wrong-format.json", "well-formed but declares SPDX, not CycloneDX"},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			if err := validateSBOM(fixture(t, tc.fixture)); !errors.Is(err, ErrMalformedSBOM) {
				t.Fatalf("error = %v, want ErrMalformedSBOM (%s)", err, tc.why)
			}
		})
	}
}

// Hostile scanner output is in the threat model (§15.7): a structured error,
// never a panic.
func TestValidateSurvivesHostileInput(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":"not an array"}`),
		[]byte(`[[[[[[[`),
		[]byte("\x00\x01\x02"),
		[]byte(`{"bomFormat":null,"specVersion":null}`),
		[]byte(`{"components":[null]}`),
	} {
		_ = validateSBOM(data)
	}
}

// --- the workspace-path invariant ------------------------------------------

// The control: an SBOM naming components by absolute workspace path would
// differ between two scans of the identical commit, so it could never be
// compared and Phase 4 could not track a component across scans.
func TestWorkspacePathLeakIsRejected(t *testing.T) {
	data := fixture(t, "workspace-path-leak.json")

	err := assertNoWorkspacePaths(data, "/workspaces/scan-abc123-4030914750/repo")
	if !errors.Is(err, ErrWorkspacePathLeak) {
		t.Fatalf("assertNoWorkspacePaths: error = %v, want ErrWorkspacePathLeak", err)
	}
}

// The parent is checked too: the checkout sits inside the job workspace, and
// leaking either reveals the layout and breaks reproducibility.
func TestWorkspaceParentPathIsAlsoRejected(t *testing.T) {
	data := []byte(`{"components":[{"name":"/workspaces/scan-abc123-4030914750/other"}]}`)

	err := assertNoWorkspacePaths(data, "/workspaces/scan-abc123-4030914750/repo")
	if !errors.Is(err, ErrWorkspacePathLeak) {
		t.Fatalf("a sibling path inside the job workspace should be rejected, got %v", err)
	}
}

func TestCleanSBOMPassesTheWorkspaceCheck(t *testing.T) {
	if err := assertNoWorkspacePaths(fixture(t, "valid.json"), "/workspaces/scan-abc/repo"); err != nil {
		t.Errorf("a clean SBOM was rejected: %v", err)
	}
}

// The error must not echo the path it is refusing to let travel.
func TestWorkspaceLeakErrorDoesNotEchoThePath(t *testing.T) {
	const workspace = "/workspaces/scan-abc123-4030914750/repo"
	data := fixture(t, "workspace-path-leak.json")

	err := assertNoWorkspacePaths(data, workspace)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), workspace) {
		t.Errorf("the error echoed the workspace path: %q", err)
	}
}

func TestNoWorkspaceConfiguredIsNotAnError(t *testing.T) {
	if err := assertNoWorkspacePaths(fixture(t, "workspace-path-leak.json"), ""); err != nil {
		t.Errorf("with no workspace path there is nothing to check, got %v", err)
	}
}

// --- live binary -----------------------------------------------------------

func TestScanProducesAValidSBOM(t *testing.T) {
	requireSyft(t)
	dir := seedProject(t)

	raw, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}

	if err := validateSBOM(raw.Output); err != nil {
		t.Fatalf("the adapter returned output that fails its own validation: %v", err)
	}
	n, err := componentCount(raw.Output)
	if err != nil {
		t.Fatalf("componentCount: %v", err)
	}
	if n < 3 {
		t.Errorf("cataloged %d components, want at least 3 "+
			"(the fixture declares a Go module and an npm lockfile)", n)
	}
	if raw.Version == "" {
		t.Error("the scanner version was not captured; results are only reproducible relative to it")
	}
	if raw.Scanner != Name {
		t.Errorf("Scanner = %q, want %q", raw.Scanner, Name)
	}
}

// The guarantee, asserted against the real binary rather than a fixture.
func TestRealSBOMContainsNoWorkspacePaths(t *testing.T) {
	requireSyft(t)
	dir := seedProject(t)

	raw, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if strings.Contains(string(raw.Output), dir) {
		t.Errorf("the SBOM embeds the scan directory %q", dir)
	}
	if err := assertNoWorkspacePaths(raw.Output, dir); err != nil {
		t.Errorf("the real SBOM failed the workspace-path check: %v", err)
	}
}

// Two scans of identical content must produce comparable SBOMs. Absolute paths
// or other per-run state would break that, and Phase 4 depends on it.
func TestSBOMComponentsAreStableAcrossRuns(t *testing.T) {
	requireSyft(t)
	dir := seedProject(t)
	s := New()

	first, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("first Scan: %v", err)
	}
	second, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("second Scan: %v", err)
	}

	a, err := componentCount(first.Output)
	if err != nil {
		t.Fatalf("count first: %v", err)
	}
	b, err := componentCount(second.Output)
	if err != nil {
		t.Fatalf("count second: %v", err)
	}
	if a != b {
		t.Errorf("first run cataloged %d components, second %d; the SBOM is not stable", a, b)
	}
}

// A directory with nothing recognisable is a clean result, not a failure.
func TestEmptyDirectoryIsNotAFailure(t *testing.T) {
	requireSyft(t)

	raw, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: t.TempDir()})
	if err != nil {
		t.Fatalf("Scan of an empty directory should succeed, got: %v", err)
	}
	if err := validateSBOM(raw.Output); err != nil {
		t.Errorf("an empty directory should still yield a valid SBOM: %v", err)
	}
}

func TestScanHonoursCancellation(t *testing.T) {
	requireSyft(t)
	dir := seedProject(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := New().Scan(ctx, scanners.Target{Kind: scanners.KindFilesystem, Path: dir}); err == nil {
		t.Error("Scan with a cancelled context should fail")
	}
}

func TestVersionReportsMissingBinary(t *testing.T) {
	if _, err := exec.LookPath("syft"); err == nil {
		t.Skip("syft is installed; this asserts the not-installed path")
	}
	if _, err := New().Version(t.Context()); !errors.Is(err, scanners.ErrBinaryMissing) {
		t.Errorf("Version: error = %v, want ErrBinaryMissing", err)
	}
}
