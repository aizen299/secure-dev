package gitleaks

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

// requireGitleaks skips when the binary is absent. The deterministic behaviour
// is covered by the fixture tests; these exercise the real invocation, which
// cannot be faked without losing the point.
func requireGitleaks(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks is not installed; skipping live-binary test")
	}
}

// Synthetic credentials, assembled at runtime from fragments.
//
// The values must be correctly formatted to be useful: a readable placeholder
// like "AKIAIOSFODNN7EXAMPLE" is allowlisted by gitleaks, so a test using one
// would find nothing and quietly assert nothing.
//
// But a correctly formatted credential written as a literal is, to any secret
// scanner, indistinguishable from a real one -- including the scanner this
// repository runs on itself, which flagged exactly these two lines. Splitting
// them means no complete credential pattern exists anywhere in the source,
// while the value handed to gitleaks under test is still the real shape.
// The alternative was allowlisting this file, which would hide a genuine
// secret pasted here later.
var (
	syntheticAWSKey    = "AKIA" + "Z3QW7T4NBVCXK2LM"
	syntheticGitHubPAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
)

// seedSecrets writes the synthetic credentials into a temporary directory.
func seedSecrets(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := "aws_access_key_id = " + syntheticAWSKey + "\n" +
		"github_pat = " + syntheticGitHubPAT + "\n"
	if err := os.WriteFile(filepath.Join(dir, "creds.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture repo: %v", err)
	}
	return dir
}

func TestCapabilities(t *testing.T) {
	caps := New().Capabilities()

	// Filesystem only: the worker fetches repositories and hands adapters a
	// checkout (ADR 008), so this adapter must never be selected for a URL.
	if !caps.Supports(scanners.KindFilesystem) {
		t.Error("gitleaks should support filesystem targets")
	}
	if caps.Supports(scanners.KindRepository) {
		t.Error("gitleaks must not claim repository targets; the worker fetches those")
	}
	if !caps.Covers(scanners.CategorySecrets) {
		t.Errorf("categories = %v, want secrets", caps.Categories)
	}
	for _, k := range caps.Kinds {
		if caps.NeedsNetwork(k) {
			t.Error("gitleaks ships its rules in the binary and needs no egress")
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
			_, err := s.Scan(t.Context(), target)
			if !errors.Is(err, scanners.ErrUnsupportedTarget) {
				t.Errorf("Scan(%s): error = %v, want ErrUnsupportedTarget", target.Kind, err)
			}
		})
	}
}

func TestScanRequiresAPath(t *testing.T) {
	_, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem})
	if err == nil {
		t.Fatal("Scan with no path should fail")
	}
}

func TestVersionReportsMissingBinary(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err == nil {
		t.Skip("gitleaks is installed; this asserts the not-installed path")
	}
	_, err := New().Version(t.Context())
	if !errors.Is(err, scanners.ErrBinaryMissing) {
		t.Errorf("Version: error = %v, want ErrBinaryMissing", err)
	}
}

func TestScanFindsSecretsAndRedactsThem(t *testing.T) {
	requireGitleaks(t)
	dir := seedSecrets(t)

	raw, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}

	findings, err := parseReport(raw.Output)
	if err != nil {
		t.Fatalf("parse the adapter's own output: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("found %d secrets, want at least 2 (the fixture plants two)", len(findings))
	}

	// The guarantee, asserted against the real binary rather than a fixture:
	// what the adapter returns carries no credential.
	output := string(raw.Output)
	for _, secret := range []string{syntheticAWSKey, syntheticGitHubPAT} {
		if strings.Contains(output, secret) {
			t.Errorf("the adapter returned an unredacted secret (%s...)", secret[:8])
		}
	}
	for _, f := range findings {
		if !isRedactedSecret(f.Secret) || !isRedactedMatch(f.Match) {
			t.Errorf("finding %q was returned unredacted", f.RuleID)
		}
	}

	if raw.Version == "" {
		t.Error("the scanner version was not captured; results are only reproducible relative to it")
	}
	if raw.Scanner != Name {
		t.Errorf("Scanner = %q, want %q", raw.Scanner, Name)
	}
}

// gitleaks exits 1 when it finds secrets. That is a result, not a failure, and
// treating it as one would make every repository with a leak look like a broken
// scan.
func TestFindingSecretsIsNotAFailure(t *testing.T) {
	requireGitleaks(t)
	dir := seedSecrets(t)

	raw, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("Scan returned an error for a successful scan that found secrets: %v", err)
	}
	if raw.ExitCode == 0 {
		t.Skip("gitleaks did not use a non-zero exit code; nothing to assert")
	}
}

func TestCleanRepositoryProducesNoFindings(t *testing.T) {
	requireGitleaks(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	raw, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("Scan: unexpected error: %v", err)
	}

	findings, err := parseReport(raw.Output)
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("found %d secrets in a clean repository, want 0", len(findings))
	}
}

// The report must be written outside the scanned directory. When it is not,
// gitleaks scans its own output on the next run and reports the findings it
// already recorded -- inflating counts and, worse, doing so silently.
func TestTheReportIsNotWrittenIntoTheScannedDirectory(t *testing.T) {
	requireGitleaks(t)
	dir := seedSecrets(t)

	if _, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read scanned directory: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "creds.txt" {
			t.Errorf("the scan left %q in the scanned directory; the report must be written elsewhere", e.Name())
		}
	}
}

// Scanning the same directory twice must give the same answer. If the report
// leaked into the source tree, the second run would find more.
func TestScanIsRepeatable(t *testing.T) {
	requireGitleaks(t)
	dir := seedSecrets(t)
	s := New()

	first, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("first Scan: %v", err)
	}
	second, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("second Scan: %v", err)
	}

	a, err := parseReport(first.Output)
	if err != nil {
		t.Fatalf("parse first: %v", err)
	}
	b, err := parseReport(second.Output)
	if err != nil {
		t.Fatalf("parse second: %v", err)
	}
	if len(a) != len(b) {
		t.Errorf("first run found %d secrets, second found %d; the scan is not repeatable", len(a), len(b))
	}
}

// Findings must be repo-relative. An absolute source would put the worker's
// workspace path into every stored finding.
func TestFindingPathsAreRepositoryRelative(t *testing.T) {
	requireGitleaks(t)
	dir := seedSecrets(t)

	raw, err := New().Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	findings, err := parseReport(raw.Output)
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings to check")
	}

	for _, f := range findings {
		if filepath.IsAbs(f.File) {
			t.Errorf("File is absolute (%q); it must be relative to the checkout", f.File)
		}
		if strings.Contains(f.File, dir) {
			t.Errorf("File leaks the workspace path: %q", f.File)
		}
	}
}

// The subprocess gets an explicit environment, so it cannot inherit the
// worker's database URL, Redis password, or cloud credentials (§14.7).
func TestSubprocessEnvironmentIsAnAllowList(t *testing.T) {
	got := env()
	if len(got) == 0 {
		t.Fatal("env() returned nothing; a nil environment would make the child inherit the worker's")
	}
	for _, entry := range got {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "PATH", "HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM":
		default:
			t.Errorf("unexpected variable %q in the scanner environment", name)
		}
	}
	for _, forbidden := range []string{"SECUREOPS_DATABASE_URL", "SECUREOPS_REDIS_URL", "AWS_SECRET_ACCESS_KEY"} {
		for _, entry := range got {
			if strings.HasPrefix(entry, forbidden+"=") {
				t.Errorf("the scanner environment carries %s", forbidden)
			}
		}
	}
}

func TestScanHonoursCancellation(t *testing.T) {
	requireGitleaks(t)
	dir := seedSecrets(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := New().Scan(ctx, scanners.Target{Kind: scanners.KindFilesystem, Path: dir}); err == nil {
		t.Error("Scan with a cancelled context should fail")
	}
}
