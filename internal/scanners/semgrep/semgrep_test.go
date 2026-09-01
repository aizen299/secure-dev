package semgrep

import (
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
	data, err := os.ReadFile(filepath.Join("../../../tests/fixtures/semgrep", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestCapabilities(t *testing.T) {
	c := New("/var/lib/semgrep").Capabilities()

	if !c.Supports(scanners.KindFilesystem) {
		t.Error("semgrep must accept filesystem targets")
	}
	if c.Supports(scanners.KindRepository) {
		t.Error("semgrep must not claim repository targets: the worker fetches them (ADR 008)")
	}
	if c.Category != scanners.CategorySAST {
		t.Errorf("category = %q, want sast", c.Category)
	}
	// Rules are provisioned before any job is claimed, so a scan of untrusted
	// content needs no egress at all.
	if c.RequiresNetwork {
		t.Error("semgrep must not require network during a scan (ADR 012, ADR 014)")
	}
}

// The control this adapter exists for. Semgrep can put the matched line in
// every finding, and for a credential rule that line IS the credential (§15.3).
func TestMatchedSourceIsRefused(t *testing.T) {
	for _, name := range []string{"source-leak.json", "source-leak-benign.json"} {
		t.Run(name, func(t *testing.T) {
			err := assertNoMatchedSource(fixture(t, name))
			if !errors.Is(err, ErrSourceLeak) {
				t.Errorf("err = %v, want ErrSourceLeak", err)
			}
			// The offending value must not travel in the error either: an
			// error message is logged, and a logged credential is a stored
			// credential (§15.3).
			if err != nil && strings.Contains(err.Error(), "AWS_SECRET_ACCESS_KEY") {
				t.Error("the error message quotes the matched source")
			}
		})
	}
}

// Unauthenticated semgrep writes "requires login" rather than source, which is
// what makes the redacted case the normal one.
func TestRedactedSourceIsAccepted(t *testing.T) {
	for _, name := range []string{"valid.json", "no-findings.json"} {
		if err := assertNoMatchedSource(fixture(t, name)); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
}

func TestIsRedactedSource(t *testing.T) {
	for _, ok := range []string{"", "   ", "requires login", " requires login "} {
		if !isRedactedSource(ok) {
			t.Errorf("isRedactedSource(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"x = 1",
		"requires login extra",
		"# requires login",
		"AWS_KEY = \"redacted-but-still-source\"",
	} {
		if isRedactedSource(bad) {
			t.Errorf("isRedactedSource(%q) = true, want false", bad)
		}
	}
}

// The worker's ephemeral workspace must not reach the artifact, for the reason
// recorded as T-30 against syft: a document that differs between two scans of
// the same commit can never be compared.
func TestWorkspacePathIsRefused(t *testing.T) {
	err := assertNoWorkspacePaths(fixture(t, "workspace-path-leak.json"), "/workspaces/scan-abc123")
	if !errors.Is(err, ErrSourceLeak) {
		t.Errorf("err = %v, want a refusal", err)
	}
	if err := assertNoWorkspacePaths(fixture(t, "valid.json"), "/workspaces/scan-abc123"); err != nil {
		t.Errorf("a clean report was rejected: %v", err)
	}
}

func TestValidateAcceptsRealReports(t *testing.T) {
	for _, name := range []string{"valid.json", "no-findings.json"} {
		if err := validateReport(fixture(t, name)); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
}

func TestValidateRejectsBadOutput(t *testing.T) {
	for _, name := range []string{
		"empty.json", "malformed.json", "truncated.json", "wrong-tool.json",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateReport(fixture(t, name)); err == nil {
				t.Error("accepted output that is not a usable semgrep report")
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
	n, err := resultCount(data)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("results = %d, want 0", n)
	}
}

func TestValidReportIsPopulated(t *testing.T) {
	n, err := resultCount(fixture(t, "valid.json"))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n == 0 {
		t.Error("the valid fixture has no findings, so it asserts nothing")
	}
}

// Secret detection belongs to gitleaks (§6). Two scanners reporting the same
// credential would also mean ADR 007's redaction control has to be
// reimplemented here, correctly, a second time.
func TestSecretsRulesAreNotDuplicated(t *testing.T) {
	if slices.Contains(DefaultRulesets, "p/secrets") {
		t.Error("p/secrets duplicates gitleaks' domain (§6)")
	}
	if len(DefaultRulesets) == 0 {
		t.Error("no rulesets configured; the adapter would find nothing")
	}
}

func TestArgsCarryTheControls(t *testing.T) {
	got := New("/var/lib/semgrep").args()

	if !slices.Contains(got, "--metrics=off") {
		t.Error("metrics must be off: they are on by default")
	}
	if !slices.Contains(got, "--no-autofix") {
		t.Error("autofix would let an analyser write to the thing it is analysing")
	}
	if !slices.Contains(got, "--json") {
		t.Error("output format must be json")
	}
	if got[len(got)-1] != "." {
		t.Errorf("scan root = %q, want . so paths stay repository-relative", got[len(got)-1])
	}
	// A registry name here would mean fetching rules mid-scan, with untrusted
	// content already on disk.
	for i, a := range got {
		if a == "--config" && strings.HasPrefix(got[i+1], "p/") {
			t.Errorf("--config points at a registry name (%q); rules must be provisioned", got[i+1])
		}
	}
}

// Semgrep withholds matched source only while unauthenticated. A token in the
// environment would silently turn that off, so nothing unlisted may reach the
// subprocess.
func TestEnvIsAnAllowListWithoutTokens(t *testing.T) {
	t.Setenv("SEMGREP_APP_TOKEN", "should-never-be-inherited")
	env := New("/var/lib/semgrep").env()

	for _, e := range env {
		if strings.HasPrefix(e, "SEMGREP_APP_TOKEN") {
			t.Error("a Semgrep token reached the subprocess environment")
		}
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "SEMGREP_SEND_METRICS=off") {
		t.Error("metrics must be disabled in the environment as well as the flags")
	}
	// HOME must be writable: semgrep creates $HOME/.semgrep on every run.
	if strings.Contains(joined, "HOME=/nonexistent") {
		t.Error("HOME=/nonexistent makes semgrep die creating $HOME/.semgrep")
	}
}

// Rules and semgrep's own state must not share a directory: semgrep would be
// offered its own state as a rule file.
func TestRulesAndStateAreSeparate(t *testing.T) {
	s := New("/var/lib/semgrep")
	if s.rulesDir() == s.homeDir() {
		t.Fatal("rules and state share a directory")
	}
	if strings.HasPrefix(s.homeDir(), s.rulesDir()+string(filepath.Separator)) {
		t.Error("semgrep's state lives inside the rules directory")
	}
}

func TestRulesetFilenameRejectsHostileNames(t *testing.T) {
	if got, err := rulesetFilename("p/golang"); err != nil || got != "p_golang.yaml" {
		t.Errorf("rulesetFilename(p/golang) = %q, %v", got, err)
	}
	for _, bad := range []string{
		"", "../../etc/passwd", "-oProxyCommand=x", "p/../../escape", "p/x;rm -rf /",
	} {
		if _, err := rulesetFilename(bad); err == nil {
			t.Errorf("rulesetFilename(%q) was accepted", bad)
		}
	}
}

func TestAssertIsRulesDocument(t *testing.T) {
	// The registry content-negotiates: YAML for curl, JSON for a Go client.
	// Both are real responses and both must be accepted.
	if err := assertIsRulesDocument([]byte("rules:\n  - id: x\n    message: y\n")); err != nil {
		t.Errorf("YAML ruleset rejected: %v", err)
	}
	if err := assertIsRulesDocument([]byte(`{"rules":[{"id":"x","message":"y"}]}`)); err != nil {
		t.Errorf("JSON ruleset rejected: %v", err)
	}
	for _, bad := range [][]byte{
		[]byte("<html><body>404 not found</body></html>"),
		[]byte(`{"rules":[]}`),
		[]byte("rules:\n"),
		[]byte(""),
	} {
		if err := assertIsRulesDocument(bad); err == nil {
			t.Errorf("accepted %q as a rules document", string(bad))
		}
	}
}

func TestScanRejectsNonFilesystemTargets(t *testing.T) {
	_, err := New("/var/lib/semgrep").Scan(
		t.Context(), scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://x/y"})
	if err == nil {
		t.Fatal("a repository target was accepted")
	}
}

func TestScanRequiresAConfiguredDirectory(t *testing.T) {
	s := &Scanner{}
	_, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: t.TempDir()})
	if err == nil {
		t.Fatal("a scan ran with no rules directory configured")
	}
}

// The deterministic checks above are the real coverage (§19). This confirms the
// adapter drives the actual tool, which fixtures cannot.
func TestScanAgainstRealSemgrep(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep is not installed; skipping live-binary test")
	}
	dir := os.Getenv("SECUREOPS_SEMGREP_DIR")
	if dir == "" {
		t.Skip("SECUREOPS_SEMGREP_DIR is not set; provisioning rules would need network")
	}

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "app.py"),
		[]byte("import hashlib\ndef f(p):\n    return hashlib.md5(p).hexdigest()\n"), 0o600); err != nil {
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
	// The real run must satisfy the same control the fixtures assert.
	if err := assertNoMatchedSource(raw.Output); err != nil {
		t.Errorf("real semgrep output carried matched source: %v", err)
	}
	if err := assertNoWorkspacePaths(raw.Output, project); err != nil {
		t.Errorf("real semgrep output embedded the workspace: %v", err)
	}
}

// The worker's root filesystem is read-only. Semgrep needs scratch space and
// dies with an obscure Python error without it -- the third scanner to hit this
// same wall, so it is asserted rather than remembered.
func TestEnvGivesSemgrepAWritableTempDir(t *testing.T) {
	s := New("/var/lib/semgrep")
	joined := strings.Join(s.env(), "\n")

	if !strings.Contains(joined, "TMPDIR="+s.tmpDir()) {
		t.Error("TMPDIR is not set; semgrep cannot find a temporary directory on a read-only root")
	}
	// Scratch space must not sit among the rules, which are loaded as a
	// directory.
	if strings.HasPrefix(s.tmpDir(), s.rulesDir()+string(filepath.Separator)) {
		t.Error("the temp directory lives inside the rules directory")
	}
}

// Dir arrives from the environment, so it is validated rather than trusted and
// canonicalised before anything is joined onto it (§14.5).
func TestBaseDirIsValidated(t *testing.T) {
	for _, bad := range []string{"", "   ", "relative/path", "./rules", "../escape"} {
		if _, err := (&Scanner{Dir: bad}).baseDir(); err == nil {
			t.Errorf("baseDir accepted %q", bad)
		}
	}
	got, err := (&Scanner{Dir: "/var/cache/semgrep/../semgrep/"}).baseDir()
	if err != nil {
		t.Fatalf("a valid absolute path was rejected: %v", err)
	}
	if got != "/var/cache/semgrep" {
		t.Errorf("baseDir = %q, want the cleaned path /var/cache/semgrep", got)
	}
}
