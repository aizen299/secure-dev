package fetch

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; skipping live-binary test")
	}
}

func repoTarget(url, ref string) scanners.Target {
	return scanners.Target{Kind: scanners.KindRepository, RepositoryURL: url, Ref: ref}
}

// --- argument vector -------------------------------------------------------

// The clone flags are the security controls from ADR 008. Asserting them
// directly means a flag cannot be dropped without a test noticing, which
// observing a subprocess would not reliably catch.
func TestCloneArgsCarryTheSecurityControls(t *testing.T) {
	args := cloneArgs("/workspace/repo", repoTarget("https://github.com/acme/app", ""))
	joined := strings.Join(args, " ")

	required := map[string]string{
		"protocol.allow=never":        "ext:: executes an arbitrary command; file:// reads the worker's disk",
		"protocol.https.allow=always": "https is one of the two transports the validator permits",
		"protocol.ssh.allow=always":   "ssh is the other",
		"credential.helper=":          "stops git attaching host credentials to an attacker-chosen URL",
		"core.hooksPath=/dev/null":    "asserts no repository hook can run",
		"--recurse-submodules=no":     "a submodule is an attacker-controlled URL fetched on our behalf",
		"--depth":                     "full history is enormous and not needed for a working-tree scan",
		"--single-branch":             "limits what is fetched",
		"--no-tags":                   "limits what is fetched",
	}
	for flag, why := range required {
		if !strings.Contains(joined, flag) {
			t.Errorf("clone is missing %q\n  why it is there: %s", flag, why)
		}
	}
}

// "--" must precede the URL so that neither it nor the destination can be read
// as a flag, whatever they contain.
func TestCloneArgsTerminateOptionParsing(t *testing.T) {
	const url = "https://github.com/acme/app"
	args := cloneArgs("/workspace/repo", repoTarget(url, ""))

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatal(`the argument vector has no "--" terminator`)
	}
	if sep != len(args)-3 {
		t.Errorf(`"--" is at %d; it must immediately precede the URL and destination (len %d)`, sep, len(args))
	}
	if args[sep+1] != url {
		t.Errorf("argument after -- is %q, want the URL", args[sep+1])
	}
}

func TestCloneArgsIncludeTheRefOnlyWhenSet(t *testing.T) {
	withRef := strings.Join(cloneArgs("/w/repo", repoTarget("https://x/y", "release/2.0")), " ")
	if !strings.Contains(withRef, "--branch release/2.0") {
		t.Errorf("a ref should be passed as --branch, got %q", withRef)
	}

	withoutRef := strings.Join(cloneArgs("/w/repo", repoTarget("https://x/y", "")), " ")
	if strings.Contains(withoutRef, "--branch") {
		t.Errorf("no ref should mean no --branch, got %q", withoutRef)
	}
}

// The subprocess must not inherit the worker's database URL, Redis password,
// or cloud credentials (§14.7).
func TestCloneEnvIsAnAllowList(t *testing.T) {
	got := cloneEnv()
	if len(got) == 0 {
		t.Fatal("cloneEnv returned nothing; a nil environment makes the child inherit the worker's")
	}

	allowed := map[string]bool{
		"GIT_TERMINAL_PROMPT": true, "GIT_ASKPASS": true, "GIT_CONFIG_NOSYSTEM": true,
		"HOME": true, "GIT_CONFIG_GLOBAL": true, "GIT_CONFIG_SYSTEM": true, "PATH": true,
	}
	for _, entry := range got {
		name, _, _ := strings.Cut(entry, "=")
		if !allowed[name] {
			t.Errorf("unexpected variable %q in the git environment", name)
		}
	}

	joined := strings.Join(got, " ")
	// Without these two a private repository blocks the worker on a password
	// prompt instead of failing fast.
	if !strings.Contains(joined, "GIT_TERMINAL_PROMPT=0") {
		t.Error("GIT_TERMINAL_PROMPT=0 is missing; a credential prompt would pin a worker slot")
	}
	if !strings.Contains(joined, "GIT_ASKPASS=") {
		t.Error("GIT_ASKPASS is missing")
	}
}

// --- transport restrictions ------------------------------------------------

// The strongest property of the clone configuration: git treats a bare local
// path as the "file" transport, so protocol.allow=never blocks reading the
// worker's own disk even if a local path somehow reached this far. The target
// validator already rejects non-https/ssh URLs; this is the second line.
func TestLocalPathsCannotBeCloned(t *testing.T) {
	requireGit(t)

	source := t.TempDir()
	mustRun(t, source, "git", "init", "-q", "-b", "main")
	mustRun(t, source, "git", "config", "user.email", "test@example.invalid")
	mustRun(t, source, "git", "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(source, "a.txt"), []byte("hi\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	mustRun(t, source, "git", "add", "-A")
	mustRun(t, source, "git", "commit", "-qm", "init")

	for _, url := range []string{source, "file://" + source} {
		t.Run(url[:min(len(url), 20)], func(t *testing.T) {
			workspace := t.TempDir()
			_, err := Repository(t.Context(), Options{}, workspace, repoTarget(url, ""))
			if err == nil {
				t.Fatal("a local path was cloned; the file transport must be refused")
			}
			if !errors.Is(err, ErrFetchFailed) {
				t.Errorf("error = %v, want ErrFetchFailed", err)
			}
			// A failed fetch must not leave a partial checkout behind.
			if _, statErr := os.Stat(filepath.Join(workspace, defaultCheckout)); !os.IsNotExist(statErr) {
				t.Error("a failed fetch left a checkout directory behind")
			}
		})
	}
}

// --- input validation ------------------------------------------------------

func TestRepositoryRejectsBadInput(t *testing.T) {
	tests := []struct {
		name      string
		workspace string
		target    scanners.Target
	}{
		{"wrong kind", "/tmp", scanners.Target{Kind: scanners.KindImage, Image: "alpine"}},
		{"filesystem kind", "/tmp", scanners.Target{Kind: scanners.KindFilesystem, Path: "/tmp"}},
		{"no url", "/tmp", scanners.Target{Kind: scanners.KindRepository}},
		{"no workspace", "", repoTarget("https://github.com/a/b", "")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Repository(t.Context(), Options{}, tc.workspace, tc.target); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// --- resource limits -------------------------------------------------------

func TestMeasureCountsRegularFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), 100)
	writeFile(t, filepath.Join(dir, "b.txt"), 200)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(dir, "sub", "c.txt"), 300)

	size, count, err := measure(dir, DefaultMaxBytes, DefaultMaxFiles)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	if count != 3 {
		t.Errorf("counted %d files, want 3", count)
	}
	if size != 600 {
		t.Errorf("measured %d bytes, want 600", size)
	}
}

func TestMeasureEnforcesTheSizeLimit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "big.bin"), 5000)

	_, _, err := measure(dir, 1000, DefaultMaxFiles)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("measure: error = %v, want ErrTooLarge", err)
	}
}

func TestMeasureEnforcesTheFileCountLimit(t *testing.T) {
	dir := t.TempDir()
	for i := range 10 {
		writeFile(t, filepath.Join(dir, string(rune('a'+i))+".txt"), 1)
	}

	_, _, err := measure(dir, DefaultMaxBytes, 5)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("measure: error = %v, want ErrTooLarge", err)
	}
}

// A symlink's target must not be counted, and following one could walk clean
// out of the workspace.
func TestMeasureDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "big.bin")
	writeFile(t, outside, 100_000)

	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writeFile(t, filepath.Join(dir, "real.txt"), 10)

	size, count, err := measure(dir, DefaultMaxBytes, DefaultMaxFiles)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	if count != 1 || size != 10 {
		t.Errorf("measured %d bytes across %d files, want 10 across 1 (the symlink must not be followed)",
			size, count)
	}
}

// --- helpers ---------------------------------------------------------------

func TestIsHexSHA(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{strings.Repeat("a", 40), true},
		{"0123456", true},
		{strings.Repeat("f", 64), true},
		{"abcdef", false},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("A", 40), false},
		{"ghijklm", false},
		{"", false},
		{"abc def", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := isHexSHA(tc.in); got != tc.want {
				t.Errorf("isHexSHA(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRun(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), name, args...) //nolint:gosec // G204: fixed test commands.
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
