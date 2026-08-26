package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCapturesOutputAndExitCode(t *testing.T) {
	res, err := Run(t.Context(), ExecOptions{}, "echo", "hello", "world")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello world" {
		t.Errorf("stdout = %q, want %q", got, "hello world")
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if res.Duration <= 0 {
		t.Error("duration was not recorded")
	}
}

// The core guarantee of this package: arguments are data, never syntax. If a
// shell were involved anywhere, these payloads would execute.
func TestRunNeverInvokesAShell(t *testing.T) {
	payloads := []string{
		"; touch /tmp/secureops-pwned",
		"$(touch /tmp/secureops-pwned)",
		"`touch /tmp/secureops-pwned`",
		"&& touch /tmp/secureops-pwned",
		"| touch /tmp/secureops-pwned",
		"\n touch /tmp/secureops-pwned",
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			res, err := Run(t.Context(), ExecOptions{}, "echo", payload)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			// echo prints the payload verbatim, proving it was one argv
			// element rather than interpreted syntax.
			if !strings.Contains(string(res.Stdout), strings.TrimSpace(payload)) {
				t.Errorf("payload was not passed through literally: %q", res.Stdout)
			}
		})
	}
	if _, err := os.Stat("/tmp/secureops-pwned"); err == nil {
		_ = os.Remove("/tmp/secureops-pwned")
		t.Fatal("a shell executed the payload: /tmp/secureops-pwned was created")
	}
}

func TestRunRejectsCommandLineAsBinaryName(t *testing.T) {
	for _, name := range []string{"echo hi", "sh -c id", "echo; id", "echo|id"} {
		if _, err := Run(t.Context(), ExecOptions{}, name); err == nil {
			t.Errorf("accepted command line %q as a binary name", name)
		}
	}
	if _, err := Run(t.Context(), ExecOptions{}, ""); err == nil {
		t.Error("accepted an empty binary name")
	}
}

func TestRunMissingBinary(t *testing.T) {
	_, err := Run(t.Context(), ExecOptions{}, "secureops-definitely-not-installed")
	if !errors.Is(err, ErrBinaryMissing) {
		t.Fatalf("err = %v, want ErrBinaryMissing", err)
	}
}

func TestRunTimeoutIsEnforced(t *testing.T) {
	start := time.Now()
	res, err := Run(t.Context(), ExecOptions{Timeout: 300 * time.Millisecond}, "sleep", "30")
	elapsed := time.Since(start)

	if !errors.Is(err, ErrExecTimeout) {
		t.Fatalf("err = %v, want ErrExecTimeout", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("timeout took %s to take effect", elapsed)
	}
	_ = res
}

func TestRunNonZeroExit(t *testing.T) {
	// Default: a non-zero exit is a failure.
	res, err := Run(t.Context(), ExecOptions{}, "false")
	if err == nil {
		t.Fatal("non-zero exit reported as success")
	}
	if res.ExitCode == 0 {
		t.Errorf("exit code = %d, want non-zero", res.ExitCode)
	}

	// Many scanners exit non-zero to mean "findings present".
	res, err = Run(t.Context(), ExecOptions{AllowNonZeroExit: true}, "false")
	if err != nil {
		t.Fatalf("AllowNonZeroExit still failed: %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("exit code = %d, want non-zero", res.ExitCode)
	}
}

func TestRunOutputSizeLimit(t *testing.T) {
	// yes produces output forever; the cap must stop it.
	start := time.Now()
	res, err := Run(t.Context(), ExecOptions{MaxOutputBytes: 4096, Timeout: 20 * time.Second},
		"yes", "secureops")
	elapsed := time.Since(start)

	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err = %v, want ErrOutputTooLarge", err)
	}
	// The cap must abort the process, not merely discard output while it keeps
	// running. If this regresses, the run silently burns its whole timeout.
	if elapsed > 5*time.Second {
		t.Errorf("output cap took %s to abort; it should kill the process immediately", elapsed)
	}
	if !res.Truncated {
		t.Error("result was not marked truncated")
	}
	if int64(len(res.Stdout)) > 4096 {
		t.Errorf("captured %d bytes despite a 4096-byte cap", len(res.Stdout))
	}
}

// A scanner subprocess must not inherit the worker's credentials.
func TestRunDoesNotLeakParentEnvironment(t *testing.T) {
	t.Setenv("SECUREOPS_DATABASE_URL", "postgres://user:supersecret@db:5432/secureops")

	res, err := Run(t.Context(), ExecOptions{}, "env")
	if err != nil {
		// `env` with an empty environment exits 0 and prints nothing.
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(string(res.Stdout), "supersecret") {
		t.Fatalf("child inherited a parent credential: %q", res.Stdout)
	}
	if strings.Contains(string(res.Stdout), "SECUREOPS_DATABASE_URL") {
		t.Errorf("child inherited SECUREOPS_DATABASE_URL: %q", res.Stdout)
	}
}

func TestRunExplicitEnvIsPassed(t *testing.T) {
	res, err := Run(t.Context(), ExecOptions{Env: []string{"SCANNER_MODE=fast"}}, "env")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(res.Stdout), "SCANNER_MODE=fast") {
		t.Errorf("explicit env not passed: %q", res.Stdout)
	}
}

func TestRunUsesWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(t.Context(), ExecOptions{Dir: dir}, "pwd")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := strings.TrimSpace(string(res.Stdout))
	// macOS reports /private/var for /var, so compare resolved paths.
	wantResolved, _ := filepath.EvalSymlinks(dir)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != wantResolved {
		t.Errorf("cwd = %q, want %q", gotResolved, wantResolved)
	}
}

func TestRunHonoursCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	_, err := Run(ctx, ExecOptions{Timeout: 30 * time.Second}, "sleep", "30")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestLimitedBufferTruncates(t *testing.T) {
	b := &limitedBuffer{limit: 10}

	n, err := b.Write([]byte("12345"))
	if err != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if b.truncated {
		t.Error("marked truncated before exceeding the limit")
	}

	// Overflow must report the full length written so the child never sees a
	// short write and dies with a broken pipe.
	n, err = b.Write([]byte("abcdefghij"))
	if err != nil {
		t.Fatalf("Write after limit returned an error: %v", err)
	}
	if n != 10 {
		t.Errorf("Write returned %d, want 10 (full length)", n)
	}
	if !b.truncated {
		t.Error("not marked truncated after exceeding the limit")
	}
	if len(b.Bytes()) != 10 {
		t.Errorf("buffered %d bytes, want exactly the 10-byte limit", len(b.Bytes()))
	}
}

func TestWorkspaceLifecycle(t *testing.T) {
	root := t.TempDir()

	ws, err := NewWorkspace(root, "scan-123")
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	info, err := os.Stat(ws.Path)
	if err != nil {
		t.Fatalf("workspace not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("permissions = %o, want 700", perm)
	}
	if !strings.HasPrefix(ws.Path, root) {
		t.Errorf("workspace %q is outside root %q", ws.Path, root)
	}

	if err := os.WriteFile(filepath.Join(ws.Path, "untrusted.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write into workspace: %v", err)
	}
	if err := ws.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(ws.Path); !os.IsNotExist(err) {
		t.Error("workspace survived Remove; untrusted content was not destroyed")
	}
}

// A hostile scan ID must not be able to steer the workspace path.
func TestWorkspaceRejectsPathInjectionInScanID(t *testing.T) {
	root := t.TempDir()

	for _, id := range []string{"../../etc", "a/b/c", "..", "scan;rm -rf /"} {
		ws, err := NewWorkspace(root, id)
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = ws.Remove() })

		rel, relErr := filepath.Rel(root, ws.Path)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("scan id %q escaped the workspace root: %q", id, ws.Path)
		}
	}
}

func TestNewWorkspaceRequiresRoot(t *testing.T) {
	if _, err := NewWorkspace("", "scan"); err == nil {
		t.Error("empty root accepted")
	}
}

func TestWorkspaceRemoveIsSafeOnNil(t *testing.T) {
	var ws *Workspace
	if err := ws.Remove(); err != nil {
		t.Errorf("Remove on nil workspace: %v", err)
	}
}
