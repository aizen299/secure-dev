package scanners

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Execution limit failures. These are structured outcomes, not crashes: a
// hostile repository that blows a limit must produce a recorded scanner failure
// (§14, §18), never take the worker down.
var (
	ErrExecTimeout    = errors.New("scanner exceeded its execution timeout")
	ErrOutputTooLarge = errors.New("scanner output exceeded the size limit")
	ErrBinaryMissing  = errors.New("scanner binary not found")
)

// Default execution limits. Every one is configurable (§14).
const (
	DefaultTimeout        = 10 * time.Minute
	DefaultMaxOutputBytes = 64 << 20 // 64 MiB
)

// ExecOptions bounds a single scanner invocation.
type ExecOptions struct {
	// Timeout caps wall-clock execution. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxOutputBytes caps captured stdout. Zero means DefaultMaxOutputBytes.
	MaxOutputBytes int64
	// Dir is the working directory. It should be the ephemeral workspace.
	Dir string
	// Env is the complete environment for the child process.
	//
	// It is an explicit allow-list, not an addition to the parent environment:
	// a scanner subprocess must not inherit the worker's database URL, Redis
	// password, or cloud credentials (§14.7). Nil means an empty environment.
	Env []string
	// AllowNonZeroExit treats a non-zero exit as success. Many scanners use
	// exit codes to signal "findings present", which is not an error.
	AllowNonZeroExit bool
}

func (o ExecOptions) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

func (o ExecOptions) maxOutput() int64 {
	if o.MaxOutputBytes <= 0 {
		return DefaultMaxOutputBytes
	}
	return o.MaxOutputBytes
}

// ExecResult is the outcome of one subprocess invocation.
type ExecResult struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// Run executes name with args and returns its output.
//
// The command is built as an argument vector and handed to exec.CommandContext
// directly. There is no shell anywhere in this path, so shell metacharacters in
// a target value are inert data rather than syntax (CLAUDE.md §14.4, §25.11).
// Adapters must call this rather than reaching for os/exec themselves.
func Run(ctx context.Context, opts ExecOptions, name string, args ...string) (ExecResult, error) {
	if name == "" {
		return ExecResult{}, fmt.Errorf("run: command name is empty")
	}
	// Guard against a caller smuggling a whole command line in as the binary
	// name; exec would treat it as a literal filename, but failing loudly is
	// clearer than a confusing "no such file".
	if strings.ContainsAny(name, " \t\n;|&$`") {
		return ExecResult{}, fmt.Errorf("run: command name must be a bare executable, not a command line")
	}

	binary, err := exec.LookPath(name)
	if err != nil {
		// Degrade gracefully when a scanner is not installed (§4).
		return ExecResult{}, fmt.Errorf("%w: %s", ErrBinaryMissing, name)
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	// G204 flags subprocess launch with a variable command. That is precisely
	// this function's job, and it is what makes the rest of the codebase safe:
	// the binary is resolved through LookPath, the arguments are passed as a
	// vector, and no shell is involved, so target values are inert data rather
	// than syntax. Callers additionally validate every value they pass in
	// (see Validator). Concentrating the pattern here is what lets every other
	// package avoid it.
	//nolint:gosec // G204: argv execution with no shell; see the comment above.
	cmd := exec.CommandContext(runCtx, binary, args...)
	cmd.Dir = opts.Dir
	// A nil Env would make the child inherit the worker's environment. Force
	// an explicit (possibly empty) slice so that can never happen by accident.
	if opts.Env == nil {
		cmd.Env = []string{}
	} else {
		cmd.Env = opts.Env
	}
	// Kill the whole process group, not just the direct child: scanners spawn
	// helpers, and an orphan holding the workspace open defeats cleanup.
	configureProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = 5 * time.Second

	// Hitting the cap aborts the run; the classification below turns that
	// cancellation back into an explicit ErrOutputTooLarge.
	stdout := &limitedBuffer{limit: opts.maxOutput(), onLimit: cancel}
	// stderr is capped far smaller: it is diagnostic, and an unbounded error
	// stream is its own memory-exhaustion vector.
	stderr := &limitedBuffer{limit: 256 << 10, onLimit: cancel}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	result := ExecResult{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Duration:  duration,
		Truncated: stdout.truncated,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	// Distinguish "we stopped it" from "it failed", because the two mean very
	// different things in a scan result. Truncation is checked first: it is
	// the cause of the cancellation, so reporting it as a cancel would hide
	// the real reason.
	if stdout.truncated {
		return result, fmt.Errorf("%w: limit is %d bytes", ErrOutputTooLarge, opts.maxOutput())
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("%w after %s", ErrExecTimeout, opts.timeout())
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return result, ctx.Err()
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			if opts.AllowNonZeroExit {
				return result, nil
			}
			// stderr can contain repository content; keep it short and let the
			// caller decide what to persist.
			return result, fmt.Errorf("scanner exited with code %d", result.ExitCode)
		}
		return result, fmt.Errorf("run scanner: %w", runErr)
	}
	return result, nil
}

// limitedBuffer accumulates output up to a hard byte limit.
//
// It never returns an error on overflow: returning one would make the child
// process see a broken pipe and often die with a confusing signal. Instead it
// silently drops the excess and records that it did, so the caller reports a
// clean "output too large" failure.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	written   int64
	truncated bool
	// onLimit aborts the subprocess the first time the cap is hit. Without it
	// a scanner emitting unbounded output would run until its timeout,
	// converting a size-limit breach into a much slower resource drain.
	onLimit  func()
	limitHit sync.Once
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	remaining := l.limit - l.written
	if remaining <= 0 {
		l.markTruncated()
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		l.buf.Write(p[:remaining])
		l.written = l.limit
		l.markTruncated()
		return len(p), nil
	}
	n, err := l.buf.Write(p)
	l.written += int64(n)
	return n, err
}

func (l *limitedBuffer) markTruncated() {
	l.truncated = true
	if l.onLimit != nil {
		l.limitHit.Do(l.onLimit)
	}
}

func (l *limitedBuffer) Bytes() []byte { return l.buf.Bytes() }

var _ io.Writer = (*limitedBuffer)(nil)

// Workspace is an ephemeral directory for one scan job.
//
// It is destroyed when the job ends, so untrusted repository content never
// outlives the scan that fetched it (§14.3).
type Workspace struct {
	Path string
}

// NewWorkspace creates an ephemeral directory beneath root.
func NewWorkspace(root, scanID string) (*Workspace, error) {
	if root == "" {
		return nil, fmt.Errorf("workspace: root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("workspace: create root: %w", err)
	}
	// MkdirTemp generates the suffix, so scanID cannot control the final path.
	dir, err := os.MkdirTemp(root, sanitizeForPath(scanID)+"-")
	if err != nil {
		return nil, fmt.Errorf("workspace: create: %w", err)
	}
	// G302 expects 0600 or less, but this is a directory: without the execute
	// bit the owner cannot traverse into it. 0700 is the most restrictive mode
	// a usable private directory can have.
	//nolint:gosec // G302: 0700 is correct for a directory, not a file.
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("workspace: restrict permissions: %w", err)
	}
	return &Workspace{Path: dir}, nil
}

// Remove destroys the workspace and everything in it.
func (w *Workspace) Remove() error {
	if w == nil || w.Path == "" {
		return nil
	}
	return os.RemoveAll(w.Path)
}

// sanitizeForPath reduces s to characters that are safe in a path component.
func sanitizeForPath(s string) string {
	if s == "" {
		return "scan"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	return b.String()
}
