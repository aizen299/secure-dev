// Package fetch obtains untrusted target content for a scan.
//
// This is the most dangerous operation in SecureOps: it pulls
// attacker-controlled content onto a machine we own. Everything here is written
// on that assumption, and every git capability that is not strictly needed is
// switched off rather than left at its default (ADR 008, CLAUDE.md §14).
//
// Only the worker calls this. The API server never fetches target content
// (§14.1), and adapters never fetch either -- they receive a local path.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// Fetch failures. These are structured outcomes: failing to obtain the code is
// a distinct condition from scanning it and finding nothing (§13).
var (
	// ErrFetchFailed reports that the repository could not be obtained. The
	// underlying cause is logged, never returned: git's error text quotes the
	// remote's response, which is attacker-controlled.
	ErrFetchFailed = errors.New("could not fetch the repository")
	// ErrTooLarge reports that the fetched content breached a resource limit.
	ErrTooLarge = errors.New("repository exceeds the configured limits")
	// ErrGitMissing reports that the git binary is not installed.
	ErrGitMissing = errors.New("git is not installed")
)

// Default limits. Every one is configurable (§14 resource exhaustion limits).
const (
	DefaultTimeout   = 10 * time.Minute
	DefaultMaxBytes  = 2 << 30 // 2 GiB
	DefaultMaxFiles  = 500_000
	defaultCheckout  = "repo"
	defaultDepthArgs = 1
)

// Options bounds one fetch.
type Options struct {
	// Timeout caps the clone. A slow-drip remote is a denial of service
	// against a worker slot, so this is not optional.
	Timeout time.Duration
	// MaxBytes caps the total size of the checkout.
	MaxBytes int64
	// MaxFiles caps the number of files in the checkout. Size alone does not
	// bound the cost of walking a tree of millions of empty files.
	MaxFiles int
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

func (o Options) maxBytes() int64 {
	if o.MaxBytes <= 0 {
		return DefaultMaxBytes
	}
	return o.MaxBytes
}

func (o Options) maxFiles() int {
	if o.MaxFiles <= 0 {
		return DefaultMaxFiles
	}
	return o.MaxFiles
}

// Result describes what was fetched.
type Result struct {
	// Path is the checkout directory, inside the caller's workspace.
	Path string
	// Bytes and Files are what actually landed on disk.
	Bytes int64
	Files int
	// CommitSHA is the resolved HEAD, so a scan records exactly what was
	// scanned rather than a branch name that moves.
	CommitSHA string
	Duration  time.Duration
}

// Repository clones target into workspace and returns the checkout.
//
// The returned Result.Path is the directory adapters should scan. On any
// failure the partial checkout is removed: untrusted content must not outlive
// the operation that fetched it (§14.3).
func Repository(
	ctx context.Context, opts Options, workspace string, target scanners.Target,
) (Result, error) {
	if target.Kind != scanners.KindRepository {
		return Result{}, fmt.Errorf("fetch: target kind %q is not a repository", target.Kind)
	}
	if target.RepositoryURL == "" {
		return Result{}, fmt.Errorf("fetch: repository_url is required")
	}
	if workspace == "" {
		return Result{}, fmt.Errorf("fetch: workspace is required")
	}

	// The checkout name is a fixed constant, never derived from the target, so
	// no part of the path is attacker-influenced.
	dest := filepath.Join(workspace, defaultCheckout)

	started := time.Now()
	if err := clone(ctx, opts, dest, target); err != nil {
		_ = os.RemoveAll(dest)
		return Result{}, err
	}

	size, files, err := measure(dest, opts.maxBytes(), opts.maxFiles())
	if err != nil {
		_ = os.RemoveAll(dest)
		return Result{}, err
	}

	// Best effort: a scan is still usable without the resolved SHA, and
	// failing the whole fetch over it would be disproportionate.
	sha := resolveHead(ctx, opts, dest)

	return Result{
		Path:      dest,
		Bytes:     size,
		Files:     files,
		CommitSHA: sha,
		Duration:  time.Since(started),
	}, nil
}

// cloneArgs builds the argument vector for the clone.
//
// It is a separate function so the security-relevant flags can be asserted by a
// test directly, rather than only through observing a subprocess.
func cloneArgs(dest string, target scanners.Target) []string {
	args := []string{
		// -c options come before the subcommand. Each disables a git
		// capability that is a liability on untrusted input (ADR 008).
		//
		// ext:: executes an arbitrary command named in the URL, and file://
		// reads the worker's own disk. Allowing only the two transports the
		// target validator permits closes both.
		"-c", "protocol.allow=never",
		"-c", "protocol.https.allow=always",
		"-c", "protocol.ssh.allow=always",
		// Stop git consulting a credential helper, which would attach the
		// host's credentials to an attacker-chosen URL.
		"-c", "credential.helper=",
		// git clone does not run repository hooks, but asserting it costs one
		// flag and removes the need to re-derive that fact later.
		"-c", "core.hooksPath=/dev/null",
		// Symlinks in the index are inert until something follows them; this
		// keeps a checkout from planting links to absolute host paths.
		"-c", "core.symlinks=false",
		"clone",
		"--depth", fmt.Sprint(defaultDepthArgs),
		"--single-branch",
		"--no-tags",
		// A submodule is an attacker-controlled URL fetched on our behalf,
		// bypassing the target validator entirely.
		"--recurse-submodules=no",
		"--quiet",
	}

	if target.Ref != "" {
		// Validated by scanners.Target: no leading dash, so git cannot read it
		// as a flag. The "--" terminator below is the second line of defence.
		args = append(args, "--branch", target.Ref)
	}

	// "--" ends option parsing, so neither the URL nor the destination can be
	// interpreted as a flag no matter what they contain.
	args = append(args, "--", target.RepositoryURL, dest)
	return args
}

// cloneEnv is the complete environment for the git subprocess.
//
// It is an allow-list, not an addition to the worker's environment: the child
// must not inherit the database URL, the Redis password, or cloud credentials
// (§14.7).
func cloneEnv() []string {
	return []string{
		// Never block on an interactive credential prompt. A private
		// repository must fail fast rather than pin a worker slot forever.
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/true",
		"GIT_CONFIG_NOSYSTEM=1",
		// Ignore the invoking user's ~/.gitconfig, which could otherwise
		// re-enable anything switched off above.
		"HOME=/nonexistent",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
}

func clone(ctx context.Context, opts Options, dest string, target scanners.Target) error {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout: opts.timeout(),
		// git writes progress to stderr; the cap in Run bounds it.
		MaxOutputBytes: 4 << 20,
		Env:            cloneEnv(),
	}, "git", cloneArgs(dest, target)...)

	if err != nil {
		if errors.Is(err, scanners.ErrBinaryMissing) {
			return ErrGitMissing
		}
		if errors.Is(err, scanners.ErrExecTimeout) {
			return fmt.Errorf("%w: the clone exceeded %s", ErrFetchFailed, opts.timeout())
		}
		// git's stderr quotes the remote's response, which is
		// attacker-controlled, so it is not wrapped into the returned error.
		// The caller logs the detail; the stored reason stays fixed (§15.3).
		return fmt.Errorf("%w (exit %d)", ErrFetchFailed, res.ExitCode)
	}
	return nil
}

// measure walks the checkout, enforcing the size and file-count limits.
//
// It stops at the first breach rather than completing the walk: the point of a
// limit is to stop doing work, not to find out how much work there would have
// been.
func measure(root string, maxBytes int64, maxFiles int) (int64, int, error) {
	var total int64
	var count int

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Lstat, not Stat: a symlink's target is not counted, and following
		// one could walk out of the workspace entirely.
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		count++
		if count > maxFiles {
			return fmt.Errorf("%w: more than %d files", ErrTooLarge, maxFiles)
		}
		total += info.Size()
		if total > maxBytes {
			return fmt.Errorf("%w: larger than %d bytes", ErrTooLarge, maxBytes)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return 0, 0, err
		}
		return 0, 0, fmt.Errorf("%w: could not measure the checkout", ErrFetchFailed)
	}
	return total, count, nil
}

// resolveHead reads the checked-out commit. Best effort by design.
func resolveHead(ctx context.Context, opts Options, dest string) string {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        30 * time.Second,
		MaxOutputBytes: 4 << 10,
		Dir:            dest,
		Env:            cloneEnv(),
	}, "git", "rev-parse", "HEAD")
	if err != nil {
		return ""
	}

	sha := trimSpace(string(res.Stdout))
	// The value is written to a column with a format CHECK constraint, so it
	// is validated rather than trusted.
	if !isHexSHA(sha) {
		return ""
	}
	return sha
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func isHexSHA(s string) bool {
	if len(s) < 7 || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		if !isDigit && !isLowerHex {
			return false
		}
	}
	return true
}
