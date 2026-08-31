// Package gitleaks adapts the gitleaks secret scanner.
//
// Everything gitleaks-specific lives here and nowhere else (CLAUDE.md §7).
// Nothing outside this package may import its types or branch on its name.
//
// The security rule that shapes this adapter: gitleaks output contains the
// credentials it found, and SecureOps must never store one (§15.3). The value
// is redacted inside the gitleaks process, and this adapter refuses to return
// output it cannot prove is redacted. See ADR 007.
package gitleaks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// Name is the adapter's stable identifier, used for registration, persistence,
// and reporting.
const Name = "gitleaks"

// redactedMarker is what gitleaks writes in place of a secret under --redact.
const redactedMarker = "REDACTED"

// ErrRedactionFailed reports that gitleaks returned an unredacted secret.
//
// This is a fail-closed control, not a diagnostic. If it fires, the output is
// discarded rather than persisted: a gitleaks release that changes its
// redaction behaviour must break the scan, not quietly fill the database with
// live credentials (ADR 007).
var ErrRedactionFailed = errors.New("gitleaks returned an unredacted secret; output discarded")

// ErrMalformedReport reports that gitleaks did not produce a parseable report.
//
// It matters because gitleaks exits 1 both when it finds secrets and when it
// fails to run. Exit code alone therefore cannot distinguish "found three
// secrets" from "could not read the source", and treating the latter as success
// would report a broken scan as clean.
var ErrMalformedReport = errors.New("gitleaks did not produce a parseable report")

// Scanner runs gitleaks against a local checkout.
type Scanner struct {
	// Timeout bounds one invocation. Zero uses the shared default.
	Timeout time.Duration
	// MaxOutputBytes caps the report size. Zero uses the shared default.
	MaxOutputBytes int64
	// ConfigPath optionally points at a gitleaks TOML config. Empty uses
	// gitleaks' built-in rules.
	ConfigPath string
}

// New returns a Scanner with default limits.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
//
// Filesystem only. A repository target is fetched by the worker and handed to
// adapters as a filesystem path (ADR 008), so this adapter never sees a URL and
// never fetches anything itself.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		Kinds:    []scanners.Kind{scanners.KindFilesystem},
		Category: scanners.CategorySecrets,
		// gitleaks ships its rules in the binary; it needs no egress.
		RequiresNetwork: false,
	}
}

// Version implements scanners.Scanner.
func (s *Scanner) Version(ctx context.Context) (string, error) {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        30 * time.Second,
		MaxOutputBytes: 4 << 10,
		Env:            env(),
	}, "gitleaks", "version")
	if err != nil {
		// A missing binary is absent coverage, not a broken scan. The worker
		// distinguishes the two (§13), so the sentinel is passed through.
		return "", err
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, target scanners.Target) (scanners.RawResult, error) {
	if target.Kind != scanners.KindFilesystem {
		return scanners.RawResult{Scanner: Name}, scanners.ErrUnsupportedTarget
	}
	if target.Path == "" {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("gitleaks: target path is required")
	}

	// The report is written outside the scanned directory on purpose. gitleaks
	// scans every file under its source, so a report written inside would be
	// scanned on the next run and its own contents reported as findings.
	reportDir, err := newReportDir(target.Path)
	if err != nil {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("gitleaks: create report directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(reportDir) }()
	reportPath := filepath.Join(reportDir, "report.json")

	version, _ := s.Version(ctx)
	started := time.Now()

	args := []string{
		"detect",
		// The worker fetches a shallow checkout, so there is no history to
		// walk. Scanning the working tree is what matches what was fetched.
		"--no-git",
		"--source", ".",
		"--report-format", "json",
		"--report-path", reportPath,
		// The control from ADR 007: the credential is replaced inside the
		// gitleaks process, so the plaintext never enters this one.
		"--redact",
		"--exit-code", "1",
	}
	if s.ConfigPath != "" {
		args = append(args, "--config", s.ConfigPath)
	}

	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: s.MaxOutputBytes,
		// Running inside the checkout with a relative source keeps the File
		// field repo-relative. An absolute source would embed the worker's
		// workspace path in every finding.
		Dir: target.Path,
		Env: env(),
		// gitleaks exits 1 when it finds secrets, which is a result, not a
		// failure. It also exits 1 on error, so the report is what actually
		// distinguishes the two; see below.
		AllowNonZeroExit: true,
	}, "gitleaks", args...)

	raw := scanners.RawResult{
		Scanner:   Name,
		Version:   version,
		Target:    target,
		ExitCode:  res.ExitCode,
		Duration:  time.Since(started),
		Truncated: res.Truncated,
		StartedAt: started,
	}

	if err != nil {
		return raw, err
	}

	report, err := os.ReadFile(reportPath) //nolint:gosec // G304: path is built from MkdirTemp, not from input.
	if err != nil {
		// No report and a non-zero exit means gitleaks failed to run rather
		// than finding nothing.
		return raw, fmt.Errorf("%w: %w", ErrMalformedReport, err)
	}

	findings, err := parseReport(report)
	if err != nil {
		return raw, err
	}
	// The fail-closed check. It runs before the bytes are returned, so output
	// that cannot be proven redacted never reaches the caller, and therefore
	// never reaches the database.
	if err := assertRedacted(findings); err != nil {
		return scanners.RawResult{Scanner: Name, Version: version, Target: target}, err
	}

	raw.Output = report
	return raw, nil
}

// newReportDir creates a directory for the gitleaks report.
//
// It prefers a sibling of the scanned path, which for a fetched repository is
// the job's ephemeral workspace: that is the one writable location a worker is
// guaranteed to have (its root filesystem is read-only, §14.3), and anything
// left there is destroyed with the workspace even if cleanup here fails.
//
// It must not be inside the scanned path, or gitleaks would scan its own
// report. The system temp directory is the fallback for a bare filesystem
// target whose parent is not writable.
func newReportDir(scanPath string) (string, error) {
	if parent := filepath.Dir(scanPath); parent != "" && parent != scanPath {
		if dir, err := os.MkdirTemp(parent, "gitleaks-report-"); err == nil {
			return dir, nil
		}
	}
	return os.MkdirTemp("", "gitleaks-report-")
}

// env is the complete environment for the gitleaks subprocess: an allow-list,
// so it cannot inherit the worker's credentials (§14.7).
func env() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/nonexistent",
		// gitleaks reads git config for history scans; neutralise it even
		// though --no-git is used, so behaviour does not depend on the host.
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	}
}
