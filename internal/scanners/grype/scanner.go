// Package grype adapts the Grype vulnerability matcher.
//
// Everything grype-specific lives here and nowhere else (CLAUDE.md §7). Nothing
// outside this package may import its types or branch on its name.
//
// What separates this adapter from the others is that its answer depends on
// data it did not derive from the target: a local vulnerability database. The
// same repository scanned with two different databases yields two different
// answers, and the older one is wrong in the direction that matters -- it
// reports fewer vulnerabilities than exist. Establishing how old that data was,
// and refusing to present a stale answer as a clean one, is most of what this
// package does. See ADR 012.
package grype

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
const Name = "grype"

// DefaultMaxDBAge is how old the vulnerability database may be before a result
// is reported as degraded.
//
// Deliberately grype's own threshold (`db.max-allowed-built-age`, five days).
// What SecureOps changes is not the judgement of when data is too old -- grype
// is better placed to make that call -- but the response to it. Grype exits
// non-zero and yields nothing; this adapter keeps the findings, which are real,
// and marks the coverage as degraded (ADR 010).
const DefaultMaxDBAge = 120 * time.Hour

// DefaultDownloadTimeout bounds the vulnerability database download. The
// database is measured in gigabytes, so this is far longer than any scanner
// invocation is allowed to take.
const DefaultDownloadTimeout = 20 * time.Minute

// ErrMalformedReport reports that grype did not produce a usable report.
var ErrMalformedReport = errors.New("grype did not produce a valid report")

// ErrInvalidVulnerabilityDB reports that grype itself declared its database
// invalid. Distinct from staleness: stale data is correct but incomplete, while
// an invalid database is wrong in ways that cannot be characterised, so the
// result is refused rather than degraded.
var ErrInvalidVulnerabilityDB = errors.New("grype reported its vulnerability database as invalid")

// Scanner runs grype against a local checkout.
type Scanner struct {
	// Timeout bounds one invocation. Zero uses the shared default.
	Timeout time.Duration
	// MaxOutputBytes caps the report size. Zero uses the shared default.
	MaxOutputBytes int64
	// MaxDBAge bounds the age of the vulnerability database before the result
	// is degraded. Zero uses DefaultMaxDBAge.
	MaxDBAge time.Duration
	// DBCacheDir is where grype reads its database. Required in the worker:
	// the default is under $HOME, and the subprocess runs without one.
	DBCacheDir string
	// DownloadTimeout bounds provisioning. Zero uses DefaultDownloadTimeout.
	DownloadTimeout time.Duration

	// now is injectable so staleness can be tested without waiting five days.
	now func() time.Time
}

// New returns a Scanner reading its database from cacheDir.
func New(cacheDir string) *Scanner {
	return &Scanner{DBCacheDir: cacheDir}
}

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		// Filesystem only. The worker fetches repository targets and hands
		// adapters the checkout (ADR 008).
		Kinds:      []scanners.Kind{scanners.KindFilesystem},
		Categories: []scanners.Category{scanners.CategoryDependency},
		// No NetworkKinds, and that is the point of the whole design. The
		// database is provisioned before the worker takes any job, so a scan of
		// untrusted content runs with no egress at all (ADR 012, §14.3).
	}
}

// Version implements scanners.Scanner.
func (s *Scanner) Version(ctx context.Context) (string, error) {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        30 * time.Second,
		MaxOutputBytes: 8 << 10,
		Env:            s.env(),
	}, "grype", "version", "-o", "text")
	if err != nil {
		return "", err
	}
	return parseVersion(string(res.Stdout)), nil
}

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, target scanners.Target) (scanners.RawResult, error) {
	if target.Kind != scanners.KindFilesystem {
		return scanners.RawResult{Scanner: Name}, scanners.ErrUnsupportedTarget
	}
	if target.Path == "" {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("grype: target path is required")
	}

	version, _ := s.Version(ctx)
	started := time.Now()

	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: s.MaxOutputBytes,
		// Run inside the checkout and scan ".", so component locations are
		// recorded relative to the repository rather than to the worker.
		Dir: target.Path,
		Env: s.env(),
	}, "grype", args()...)

	raw := scanners.RawResult{
		Scanner:   Name,
		Version:   version,
		Target:    target,
		ExitCode:  res.ExitCode,
		Duration:  time.Since(started),
		StartedAt: started,
	}
	if res.Truncated {
		raw.Degrade(scanners.DegradedOutputTruncated)
	}

	if err != nil {
		return raw, err
	}

	if err := validateReport(res.Stdout); err != nil {
		return raw, err
	}

	// Freshness is assessed before the report is accepted, so a result can
	// never be persisted without a verdict on the data behind it.
	for _, d := range s.assessDatabase(res.Stdout) {
		raw.Degrade(d)
	}
	if invalidDatabase(res.Stdout) {
		return raw, ErrInvalidVulnerabilityDB
	}

	raw.Output = res.Stdout
	return raw, nil
}

// assessDatabase reports what is wrong with the vulnerability data behind a
// report, if anything.
func (s *Scanner) assessDatabase(data []byte) []scanners.Degradation {
	built, ok := dbBuiltAt(data)
	if !ok {
		// No usable timestamp: freshness cannot be established either way, and
		// silence is not evidence of freshness.
		return []scanners.Degradation{scanners.DegradedUnknownVulnerabilityDB}
	}
	if s.clock().Sub(built) > s.maxDBAge() {
		return []scanners.Degradation{scanners.DegradedStaleVulnerabilityDB}
	}
	return nil
}

func (s *Scanner) maxDBAge() time.Duration {
	if s.MaxDBAge > 0 {
		return s.MaxDBAge
	}
	return DefaultMaxDBAge
}

func (s *Scanner) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// args is the grype argument vector.
//
// A function so a test can assert the flags directly rather than only by
// observing a subprocess.
func args() []string {
	return []string{
		// Combined with Dir, this keeps recorded locations repository-relative.
		"dir:.",
		"-o", "json",
		// Suppress the progress UI so stdout is the report and nothing else.
		"-q",
	}
}

// env is the complete environment for the grype subprocess: an allow-list, so
// it cannot inherit the worker's credentials (§14.7).
func (s *Scanner) env() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/nonexistent",
		"GRYPE_DB_CACHE_DIR=" + s.DBCacheDir,
		// No egress while untrusted content is on disk. The database is
		// provisioned before the worker takes any job (ADR 012).
		"GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_DB_REQUIRE_UPDATE_CHECK=false",
		// An update check on startup is unnecessary egress from a process
		// handling untrusted content.
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		// Grype's own staleness guard is disabled deliberately. Left on, a
		// database older than five days makes grype exit non-zero and produce
		// nothing, discarding findings that are real. This adapter assesses the
		// same threshold itself and degrades instead (ADR 010, ADR 012).
		"GRYPE_DB_VALIDATE_AGE=false",
		// The database is downloaded over the network and then trusted to
		// decide what counts as vulnerable, which makes it supply chain. Verify
		// it matches its published hash on every run.
		"GRYPE_DB_VALIDATE_BY_HASH_ON_START=true",
	}
}

// parseVersion extracts the version from `grype version -o text`, which is a
// block of "Key: value" lines rather than a bare version string.
func parseVersion(out string) string {
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), "version") {
			return strings.TrimSpace(value)
		}
	}
	return strings.TrimSpace(out)
}

// Provision downloads or refreshes the vulnerability database.
//
// This is the only moment grype is allowed near the network. It runs at worker
// startup, before any job is claimed, so the egress happens while no untrusted
// repository exists on disk (§14.3). Every scan afterwards runs offline against
// whatever this left behind.
//
// A failure is deliberately not fatal, and deliberately not silent. The worker
// logs it and keeps the adapter registered, so a scan that needed grype records
// a failed scanner and settles at PARTIAL. The alternative -- dropping the
// adapter -- would produce a scan that never mentions grype at all and still
// claims complete coverage.
func (s *Scanner) Provision(ctx context.Context) error {
	if s.DBCacheDir == "" {
		return fmt.Errorf("grype: database cache directory is not configured")
	}

	// Grype stages the download through a temporary file. The worker's root
	// filesystem is read-only, so the default /tmp is not writable and the
	// update fails with an error that names a temp path rather than the real
	// cause. Point it at the database volume, which is writable by definition:
	// it is the thing being written. Found by running the worker, not by any
	// test -- the same read-only-filesystem shape that broke the gitleaks
	// report path in ADR 008.
	tmpDir := filepath.Join(s.DBCacheDir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return fmt.Errorf("grype: preparing the database staging directory: %w", err)
	}

	// Generous relative to other scanner invocations: the database is measured
	// in gigabytes, and a partial download is worse than a slow one.
	ctx, cancel := context.WithTimeout(ctx, s.provisionTimeout())
	defer cancel()

	if _, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.provisionTimeout(),
		MaxOutputBytes: 64 << 10,
		Env:            s.provisionEnv(tmpDir),
	}, "grype", "db", "update"); err != nil {
		return fmt.Errorf("grype: refreshing the vulnerability database: %w", err)
	}
	return nil
}

// ProvisionTimeout bounds the database download. Zero uses the default.
func (s *Scanner) provisionTimeout() time.Duration {
	if s.DownloadTimeout > 0 {
		return s.DownloadTimeout
	}
	return DefaultDownloadTimeout
}

// provisionEnv is env with the update path re-enabled.
//
// It is a separate function rather than a flag on env() so that the scanning
// environment cannot accidentally acquire network access: the only way to get
// an environment that can reach the network is to ask for this one by name.
func (s *Scanner) provisionEnv(tmpDir string) []string {
	out := make([]string, 0, len(s.env()))
	for _, e := range s.env() {
		switch {
		case strings.HasPrefix(e, "GRYPE_DB_AUTO_UPDATE="):
			continue
		case strings.HasPrefix(e, "GRYPE_CHECK_FOR_APP_UPDATE="):
			continue
		}
		out = append(out, e)
	}
	return append(out,
		"GRYPE_DB_AUTO_UPDATE=true",
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		// See Provision: the root filesystem is read-only, so the default
		// temp directory is not writable.
		"TMPDIR="+tmpDir,
		// Certificate verification needs the system trust store, which the
		// scanning environment has no reason to expose.
		"SSL_CERT_DIR=/etc/ssl/certs",
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
	)
}
