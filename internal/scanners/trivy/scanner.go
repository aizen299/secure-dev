// Package trivy adapts the Trivy scanner for infrastructure-as-code and
// configuration misconfiguration.
//
// Everything trivy-specific lives here and nowhere else (CLAUDE.md §7). Nothing
// outside this package may import its types or branch on its name.
//
// Trivy can do far more than this adapter asks of it -- dependency
// vulnerabilities, secrets, licences -- and it is deliberately asked for none of
// those. Grype owns dependency vulnerabilities and Gitleaks owns secrets; §6
// forbids duplicating coverage across scanners without a documented reason, and
// two scanners reporting the same finding is a correlation problem invented for
// no gain. What Trivy alone covers is misconfiguration: Dockerfiles, Kubernetes
// manifests, Terraform, and the rest.
//
// This is also the first adapter that rewrites scanner output rather than only
// validating it. Trivy embeds the source lines that caused each finding, and
// for an IaC file that source routinely contains credentials. See ADR 015.
package trivy

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
const Name = "trivy"

// ErrMalformedReport reports that trivy did not produce a usable report.
var ErrMalformedReport = errors.New("trivy did not produce a valid report")

// ErrSourceLeak reports that source content survived redaction.
//
// Trivy always embeds the lines that caused a finding, and an IaC file is
// exactly where a hardcoded credential lives -- a Terraform resource with a
// password in it produces a misconfiguration whose cause lines contain that
// password. Redaction is applied before anything is persisted, and this error
// means the check afterwards found something it missed (ADR 015, §15.3).
var ErrSourceLeak = errors.New("trivy output still contains source content after redaction; discarded")

// Scanner runs trivy against a local checkout.
type Scanner struct {
	// Timeout bounds one invocation. Zero uses the shared default.
	Timeout time.Duration
	// MaxOutputBytes caps the report size. Zero uses the shared default.
	MaxOutputBytes int64
	// CacheDir holds the provisioned checks bundle. Required in the worker:
	// trivy's default is under $HOME, and the subprocess runs without one.
	CacheDir string
	// ProvisionTimeout bounds the checks-bundle download. Zero uses a default.
	ProvisionTimeout time.Duration
}

// New returns a Scanner reading its checks from cacheDir.
func New(cacheDir string) *Scanner { return &Scanner{CacheDir: cacheDir} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		// Filesystem only for now. Image targets are a separate change: they
		// introduce a target kind that is not a checkout, registry
		// credentials, and their own validation surface.
		Kinds:    []scanners.Kind{scanners.KindFilesystem},
		Category: scanners.CategoryIaC,
		// False by design: the checks bundle is provisioned before any job is
		// claimed, so a scan of untrusted content runs with no egress
		// (ADR 012, §14.3).
		RequiresNetwork: false,
	}
}

// Version implements scanners.Scanner.
func (s *Scanner) Version(ctx context.Context) (string, error) {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        30 * time.Second,
		MaxOutputBytes: 8 << 10,
		Env:            s.env(),
	}, "trivy", "--cache-dir", s.cacheDir(), "version", "--format", "json")
	if err != nil {
		return "", err
	}
	return parseVersion(res.Stdout), nil
}

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, target scanners.Target) (scanners.RawResult, error) {
	if target.Kind != scanners.KindFilesystem {
		return scanners.RawResult{Scanner: Name}, scanners.ErrUnsupportedTarget
	}
	if target.Path == "" {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("trivy: target path is required")
	}
	if _, err := s.baseDir(); err != nil {
		return scanners.RawResult{Scanner: Name}, err
	}

	version, _ := s.Version(ctx)
	started := time.Now()

	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: s.MaxOutputBytes,
		// Run inside the checkout and scan ".", so reported paths are
		// repository-relative rather than rooted in the worker's workspace.
		Dir: target.Path,
		Env: s.env(),
	}, "trivy", s.args()...)

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

	// Redaction happens before anything is persisted, and its result is
	// checked. Unlike every other adapter here, this one modifies what it
	// stores -- see ADR 015 for why §15.3 outweighs §8's "verbatim" for this
	// scanner specifically.
	redacted, err := redactSourceContent(res.Stdout)
	if err != nil {
		return raw, err
	}
	if err := assertNoSourceContent(redacted); err != nil {
		return scanners.RawResult{Scanner: Name, Version: version, Target: target}, err
	}
	if err := assertNoWorkspacePaths(redacted, target.Path); err != nil {
		return scanners.RawResult{Scanner: Name, Version: version, Target: target}, err
	}

	raw.Output = redacted
	return raw, nil
}

// args is the trivy argument vector.
//
// A function so a test can assert the flags directly rather than only by
// observing a subprocess. The scanner selection is the §6 boundary made
// explicit in the command line, where a test can see it.
func (s *Scanner) args() []string {
	return []string{
		"--cache-dir", s.cacheDir(),
		"fs",
		// misconfig ONLY. vuln belongs to grype and secret to gitleaks; asking
		// trivy for either would duplicate a domain another adapter owns (§6).
		"--scanners", "misconfig",
		// No egress during a scan. The checks bundle is already on disk.
		"--skip-check-update",
		"--skip-db-update",
		"--skip-version-check",
		// Findings are the output; a version notice is not.
		"--format", "json",
		"--quiet",
		// Findings must not make trivy exit non-zero: a scan that found
		// misconfigurations succeeded at its job. Failing the scan here would
		// make "we found problems" indistinguishable from "we broke".
		"--exit-code", "0",
		".",
	}
}

// env is the complete environment for the trivy subprocess: an allow-list, so
// it cannot inherit the worker's credentials (§14.7).
//
// Registry credentials matter here even though this adapter scans no images:
// TRIVY_USERNAME, TRIVY_PASSWORD, and GITHUB_TOKEN are all read from the
// environment by trivy, and none of them can reach it because nothing unlisted
// does.
func (s *Scanner) env() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/nonexistent",
		// Trivy phones home for version notices unless told not to.
		"TRIVY_SKIP_VERSION_CHECK=true",
		// Scratch space: the worker's root filesystem is read-only, which
		// three scanners have now tripped over.
		"TMPDIR=" + s.tmpDir(),
	}
}

// baseDir canonicalises the configured cache directory.
//
// CacheDir arrives from the environment, so it is validated rather than trusted
// and canonicalised before anything is joined onto it (§14.5).
func (s *Scanner) baseDir() (string, error) {
	if strings.TrimSpace(s.CacheDir) == "" {
		return "", fmt.Errorf("trivy: cache directory is not configured")
	}
	clean := filepath.Clean(s.CacheDir)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("trivy: cache directory %q must be an absolute path", s.CacheDir)
	}
	return clean, nil
}

func (s *Scanner) cacheDir() string { return filepath.Join(filepath.Clean(s.CacheDir), "cache") }
func (s *Scanner) tmpDir() string   { return filepath.Join(filepath.Clean(s.CacheDir), "tmp") }

func (s *Scanner) provisionTimeout() time.Duration {
	if s.ProvisionTimeout > 0 {
		return s.ProvisionTimeout
	}
	return 5 * time.Minute
}

// Provision downloads the misconfiguration checks bundle.
//
// Trivy has no "download checks only" flag, so the bundle is fetched by running
// one throwaway scan against an empty directory. Inelegant, and the alternative
// is fetching rules during a real scan with untrusted content on disk, which is
// what ADR 012 exists to avoid.
//
// This is the third consumer of the Provisioner hook, after grype's database
// and semgrep's rules. The bundle is ~2.6 MB, so unlike grype's 2 GB this is
// cheap enough to do on every worker start.
func (s *Scanner) Provision(ctx context.Context) error {
	base, err := s.baseDir()
	if err != nil {
		return err
	}
	for _, name := range []string{"cache", "tmp", "empty"} {
		//nolint:gosec // G703: base is validated absolute and cleaned by baseDir.
		if err := os.MkdirAll(filepath.Join(base, name), 0o700); err != nil {
			return fmt.Errorf("trivy: preparing %s: %w", name, err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.provisionTimeout())
	defer cancel()

	// Deliberately WITHOUT --skip-check-update: this is the one moment trivy is
	// allowed to fetch, and it happens before any job is claimed.
	_, err = scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.provisionTimeout(),
		MaxOutputBytes: 4 << 20,
		Env:            s.env(),
	}, "trivy", "--cache-dir", s.cacheDir(), "fs",
		"--scanners", "misconfig", "--skip-db-update", "--skip-version-check",
		"--format", "json", "--quiet", filepath.Join(base, "empty"))
	if err != nil {
		return fmt.Errorf("trivy: provisioning the checks bundle: %w", err)
	}
	return nil
}
