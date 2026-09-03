// Package trivy adapts the Trivy scanner for two domains: misconfiguration of a
// checkout, and vulnerabilities of a container image.
//
// Everything trivy-specific lives here and nowhere else (CLAUDE.md §7). Nothing
// outside this package may import its types or branch on its name.
//
// Which question is asked depends on the target kind, and each mode is
// deliberately narrow. A filesystem target gets misconfiguration only:
// Dockerfiles, Kubernetes manifests, Terraform. Grype owns dependency
// vulnerabilities of a checkout and Gitleaks owns secrets, and §6 forbids
// duplicating a domain another adapter covers.
//
// An image target gets vulnerabilities only, which is not that duplication
// though it may look like it. Grype answers "what does this repository
// declare?"; this answers "what is installed in this image?" The overlap is the
// product: a vulnerable declared dependency that also appears in an image is a
// vulnerability that is actually deployed, which is the contextual judgement §9
// exists to make and §10 scores. See ADR 025.
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
	"regexp"
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

// Scanner runs trivy against a local checkout or a container image.
type Scanner struct {
	// Timeout bounds one invocation. Zero uses the shared default.
	Timeout time.Duration
	// MaxOutputBytes caps the report size. Zero uses the shared default.
	MaxOutputBytes int64
	// CacheDir holds the provisioned checks bundle and vulnerability database.
	// Required in the worker: trivy's default is under $HOME, and the
	// subprocess runs without one.
	CacheDir string
	// ProvisionTimeout bounds each provisioning download. Zero uses a default.
	ProvisionTimeout time.Duration
}

// New returns a Scanner reading its checks from cacheDir.
func New(cacheDir string) *Scanner { return &Scanner{CacheDir: cacheDir} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		Kinds: []scanners.Kind{scanners.KindFilesystem, scanners.KindImage},
		// Two domains, because the target kind decides the question asked:
		// misconfiguration of a checkout, vulnerabilities of an image
		// (ADR 025).
		Categories: []scanners.Category{scanners.CategoryIaC, scanners.CategoryContainer},
		// Only image targets need egress, and only to reach a registry. A
		// filesystem scan still runs with no network at all: both the checks
		// bundle and the vulnerability database are provisioned before any job
		// is claimed (ADR 012, §14.3).
		NetworkKinds: []scanners.Kind{scanners.KindImage},
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
	var (
		args []string
		dir  string
	)
	switch target.Kind {
	case scanners.KindFilesystem:
		if target.Path == "" {
			return scanners.RawResult{Scanner: Name}, fmt.Errorf("trivy: target path is required")
		}
		args = s.fsArgs()
		// Run inside the checkout and scan ".", so reported paths are
		// repository-relative rather than rooted in the worker's workspace.
		dir = target.Path
	case scanners.KindImage:
		if target.Image == "" {
			return scanners.RawResult{Scanner: Name}, fmt.Errorf("trivy: target image is required")
		}
		// Re-checked here rather than trusted from validation. This is the
		// last point before a subprocess is handed the value, and a reference
		// beginning with "-" would be read as a flag rather than as data.
		if !imageRefIsSafe(target.Image) {
			return scanners.RawResult{Scanner: Name}, fmt.Errorf("trivy: image reference is not acceptable")
		}
		args = s.imageArgs(target.Image)
	default:
		return scanners.RawResult{Scanner: Name}, scanners.ErrUnsupportedTarget
	}
	if _, err := s.baseDir(); err != nil {
		return scanners.RawResult{Scanner: Name}, err
	}

	version, _ := s.Version(ctx)
	started := time.Now()

	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: s.MaxOutputBytes,
		Dir:            dir,
		Env:            s.env(),
	}, "trivy", args...)

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

// fsArgs is the trivy argument vector for a filesystem target.
//
// A function so a test can assert the flags directly rather than only by
// observing a subprocess. The scanner selection is the §6 boundary made
// explicit in the command line, where a test can see it.
func (s *Scanner) fsArgs() []string {
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

// imageArgs is the trivy argument vector for an image target.
//
// The image reference is the final element and is never interpolated into a
// string: scanners.Run takes an argument vector and forbids a shell, so a
// reference cannot become a second command (§14.4, §25.11).
func (s *Scanner) imageArgs(image string) []string {
	return []string{
		"--cache-dir", s.cacheDir(),
		"image",
		// vuln ONLY. Secrets belong to gitleaks and misconfiguration is what
		// the filesystem mode already covers; asking for either here would
		// duplicate a domain another adapter owns (§6).
		"--scanners", "vuln",
		// Both OS packages and the language packages actually installed in the
		// image. Trivy ignores a lock file inside an image and reads what is
		// installed, which is what makes an image finding evidence that a
		// component is deployed rather than merely declared (ADR 025).
		"--pkg-types", "os,library",
		// THE security-critical flag. Trivy otherwise tries docker, then
		// containerd, then podman, before the registry. A worker with a socket
		// mounted would let a scan read images it was never pointed at, and
		// would sidestep the address policy that validated this reference.
		"--image-src", "remote",
		// No egress beyond the registry: the database is already on disk.
		"--skip-db-update",
		"--skip-version-check",
		"--format", "json",
		"--quiet",
		// Findings must not make trivy exit non-zero, for the same reason as
		// the filesystem mode: "we found problems" and "we broke" have to stay
		// distinguishable.
		"--exit-code", "0",
		image,
	}
}

// imageRefIsSafe re-applies the target validator's character rule.
//
// Deliberately duplicated. Validation happens at the API boundary, and this is
// the worker, on the other side of a queue -- a payload that reached the queue
// by any other route has still never been checked here. Defence in depth is
// cheap when the check is a regexp.
func imageRefIsSafe(ref string) bool {
	return safeImageRef.MatchString(ref) && !strings.Contains(ref, "..")
}

var safeImageRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@\-]{0,254}$`)

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
//
// Image targets need a second artefact, the vulnerability database, which is
// fetched here for the same reason and by the same rule: the one moment this
// adapter is allowed to fetch is before any job is claimed, so no untrusted
// content is on disk while it happens (ADR 012, §14.3).
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

	// The vulnerability database, for image targets. --download-db-only exists
	// precisely for this, so unlike the checks bundle it needs no throwaway
	// scan. Fetched unconditionally: an adapter that declares KindImage must be
	// able to serve it, and discovering the database is missing at scan time
	// would mean egress with untrusted content already on disk.
	dbCtx, dbCancel := context.WithTimeout(ctx, s.provisionTimeout())
	defer dbCancel()
	if _, err := scanners.Run(dbCtx, scanners.ExecOptions{
		Timeout:        s.provisionTimeout(),
		MaxOutputBytes: 4 << 20,
		Env:            s.env(),
	}, "trivy", "--cache-dir", s.cacheDir(), "image",
		"--download-db-only", "--skip-version-check", "--quiet"); err != nil {
		return fmt.Errorf("trivy: provisioning the vulnerability database: %w", err)
	}
	return nil
}
