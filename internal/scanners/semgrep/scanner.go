// Package semgrep adapts the Semgrep static analysis engine.
//
// Everything semgrep-specific lives here and nowhere else (CLAUDE.md §7).
// Nothing outside this package may import its types or branch on its name.
//
// Two things make this adapter unlike the others. Semgrep is Python rather than
// Go, so it cannot be built from source with our toolchain the way gitleaks,
// syft, and grype are (ADR 009 does not transfer; see ADR 014). And its rules
// live in a remote registry, so they are provisioned before any job is claimed
// rather than fetched mid-scan, exactly as grype's vulnerability database is
// (ADR 012).
package semgrep

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// Name is the adapter's stable identifier, used for registration, persistence,
// and reporting.
const Name = "semgrep"

// DefaultRulesets is what gets provisioned when nothing else is configured.
//
// Note what is absent: `p/secrets`. Gitleaks owns secret detection, and §6
// forbids duplicating coverage across scanners without a documented reason.
// Two scanners reporting the same credential would also mean the redaction
// control in ADR 007 has to be reimplemented here, correctly, a second time.
var DefaultRulesets = []string{
	"p/security-audit",
	"p/golang",
	"p/javascript",
	"p/typescript",
	"p/python",
	"p/java",
	"p/dockerfile",
}

// ErrMalformedReport reports that semgrep did not produce a usable report.
var ErrMalformedReport = errors.New("semgrep did not produce a valid report")

// ErrSourceLeak reports that the output carried matched source code.
//
// Semgrep can embed the matched line in every finding. That line is the code
// the rule fired on, which for a credential rule is the credential itself --
// the exact thing §15.3 forbids storing. Unauthenticated semgrep withholds it
// ("requires login"), but that is a property of its login state rather than a
// flag under our control, so the result is asserted rather than assumed.
var ErrSourceLeak = errors.New("semgrep output contains matched source; discarded")

// Scanner runs semgrep against a local checkout.
type Scanner struct {
	// Timeout bounds one invocation. Zero uses the shared default.
	Timeout time.Duration
	// MaxOutputBytes caps the report size. Zero uses the shared default.
	MaxOutputBytes int64
	// Dir is the adapter's own writable directory. Required in the worker.
	//
	// It holds two things that must not share a path. Provisioned rules go in
	// Dir/rules, which is what --config points at, and semgrep's own state
	// goes in Dir/home. Semgrep creates $HOME/.semgrep on every run whatever
	// SEMGREP_SETTINGS_FILE says, and putting that inside the rules directory
	// would offer semgrep its own state as a rule file.
	Dir string
	// Rulesets overrides DefaultRulesets.
	Rulesets []string
	// ProvisionTimeout bounds rule fetching. Zero uses a default.
	ProvisionTimeout time.Duration
}

// New returns a Scanner using dir for its rules and its own state.
func New(dir string) *Scanner { return &Scanner{Dir: dir} }

// baseDir canonicalises the configured directory.
//
// Dir arrives from the environment, so it is validated rather than trusted, and
// canonicalised before anything is joined onto it (§14.5). Requiring an
// absolute, cleaned path means the subdirectories below cannot be talked out of
// the location an operator configured -- and it is what lets the rest of this
// package treat those paths as safe.
func (s *Scanner) baseDir() (string, error) {
	if strings.TrimSpace(s.Dir) == "" {
		return "", fmt.Errorf("semgrep: directory is not configured")
	}
	clean := filepath.Clean(s.Dir)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("semgrep: directory %q must be an absolute path", s.Dir)
	}
	return clean, nil
}

// rulesDir is what --config points at: provisioned rules and nothing else.
func (s *Scanner) rulesDir() string { return filepath.Join(filepath.Clean(s.Dir), "rules") }

// homeDir is semgrep's $HOME. Separate from the rules, deliberately: semgrep
// creates $HOME/.semgrep on every run, and a state directory sitting among the
// rules would be offered to semgrep as rules.
func (s *Scanner) homeDir() string { return filepath.Join(filepath.Clean(s.Dir), "home") }

// tmpDir is semgrep's scratch space.
//
// The worker's root filesystem is read-only, so Python cannot find a usable
// temporary directory and semgrep dies before it parses a single file. Every
// scanner that needs scratch space has hit this -- gitleaks' report path, the
// grype database staging, and now this -- and the fix is always the same: hand
// it a writable path we control rather than relaxing the filesystem.
//
// Shared across concurrent scans, which is safe: Python's tempfile generates
// unique names within the directory.
func (s *Scanner) tmpDir() string { return filepath.Join(filepath.Clean(s.Dir), "tmp") }

// ensureDirs creates the directories semgrep needs. Called from both Provision
// and Scan: a scan must not fail with an obscure Python error just because
// provisioning was skipped.
func (s *Scanner) ensureDirs() error {
	base, err := s.baseDir()
	if err != nil {
		return err
	}
	for _, name := range []string{"rules", "home", "tmp"} {
		// gosec traces `base` back to configuration and cannot see the
		// validation in baseDir, which requires an absolute, cleaned path
		// before anything is joined onto it (§14.5). The leaf names are
		// constants, and this value is operator configuration -- it is not a
		// scan target, a repository path, or anything else that arrives from
		// untrusted input.
		//nolint:gosec // G703: base is validated absolute and cleaned by baseDir.
		if err := os.MkdirAll(filepath.Join(base, name), 0o700); err != nil {
			return fmt.Errorf("semgrep: preparing %s: %w", name, err)
		}
	}
	return nil
}

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		// Filesystem only. The worker fetches repository targets and hands
		// adapters the checkout (ADR 008).
		Kinds:      []scanners.Kind{scanners.KindFilesystem},
		Categories: []scanners.Category{scanners.CategorySAST},
		// No NetworkKinds by design: rules are provisioned before any job is
		// claimed, so a scan of untrusted content runs with no egress
		// (ADR 012, §14.3).
	}
}

// Version implements scanners.Scanner.
func (s *Scanner) Version(ctx context.Context) (string, error) {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        60 * time.Second,
		MaxOutputBytes: 4 << 10,
		Env:            s.env(),
	}, "semgrep", "--version")
	if err != nil {
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
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("semgrep: target path is required")
	}
	if _, err := s.baseDir(); err != nil {
		return scanners.RawResult{Scanner: Name}, err
	}

	if err := s.ensureDirs(); err != nil {
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
	}, "semgrep", s.args()...)

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
	// Fail closed if matched source reached the output. Nothing is persisted:
	// a report that carries a credential must not be stored while we decide
	// what to do about it (§15.3).
	if err := assertNoMatchedSource(res.Stdout); err != nil {
		return scanners.RawResult{Scanner: Name, Version: version, Target: target}, err
	}
	// The workspace path must not travel either, for the reason recorded as
	// T-30 against syft.
	if err := assertNoWorkspacePaths(res.Stdout, target.Path); err != nil {
		return scanners.RawResult{Scanner: Name, Version: version, Target: target}, err
	}

	raw.Output = res.Stdout
	return raw, nil
}

// args is the semgrep argument vector.
//
// A function so a test can assert the flags directly rather than only by
// observing a subprocess.
func (s *Scanner) args() []string {
	return []string{
		"scan",
		// The provisioned local rules. Never a registry name: that would fetch
		// over the network mid-scan, with untrusted content already on disk.
		"--config", s.rulesDir(),
		"--json",
		// Semgrep sends usage metrics by default, and "auto" enables them
		// whenever a registry config is used. Off, explicitly, always.
		"--metrics=off",
		// Findings are the output; progress and banners are not.
		"--quiet",
		"--no-rewrite-rule-ids",
		// A repository is untrusted input, so its size is bounded like any
		// other (§15.8).
		"--max-target-bytes", "1000000",
		"--timeout", "30",
		// Autofix would modify the checkout. An analyser must not write to the
		// thing it is analysing.
		"--no-autofix",
		".",
	}
}

// env is the complete environment for the semgrep subprocess: an allow-list, so
// it cannot inherit the worker's credentials (§14.7).
//
// The allow-list is load-bearing here in a way it is not for the other
// adapters. Semgrep withholds matched source only while it is unauthenticated;
// a SEMGREP_APP_TOKEN in the worker's environment would silently turn that off
// and start writing matched lines -- credentials included -- into stored
// output. It cannot reach the subprocess because nothing that is not listed
// here ever does.
func (s *Scanner) env() []string {
	binDir, pythonPath := semgrepLayout()

	env := []string{
		// The installation's own bin directory comes first. The `semgrep`
		// entrypoint is an OCaml binary that execs a `pysemgrep` helper living
		// beside it, and fails with a bare "execvp pysemgrep" if it is absent
		// from the child's PATH.
		"PATH=" + binDir + ":/usr/local/bin:/usr/bin:/bin",
		// A writable HOME, not /nonexistent. Semgrep creates $HOME/.semgrep on
		// every run and dies with a bare FileNotFoundError when it cannot --
		// found by running it, since nothing about the flags suggests it.
		"HOME=" + s.homeDir(),
		"SEMGREP_SEND_METRICS=off",
		"SEMGREP_SETTINGS_FILE=" + filepath.Join(s.homeDir(), "settings.yml"),
		// See tmpDir: the root filesystem is read-only, so Python finds no
		// usable temporary directory and semgrep exits before scanning.
		"TMPDIR=" + s.tmpDir(),
	}
	if pythonPath != "" {
		env = append(env, "PYTHONPATH="+pythonPath)
	}
	return env
}

// semgrepLayout locates the installation that will actually run.
//
// Derived from the resolved binary rather than hardcoded, for two reasons. The
// worker image installs semgrep under its own prefix (ADR 014) while a
// developer's machine puts it wherever their package manager does, and an
// adapter that only works in one of those is an adapter nobody can test where
// they are working. It also means the image layout can change without this
// package knowing.
//
// Both values fall back to empty, which is correct for an installation that
// needs no help finding its own libraries.
func semgrepLayout() (binDir, pythonPath string) {
	resolved, err := exec.LookPath("semgrep")
	if err != nil {
		return "", ""
	}
	binDir = filepath.Dir(resolved)

	// A prefix install keeps its packages in ../lib/pythonX.Y/site-packages.
	// Globbed rather than pinned to a version, so a Python upgrade in the base
	// image does not silently break every scan.
	//
	// The glob asks for semgrep's own package, not merely for a site-packages
	// directory. A sibling site-packages that exists but belongs to something
	// else -- a package manager's shared Python, say -- would otherwise be put
	// on PYTHONPATH and break the installation it was meant to help. Measured:
	// that is exactly what happens on a Homebrew install, where semgrep lives
	// in a private libexec environment.
	matches, _ := filepath.Glob(
		filepath.Join(binDir, "..", "lib", "python3.*", "site-packages", "semgrep"))
	if len(matches) > 0 {
		pythonPath = filepath.Dir(matches[0])
	}
	return binDir, pythonPath
}

// Provision downloads the rule sets.
//
// This is the only moment semgrep is allowed near the network, and it happens
// at worker startup before any job is claimed, so the egress never coincides
// with an untrusted repository on disk (§14.3). Every scan afterwards reads the
// rules from disk.
func (s *Scanner) Provision(ctx context.Context) error {
	if err := s.ensureDirs(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, s.provisionTimeout())
	defer cancel()

	for _, ruleset := range s.rulesets() {
		if err := s.fetchRuleset(ctx, ruleset); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) rulesets() []string {
	if len(s.Rulesets) > 0 {
		return s.Rulesets
	}
	return DefaultRulesets
}

func (s *Scanner) provisionTimeout() time.Duration {
	if s.ProvisionTimeout > 0 {
		return s.ProvisionTimeout
	}
	return 10 * time.Minute
}

// rulesetFilename maps a registry name like "p/golang" to a flat filename.
// Slashes cannot appear in the stored name, and the value is validated rather
// than trusted even though it is configuration rather than target input.
func rulesetFilename(ruleset string) (string, error) {
	if ruleset == "" || strings.Contains(ruleset, "..") || strings.HasPrefix(ruleset, "-") {
		return "", fmt.Errorf("semgrep: refusing ruleset name %q", ruleset)
	}
	for _, r := range ruleset {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '-', r == '_', r == '.':
		default:
			return "", fmt.Errorf("semgrep: refusing ruleset name %q", ruleset)
		}
	}
	return strings.ReplaceAll(ruleset, "/", "_") + ".yaml", nil
}
