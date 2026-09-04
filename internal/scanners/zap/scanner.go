// Package zap adapts OWASP ZAP for dynamic application security testing.
//
// Everything ZAP-specific lives here and nowhere else (CLAUDE.md §7). Nothing
// outside this package may import its types or branch on its name.
//
// This is the only adapter that scans a running application rather than bytes
// at rest, and that difference governs the design. It runs ZAP's passive rules
// over traffic the spider generates, and it does NOT run an active scan --
// active scanning delivers crafted attack payloads to a live host, which
// changes state, is attack traffic whether or not the operator owns the target,
// and needs an authorization model SecureOps does not have. The activeScan job
// is absent from the plan rather than disabled in it. See ADR 026.
//
// It is also the second adapter to rewrite its output before storage, after
// trivy (ADR 015). ZAP puts the full request URL in every alert instance, and a
// URL's query string is where credentials live -- measured, not assumed: a
// target serving one link to `/search?api_key=...` produced seven copies of that
// key in one report.
package zap

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
const Name = "zap"

// DefaultCommand is the launcher ZAP ships. Overridable because ZAP is not on
// PATH in a default macOS install, where it lives inside an .app bundle.
const DefaultCommand = "zap.sh"

// ErrMalformedReport reports that ZAP did not produce a usable report.
var ErrMalformedReport = errors.New("zap did not produce a valid report")

// ErrTargetLeak reports that target content survived redaction.
//
// The ZAP counterpart of trivy's ErrSourceLeak, and it exists for the same
// reason: the rewrite walks a decoded document, so a schema change that renamed
// or moved a field would make the walk miss it silently. This error means the
// check afterwards found something the rewrite did not (ADR 026, §15.3).
var ErrTargetLeak = errors.New("zap output still contains target content after redaction; discarded")

// Scanner runs ZAP against a live endpoint.
type Scanner struct {
	// Command is the ZAP launcher. Empty uses DefaultCommand.
	Command string
	// HomeDir is ZAP's writable home. Required in the worker: ZAP's default is
	// under $HOME, and the subprocess runs without one.
	HomeDir string
	// ProxyPort is the local port ZAP binds. Zero uses DefaultProxyPort.
	//
	// Bound to loopback and never used as a proxy by anything -- ZAP requires a
	// listener even in headless command mode, and refuses to start when the
	// port is taken.
	ProxyPort int
	// Timeout bounds one invocation. Zero uses the shared default.
	Timeout time.Duration
	// MaxOutputBytes caps the report size. Zero uses the shared default.
	MaxOutputBytes int64
	// SpiderMinutes bounds the crawl. Zero uses DefaultSpiderMinutes.
	SpiderMinutes int
	// JarPath runs ZAP from its jar instead of through its launcher script.
	// Empty keeps the launcher.
	//
	// JarPath chooses the launch mode; Command names the executable. Set
	// together, ZAP runs as `<Command> -Xmx… -jar <JarPath> …`, which is how a
	// deployment points at a specific JVM. Set alone, the executable is
	// whatever `java` resolves to on the subprocess PATH.
	//
	// This is how ZAP runs in the worker image (ADR 030). The launcher is
	// `#!/usr/bin/env bash` and uses bash-only constructs, so honouring it
	// would mean shipping a general-purpose shell in the one container that
	// executes untrusted content. The jar is the program; the launcher only
	// finds a JVM and guesses a heap size.
	JarPath string
	// MaxHeap is the JVM's maximum heap when running from the jar, as a -Xmx
	// value ("1024m"). Empty uses DefaultMaxHeap. Ignored without JarPath,
	// because the launcher sets its own.
	//
	// Declared rather than inferred: the launcher sizes the heap from the
	// machine's memory, which makes a scan's memory ceiling a property of the
	// host. §14.3 wants it to be a property of the configuration.
	MaxHeap string
}

// Defaults for the knobs above.
const (
	DefaultProxyPort      = 8098
	DefaultSpiderMinutes  = 2
	defaultPassiveMinutes = 5
	// DefaultMaxHeap is the JVM heap ceiling when running from the jar.
	// ZAP's own launcher would take roughly a quarter of host memory; this is
	// a fixed budget instead, so a scan costs the same wherever it runs.
	DefaultMaxHeap = "1024m"
)

// New returns a Scanner using homeDir for ZAP's state.
func New(homeDir string) *Scanner { return &Scanner{HomeDir: homeDir} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		Kinds:      []scanners.Kind{scanners.KindEndpoint},
		Categories: []scanners.Category{scanners.CategoryDAST},
		// The one adapter whose whole purpose is egress: it scans a running
		// application, so there is nothing to scan without the network. The
		// per-kind declaration ADR 025 introduced says exactly that and no
		// more.
		NetworkKinds: []scanners.Kind{scanners.KindEndpoint},
	}
}

// Version implements scanners.Scanner.
//
// Two arguments here are load-bearing rather than incidental.
//
// The launch arguments are prepended: running from the jar makes the executable
// `java`, so a bare `-version` would run `java -version` and report the JVM's
// version as the scanner's -- persisted per scan (§7 rule 6), which would make
// every ZAP result claim a version of ZAP that does not exist.
//
// And `-dir`, which a version probe looks like it should not need. ZAP creates
// its home before it will print anything, and the subprocess environment sets
// HOME=/nonexistent deliberately (§14.7), so without an explicit directory ZAP
// throws on `/nonexistent/.ZAP` and prints a stack trace instead of a version.
// The failure is silent where it matters: Scan ignores this error by design,
// which would leave every result carrying an empty scanner version.
func (s *Scanner) Version(ctx context.Context) (string, error) {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        60 * time.Second,
		MaxOutputBytes: 8 << 10,
		Env:            s.env(),
	}, s.command(), append(s.launchArgs(), "-dir", s.baseDirUnchecked(), "-version")...)
	if err != nil {
		return "", err
	}
	return parseVersion(res.Stdout), nil
}

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, target scanners.Target) (scanners.RawResult, error) {
	if target.Kind != scanners.KindEndpoint {
		return scanners.RawResult{Scanner: Name}, scanners.ErrUnsupportedTarget
	}
	if target.EndpointURL == "" {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("zap: target endpoint_url is required")
	}
	// Re-checked here rather than trusted from validation: the worker is on the
	// far side of a queue from the validator, and this value is about to be
	// written into a plan file ZAP will act on.
	if !endpointIsSafe(target.EndpointURL) {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("zap: endpoint is not acceptable")
	}
	base, err := s.baseDir()
	if err != nil {
		return scanners.RawResult{Scanner: Name}, err
	}

	// A per-scan directory for the plan and the report. ZAP writes its report
	// to a file rather than to stdout, which no other adapter does.
	runDir, err := os.MkdirTemp(base, "run-")
	if err != nil {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("zap: preparing the run directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(runDir) }()

	planPath := filepath.Join(runDir, "plan.yaml")
	if err := os.WriteFile(planPath, s.plan(target.EndpointURL, runDir), 0o600); err != nil {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("zap: writing the automation plan: %w", err)
	}

	version, _ := s.Version(ctx)
	started := time.Now()

	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: s.MaxOutputBytes,
		Env:            s.env(),
	}, s.command(), s.args(planPath)...)

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

	// The report is a file, so a plan that "succeeded" without producing one is
	// a failed scan rather than a clean one -- the distinction §13 exists to
	// preserve.
	// #nosec G304 -- runDir comes from os.MkdirTemp under the validated,
	// canonicalised home directory, and reportFileName is a constant. No part
	// of this path is caller-supplied.
	report, err := os.ReadFile(filepath.Join(runDir, reportFileName))
	if err != nil {
		return raw, fmt.Errorf("%w: no report was produced", ErrMalformedReport)
	}
	if s.maxOutputBytes() > 0 && int64(len(report)) > s.maxOutputBytes() {
		raw.Degrade(scanners.DegradedOutputTruncated)
		return raw, fmt.Errorf("%w: report exceeds the output cap", ErrMalformedReport)
	}

	if err := validateReport(report); err != nil {
		return raw, err
	}

	// Redaction happens before anything is persisted, and its result is
	// checked. Same shape as ADR 015, different content: ZAP embeds the target
	// application's URLs and response fragments, and a URL's query string is
	// routinely a credential (ADR 026, §15.3).
	redacted, err := redactTargetContent(report)
	if err != nil {
		return raw, err
	}
	if err := assertNoTargetContent(redacted); err != nil {
		return scanners.RawResult{Scanner: Name, Version: version, Target: target}, err
	}

	raw.Output = redacted
	return raw, nil
}

// reportFileName is what the plan's report job writes. ZAP appends the
// extension implied by the template.
const reportFileName = "zap-report.json"

// args is the ZAP argument vector.
//
// A function so a test can assert the flags directly rather than only by
// observing a subprocess -- the same reason the other adapters expose theirs.
func (s *Scanner) args(planPath string) []string {
	return append(s.launchArgs(), s.zapArgs(planPath)...)
}

// launchArgs is what precedes ZAP's own flags.
//
// Empty for the launcher script, which is itself the executable. For the jar it
// is the JVM's arguments, and the heap ceiling is one of them -- a declared
// limit rather than whatever the launcher would have inferred from the host.
func (s *Scanner) launchArgs() []string {
	if strings.TrimSpace(s.JarPath) == "" {
		return nil
	}
	return []string{"-Xmx" + s.maxHeap(), "-jar", strings.TrimSpace(s.JarPath)}
}

// zapArgs is ZAP's own argument vector, identical either way it is launched.
func (s *Scanner) zapArgs(planPath string) []string {
	return []string{
		"-cmd",
		"-dir", s.baseDirUnchecked(),
		// Headless, no add-on update check, and no call home. ZAP's callhome
		// add-on reports version and usage; a scan must not be conditional on a
		// vendor endpoint being reachable, nor report our usage to one. Same
		// posture ADR 014 takes toward semgrep's --config auto.
		"-silent",
		"-config", "telemetry.enabled=false",
		"-config", "callhome.telemetryEnabled=false",
		// ZAP requires a listener even headless. Loopback only: nothing is
		// meant to reach it, and binding a wildcard would make the worker an
		// open proxy for the length of the scan.
		"-host", "127.0.0.1",
		"-port", fmt.Sprintf("%d", s.proxyPort()),
		"-autorun", planPath,
	}
}

// plan is the Automation Framework plan for one scan.
//
// Declarative on purpose. The baseline script hides its configuration in flags
// and exit codes; a plan is data this adapter writes and a test can assert --
// the same reasoning that keeps semgrep's rulesets in the argument vector.
//
// Note what is NOT here: an `activeScan` job. Its absence is the security
// control, and it is absent rather than present-and-disabled so that no
// configuration change can switch it on (ADR 026).
func (s *Scanner) plan(endpoint, outDir string) []byte {
	var b strings.Builder
	b.WriteString("env:\n")
	b.WriteString("  contexts:\n")
	b.WriteString("    - name: target\n")
	b.WriteString("      urls: [" + yamlString(endpoint) + "]\n")
	b.WriteString("  parameters:\n")
	// A scan that cannot reach its target must fail, not report zero findings:
	// "the application is clean" and "we never got a response" are the same
	// distinction PARTIAL exists to preserve for whole scans (§13).
	b.WriteString("    failOnError: true\n")
	b.WriteString("    progressToStdout: true\n")
	b.WriteString("jobs:\n")
	b.WriteString("  - type: spider\n")
	b.WriteString("    parameters:\n")
	b.WriteString("      context: target\n")
	fmt.Fprintf(&b, "      maxDuration: %d\n", s.spiderMinutes())
	b.WriteString("  - type: passiveScan-wait\n")
	b.WriteString("    parameters:\n")
	fmt.Fprintf(&b, "      maxDuration: %d\n", defaultPassiveMinutes)
	b.WriteString("  - type: report\n")
	b.WriteString("    parameters:\n")
	// traditional-json, NOT traditional-json-plus: the -plus template embeds
	// full request and response bodies, which is the entire target application
	// including anything it renders.
	b.WriteString("      template: traditional-json\n")
	b.WriteString("      reportDir: " + yamlString(outDir) + "\n")
	b.WriteString("      reportFile: " + yamlString(strings.TrimSuffix(reportFileName, ".json")) + "\n")
	return []byte(b.String())
}

// yamlString quotes a value so it cannot terminate the scalar and inject
// structure into the plan.
//
// The endpoint is validated upstream and again in Scan, so this is the third
// layer rather than the only one -- but a plan is a document built from a
// caller-supplied value, and building documents from untrusted values without
// quoting is how injection happens whatever the format (§15.7).
func yamlString(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", "", "\r", "").Replace(v) + `"`
}

// env is the complete environment for the ZAP subprocess: an allow-list, so it
// cannot inherit the worker's credentials (§14.7).
func (s *Scanner) env() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		// ZAP is a Java application and resolves JAVA_HOME itself when unset.
		"HOME=/nonexistent",
		"TMPDIR=" + s.tmpDirUnchecked(),
		// Headless, so no display is needed and none should be attempted.
		"JAVA_TOOL_OPTIONS=-Djava.awt.headless=true",
	}
}

// command is the executable to run.
//
// An explicit Command always wins, so a deployment can point at a launcher in
// an unusual place (a macOS .app bundle, for instance). Otherwise a configured
// jar means the executable is the JVM, and the fallback is ZAP's launcher.
func (s *Scanner) command() string {
	if c := strings.TrimSpace(s.Command); c != "" {
		return c
	}
	if strings.TrimSpace(s.JarPath) != "" {
		return javaCommand
	}
	return DefaultCommand
}

// javaCommand is resolved through the subprocess PATH, which the env
// allow-list sets to the image's own directories.
const javaCommand = "java"

func (s *Scanner) maxHeap() string {
	if h := strings.TrimSpace(s.MaxHeap); h != "" {
		return h
	}
	return DefaultMaxHeap
}

func (s *Scanner) proxyPort() int {
	if s.ProxyPort > 0 {
		return s.ProxyPort
	}
	return DefaultProxyPort
}

func (s *Scanner) spiderMinutes() int {
	if s.SpiderMinutes > 0 {
		return s.SpiderMinutes
	}
	return DefaultSpiderMinutes
}

func (s *Scanner) maxOutputBytes() int64 { return s.MaxOutputBytes }

// baseDir canonicalises the configured home directory.
//
// HomeDir arrives from the environment, so it is validated rather than trusted
// and canonicalised before anything is joined onto it (§14.5).
func (s *Scanner) baseDir() (string, error) {
	if strings.TrimSpace(s.HomeDir) == "" {
		return "", fmt.Errorf("zap: home directory is not configured")
	}
	clean := filepath.Clean(s.HomeDir)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("zap: home directory %q must be an absolute path", s.HomeDir)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return "", fmt.Errorf("zap: preparing the home directory: %w", err)
	}
	return clean, nil
}

func (s *Scanner) baseDirUnchecked() string { return filepath.Clean(s.HomeDir) }
func (s *Scanner) tmpDirUnchecked() string  { return filepath.Join(filepath.Clean(s.HomeDir), "tmp") }

// Provision prepares ZAP's home directory.
//
// Unlike grype's database, semgrep's rules, and trivy's checks bundle, there is
// nothing to download: ZAP's passive rules ship inside the installation. This
// exists so the writable state ZAP needs is created before a job is claimed
// rather than during a scan, and to fail early when the directory is
// unusable.
func (s *Scanner) Provision(_ context.Context) error {
	base, err := s.baseDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(base, "tmp"), 0o700); err != nil {
		return fmt.Errorf("zap: preparing the scratch directory: %w", err)
	}
	return nil
}
