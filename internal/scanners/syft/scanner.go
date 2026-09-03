// Package syft adapts the Syft SBOM generator.
//
// Everything syft-specific lives here and nowhere else (CLAUDE.md §7). Nothing
// outside this package may import its types or branch on its name.
//
// This adapter is unlike the others in one respect worth stating: it produces
// no findings. Its output is an artifact -- a CycloneDX Software Bill of
// Materials describing what the target is built from. Nothing is "wrong" in a
// SBOM; it is the input other analysis depends on.
package syft

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// Name is the adapter's stable identifier, used for registration, persistence,
// and reporting.
const Name = "syft"

// ErrMalformedSBOM reports that syft did not produce a usable CycloneDX
// document. Output that cannot be proven well-formed is discarded rather than
// persisted: a truncated or garbled SBOM that later reads as "no components"
// would understate a project's dependencies, which is a silent false clean.
var ErrMalformedSBOM = errors.New("syft did not produce a valid CycloneDX SBOM")

// ErrWorkspacePathLeak reports that the SBOM embeds the worker's filesystem
// layout. See assertNoWorkspacePaths.
var ErrWorkspacePathLeak = errors.New("SBOM contains worker filesystem paths; output discarded")

// Scanner runs syft against a local checkout.
type Scanner struct {
	// Timeout bounds one invocation. Zero uses the shared default.
	Timeout time.Duration
	// MaxOutputBytes caps the SBOM size. Zero uses the shared default. A
	// repository with an enormous dependency tree is still untrusted input.
	MaxOutputBytes int64
}

// New returns a Scanner with default limits.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		// Filesystem only. The worker fetches repository targets and hands
		// adapters the checkout (ADR 008).
		Kinds:      []scanners.Kind{scanners.KindFilesystem},
		Categories: []scanners.Category{scanners.CategorySBOM},
		// No NetworkKinds: syft catalogs what is on disk and resolves no remote
		// metadata, so it runs correctly with egress denied -- verified, not
		// assumed.
	}
}

// Version implements scanners.Scanner.
func (s *Scanner) Version(ctx context.Context) (string, error) {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        30 * time.Second,
		MaxOutputBytes: 4 << 10,
		Env:            env(),
	}, "syft", "version", "-o", "text")
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
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("syft: target path is required")
	}

	version, _ := s.Version(ctx)
	started := time.Now()

	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: s.MaxOutputBytes,
		// Run inside the checkout and catalog ".", so component locations are
		// repository-relative rather than rooted in the worker's workspace.
		Dir: target.Path,
		Env: env(),
	}, "syft", args()...)

	raw := scanners.RawResult{
		Scanner:   Name,
		Version:   version,
		Target:    target,
		ExitCode:  res.ExitCode,
		Duration:  time.Since(started),
		StartedAt: started,
	}
	if res.Truncated {
		// Findings past the cap were never seen, so this scanner's coverage
		// is an under-count and the scan cannot settle at COMPLETED.
		raw.Degrade(scanners.DegradedOutputTruncated)
	}

	if err != nil {
		return raw, err
	}

	if err := validateSBOM(res.Stdout); err != nil {
		return raw, err
	}
	// Fail closed if the worker's filesystem layout leaked into the artifact.
	if err := assertNoWorkspacePaths(res.Stdout, target.Path); err != nil {
		return scanners.RawResult{Scanner: Name, Version: version, Target: target}, err
	}

	raw.Output = res.Stdout
	return raw, nil
}

// args is the syft argument vector.
//
// It is a function so a test can assert the flags directly, rather than only by
// observing a subprocess.
func args() []string {
	return []string{
		// The scan root. Combined with Dir, this keeps locations relative.
		".",
		"-o", "cyclonedx-json",
		// Suppress the progress UI so stdout is the document and nothing else.
		"-q",
		// Drop the file cataloger. It records individual files as components
		// using their ABSOLUTE paths, which embeds the worker's ephemeral
		// workspace in the artifact: every scan of the same commit would
		// produce a different SBOM, and the worker's layout would be stored.
		//
		// It costs nothing: on this repository the file cataloger contributed
		// 13 file components and zero library components. Dependencies -- the
		// point of the SBOM -- come from the package catalogers.
		"--select-catalogers", "-file",
	}
}

// env is the complete environment for the syft subprocess: an allow-list, so
// it cannot inherit the worker's credentials (§14.7).
func env() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/nonexistent",
		// Syft checks for updates by default; that is an unnecessary egress
		// from a process handling untrusted content.
		"SYFT_CHECK_FOR_APP_UPDATE=false",
	}
}

// parseVersion extracts the version from `syft version -o text` output, which
// is a block of "Key: value" lines rather than a bare version string.
func parseVersion(out string) string {
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), "version") {
			return strings.TrimSpace(value)
		}
	}
	return strings.TrimSpace(out)
}
