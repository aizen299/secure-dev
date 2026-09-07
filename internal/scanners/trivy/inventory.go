package trivy

import (
	"context"
	"fmt"
	"time"

	"github.com/aizen299/secure-dev/internal/sbom"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Inventory implements sbom.Inventorier for image targets.
//
// Syft, the adapter that produces SBOMs, is filesystem-only: it catalogues a
// checkout and never touches an image. So without this there is no inventory of
// what a built artifact actually contains, and the deployment evidence ADR 037
// describes can never be anything but `unknown`. Discovered by wiring 10b end
// to end and finding it inert.
//
// It parses whatever CycloneDX document it is handed. Whether that document
// exists is decided by ScanInventory below, which is the half that runs trivy a
// second time.
func (s *Scanner) Inventory(raw []byte) (sbom.Result, error) {
	return sbom.Parse(raw)
}

// ScanInventory produces a CycloneDX bill of materials for an image.
//
// A SECOND trivy invocation rather than a different format for the first.
// `--format cyclonedx` returns an SBOM with vulnerabilities embedded, which
// would mean rewriting the finding parser to read a format it was not built for
// -- a change to how every image finding is produced, in service of a feature
// that produces none. Two invocations keep the finding path exactly as it was
// (ADR 025) and pay for it in time, which an image scan already spends pulling.
//
// Filesystem targets get nothing here: syft already inventories a checkout, and
// two inventories of one thing would disagree the moment their cataloguers did.
func (s *Scanner) ScanInventory(ctx context.Context, target scanners.Target) (scanners.RawResult, error) {
	if target.Kind != scanners.KindImage {
		return scanners.RawResult{Scanner: Name}, scanners.ErrUnsupportedTarget
	}
	if target.Image == "" {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("trivy: target image is required")
	}
	// Re-checked here as everywhere else a value reaches a subprocess: this is
	// its own entry point, and a reference that arrived by another route has
	// still never been checked on this path.
	if !imageRefIsSafe(target.Image) {
		return scanners.RawResult{Scanner: Name}, fmt.Errorf("trivy: image reference is not acceptable")
	}

	started := time.Now()
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: s.MaxOutputBytes,
		Env:            s.env(),
	}, "trivy", s.inventoryArgs(target.Image)...)

	raw := scanners.RawResult{
		Scanner:   Name,
		Target:    target,
		ExitCode:  res.ExitCode,
		Duration:  time.Since(started),
		StartedAt: started,
		Output:    res.Stdout,
	}
	if err != nil {
		return raw, fmt.Errorf("trivy: inventorying %s: %w", target.Image, err)
	}
	if res.Truncated {
		raw.Degradations = append(raw.Degradations, scanners.DegradedOutputTruncated)
	}
	return raw, nil
}

// inventoryArgs asks for the bill of materials and nothing else.
//
// Every security-relevant flag from imageArgs is repeated rather than shared,
// and that duplication is deliberate: this is a separate subprocess reaching a
// registry, and a flag that mattered there matters identically here. Factoring
// them into a common slice would make it possible to add one to a single path
// and believe both were covered.
func (s *Scanner) inventoryArgs(image string) []string {
	return []string{
		"--cache-dir", s.cacheDir(),
		"image",
		// The bill of materials. No `--scanners`: an SBOM is an inventory and
		// asking for vulnerabilities here would duplicate the findings the
		// first invocation already produced.
		"--format", "cyclonedx",
		// Both OS and language packages, matching the finding pass. An
		// inventory narrower than the findings it is compared against would
		// report a package as absent that the same scan reported as present.
		"--pkg-types", "os,library",
		// THE security-critical flag, repeated. Trivy otherwise tries docker,
		// then containerd, then podman, before the registry -- a worker with a
		// socket mounted would let a scan read images it was never pointed at.
		"--image-src", "remote",
		// §14's max artifact size, applied to this pull as to the other.
		"--max-image-size", s.maxImageSize(),
		"--offline-scan",
		"--skip-db-update",
		"--skip-version-check",
		"--quiet",
		"--exit-code", "0",
		image,
	}
}
