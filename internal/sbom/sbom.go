// Package sbom turns a CycloneDX document into components SecureOps can query.
//
// It lives here rather than inside the syft adapter because CycloneDX is a
// format, not a scanner: trivy emits it too, and a parser behind the adapter
// boundary would have to be duplicated or reached across it (CLAUDE.md §7
// rule 3). What stays in the adapter is the decision to ask syft for CycloneDX.
//
// Parsing is pure: bytes in, components out, no I/O and no network. That is
// what makes it testable against captured output, including the malformed,
// truncated and hostile fixtures Phase 3b already wrote (§19).
//
// A component is not a finding, and this package exists because of that
// distinction. An SBOM is an inventory and nothing in it is wrong; forcing
// components into the canonical Finding model would mean every consumer
// filtering them back out, and would turn a project's finding count into its
// dependency count. See docs/adr/035-sbom-component-storage.md.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// ErrMalformed reports output that is not a usable CycloneDX document.
//
// Failing closed matters more here than it looks. A truncated SBOM stored as-is
// later reads as "this project has few dependencies" rather than "this scan did
// not work" -- the same failure the stale-vulnerability-database guard exists to
// prevent (ADR 012).
var ErrMalformed = errors.New("malformed sbom")

// MaxComponents bounds what one scan contributes.
//
// An image SBOM can carry thousands of components, and every value in one is
// derived from a manifest inside untrusted content (§15.8). Ten thousand is far
// above a normal repository -- the scan that motivated this ADR produced 52 --
// and below what a large image can reach, so the cap is a real bound rather
// than a number that never fires.
const MaxComponents = 10_000

// Field bounds, matching the database's CHECK constraints.
//
// Enforced here as well as there so an over-long value is a truncation with a
// recorded reason rather than a failed INSERT that takes a whole scan's
// inventory with it.
const (
	MaxNameLength     = 512
	MaxPURLLength     = 1024
	MaxVersionLength  = 256
	MaxTypeLength     = 64
	MaxCPELength      = 1024
	MaxLocationLength = 1024
)

// Component is one entry in a project's bill of materials.
//
// Deliberately not a Finding. It carries no severity, no status and no
// lifecycle, because it describes something present rather than something
// wrong.
type Component struct {
	// PURL is the identity that matters: Grype and Trivy emit purls byte for
	// byte, which is what lets a dependency finding and a container finding
	// meet on one key (ADR 025).
	//
	// Empty when the document carried none. Such a component is still stored --
	// something syft could not name is still evidence of something present, and
	// dropping it would make the inventory quietly incomplete.
	PURL string `json:"purl,omitempty"`

	Name    string `json:"name"`
	Version string `json:"version,omitempty"`

	// Type is CycloneDX's own vocabulary: library, application, file,
	// operating-system. Passed through rather than mapped onto an enum of ours
	// -- a value we have not seen must not fail a scan.
	Type string `json:"type,omitempty"`

	// CPE is kept because some advisory sources key on it where no purl exists.
	CPE string `json:"cpe,omitempty"`

	// Location is where the component was found, relative to the scan root:
	// `/requirements.txt`, `/go.mod`. It answers "which manifest declared
	// this", which is the first question anybody asks about an unexpected
	// dependency.
	Location string `json:"location,omitempty"`
}

// Result is one document's worth of components.
type Result struct {
	Components []Component
	// Degradations explains anything the caller must not read past. Empty on a
	// complete parse.
	//
	// The scanners vocabulary rather than a parallel one of this package's own:
	// a degradation is how a partial result reaches the gate, and two
	// vocabularies would mean the gate understanding one of them (ADR 010).
	Degradations []scanners.Degradation
}

// document is the subset of CycloneDX this package reads.
//
// A subset on purpose: a format's full schema is a large surface to accept from
// untrusted output, and everything omitted here is something no consumer asks
// for yet.
type document struct {
	BOMFormat  string         `json:"bomFormat"`
	Components []rawComponent `json:"components"`
}

type rawComponent struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	PURL       string     `json:"purl"`
	CPE        string     `json:"cpe"`
	Properties []property `json:"properties"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// locationProperty is syft's key for where it found a component.
//
// Indexed -- `syft:location:0:path`, `syft:location:1:path` -- because one
// component can be declared in several places. The first is taken: a component
// declared twice is one component, and the alternative is a row per location,
// which multiplies the table for a detail nothing queries.
const locationPrefix = "syft:location:"
const locationSuffix = ":path"

// Parse turns a CycloneDX document into components.
//
// Order is preserved from the document. Nothing is sorted here: the caller may
// want it, and a parser that reorders makes its own output harder to compare
// against the bytes it came from.
func Parse(data []byte) (Result, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		// Distinct from a document with no components, which is a legitimate
		// result for a repository with no recognised manifests.
		return Result{}, fmt.Errorf("%w: output was empty", ErrMalformed)
	}

	var doc document
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	// The format marker, checked rather than assumed. Syft can emit SPDX and
	// its own JSON, and both parse as valid JSON while carrying nothing this
	// package understands -- so without this check a wrong-format document
	// would come back as an empty inventory rather than an error.
	if doc.BOMFormat != "CycloneDX" {
		return Result{}, fmt.Errorf("%w: bomFormat is %q, want CycloneDX", ErrMalformed, doc.BOMFormat)
	}

	var result Result
	raw := doc.Components
	if len(raw) > MaxComponents {
		raw = raw[:MaxComponents]
		result.Degradations = append(result.Degradations, scanners.DegradedSBOMTruncated)
	}

	result.Components = make([]Component, 0, len(raw))
	for _, rc := range raw {
		name := strings.TrimSpace(rc.Name)
		if name == "" {
			// A component with no name cannot be reported, queried or matched.
			// Skipped rather than stored blank, and skipped silently rather
			// than failing the scan: one unnamed entry does not make the other
			// nine hundred untrustworthy.
			continue
		}
		result.Components = append(result.Components, Component{
			PURL:     clamp(rc.PURL, MaxPURLLength),
			Name:     clamp(name, MaxNameLength),
			Version:  clamp(strings.TrimSpace(rc.Version), MaxVersionLength),
			Type:     clamp(strings.TrimSpace(rc.Type), MaxTypeLength),
			CPE:      clamp(strings.TrimSpace(rc.CPE), MaxCPELength),
			Location: clamp(locationOf(rc.Properties), MaxLocationLength),
		})
	}
	return result, nil
}

// locationOf reads the first location property syft attached.
func locationOf(props []property) string {
	for _, p := range props {
		if strings.HasPrefix(p.Name, locationPrefix) && strings.HasSuffix(p.Name, locationSuffix) {
			return strings.TrimSpace(p.Value)
		}
	}
	return ""
}

// clamp bounds a value the database also bounds.
//
// Truncating rather than rejecting: an over-long package name is a strange
// manifest, not a reason to lose an inventory. The database's CHECK constraints
// are the backstop, and this keeps them from ever firing on real output.
func clamp(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// Inventorier is implemented by adapters whose output is a bill of materials.
//
// An optional interface, mirroring normalization.Normalizer exactly and for the
// same reason: most adapters produce findings and have no inventory, so
// requiring this of every Scanner would force a meaningless implementation on
// them. The worker asks whether an adapter has an inventory and skips those
// that do not -- which is how a scanner-specific capability reaches the
// pipeline without any core code branching on a scanner's name (§7 rule 2).
type Inventorier interface {
	// Inventory converts one raw scanner result into components. It must be
	// pure: same bytes, same components, no I/O.
	Inventory(raw []byte) (Result, error)
}
