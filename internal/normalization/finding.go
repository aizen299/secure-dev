// Package normalization converts scanner output into the canonical Finding.
//
// This is where SecureOps stops running tools and starts having an opinion:
// five scanners with five vocabularies, five severity scales, and five ideas of
// what a location is, reduced to one model that the rest of the platform can
// reason about.
//
// The package is pure. Given the same bytes it produces the same findings, with
// no I/O, no network, no clock, and no database. That is what makes it testable
// against fixtures, and fixtures are the only way to test the hostile output
// that §15.7 puts in the threat model.
//
// See docs/architecture/normalization.md and docs/architecture/fingerprinting.md.
package normalization

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// ErrInvalidFinding reports a finding that cannot be trusted into the model.
//
// Returned rather than tolerated: a finding with a missing required field is an
// error, not a finding with an empty field. "We could not read this" and "there
// was nothing here" must never collapse into each other -- the same distinction
// PARTIAL exists to preserve for whole scans (§13).
var ErrInvalidFinding = errors.New("invalid finding")

// Status is a finding's lifecycle state (§17).
type Status string

const (
	StatusOpen          Status = "open"
	StatusAcknowledged  Status = "acknowledged"
	StatusInProgress    Status = "in_progress"
	StatusResolved      Status = "resolved"
	StatusReopened      Status = "reopened"
	StatusFalsePositive Status = "false_positive"
	StatusIgnored       Status = "ignored"
)

// Valid reports whether s is a known lifecycle state.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusAcknowledged, StatusInProgress,
		StatusResolved, StatusReopened, StatusFalsePositive, StatusIgnored:
		return true
	default:
		return false
	}
}

// Finding is the canonical model every scanner's output converges on (§8).
//
// Fields fall into groups with different lifetimes. Identity never changes.
// Classification and description change when a scanner is upgraded. Location
// belongs to an Occurrence rather than here, because a finding that moves down
// a file is the same finding.
type Finding struct {
	// --- identity ---------------------------------------------------------
	// Fingerprint is the stable identity across scans. See fingerprint.go.
	Fingerprint string
	ProjectID   string

	// --- source -----------------------------------------------------------
	// Scanner is recorded and queryable but deliberately NOT part of identity,
	// so two scanners reporting one problem can be seen to agree (§9).
	Scanner string
	// ScannerFindingID is the scanner's own identifier for this finding, kept
	// for traceability back to the raw result.
	ScannerFindingID string
	// ScannerSeverity is the original severity string, verbatim. Kept so a
	// future disagreement about a mapping is a question about the mapping
	// rather than a lost fact (§8).
	ScannerSeverity string

	// --- classification ---------------------------------------------------
	Category   scanners.Category
	Severity   Severity
	Confidence Confidence

	// --- description ------------------------------------------------------
	// Prose. Never used for identity, and never used for deduplication
	// (§25.5).
	Title       string
	Description string
	Remediation string

	// --- component --------------------------------------------------------
	Package        string
	PackageVersion string
	PURL           string

	// --- vulnerability ----------------------------------------------------
	CVE  string
	CWE  string
	CVSS float64

	// --- lifecycle --------------------------------------------------------
	Status Status
}

// Occurrence is one sighting of a finding, in one scan, at one place.
//
// Separate from Finding because location is the thing that moves. A secret on
// line 12 that becomes a secret on line 40 after an edit above it is the same
// secret, and the fingerprint is built to say so; the line lives here.
type Occurrence struct {
	Fingerprint string
	ScanID      string
	File        string
	StartLine   int
	EndLine     int
	// Scanner is recorded per occurrence too: when two scanners report one
	// finding, each sighting keeps its source.
	Scanner string
	SeenAt  time.Time
}

// Result is what normalizing one raw scanner result produces.
//
// Findings and Errors are both returned, deliberately. A scanner result with
// one unparseable entry among fifty should yield forty-nine findings and one
// recorded error, not zero findings and not a silent forty-nine: the operator
// needs both halves to know what they are looking at.
type Result struct {
	Findings    []Finding
	Occurrences []Occurrence
	// Errors are per-entry parse failures, already made safe to store: they
	// name the field at fault and never quote the value, which came from
	// untrusted content and may be a credential.
	Errors []string
}

// Validate checks a finding is complete enough to store.
//
// Enum fields reject unknown values rather than passing them through, so a
// scanner that invents a severity fails loudly instead of writing something
// nothing downstream understands.
func (f Finding) Validate() error {
	if strings.TrimSpace(f.Fingerprint) == "" {
		return fmt.Errorf("%w: fingerprint is required", ErrInvalidFinding)
	}
	if strings.TrimSpace(f.Scanner) == "" {
		return fmt.Errorf("%w: scanner is required", ErrInvalidFinding)
	}
	if strings.TrimSpace(f.Title) == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidFinding)
	}
	if !validCategory(f.Category) {
		return fmt.Errorf("%w: unknown category %q", ErrInvalidFinding, f.Category)
	}
	if !f.Severity.Valid() {
		return fmt.Errorf("%w: unknown severity %q", ErrInvalidFinding, f.Severity)
	}
	if !f.Confidence.Valid() {
		return fmt.Errorf("%w: unknown confidence %q", ErrInvalidFinding, f.Confidence)
	}
	if f.Status != "" && !f.Status.Valid() {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidFinding, f.Status)
	}
	if f.CVSS < 0 || f.CVSS > 10 {
		return fmt.Errorf("%w: cvss %v is outside 0-10", ErrInvalidFinding, f.CVSS)
	}
	return nil
}

// validCategory reports whether c is one a finding may carry.
//
// CategorySBOM is absent on purpose: an SBOM is an inventory and nothing in it
// is wrong, so syft produces components rather than findings. Forcing them into
// this model would mean every consumer filtering them back out.
func validCategory(c scanners.Category) bool {
	switch c {
	case scanners.CategorySAST, scanners.CategorySecrets, scanners.CategoryDependency,
		scanners.CategoryContainer, scanners.CategoryIaC, scanners.CategoryDAST,
		scanners.CategoryLicense:
		return true
	default:
		return false
	}
}

// Normalizer is implemented by adapters that turn their own raw output into
// canonical findings.
//
// An optional interface rather than a method on scanners.Scanner: syft produces
// an SBOM and no findings, so requiring every adapter to implement this would
// force a meaningless implementation on it. The worker asks whether an adapter
// normalizes and skips those that do not.
//
// It lives here rather than in the scanners package because normalization
// already imports scanners for Category, and the reverse would be a cycle.
type Normalizer interface {
	// Normalize converts one raw scanner result into canonical findings. It
	// must be pure: same bytes, same findings, no I/O.
	Normalize(raw []byte, scanID string) (Result, error)
}
