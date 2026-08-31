package scanners

import (
	"context"
	"errors"
	"time"
)

// Category is the security domain an adapter reports on. It is metadata about
// the adapter, not a switch: core code must never branch on it to change
// behaviour, only to describe or group results.
type Category string

const (
	CategorySAST       Category = "sast"
	CategorySecrets    Category = "secrets"
	CategorySBOM       Category = "sbom"
	CategoryDependency Category = "dependency"
	CategoryContainer  Category = "container"
	CategoryIaC        Category = "iac"
	CategoryDAST       Category = "dast"
	CategoryLicense    Category = "license"
)

// Capabilities describe what an adapter can do, so the platform can select
// scanners declaratively.
//
// This is the mechanism that makes CLAUDE.md §7 rule 2 enforceable: the core
// asks "which scanners support this target kind?", never "is this trivy?".
// Adding a scanner therefore requires no change to selection logic.
type Capabilities struct {
	// Kinds lists the target kinds the adapter accepts.
	Kinds []Kind
	// Category is the security domain the adapter covers.
	Category Category
	// RequiresNetwork indicates the adapter needs egress (for example to
	// refresh a vulnerability database). Workers use this to decide whether a
	// job may run under a deny-all network policy (§14.3).
	RequiresNetwork bool
}

// Supports reports whether the adapter accepts targets of kind k.
func (c Capabilities) Supports(k Kind) bool {
	for _, kind := range c.Kinds {
		if kind == k {
			return true
		}
	}
	return false
}

// Degradation names a reason a scanner ran but its coverage cannot be fully
// trusted.
//
// This is deliberately a reason rather than a status. A security gate has to
// explain the exact conditions behind its verdict (CLAUDE.md §12), and
// "degraded" on its own is not something an operator can act on. See ADR 010.
//
// The vocabulary lives here, in the adapter contract, so a new adapter can name
// a new reason without touching the core or the schema (§7 rule 4). Add a
// reason only together with the code that emits it.
type Degradation string

const (
	// DegradedOutputTruncated means output hit the configured size cap, so
	// findings past that point were never seen.
	DegradedOutputTruncated Degradation = "output_truncated"
)

// RawResult is a scanner's unmodified output plus the metadata needed to
// interpret it later.
//
// The bytes are stored verbatim (size-capped) so results can be re-parsed when
// normalization improves, and so a disputed finding can be traced to what the
// scanner actually said (CLAUDE.md §8). Nothing outside the producing adapter
// may interpret Output.
type RawResult struct {
	Scanner  string        `json:"scanner"`
	Version  string        `json:"version"`
	Target   Target        `json:"target"`
	Output   []byte        `json:"-"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
	// Degradations are the reasons this scanner's coverage cannot be fully
	// trusted, even though it ran. A non-empty set stops the scan from being
	// reported as COMPLETED; see ADR 010.
	Degradations []Degradation `json:"degradations,omitempty"`
	StartedAt    time.Time     `json:"started_at"`
}

// Degrade records a reason this result's coverage is incomplete, ignoring a
// reason already present so a retry cannot accumulate duplicates.
func (r *RawResult) Degrade(d Degradation) {
	for _, existing := range r.Degradations {
		if existing == d {
			return
		}
	}
	r.Degradations = append(r.Degradations, d)
}

// Degraded reports whether any reason was recorded.
func (r RawResult) Degraded() bool { return len(r.Degradations) > 0 }

// OutputTruncated reports whether Output is short of what the scanner actually
// produced.
//
// Asked by the raw-result archive, which needs to flag stored bytes that are
// not the whole output. It is a method rather than a comparison at the call
// site so that core code never has to inspect a reason's value -- it asks the
// contract a question and the contract answers.
func (r RawResult) OutputTruncated() bool {
	for _, d := range r.Degradations {
		if d == DegradedOutputTruncated {
			return true
		}
	}
	return false
}

// Scanner is the contract every security tool adapter implements.
//
// The interface is intentionally tiny. Everything scanner-specific -- argument
// construction, output format, severity vocabulary -- lives behind it.
type Scanner interface {
	// Name is the adapter's stable identifier, used for registration,
	// persistence, and reporting.
	Name() string

	// Capabilities declares what this adapter supports.
	Capabilities() Capabilities

	// Version reports the underlying tool's version. Results are only
	// reproducible relative to it, so it is captured per scan (§7 rule 6).
	Version(ctx context.Context) (string, error)

	// Scan executes the tool and returns its raw output.
	//
	// Implementations must honour ctx for cancellation and timeout, must never
	// build a shell command string, and must not write outside the workspace
	// they are given.
	Scan(ctx context.Context, target Target) (RawResult, error)
}

// ErrUnsupportedTarget reports that an adapter was handed a target kind it does
// not support. Selection should prevent this; adapters return it defensively.
var ErrUnsupportedTarget = errors.New("scanner does not support this target kind")
