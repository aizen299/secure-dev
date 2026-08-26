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
	// Truncated reports that Output hit the configured size cap. A truncated
	// result must never be normalized as if it were complete.
	Truncated bool      `json:"truncated"`
	StartedAt time.Time `json:"started_at"`
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
