// Package scanjob is the contract between a scan running in its own Job and
// the controller that asked for it (ADR 039).
//
// The shape of this package follows from one property: the Job holds no
// database credential, no queue credential and no Kubernetes token. Everything
// it learns, it is told; everything it produces, it reports here. A compromised
// scanner therefore gains a channel to one scan's results and nothing else.
package scanjob

import (
	"time"

	"github.com/aizen299/secure-dev/internal/scans"
)

// Wire field names. Multipart rather than JSON, and that is a size decision
// rather than a style one: a scanner's output runs to 64 MB
// (SECUREOPS_SCANNER_MAX_OUTPUT_BYTES), base64 inside JSON would add a third to
// that, and both ends would have to hold the whole thing in memory to encode
// it. Multipart streams and can be bounded before anything is read.
const (
	// FieldMeta carries a JSON Report.
	FieldMeta = "meta"
	// FieldOutput carries the scanner's verbatim bytes.
	FieldOutput = "output"
	// FieldInventory carries a bill of materials produced by a separate run,
	// for the adapters that have one (ADR 037). Absent otherwise.
	FieldInventory = "inventory"
)

// Paths on the controller. Both are scoped to one scan id, and the token the
// Job carries is accepted for that id alone.
const (
	PathCheckout = "/scanjob/checkout"
	PathResult   = "/scanjob/result"
)

// HeaderScanID identifies which scan is reporting.
//
// Sent explicitly rather than derived from the token, so that a mismatch
// between the two is detectable. A token that silently determined its own scope
// would make "this token was replayed against another scan" unanswerable.
const HeaderScanID = "X-SecureOps-Scan"

// Report is the metadata half of a result submission.
//
// It carries scans.ScannerResult verbatim rather than a parallel wire struct.
// A second shape would be a second place for the vocabulary of degradations and
// statuses to drift, and this one is already the type the database stores.
type Report struct {
	Result scans.ScannerResult `json:"result"`
}

// Checkout reports the revision a fetch actually landed on.
//
// Its own message rather than a field on the first result, because a scan can
// fetch successfully and then have every scanner fail, and the revision is
// still worth recording: "we scanned this commit and found nothing" and "we
// never got the code" are different claims.
type Checkout struct {
	CommitSHA string `json:"commit_sha"`
	Branch    string `json:"branch"`
}

// Limits bound what the controller will accept from a Job.
//
// The Job is the least trusted thing that will ever talk to the controller, so
// these are applied before a body is read rather than after (§15.8).
type Limits struct {
	// MaxOutputBytes caps one scanner's verbatim output.
	MaxOutputBytes int64
	// MaxMetaBytes caps the JSON part. Small: a Report is a few hundred bytes,
	// and anything larger is either a bug or an attempt to exhaust memory
	// through a field that has no reason to grow.
	MaxMetaBytes int64
	// Timeout bounds one submission.
	Timeout time.Duration
}

// DefaultLimits are sized from the scanner output cap they have to carry.
func DefaultLimits(maxOutput int64) Limits {
	if maxOutput <= 0 {
		maxOutput = 64 << 20
	}
	return Limits{
		MaxOutputBytes: maxOutput,
		MaxMetaBytes:   64 << 10,
		Timeout:        5 * time.Minute,
	}
}
