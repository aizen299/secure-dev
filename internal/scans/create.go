package scans

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// ErrInvalidScan reports that a scan request failed validation.
var ErrInvalidScan = errors.New("invalid scan request")

// ErrNotFound reports that no scan matched.
var ErrNotFound = errors.New("scan not found")

// MaxRequestedScanners bounds an explicit scanner selection, matching the
// scans_requested_scanners_bounded constraint in migration 0003.
const MaxRequestedScanners = 32

var (
	// commitSHAPattern mirrors the scans_commit_sha_format CHECK constraint in
	// migration 0001. The two must agree, or a value the API accepts becomes a
	// constraint violation instead of a validation error.
	commitSHAPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

	// branchPattern is deliberately narrower than git's own rules. A branch
	// name reaches a scanner as an argv element, so a leading "-" would be
	// read as a flag rather than as data (the same argument-injection defence
	// as scanners.Target).
	branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/\-]{0,254}$`)

	// scannerNamePattern bounds an adapter name. The API does not know which
	// adapters exist -- that knowledge belongs to the worker's registry, and
	// putting it here would leak scanner specifics into the core (§7) -- so it
	// validates the shape only and lets the worker reject unknown names.
	scannerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// NewScan is the validated input for creating a scan.
//
// Server-assigned values (id, status, timestamps) are absent by design: they
// are not a client's to set.
type NewScan struct {
	ProjectID    string
	RepositoryID *string
	Target       scanners.Target
	CommitSHA    string
	Branch       string
	// Scanners names an explicit adapter selection. Empty means "every
	// scanner that supports this target kind", resolved at execution time.
	Scanners []string
}

// Normalize validates the request and returns a canonical copy.
//
// The target itself is NOT validated here: that requires a scanners.Validator
// with the deployment's SSRF policy and workspace root, which is a caller
// concern. This checks everything else, so the two validations compose without
// this package needing network or filesystem access.
func (n NewScan) Normalize() (NewScan, error) {
	out := NewScan{
		ProjectID:    strings.TrimSpace(n.ProjectID),
		RepositoryID: n.RepositoryID,
		Target:       n.Target,
		CommitSHA:    strings.ToLower(strings.TrimSpace(n.CommitSHA)),
		Branch:       strings.TrimSpace(n.Branch),
	}

	if out.ProjectID == "" {
		return NewScan{}, fmt.Errorf("%w: project_id is required", ErrInvalidScan)
	}
	if !out.Target.Kind.Valid() {
		return NewScan{}, fmt.Errorf(
			"%w: target.kind must be one of repository, filesystem, image, endpoint", ErrInvalidScan)
	}

	if out.CommitSHA != "" && !commitSHAPattern.MatchString(out.CommitSHA) {
		return NewScan{}, fmt.Errorf(
			"%w: commit_sha must be 7 to 64 hexadecimal characters", ErrInvalidScan)
	}
	if out.Branch != "" {
		if !branchPattern.MatchString(out.Branch) {
			// The value is not echoed: it is attacker-controlled and ends up
			// in logs.
			return NewScan{}, fmt.Errorf("%w: branch contains characters that are not permitted", ErrInvalidScan)
		}
		if strings.Contains(out.Branch, "..") {
			return NewScan{}, fmt.Errorf("%w: branch must not contain '..'", ErrInvalidScan)
		}
	}

	if n.RepositoryID != nil {
		id := strings.TrimSpace(*n.RepositoryID)
		if id == "" {
			return NewScan{}, fmt.Errorf("%w: repository_id must not be blank when present", ErrInvalidScan)
		}
		out.RepositoryID = &id
	}

	selection, err := normalizeScannerNames(n.Scanners)
	if err != nil {
		return NewScan{}, err
	}
	out.Scanners = selection

	return out, nil
}

// normalizeScannerNames validates, deduplicates, and sorts a scanner selection.
//
// Sorting makes scan composition deterministic, which matters because the same
// request must produce the same stored selection every time.
func normalizeScannerNames(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if len(names) > MaxRequestedScanners {
		return nil, fmt.Errorf(
			"%w: at most %d scanners may be requested", ErrInvalidScan, MaxRequestedScanners)
	}

	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))

	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			return nil, fmt.Errorf("%w: scanner names must not be blank", ErrInvalidScan)
		}
		if !scannerNamePattern.MatchString(name) {
			return nil, fmt.Errorf(
				"%w: scanner names must be lowercase alphanumeric, hyphen, or underscore", ErrInvalidScan)
		}
		if _, dup := seen[name]; dup {
			// A duplicate is dropped rather than rejected: asking for the same
			// scanner twice is redundant, not malformed.
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	sort.Strings(out)
	return out, nil
}

// FailureReason explains why a scan reached a terminal state without usable
// results.
//
// It is a closed set of fixed strings on purpose. The alternative -- storing
// the underlying error -- would put repository content, and potentially a
// detected secret, into a field the API returns to clients (§15.3).
type FailureReason string

const (
	// FailureTargetInvalid means the target failed re-validation at the worker.
	FailureTargetInvalid FailureReason = "target failed validation"
	// FailureNoScannerAvailable means nothing is registered for this target
	// kind. Until Phase 3 registers adapters, this is the expected outcome of
	// every scan.
	FailureNoScannerAvailable FailureReason = "no registered scanner supports this target kind"
	// FailureScannerNotRegistered means an explicitly requested scanner does
	// not exist, or does not support the target kind.
	FailureScannerNotRegistered FailureReason = "a requested scanner is not registered for this target kind"
	// FailureWorkspaceUnavailable means the isolated workspace could not be
	// created, so there was nowhere safe to put untrusted content.
	FailureWorkspaceUnavailable FailureReason = "the worker could not create an isolated workspace"
	// FailureMaxAttemptsExceeded retires a job that keeps killing its handler.
	FailureMaxAttemptsExceeded FailureReason = "the job exceeded the maximum number of delivery attempts"
	// FailureAllScannersDegraded means every scanner failed or was skipped, so
	// the scan produced no usable coverage at all.
	FailureAllScannersDegraded FailureReason = "every scanner failed or was skipped"
	// FailureNotEnqueued means the scan was persisted but its job never
	// reached the queue, so no worker will ever pick it up. Without this the
	// scan would sit in QUEUED forever, looking merely slow.
	FailureNotEnqueued FailureReason = "the scan job could not be enqueued"
)
