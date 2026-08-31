package scanners

import "testing"

// Degrade must be idempotent: a retried scan that re-reports the same reason
// should not accumulate duplicates, which would turn a bounded column into an
// unbounded one.
func TestDegradeIsIdempotent(t *testing.T) {
	var r RawResult
	r.Degrade(DegradedOutputTruncated)
	r.Degrade(DegradedOutputTruncated)

	if len(r.Degradations) != 1 {
		t.Errorf("Degradations = %v, want exactly one entry", r.Degradations)
	}
	if !r.Degraded() {
		t.Error("Degraded() = false after recording a reason")
	}
}

// OutputTruncated answers a specific question for the raw-result archive. It
// must not fire for an unrelated reason, or every degraded scan would have its
// stored output wrongly flagged as clipped.
func TestOutputTruncatedIsSpecificToItsReason(t *testing.T) {
	var clean RawResult
	if clean.Degraded() || clean.OutputTruncated() {
		t.Error("a result with no reasons reported as degraded")
	}

	var other RawResult
	other.Degrade("some_other_reason")
	if !other.Degraded() {
		t.Error("Degraded() = false despite a recorded reason")
	}
	if other.OutputTruncated() {
		t.Error("OutputTruncated() = true for an unrelated reason")
	}

	var truncated RawResult
	truncated.Degrade("some_other_reason")
	truncated.Degrade(DegradedOutputTruncated)
	if !truncated.OutputTruncated() {
		t.Error("OutputTruncated() = false when the reason is present alongside another")
	}
}
