package normalization

import "sort"

// DedupResult is the outcome of normalizing one whole scan.
type DedupResult struct {
	// Findings are unique by fingerprint. Where several inputs shared an
	// identity they are merged into one, with Sources naming every scanner
	// that reported it.
	Findings []MergedFinding
	// Occurrences are every sighting, carried through unmerged: merging
	// findings must not lose the places they were seen, which is the whole
	// reason location lives on the occurrence.
	Occurrences []Occurrence
	// Errors are the per-entry parse failures every mapper reported, already
	// safe to store.
	Errors []string
}

// Combine normalizes a whole scan: every scanner's result in, one deduplicated
// set of findings out.
//
// This is the entry point the worker uses. Deduplicate is exported alongside it
// because the merge semantics are worth testing on their own, but a caller
// holding several scanners' results wants this.
func Combine(results []Result) DedupResult {
	var (
		all         []Finding
		occurrences []Occurrence
		errs        []string
	)
	for _, r := range results {
		all = append(all, r.Findings...)
		occurrences = append(occurrences, r.Occurrences...)
		errs = append(errs, r.Errors...)
	}

	out := Deduplicate(all)
	out.Occurrences = occurrences
	out.Errors = errs
	return out
}

// MergedFinding is a finding plus the scanners that reported it.
type MergedFinding struct {
	Finding
	// Sources are the scanner names that produced this identity, sorted. More
	// than one means independent agreement, which Phase 6 treats as raising
	// confidence rather than as noise.
	Sources []string
}

// Deduplicate collapses exact duplicates, and does nothing else.
//
// Only identical fingerprints merge. Everything weaker than identity -- the
// same CVE, the same component, the same file -- is a *relationship* rather
// than a merge, and relationships are internal/correlation's job (ADR 017).
// This function used to emit them too, which put claims about how findings
// from different scanners relate inside a package documented as a pure
// bytes-to-findings transformation.
//
// The input is one scan's findings across every scanner. Order of input does
// not affect the output: findings are keyed by fingerprint and sources are
// sorted, so re-running over the same scan produces the same result.
func Deduplicate(findings []Finding) DedupResult {
	byFingerprint := map[string]*MergedFinding{}
	var order []string

	for _, f := range findings {
		existing, seen := byFingerprint[f.Fingerprint]
		if !seen {
			merged := &MergedFinding{Finding: f, Sources: []string{f.Scanner}}
			byFingerprint[f.Fingerprint] = merged
			order = append(order, f.Fingerprint)
			continue
		}

		// An exact duplicate. The finding itself is not overwritten -- the
		// first report wins for prose -- but the reporting scanner is recorded,
		// and the higher severity is kept: if two scanners disagree about how
		// bad something is, under-reporting is the dangerous direction.
		if !containsString(existing.Sources, f.Scanner) {
			existing.Sources = append(existing.Sources, f.Scanner)
		}
		if f.Severity.Rank() > existing.Severity.Rank() {
			existing.Severity = f.Severity
		}
	}

	out := DedupResult{Findings: make([]MergedFinding, 0, len(order))}
	for _, fpr := range order {
		m := byFingerprint[fpr]
		sort.Strings(m.Sources)
		out.Findings = append(out.Findings, *m)
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
