package grype

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// maxMatches bounds how many matches are accepted from one report.
//
// The report describes attacker-controlled content, so it is bounded like any
// other external input (§15.8). A repository crafted to produce millions of
// matches must not exhaust the worker.
const maxMatches = 200_000

// report is the subset of grype's JSON this adapter reads.
//
// Adapter-local by design: nothing outside this package may import it (§7 rule
// 3). Phase 4 adds the mapping into the canonical model; Phase 3 needs the
// parsed form only to enforce the invariants below.
type report struct {
	Matches    []match     `json:"matches"`
	Descriptor *descriptor `json:"descriptor"`
}

type match struct {
	Vulnerability vulnerability `json:"vulnerability"`
	Artifact      artifact      `json:"artifact"`
	// RelatedVulnerabilities carries the advisory's aliases. Grype reports a
	// GHSA id as the vulnerability, and the CVE it corresponds to appears
	// here -- which is the only way to associate an EPSS entry with the
	// finding, since EPSS is keyed by CVE.
	RelatedVulnerabilities []relatedVulnerability `json:"relatedVulnerabilities"`
}

type relatedVulnerability struct {
	ID string `json:"id"`
}

type vulnerability struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// EPSS is an array because one advisory can cover several CVEs, each with
	// its own score. Which entry applies is a decision, not a field read --
	// see epssFor in mapper.go.
	EPSS []epssEntry `json:"epss"`

	// Grype's own composite `risk` field is deliberately NOT modelled. Using
	// it would mean two different formulas producing two different numbers
	// both called risk, and §10 makes SecureOps' risk one deterministic
	// function with documented weights (ADR 018).
}

type epssEntry struct {
	CVE         string  `json:"cve"`
	Probability float64 `json:"epss"`
	Percentile  float64 `json:"percentile"`
	// Date is the EPSS model date. EPSS is recomputed daily, so a value
	// without it cannot be aged out or compared against a newer one.
	Date string `json:"date"`
}

type artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type descriptor struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	DB      *database `json:"db"`
}

type database struct {
	Status *dbStatus `json:"status"`
}

type dbStatus struct {
	// Built is when the vulnerability data was assembled. It is the only field
	// that says how much of the world this scan could possibly have seen.
	Built string `json:"built"`
	Valid *bool  `json:"valid"`
}

// validateReport checks that the output really is a grype report.
//
// A garbled or truncated report is more dangerous than an obviously broken one:
// stored as-is, it later reads as "this project has few vulnerabilities" rather
// than "this scan did not work". Failing closed keeps that distinction.
func validateReport(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		// Distinct from a report with no matches, which is the expected result
		// for a project with no known-vulnerable dependencies.
		return fmt.Errorf("%w: output was empty", ErrMalformedReport)
	}

	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		// The error text quotes the offending bytes, which came from scanning
		// untrusted content, so it is not wrapped into the returned message.
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	// Guards against a flag change or a substituted binary silently producing
	// another tool's format, which would be valid JSON and would otherwise be
	// stored as if grype had produced it.
	if r.Descriptor == nil || r.Descriptor.Name != Name {
		return fmt.Errorf("%w: report is not from grype", ErrMalformedReport)
	}
	if len(r.Matches) > maxMatches {
		return fmt.Errorf("%w: more than %d matches", ErrMalformedReport, maxMatches)
	}
	return nil
}

// dbBuiltAt reports when the vulnerability database was built.
//
// The boolean is false when the report does not say, which must not be read as
// "recent": a report that omits its own provenance has not proven anything
// about its coverage.
func dbBuiltAt(data []byte) (time.Time, bool) {
	st := parseDBStatus(data)
	if st == nil || st.Built == "" {
		return time.Time{}, false
	}
	built, err := time.Parse(time.RFC3339, st.Built)
	if err != nil {
		return time.Time{}, false
	}
	return built, true
}

// invalidDatabase reports whether grype itself declared its database invalid.
//
// Absence of the field is not treated as invalid: older report shapes omit it,
// and refusing those would fail closed on the wrong signal. Missing provenance
// is handled as a degradation by dbBuiltAt instead.
func invalidDatabase(data []byte) bool {
	st := parseDBStatus(data)
	return st != nil && st.Valid != nil && !*st.Valid
}

func parseDBStatus(data []byte) *dbStatus {
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil
	}
	if r.Descriptor == nil || r.Descriptor.DB == nil {
		return nil
	}
	return r.Descriptor.DB.Status
}

// matchCount reports how many matches the report holds. Used by tests to
// confirm the adapter's output is not merely well-formed but populated.
func matchCount(data []byte) (int, error) {
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return 0, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}
	return len(r.Matches), nil
}
