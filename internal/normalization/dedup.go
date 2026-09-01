package normalization

import "sort"

// Relationship describes how two findings relate (§8).
//
// Only the first of these merges anything. The rest are links, because §8 is
// explicit that findings must not be merged for looking similar, and §25.5
// forbids deduplicating by title or fuzzy comparison entirely.
type Relationship string

const (
	// RelationExactDuplicate means identical fingerprints: one problem,
	// reported more than once. These merge.
	RelationExactDuplicate Relationship = "exact_duplicate"
	// RelationLikelyDuplicate means the same category, location, and package
	// but a different rule. Probably one problem seen by two rules -- and
	// "probably" is why it is a link with a confidence rather than a merge.
	RelationLikelyDuplicate Relationship = "likely_duplicate"
	// RelationRelated means the findings share a component, vulnerability, or
	// file without being the same problem. This is the raw material for
	// correlation (§9).
	RelationRelated Relationship = "related"
)

// Link records why two findings are believed to be connected.
//
// Every link carries its evidence. §9 requires correlation to be explainable,
// and a relationship with no stated reason is an assertion rather than a
// finding about the code.
type Link struct {
	From         string // fingerprint
	To           string // fingerprint
	Relationship Relationship
	Confidence   Confidence
	// Evidence names what the two findings share, in a form a person can read.
	Evidence string
}

// DedupResult is the outcome of deduplicating one scan's findings.
type DedupResult struct {
	// Findings are unique by fingerprint. Where several inputs shared an
	// identity they are merged into one, with Sources naming every scanner
	// that reported it.
	Findings []MergedFinding
	// Links are the non-merging relationships, kept for correlation.
	Links []Link
}

// MergedFinding is a finding plus the scanners that reported it.
type MergedFinding struct {
	Finding
	// Sources are the scanner names that produced this identity, sorted. More
	// than one means independent agreement, which Phase 6 treats as raising
	// confidence rather than as noise.
	Sources []string
}

// Deduplicate collapses exact duplicates and links everything else.
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
	out.Links = linkRelated(out.Findings)
	return out
}

// linkRelated finds non-identical relationships between distinct findings.
//
// Deliberately conservative. Everything here is a claim about two findings
// being connected, and a wrong claim is worse than a missing one: it sends
// somebody to investigate a relationship that does not exist.
func linkRelated(findings []MergedFinding) []Link {
	var links []Link

	for i := range findings {
		for j := i + 1; j < len(findings); j++ {
			a, b := findings[i], findings[j]

			switch {
			// Same place, same component, different rule. Two rules firing on
			// one thing is usually one problem -- but only usually, which is
			// why this links rather than merges.
			case a.Category == b.Category &&
				a.PURL != "" && a.PURL == b.PURL &&
				a.CVE == "" && b.CVE == "":
				links = append(links, Link{
					From: a.Fingerprint, To: b.Fingerprint,
					Relationship: RelationLikelyDuplicate,
					Confidence:   ConfidenceMedium,
					Evidence:     "same component " + a.PURL + " and category " + string(a.Category),
				})

			// The same vulnerability in two places, or two vulnerabilities in
			// one component. Related, not duplicate: both are real and both
			// need action.
			case a.CVE != "" && a.CVE == b.CVE:
				links = append(links, Link{
					From: a.Fingerprint, To: b.Fingerprint,
					Relationship: RelationRelated,
					Confidence:   ConfidenceHigh,
					Evidence:     "same vulnerability " + a.CVE,
				})
			case a.PURL != "" && a.PURL == b.PURL:
				links = append(links, Link{
					From: a.Fingerprint, To: b.Fingerprint,
					Relationship: RelationRelated,
					Confidence:   ConfidenceMedium,
					Evidence:     "same component " + a.PURL,
				})
			}
		}
	}
	return links
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
