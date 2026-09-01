// Package correlation decides when several findings describe one underlying
// problem.
//
// Normalization makes five scanners speak one language. This is where SecureOps
// starts saying things no individual scanner said: that a vulnerable dependency
// and a code path that misuses it are one issue rather than two, and that the
// combination is worse than either part.
//
// The package is pure. Given the same findings it produces the same issues,
// with no I/O, no network, no clock, and no database — the same contract
// normalization holds, for the same reason: it is the only way to test the
// rules against fixtures instead of against a live scanner. Persistence lives
// in internal/findings.
//
// It never sees raw scanner output (§9) and never branches on a scanner's name
// (§7): every rule below is expressed over categories and canonical fields.
//
// See docs/architecture/correlation.md for the rule set and
// docs/adr/017-correlation-issues-and-severity.md for why it is shaped this way.
package correlation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
)

// DefaultMaxBucketSize caps how many findings may share one correlation key.
//
// Comparison within a bucket is pairwise, so an uncapped bucket in a monorepo
// is a hang in the scan-completion path. Reaching the cap is reported rather
// than silently absorbed, following ADR 010: a limit being hit is a structured,
// visible outcome.
const DefaultMaxBucketSize = 500

// Options tunes the engine. The zero value is the documented default.
type Options struct {
	// MaxBucketSize overrides DefaultMaxBucketSize when positive.
	MaxBucketSize int
}

// Subject is a finding as correlation sees it: the canonical finding plus the
// files it has been seen in.
//
// Files come from occurrences rather than the finding itself, because location
// is deliberately not part of identity (see fingerprinting.md). Assembling them
// is the caller's job, which is what keeps this package free of a database.
type Subject struct {
	normalization.Finding
	// Files are the distinct paths this finding has been seen at.
	Files []string
}

// Result is one project's correlation, recomputed from its live findings.
type Result struct {
	// Issues are sets of findings that share one attribute, sorted by key.
	Issues []Issue
	// Links are the pairwise relationships, deduplicated so a pair related by
	// several keys appears once with its strongest evidence.
	Links []Link
	// Truncated names the keys whose buckets exceeded the cap. Never empty in
	// silence: a truncated bucket means correlation is incomplete, and the
	// caller has to be able to say so.
	Truncated []string
}

// Correlate runs the engine with default options.
func Correlate(subjects []Subject) Result {
	return CorrelateWith(subjects, Options{})
}

// CorrelateWith runs the engine.
//
// Determinism is structural rather than incidental: subjects are sorted by
// fingerprint first, keys are iterated in sorted order, and truncation picks by
// fingerprint order. Input order cannot reach the output.
func CorrelateWith(subjects []Subject, opts Options) Result {
	limit := opts.MaxBucketSize
	if limit <= 0 {
		limit = DefaultMaxBucketSize
	}

	subjects = sortedByFingerprint(subjects)
	buckets, keys := bucketize(subjects)

	var (
		result Result
		links  = newLinkSet()
	)

	for _, key := range keys {
		members := buckets[key]
		if len(members) > limit {
			// Already in fingerprint order, so the same findings survive the
			// cap every time rather than an arbitrary subset.
			members = members[:limit]
			result.Truncated = append(result.Truncated, key.String())
		}
		if len(members) < 2 {
			continue
		}

		linkBucket(key, members, links)
		if issue, ok := formIssue(key, members); ok {
			result.Issues = append(result.Issues, issue)
		}
	}

	result.Links = links.sorted()
	return result
}

// bucketize groups subjects by every key each one carries.
//
// A finding usually lands in more than one bucket -- a Grype result has both a
// CVE and a PURL -- which is intended: it participates in the "this
// vulnerability" grouping and the "this component" grouping, and those are
// different questions.
func bucketize(subjects []Subject) (map[Key][]Subject, []Key) {
	buckets := map[Key][]Subject{}
	for _, s := range subjects {
		for _, k := range keysOf(s) {
			buckets[k] = append(buckets[k], s)
		}
	}

	keys := make([]Key, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	return buckets, keys
}

// keysOf returns every correlation key a subject carries, deduplicated.
//
// An empty value is not a key. Two findings that both lack a CVE have not been
// shown to share anything, and bucketing them together on "" would assert a
// relationship built from absence.
func keysOf(s Subject) []Key {
	var keys []Key
	if cve := strings.TrimSpace(s.CVE); cve != "" {
		keys = append(keys, Key{Kind: KindCVE, Value: cve})
	}
	if purl := strings.TrimSpace(s.PURL); purl != "" {
		keys = append(keys, Key{Kind: KindComponent, Value: purl})
	}

	seen := map[string]bool{}
	for _, f := range s.Files {
		p := normalization.NormalizeLocation(f)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		keys = append(keys, Key{Kind: KindFile, Value: p})
	}
	return keys
}

// linkBucket emits the pairwise relationships for one bucket.
//
// The rules are equality tests on structured fields and nothing else: §25.5
// forbids relating findings by title or string similarity, and every assertion
// here has to be traceable to one shared attribute.
func linkBucket(key Key, members []Subject, into *linkSet) {
	for i := range members {
		for j := i + 1; j < len(members); j++ {
			a, b := members[i], members[j]
			if link, ok := linkFor(key, a, b); ok {
				into.add(link)
			}
		}
	}
}

func linkFor(key Key, a, b Subject) (Link, bool) {
	switch key.Kind {
	case KindCVE:
		return Link{
			From: a.Fingerprint, To: b.Fingerprint,
			Relationship: RelationRelated,
			Confidence:   normalization.ConfidenceHigh,
			Evidence:     "same vulnerability " + key.Value,
		}, true

	case KindComponent:
		// Two rules firing on one component, neither naming a vulnerability,
		// is usually one problem seen twice -- but only usually, which is why
		// this is a link with a confidence rather than a merge (§8).
		if a.Category == b.Category && a.CVE == "" && b.CVE == "" {
			return Link{
				From: a.Fingerprint, To: b.Fingerprint,
				Relationship: RelationLikelyDuplicate,
				Confidence:   normalization.ConfidenceMedium,
				Evidence: fmt.Sprintf("same component %s and category %s",
					key.Value, a.Category),
			}, true
		}
		return Link{
			From: a.Fingerprint, To: b.Fingerprint,
			Relationship: RelationRelated,
			Confidence:   normalization.ConfidenceMedium,
			Evidence:     "same component " + key.Value,
		}, true

	case KindFile:
		// Co-location only counts across domains. Two SAST findings in one
		// file are two findings in one file, and asserting a relationship
		// between them adds nothing a path sort would not already show.
		if a.Category == b.Category {
			return Link{}, false
		}
		return Link{
			From: a.Fingerprint, To: b.Fingerprint,
			Relationship: RelationRelated,
			// The weakest evidence in the rule set, and labelled as such so a
			// reader can discount it (§9).
			Confidence: normalization.ConfidenceLow,
			Evidence: fmt.Sprintf("same file %s, categories %s and %s",
				key.Value, a.Category, b.Category),
		}, true

	default:
		return Link{}, false
	}
}

// formIssue builds the issue for a bucket, if that bucket earns one.
//
// Issues are keyed by the shared attribute rather than by connected components
// of the link graph. Transitive closure would place two findings in one issue
// on the strength of a chain no rule ever evaluated -- exactly the invention §9
// forbids.
func formIssue(key Key, members []Subject) (Issue, bool) {
	categories := distinctCategories(members)

	// A file with many findings of one kind is a busy file, not a contextual
	// issue. CVE and component keys are self-evidently one subject and need no
	// such restriction.
	if key.Kind == KindFile && len(categories) < 2 {
		return Issue{}, false
	}

	issue := Issue{
		Key:        key,
		Categories: categories,
		Members:    make([]Member, 0, len(members)),
	}
	for _, m := range members {
		issue.Members = append(issue.Members, Member{
			Fingerprint: m.Fingerprint,
			Scanner:     m.Scanner,
			Severity:    m.Severity,
			Evidence:    membershipEvidence(key, m),
		})
	}

	issue.Severity, issue.Escalated = issueSeverity(members, categories)
	issue.Explanation = explain(key, issue)
	return issue, true
}

func membershipEvidence(key Key, m Subject) string {
	switch key.Kind {
	case KindCVE:
		return "reports " + key.Value
	case KindComponent:
		return "concerns component " + key.Value
	case KindFile:
		return fmt.Sprintf("found in %s (%s)", key.Value, m.Category)
	default:
		return "shares " + key.String()
	}
}

func explain(key Key, issue Issue) string {
	var subject string
	switch key.Kind {
	case KindCVE:
		subject = fmt.Sprintf("%d findings report vulnerability %s", len(issue.Members), key.Value)
	case KindComponent:
		subject = fmt.Sprintf("%d findings concern component %s", len(issue.Members), key.Value)
	case KindFile:
		subject = fmt.Sprintf("%d findings share the file %s", len(issue.Members), key.Value)
	default:
		subject = fmt.Sprintf("%d findings share %s", len(issue.Members), key.String())
	}

	if !issue.Escalated {
		return subject + "."
	}
	return fmt.Sprintf(
		"%s. Severity raised one step to %s because the findings span %s, "+
			"which corroborate each other across domains.",
		subject, issue.Severity, strings.Join(issue.Categories, " and "))
}

func distinctCategories(members []Subject) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range members {
		c := string(m.Category)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func sortedByFingerprint(subjects []Subject) []Subject {
	out := make([]Subject, len(subjects))
	copy(out, subjects)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}
