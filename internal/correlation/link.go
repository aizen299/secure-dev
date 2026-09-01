package correlation

import (
	"sort"

	"github.com/aizen299/secure-dev/internal/normalization"
)

// Relationship describes how two findings relate (§8).
//
// All four of §8's relationships are named here so the vocabulary is complete
// and the boundaries between them are legible, even though only two are ever
// emitted as links:
//
//   - exact duplicate is handled by normalization, which merges identical
//     fingerprints before correlation runs. It never reaches this package.
//   - independent is the absence of a link, not a stored value. Recording every
//     unrelated pair would be quadratic and would say nothing.
type Relationship string

const (
	// RelationExactDuplicate is one problem reported twice, identified by an
	// identical fingerprint. Merged by normalization; never emitted here.
	RelationExactDuplicate Relationship = "exact_duplicate"
	// RelationLikelyDuplicate is probably one problem seen by two rules --
	// and "probably" is exactly why it is a link with a confidence rather than
	// a merge (§8 forbids merging findings for looking similar).
	RelationLikelyDuplicate Relationship = "likely_duplicate"
	// RelationRelated is a real connection that is not the same problem: the
	// same vulnerability in two components, or two problems in one file.
	RelationRelated Relationship = "related"
	// RelationIndependent is no relationship. Never stored.
	RelationIndependent Relationship = "independent"
)

// Link records why two findings are believed to be connected.
//
// Every link carries its evidence. §9 requires correlation to be explainable,
// and a relationship with no stated reason is an assertion rather than a
// finding about the code.
type Link struct {
	From         string // fingerprint, always the lexicographically smaller
	To           string // fingerprint
	Relationship Relationship
	Confidence   normalization.Confidence
	// Evidence names what the two findings share, in a form a person can read.
	Evidence string
}

// linkSet deduplicates links across buckets, keeping the strongest.
//
// A pair of findings often shares more than one key -- the same CVE and the
// same component -- and would otherwise be linked twice with different
// evidence. Two rows saying the same thing at different confidences is worse
// than one: a reader has to work out which to believe.
type linkSet struct {
	byPair map[[2]string]Link
}

func newLinkSet() *linkSet { return &linkSet{byPair: map[[2]string]Link{}} }

// add records a link, keeping the stronger of any two claims about one pair.
//
// Direction is normalized so (a,b) and (b,a) are one pair. The link graph is
// undirected -- "shares a CVE with" is symmetric -- and storing both directions
// would double every traversal for no information.
func (s *linkSet) add(l Link) {
	if l.From > l.To {
		l.From, l.To = l.To, l.From
	}
	pair := [2]string{l.From, l.To}

	existing, seen := s.byPair[pair]
	if !seen || stronger(l, existing) {
		s.byPair[pair] = l
	}
}

// stronger reports whether a is a better claim about a pair than b.
//
// Confidence first, because it is the honest measure of how much the evidence
// supports the claim. Relationship breaks ties: likely_duplicate is the more
// specific statement, so it survives over the vaguer related.
func stronger(a, b Link) bool {
	if ar, br := confidenceRank(a.Confidence), confidenceRank(b.Confidence); ar != br {
		return ar > br
	}
	return a.Relationship == RelationLikelyDuplicate && b.Relationship != RelationLikelyDuplicate
}

// confidenceRank orders confidence for comparison. Local rather than a method
// on normalization.Confidence: correlation is the only caller that needs to
// order them, and widening that package's API for one internal comparison
// would be the wrong trade.
func confidenceRank(c normalization.Confidence) int {
	switch c {
	case normalization.ConfidenceHigh:
		return 3
	case normalization.ConfidenceMedium:
		return 2
	case normalization.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// sorted returns the links in a stable order, so the same findings produce a
// byte-identical result on every run.
func (s *linkSet) sorted() []Link {
	out := make([]Link, 0, len(s.byPair))
	for _, l := range s.byPair {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}
