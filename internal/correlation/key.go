package correlation

// KeyKind names what two findings share.
//
// The set is deliberately small and closed. Every relationship SecureOps
// asserts traces to exactly one of these, which is what makes the engine's
// claims enumerable: "why do you think these are connected?" always has a
// one-line answer.
type KeyKind string

const (
	// KindCVE is the same named vulnerability.
	KindCVE KeyKind = "cve"
	// KindComponent is the same package at the same version, by PURL.
	KindComponent KeyKind = "purl"
	// KindFile is the same file. The weakest of the three, and the only one
	// that requires differing categories before it asserts anything.
	KindFile KeyKind = "file"

	// `endpoint:<method> <path>` is the one future kind still expected here,
	// blocked on ZAP rather than on this design: one more constant, one more
	// case in linkFor, and nothing else.
	//
	// An `image:` kind was expected too and is deliberately NOT added, now
	// that Trivy image targets exist (ADR 025). Every finding in one image
	// would share the key, so the bucket is the whole scan; linkBucket is
	// pairwise, so a bucket at DefaultMaxBucketSize emits 124,750 links each
	// asserting one fact the findings.image column already stores. It would
	// form no issues either, every member having the one category that
	// formIssue requires two of. Findings from a repository and from an image
	// are already joined by `cve` and `purl`, which is where the cross-domain
	// escalation actually comes from -- "in the same image" is a filter, and
	// filters belong in a query.
)

// Key is a correlation bucket: a kind and the value findings share.
type Key struct {
	Kind  KeyKind
	Value string
}

// String renders the key as it is stored and shown, e.g. "cve:CVE-2026-1234".
//
// Used for ordering as well as display, so issue and link output is sorted by
// something stable and meaningful rather than by map iteration.
func (k Key) String() string { return string(k.Kind) + ":" + k.Value }
