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

	// Future kinds, named in docs/architecture/correlation.md and blocked on
	// scanners rather than on this design: `image:<digest>` needs Trivy image
	// targets, `endpoint:<method> <path>` needs ZAP. Each is one more constant
	// here, one more case in linkFor, and nothing else.
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
