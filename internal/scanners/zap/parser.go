package zap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// maxAlerts bounds how many alerts are accepted from one report. The report
// describes an attacker-influenced application, so it is bounded like any other
// external input (§15.8).
const maxAlerts = 100_000

// redactedPrefix marks a field whose content was removed.
//
// Unlike trivy's bare marker (ADR 015), a digest of the original follows it.
// §15.3 asks for "a location and a hash, not the secret", and the hash buys
// what a marker cannot: two scans are comparable, so a person can see that the
// evidence changed without the value ever being stored.
const redactedPrefix = "[redacted:"

// digestLength is how much of the SHA256 is kept, in hex characters.
//
// Short enough to read, and far too short to brute-force a high-entropy secret
// from -- but note what it is not: a defence against confirming a *guessed*
// low-entropy value. Nothing stored here is a substitute for the value being
// absent, which is why the value is absent.
const digestLength = 16

// report is the subset of ZAP's JSON this adapter validates.
type report struct {
	ProgramName string            `json:"@programName"`
	Version     string            `json:"@version"`
	Site        []json.RawMessage `json:"site"`
}

// validateReport checks that the output really is a ZAP report.
//
// A garbled report is more dangerous than an obviously broken one: stored as-is
// it later reads as "this application has no problems" rather than "this scan
// did not work".
func validateReport(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("%w: output was empty", ErrMalformedReport)
	}

	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		// The error text quotes the offending bytes, which came from scanning
		// an untrusted application, so it is not wrapped into the message.
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	// ZAP stamps its own name into every report. Its absence means this is
	// valid JSON from something else, which would otherwise be stored as if
	// ZAP had produced it.
	if !strings.EqualFold(strings.TrimSpace(r.ProgramName), "ZAP") {
		return fmt.Errorf("%w: report is not from zap", ErrMalformedReport)
	}
	if len(r.Site) > maxAlerts {
		return fmt.Errorf("%w: more than %d sites", ErrMalformedReport, maxAlerts)
	}
	return nil
}

// contentBearingFields are the keys whose values come from the scanned
// application and may therefore contain its secrets.
//
// Measured rather than guessed. Against a target serving one link to
// `/search?api_key=…`, one hidden form token, and one session cookie, ZAP
// 2.17.0 put the API key in seven `uri` values and the form token in two
// `otherinfo` values. It put the cookie value nowhere -- it reports cookie
// names only -- and it did not capture the value inside a `<script>`.
//
// `attack` is treated too. It is always empty without an active scan, and
// including it means the control does not depend on the scan mode staying as
// it is (ADR 026).
var contentBearingFields = []string{"evidence", "otherinfo", "attack"}

// redactTargetContent removes application content from a ZAP report.
//
// Two different treatments, because two different problems:
//
//   - `uri` keeps its path and loses its query string. The query is where the
//     credentials are AND what makes the value unstable between scans, so one
//     rewrite serves both §15.3 and the identity design.
//   - The free-text fields are replaced wholesale with a digest. Their content
//     is a fragment of the application's own response, and deciding which
//     fragments are safe would mean pattern-matching against an unbounded
//     space, where being wrong means storing a credential.
//
// Structural rather than textual: the document is parsed, the fields are
// rewritten, and it is re-serialised. A regex over the bytes would be guessing
// at where the fields are.
func redactTargetContent(data []byte) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	redactNode(doc)

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: could not re-serialise after redaction", ErrMalformedReport)
	}
	return out, nil
}

func redactNode(node any) {
	switch v := node.(type) {
	case map[string]any:
		for _, field := range contentBearingFields {
			if raw, present := v[field]; present {
				if s, ok := raw.(string); ok && s != "" {
					v[field] = redactedValue(s)
				}
			}
		}
		// uri and nodeName both carry the request URL; ZAP populates them
		// alike, so both are stripped.
		for _, field := range []string{"uri", "nodeName"} {
			if raw, present := v[field]; present {
				if s, ok := raw.(string); ok && s != "" {
					v[field] = StripQuery(s)
				}
			}
		}
		for _, child := range v {
			redactNode(child)
		}
	case []any:
		for _, child := range v {
			redactNode(child)
		}
	}
}

// redactedValue replaces content with a marker carrying its digest.
func redactedValue(s string) string {
	sum := sha256.Sum256([]byte(s))
	return redactedPrefix + hex.EncodeToString(sum[:])[:digestLength] + "]"
}

// StripQuery removes a URL's query string and fragment, keeping the rest.
//
// Exported because the mapper derives a finding's location from the same value
// and the two must not disagree -- a stored URL that still carried a query
// while the identity did not would make the finding's own record contradict its
// fingerprint.
//
// Falls back to a textual cut when the value does not parse as a URL: ZAP
// output is untrusted (§15.7), and an unparseable value must still lose
// everything after the '?' rather than being passed through intact.
func StripQuery(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

// assertNoTargetContent verifies redaction actually happened.
//
// Fail-closed, for the reason ADR 015 gives: redactTargetContent walks a
// decoded document, and a ZAP schema change that renamed or moved these fields
// would make the walk silently miss them. This checks the result rather than
// trusting the rewrite, so a miss discards the report instead of storing
// credentials.
func assertNoTargetContent(data []byte) error {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}
	if found := findUnredacted(doc); found != "" {
		// The offending value is not echoed: it may be the credential.
		return fmt.Errorf("%w: %s survived redaction", ErrTargetLeak, found)
	}
	return nil
}

func findUnredacted(node any) string {
	switch v := node.(type) {
	case map[string]any:
		for _, field := range contentBearingFields {
			if raw, present := v[field]; present {
				if s, ok := raw.(string); ok && s != "" && !strings.HasPrefix(s, redactedPrefix) {
					return field
				}
			}
		}
		for _, field := range []string{"uri", "nodeName"} {
			if raw, present := v[field]; present {
				if s, ok := raw.(string); ok && strings.ContainsAny(s, "?#") {
					return field
				}
			}
		}
		for _, child := range v {
			if found := findUnredacted(child); found != "" {
				return found
			}
		}
	case []any:
		for _, child := range v {
			if found := findUnredacted(child); found != "" {
				return found
			}
		}
	}
	return ""
}

// endpointIsSafe re-applies the target validator's scheme rule.
//
// Deliberately duplicated. Validation happens at the API boundary, and this is
// the worker, on the other side of a queue -- a payload that reached the queue
// by any other route has still never been checked here. The address policy is
// not re-run (it needs a resolver the adapter does not have); this is the
// cheap half, and it is the half that stops a value from becoming something
// other than a URL.
func endpointIsSafe(raw string) bool {
	// Length is checked here rather than in the pattern: Go's regexp caps a
	// repeat count at 1000, and a URL may legitimately be longer than that.
	if len(raw) == 0 || len(raw) > maxEndpointLength {
		return false
	}
	if !safeEndpoint.MatchString(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// No whitespace, no control characters, and no leading dash: the value becomes
// an element of a YAML document and, upstream of that, was an argv element.
var safeEndpoint = regexp.MustCompile(`^https?://[A-Za-z0-9._:/@%?&=~+\-]+$`)

// maxEndpointLength bounds the URL, matching the column that stores it.
const maxEndpointLength = 2000

// parseVersion extracts the version from `zap.sh -version`, which prints the
// version on its own line after the launcher's own JVM chatter.
func parseVersion(data []byte) string {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if versionPattern.MatchString(line) {
			return line
		}
	}
	return ""
}

var versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
