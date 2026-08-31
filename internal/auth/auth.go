// Package auth verifies API credentials.
//
// This is the interim bearer-token gate described in ADR 006. It exists because
// Phase 3 ships the first write endpoints and CLAUDE.md §15.4 requires
// server-side authentication on every request, while the real identity model
// (users, sessions, RBAC) belongs to Phase 11.
//
// The package is deliberately free of HTTP types. It answers one question --
// "does this credential belong to a known client?" -- so it can be tested
// without a server, and so the HTTP layer owns response shaping.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// MinTokenLength is the shortest secret the authenticator will accept.
//
// Enforced at construction, not at request time: a weak token must be
// impossible to configure, not merely discouraged. 32 characters of the
// generated hex in the README is 128 bits of entropy.
const MinTokenLength = 32

// ErrUnauthenticated reports a missing, malformed, or unrecognised credential.
//
// It is deliberately one error rather than three. Distinguishing "no token"
// from "wrong token" tells an unauthenticated caller which half of the problem
// to work on, and the HTTP layer would collapse them into 401 regardless.
var ErrUnauthenticated = errors.New("unauthenticated")

// Principal is the authenticated client.
//
// It holds a label, not a user. Phase 11 widens this into a real identity;
// keeping it minimal now means that widening is additive at every call site.
type Principal struct {
	// Label names the client the token was issued to. It is safe to log and
	// safe to persist: it is operator-configured, never client-supplied.
	Label string
}

// credential is one configured token, stored as a digest.
type credential struct {
	label  string
	digest [sha256.Size]byte
}

// Authenticator verifies bearer tokens against a fixed set of credentials.
//
// The zero value is not usable; build one with New.
type Authenticator struct {
	credentials []credential
}

// New builds an Authenticator from label:secret pairs.
//
// At least one credential is required. A process that starts with no
// credentials would serve an open API, so this returns an error rather than
// defaulting to a permissive mode (ADR 006).
func New(pairs []string) (*Authenticator, error) {
	if len(pairs) == 0 {
		return nil, errors.New("auth: at least one API token must be configured")
	}

	seenLabels := make(map[string]struct{}, len(pairs))
	seenDigests := make(map[[sha256.Size]byte]struct{}, len(pairs))
	creds := make([]credential, 0, len(pairs))

	for i, pair := range pairs {
		label, secret, ok := strings.Cut(pair, ":")
		if !ok {
			return nil, fmt.Errorf("auth: token %d is not in label:secret form", i+1)
		}

		label = strings.TrimSpace(label)
		// The secret is NOT trimmed. Trimming would silently accept a token
		// whose configured value differs from the one the client sends.
		if label == "" {
			return nil, fmt.Errorf("auth: token %d has an empty label", i+1)
		}
		if len(secret) < MinTokenLength {
			// The message must not quote the secret, or the length of a
			// specific secret, beyond the policy it violated.
			return nil, fmt.Errorf(
				"auth: token %q is shorter than the %d-character minimum", label, MinTokenLength)
		}
		if _, dup := seenLabels[label]; dup {
			return nil, fmt.Errorf("auth: token label %q is used more than once", label)
		}

		digest := sha256.Sum256([]byte(secret))
		if _, dup := seenDigests[digest]; dup {
			// Two labels sharing a secret makes attribution a lie: the label
			// on a request would be whichever credential matched first.
			return nil, fmt.Errorf("auth: token %q reuses another token's secret", label)
		}

		seenLabels[label] = struct{}{}
		seenDigests[digest] = struct{}{}
		creds = append(creds, credential{label: label, digest: digest})
	}

	return &Authenticator{credentials: creds}, nil
}

// Authenticate verifies the value of an Authorization header.
//
// The comparison is constant-time and every configured credential is checked
// on every call, so neither the outcome nor the matching credential's position
// is observable through response timing.
func (a *Authenticator) Authenticate(header string) (Principal, error) {
	token, err := parseBearer(header)
	if err != nil {
		return Principal{}, err
	}

	presented := sha256.Sum256([]byte(token))

	// match is not returned early: the loop always runs to completion so the
	// number of comparisons does not depend on which credential matched.
	matched := -1
	for i, cred := range a.credentials {
		if subtle.ConstantTimeCompare(presented[:], cred.digest[:]) == 1 {
			matched = i
		}
	}

	if matched < 0 {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Label: a.credentials[matched].label}, nil
}

// Labels lists the configured credential labels, sorted. It exposes labels
// only; the secrets and their digests never leave this package.
func (a *Authenticator) Labels() []string {
	out := make([]string, 0, len(a.credentials))
	for _, c := range a.credentials {
		out = append(out, c.label)
	}
	sort.Strings(out)
	return out
}

// parseBearer extracts the token from an "Authorization: Bearer <token>" value.
func parseBearer(header string) (string, error) {
	if header == "" {
		return "", ErrUnauthenticated
	}

	scheme, token, ok := strings.Cut(header, " ")
	if !ok {
		return "", ErrUnauthenticated
	}
	// RFC 7235 makes the scheme case-insensitive.
	if !strings.EqualFold(scheme, "bearer") {
		return "", ErrUnauthenticated
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", ErrUnauthenticated
	}
	return token, nil
}
