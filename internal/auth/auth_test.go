package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/auth"
)

// Synthetic values only. Fixtures containing real secrets are forbidden
// (CLAUDE.md §19).
//
// These read as words rather than as random hex on purpose. A high-entropy
// hex string is exactly what a real token looks like, so one committed here
// trips the repository's own gitleaks scan -- correctly, since a scanner
// cannot tell a fake credential from a real one. Making the value obviously
// fake fixes that at the source instead of suppressing the rule. Both are
// comfortably over the 32-character minimum auth.New enforces.
const (
	validSecret = "secureops-test-token-not-a-secret"
	otherSecret = "secureops-other-token-not-secret1"
)

func newAuth(t *testing.T, pairs ...string) *auth.Authenticator {
	t.Helper()
	a, err := auth.New(pairs)
	if err != nil {
		t.Fatalf("New(%v): unexpected error: %v", pairs, err)
	}
	return a
}

func TestNewRejectsUnusableConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		pairs []string
	}{
		{"no tokens at all", nil},
		{"empty slice", []string{}},
		{"missing separator", []string{"justatokenwithnolabel0123456789abcdef"}},
		{"empty label", []string{":" + validSecret}},
		{"blank label", []string{"   :" + validSecret}},
		{"secret below minimum", []string{"ci:tooshort"}},
		{"empty secret", []string{"ci:"}},
		{"duplicate label", []string{"ci:" + validSecret, "ci:" + otherSecret}},
		{"duplicate secret", []string{"ci:" + validSecret, "dashboard:" + validSecret}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := auth.New(tc.pairs); err == nil {
				t.Fatalf("New(%v): expected an error, got none", tc.pairs)
			}
		})
	}
}

// A process that starts with no credentials serves an open API. ADR 006 makes
// that impossible by construction, so the guarantee is asserted directly.
func TestNewRequiresAtLeastOneCredential(t *testing.T) {
	_, err := auth.New(nil)
	if err == nil {
		t.Fatal("New(nil): expected an error, got none")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Errorf("New(nil): error should explain the requirement, got %q", err)
	}
}

// The minimum length is a security control, so the boundary is pinned rather
// than assumed.
func TestNewEnforcesMinimumTokenLength(t *testing.T) {
	atMinimum := strings.Repeat("a", auth.MinTokenLength)
	belowMinimum := strings.Repeat("a", auth.MinTokenLength-1)

	if _, err := auth.New([]string{"ci:" + atMinimum}); err != nil {
		t.Errorf("a secret of exactly MinTokenLength should be accepted, got %v", err)
	}
	if _, err := auth.New([]string{"ci:" + belowMinimum}); err == nil {
		t.Error("a secret one character below MinTokenLength should be rejected")
	}
}

// An error about a weak token must name the label, never the secret.
func TestNewErrorDoesNotLeakTheSecret(t *testing.T) {
	const weak = "short-but-distinctive"

	_, err := auth.New([]string{"ci:" + weak})
	if err == nil {
		t.Fatal("expected an error for a short secret")
	}
	if strings.Contains(err.Error(), weak) {
		t.Errorf("error must not quote the secret, got %q", err)
	}
	if !strings.Contains(err.Error(), "ci") {
		t.Errorf("error should name the label, got %q", err)
	}
}

func TestAuthenticateAcceptsAValidToken(t *testing.T) {
	a := newAuth(t, "ci:"+validSecret, "dashboard:"+otherSecret)

	principal, err := a.Authenticate("Bearer " + otherSecret)
	if err != nil {
		t.Fatalf("Authenticate: unexpected error: %v", err)
	}
	if principal.Label != "dashboard" {
		t.Errorf("Label = %q, want %q", principal.Label, "dashboard")
	}
}

func TestAuthenticateIsCaseInsensitiveInTheScheme(t *testing.T) {
	a := newAuth(t, "ci:"+validSecret)

	for _, header := range []string{
		"Bearer " + validSecret,
		"bearer " + validSecret,
		"BEARER " + validSecret,
	} {
		if _, err := a.Authenticate(header); err != nil {
			t.Errorf("Authenticate(%q): unexpected error: %v", header, err)
		}
	}
}

func TestAuthenticateRejectsBadCredentials(t *testing.T) {
	a := newAuth(t, "ci:"+validSecret)

	tests := []struct {
		name   string
		header string
	}{
		{"absent header", ""},
		{"no scheme", validSecret},
		{"wrong scheme", "Basic " + validSecret},
		{"scheme only", "Bearer"},
		{"empty token", "Bearer "},
		{"whitespace token", "Bearer    "},
		{"unknown token", "Bearer " + otherSecret},
		{"token prefix", "Bearer " + validSecret[:len(validSecret)-1]},
		{"token with suffix", "Bearer " + validSecret + "x"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			principal, err := a.Authenticate(tc.header)
			if !errors.Is(err, auth.ErrUnauthenticated) {
				t.Fatalf("Authenticate(%q): error = %v, want ErrUnauthenticated", tc.header, err)
			}
			if principal.Label != "" {
				t.Errorf("a rejected request must not yield a principal, got %q", principal.Label)
			}
		})
	}
}

// Secrets are compared as digests, so a token that is a prefix of a valid one
// must not match. This is the case a naive strings.HasPrefix check would pass.
func TestAuthenticateRejectsPrefixesAndExtensions(t *testing.T) {
	a := newAuth(t, "ci:"+validSecret)

	for _, token := range []string{
		validSecret[:1],
		validSecret[:len(validSecret)/2],
		validSecret + validSecret,
	} {
		if _, err := a.Authenticate("Bearer " + token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("Authenticate with %d-character variant: error = %v, want ErrUnauthenticated",
				len(token), err)
		}
	}
}

func TestLabelsAreSortedAndExcludeSecrets(t *testing.T) {
	a := newAuth(t, "zeta:"+validSecret, "alpha:"+otherSecret)

	labels := a.Labels()
	want := []string{"alpha", "zeta"}
	if len(labels) != len(want) {
		t.Fatalf("Labels() = %v, want %v", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("Labels() = %v, want %v", labels, want)
		}
	}
	for _, label := range labels {
		if strings.Contains(label, validSecret) || strings.Contains(label, otherSecret) {
			t.Fatal("Labels() must never expose a secret")
		}
	}
}
