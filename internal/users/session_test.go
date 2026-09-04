package users

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const sessionKey = "a-signing-key-for-tests-only"

func TestASessionVerifiesAndNamesItsUser(t *testing.T) {
	s := NewSessions(sessionKey)
	now := time.Now()

	got, err := s.Verify(s.Issue("user-1", now), now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != "user-1" {
		t.Errorf("user = %q, want user-1", got)
	}
}

// The expiry lives INSIDE the signature, so extending a session means forging
// one rather than editing a field. A client holds this value, and a client is
// not a thing to take an expiry claim from.
func TestAnExtendedExpiryDoesNotVerify(t *testing.T) {
	s := NewSessions(sessionKey)
	now := time.Now()
	token := s.Issue("user-1", now)

	// Rewrite the expiry to the far future, keeping the signature.
	rest := strings.TrimPrefix(token, "usr_")
	cut := strings.LastIndex(rest, ".")
	signature := rest[cut+1:]
	forged := "usr_user-1.99999999999." + signature

	if _, err := s.Verify(forged, now); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("a rewritten expiry verified: %v", err)
	}
}

func TestATamperedSignatureDoesNotVerify(t *testing.T) {
	s := NewSessions(sessionKey)
	now := time.Now()
	token := s.Issue("user-1", now)

	flipped := token[:len(token)-1] + map[bool]string{true: "b", false: "a"}[strings.HasSuffix(token, "a")]
	if _, err := s.Verify(flipped, now); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("a tampered signature verified: %v", err)
	}
}

func TestASessionExpires(t *testing.T) {
	s := NewSessions(sessionKey)
	now := time.Now()
	token := s.Issue("user-1", now)

	if _, err := s.Verify(token, now.Add(SessionTTL-time.Minute)); err != nil {
		t.Errorf("a session expired early: %v", err)
	}
	if _, err := s.Verify(token, now.Add(SessionTTL+time.Minute)); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("an expired session verified: %v", err)
	}
}

// A session signed with one key must not verify under another. This is what
// makes the per-process fallback key safe: a restart mints a new key and every
// outstanding session stops working, which is the intended behaviour and only
// holds if the key participates in the signature.
func TestASessionDoesNotVerifyUnderADifferentKey(t *testing.T) {
	now := time.Now()
	token := NewSessions(sessionKey).Issue("user-1", now)

	if _, err := NewSessions("a-different-key-entirely").Verify(token, now); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("a session verified under a different key: %v", err)
	}
}

// Two Sessions built with no key must not agree, or the "restart signs everyone
// out" property would be a comment rather than a behaviour.
func TestAnUnsetKeyIsGeneratedPerInstance(t *testing.T) {
	now := time.Now()
	token := NewSessions("").Issue("user-1", now)

	if _, err := NewSessions("").Verify(token, now); !errors.Is(err, ErrInvalidSession) {
		t.Error("two instances with no configured key produced the same signing key")
	}
}

func TestMalformedSessionsAreRefused(t *testing.T) {
	s := NewSessions(sessionKey)
	now := time.Now()

	for _, bad := range []string{
		"", "usr_", "usr_nodot", "usr_user-1.notanumber.abc",
		"user-1.123.abc",           // missing prefix
		"usr_.123.abc",             // empty user id
		s.Issue("user-1", now)[4:], // prefix stripped
	} {
		if _, err := s.Verify(bad, now); !errors.Is(err, ErrInvalidSession) {
			t.Errorf("Verify(%q) err = %v, want ErrInvalidSession", bad, err)
		}
	}
}

// The API routes a bearer value to the right verifier by prefix, so a
// configured token that happens to contain a dot is not run through the session
// verifier.
func TestOnlyPrefixedValuesLookLikeSessions(t *testing.T) {
	if !LooksLikeSession(NewSessions(sessionKey).Issue("user-1", time.Now())) {
		t.Error("an issued session does not look like one")
	}
	for _, notASession := range []string{
		"secureops-configured-token-value", "abc.def.ghi", "", "user_something",
	} {
		if LooksLikeSession(notASession) {
			t.Errorf("%q looks like a session", notASession)
		}
	}
}
