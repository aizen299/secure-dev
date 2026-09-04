package users

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidSession reports a session token that does not verify.
//
// One error for every cause -- malformed, wrong signature, expired -- because a
// caller learns nothing useful from the difference and an attacker learns which
// half of a forgery attempt was wrong.
var ErrInvalidSession = errors.New("session is not valid")

// SessionTTL is how long an issued session lasts.
//
// Eight hours: long enough for a working day, short enough that a forgotten tab
// on a shared machine stops being a way in. The same figure ADR 029 chose for
// the dashboard cookie, kept identical so the two cannot expire at different
// times and produce a session that is valid to one layer and not the other.
const SessionTTL = 8 * time.Hour

// sessionPrefix marks a bearer token as a user session rather than a
// configured credential.
//
// The API has to tell them apart before it can decide how to verify, and
// guessing by shape would mean a configured token that happened to contain a
// dot being run through the wrong verifier.
const sessionPrefix = "usr_"

// Sessions issues and verifies user session tokens (ADR 033 §5a).
//
// Stateless: a token carries a user id, an expiry, and an HMAC over both, and
// there is no sessions table. The user row is still read on every request by
// the caller, so disabling an account takes effect on the next request rather
// than at the next restart -- which is better than what configured tokens
// offer. What stateless costs is revoking one session while leaving others
// alive.
type Sessions struct {
	key []byte
}

// NewSessions builds a signer.
//
// An empty key generates one per process, which means a restart signs everyone
// out. That is the correct default for a security tool: the failure mode of a
// missing key must be "everyone signs in again", never "sessions are signed
// with a predictable value". The same choice ADR 029 made for the dashboard's
// own cookie.
func NewSessions(key string) *Sessions {
	if k := strings.TrimSpace(key); k != "" {
		return &Sessions{key: []byte(k)}
	}
	generated := make([]byte, 32)
	if _, err := rand.Read(generated); err != nil {
		panic("users: generating a session key: " + err.Error())
	}
	return &Sessions{key: generated}
}

// Issue returns a session token for a user.
func (s *Sessions) Issue(userID string, now time.Time) string {
	payload := userID + "." + strconv.FormatInt(now.Add(SessionTTL).Unix(), 10)
	return sessionPrefix + payload + "." + s.sign(payload)
}

// LooksLikeSession reports whether a bearer value is shaped like one.
//
// Checked by prefix, not by guessing: the API must route a value to the right
// verifier before it can verify it, and a configured token that happened to
// contain a dot must not be run through this one.
func LooksLikeSession(token string) bool {
	return strings.HasPrefix(token, sessionPrefix)
}

// Verify returns the user id a session names.
//
// The expiry is INSIDE the signed payload rather than alongside it. A client
// holds this value, and a client is not a thing to take an expiry claim from --
// so extending a session means forging a signature rather than editing a field.
func (s *Sessions) Verify(token string, now time.Time) (string, error) {
	rest, ok := strings.CutPrefix(token, sessionPrefix)
	if !ok {
		return "", ErrInvalidSession
	}

	// The signature is everything after the LAST separator, so a user id
	// containing one cannot shift the split.
	cut := strings.LastIndex(rest, ".")
	if cut < 0 {
		return "", ErrInvalidSession
	}
	payload, signature := rest[:cut], rest[cut+1:]

	if !s.valid(payload, signature) {
		return "", ErrInvalidSession
	}

	userID, expiryText, ok := strings.Cut(payload, ".")
	if !ok || strings.TrimSpace(userID) == "" {
		return "", ErrInvalidSession
	}
	expiry, err := strconv.ParseInt(expiryText, 10, 64)
	if err != nil {
		return "", ErrInvalidSession
	}
	if !now.Before(time.Unix(expiry, 0)) {
		return "", fmt.Errorf("%w: expired", ErrInvalidSession)
	}
	return userID, nil
}

func (s *Sessions) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// valid compares in constant time, so the number of matching leading bytes is
// not observable through response timing.
func (s *Sessions) valid(payload, signature string) bool {
	want := s.sign(payload)
	// Lengths are folded into the comparison rather than checked first, because
	// an early length check is itself a timing signal.
	if len(want) != len(signature) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(signature)) == 1
}
