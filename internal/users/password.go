package users

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrPasswordTooShort reports a password below the minimum length.
var ErrPasswordTooShort = errors.New("password is too short")

// ErrMalformedHash reports a stored hash this package cannot read.
//
// Distinct from "wrong password" on purpose: a malformed hash is a corrupted
// row or a hash written by something else, and it must never be reported to a
// caller as a failed sign-in. That would turn a database problem into a
// lockout nobody can diagnose from the outside.
var ErrMalformedHash = errors.New("password hash is malformed")

// MinPasswordLength is the shortest password accepted.
//
// Twelve rather than eight, and no composition rules. Length is the property
// that actually resists an offline attack against a stolen hash; requiring a
// digit and a symbol mostly produces "Password1!" and a person who reuses it.
const MinPasswordLength = 12

// Argon2id parameters.
//
// From the RFC 9106 second recommended option: 64 MiB of memory, three passes,
// four lanes. Memory is the parameter that matters against an attacker with
// GPUs, because memory is the resource that does not parallelise cheaply --
// which is the whole reason Argon2id exists rather than another round count on
// a hash that fits in cache.
//
// These are constants rather than configuration. A deployment that lowered them
// would weaken every password it stored afterwards, silently, and the only
// signal would be that sign-in got faster. Raising them is a code change, and
// the encoded hash carries the parameters each row was written with, so old
// rows keep verifying at the cost they were created at.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // KiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16

	// Bounds on a hash read back from storage. Argon2id output is 16 bytes at
	// the low end of anything sane and 64 at the high end; the value is used as
	// a derivation length, so it is checked rather than trusted.
	minKeyLen = 16
	maxKeyLen = 64
)

// HashPassword returns an encoded Argon2id hash.
//
// The output is the standard PHC string -- algorithm, version, parameters,
// salt, hash -- so a row records the cost it was hashed at rather than the cost
// configured when it is read.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", fmt.Errorf("%w: minimum is %d characters", ErrPasswordTooShort, MinPasswordLength)
	}

	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		// Unreachable in practice, and fatal if it happens: a hash with a
		// predictable salt is worse than no hash, so this must never fall back
		// to anything.
		return "", fmt.Errorf("generating salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether a password matches an encoded hash.
//
// Returns (false, nil) for a wrong password and (false, err) for a hash this
// package cannot read. A caller must treat both as a failed sign-in and must
// log only the second -- the distinction is for the operator, never for the
// person at the form.
//
// The parameters come from the stored hash rather than from the constants
// above, which is what lets those constants be raised without invalidating
// every existing row.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrMalformedHash
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrMalformedHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < minKeyLen || len(want) > maxKeyLen {
		// Bounded because the length comes from the STORED VALUE and is then
		// handed to a key-derivation function as its output size. A row
		// carrying a huge hash field would otherwise make one verification
		// attempt allocate and derive that much -- a denial of service reachable
		// from a corrupted or hostile row rather than from a request.
		//
		// The bounds are what Argon2id output actually is; anything outside
		// them is malformed rather than merely unusual.
		return false, ErrMalformedHash
	}

	// #nosec G115 -- len(want) is bounded to [minKeyLen, maxKeyLen] immediately
	// above, so the conversion cannot overflow. The bound is the fix; this
	// comment only records that the linter cannot see it.
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))

	// Constant-time, so the number of matching leading bytes is not observable
	// through response timing.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// hashWith produces a hash at explicit parameters.
//
// For tests that need a hash made at a different cost than the current
// constants, so "an old row still verifies" can be asserted rather than
// assumed. Unexported: nothing in production should be choosing its own cost.
func hashWith(password string, memory, time uint32, threads uint8) string {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic("users: reading random salt: " + err.Error())
	}
	key := argon2.IDKey([]byte(password), salt, time, memory, threads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}
