package users

import (
	"errors"
	"strings"
	"testing"
)

const good = "correct-horse-battery-staple"

func TestAPasswordVerifiesAgainstItsOwnHash(t *testing.T) {
	encoded, err := HashPassword(good)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword(good, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("a password did not verify against its own hash")
	}
}

func TestAWrongPasswordDoesNotVerify(t *testing.T) {
	encoded, err := HashPassword(good)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	for _, wrong := range []string{
		"correct-horse-battery-stapl",  // one short
		"correct-horse-battery-staplE", // one different
		"correct-horse-battery-staple ",
		"",
	} {
		ok, err := VerifyPassword(wrong, encoded)
		if err != nil {
			t.Fatalf("VerifyPassword(%q): %v", wrong, err)
		}
		if ok {
			t.Errorf("%q verified against a different password's hash", wrong)
		}
	}
}

// Two hashes of the same password must differ.
//
// The salt is what makes a stolen table something an attacker has to break one
// row at a time. Without it, one cracked password reveals every account that
// shares it, and identical hashes make that visible before any cracking starts.
func TestTheSamePasswordHashesDifferentlyEveryTime(t *testing.T) {
	seen := make(map[string]struct{}, 8)
	for range 8 {
		encoded, err := HashPassword(good)
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		if _, dup := seen[encoded]; dup {
			t.Fatal("two hashes of the same password were identical; the salt is not random")
		}
		seen[encoded] = struct{}{}

		// Every one of them must still verify.
		if ok, err := VerifyPassword(good, encoded); err != nil || !ok {
			t.Fatalf("a salted hash did not verify: ok=%v err=%v", ok, err)
		}
	}
}

// The hash records the parameters it was made with, which is what lets the
// constants be raised later without invalidating every stored row.
func TestTheEncodedHashCarriesItsParameters(t *testing.T) {
	encoded, err := HashPassword(good)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Errorf("hash does not start with $argon2id$: %q", encoded)
	}
	// The database enforces this prefix too (migration 0016), so a mismatch
	// here would be an insert that fails at the constraint rather than at the
	// application.
	for _, want := range []string{"m=65536", "t=3", "p=4", "v=19"} {
		if !strings.Contains(encoded, want) {
			t.Errorf("hash is missing %q: %q", want, encoded)
		}
	}
	if n := len(strings.Split(encoded, "$")); n != 6 {
		t.Errorf("hash has %d $-separated fields, want 6: %q", n, encoded)
	}
}

// Verification reads the cost from the hash, not from the constants. A row
// written under older parameters must keep working, or raising the cost would
// lock out every existing account.
func TestAHashMadeWithDifferentParametersStillVerifies(t *testing.T) {
	// Built rather than hardcoded, so the test does not carry a hash whose
	// provenance nobody can check. m=8, t=1, p=1 is far below the current
	// constants, which is the point.
	encoded := hashWith(good, 8, 1, 1)
	ok, err := VerifyPassword(good, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword on a cheap hash: %v", err)
	}
	if !ok {
		t.Error("a hash made with lower parameters did not verify; raising the cost would lock everyone out")
	}
}

func TestShortPasswordsAreRefused(t *testing.T) {
	for _, short := range []string{"", "a", strings.Repeat("x", MinPasswordLength-1)} {
		if _, err := HashPassword(short); !errors.Is(err, ErrPasswordTooShort) {
			t.Errorf("HashPassword(%d chars) = %v, want ErrPasswordTooShort", len(short), err)
		}
	}
	// And the boundary is inclusive.
	if _, err := HashPassword(strings.Repeat("x", MinPasswordLength)); err != nil {
		t.Errorf("a password of exactly the minimum was refused: %v", err)
	}
}

// A hash this package cannot read must be an ERROR, never a failed sign-in.
//
// Reporting a corrupted row as "wrong password" turns a database problem into a
// lockout that looks like user error, and nothing in the logs would say
// otherwise.
func TestAMalformedHashIsAnErrorNotAWrongPassword(t *testing.T) {
	for _, bad := range []string{
		"",
		"hunter2",
		"$2y$10$abcdefghijklmnopqrstuv", // bcrypt
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",  // wrong variant
		"$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$aGFzaA", // wrong version
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA",    // bad base64 salt
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$",       // empty hash
		"$argon2id$v=19$nonsense$c2FsdA$aGFzaA",
	} {
		ok, err := VerifyPassword(good, bad)
		if ok {
			t.Errorf("a malformed hash %q verified", bad)
		}
		if !errors.Is(err, ErrMalformedHash) {
			t.Errorf("VerifyPassword(%q) err = %v, want ErrMalformedHash", bad, err)
		}
	}
}

// The hash length is read from the stored value and then used as a derivation
// length, so it is bounded rather than trusted. A row carrying a huge hash
// field would otherwise make one verification attempt derive that much.
func TestAnOutOfRangeHashLengthIsMalformed(t *testing.T) {
	salt := "c2FsdHNhbHRzYWx0c2Ex" // 16 bytes, valid
	for name, hash := range map[string]string{
		"too short": "YWJj",                       // 3 bytes
		"too long":  strings.Repeat("QUJDRA", 40), // ~120 bytes
		"empty":     "",
	} {
		encoded := "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + hash
		ok, err := VerifyPassword(good, encoded)
		if ok || !errors.Is(err, ErrMalformedHash) {
			t.Errorf("%s: ok=%v err=%v, want ErrMalformedHash", name, ok, err)
		}
	}
}
