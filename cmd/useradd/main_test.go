package main

import (
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/users"
)

// The password comes from stdin and never from a flag.
//
// A flag is visible in `ps` to every other process on the host and lands in
// shell history, which for the one command that mints an admin is the wrong
// place for its password to end up.
func TestPasswordIsReadFromStdin(t *testing.T) {
	got, err := readPassword(strings.NewReader("a-long-enough-password"))
	if err != nil {
		t.Fatalf("readPassword: %v", err)
	}
	if got != "a-long-enough-password" {
		t.Errorf("password = %q", got)
	}
}

// `echo` adds a newline and almost nobody means it to be part of the password.
// Nothing else is trimmed: leading and interior whitespace are legitimate, and
// removing them would store a different password than the one typed.
func TestOnlyTheTrailingNewlineIsStripped(t *testing.T) {
	for input, want := range map[string]string{
		"a-long-enough-password\n":   "a-long-enough-password",
		"a-long-enough-password\r\n": "a-long-enough-password",
		" leading-space-is-kept-ok":  " leading-space-is-kept-ok",
		"interior  spaces  kept!!":   "interior  spaces  kept!!",
	} {
		got, err := readPassword(strings.NewReader(input))
		if err != nil {
			t.Fatalf("readPassword(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("readPassword(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAnEmptyOrShortPasswordIsRefused(t *testing.T) {
	for _, input := range []string{"", "\n", "short"} {
		if _, err := readPassword(strings.NewReader(input)); err == nil {
			t.Errorf("readPassword(%q) was accepted", input)
		}
	}
	// The boundary is inclusive, and matches the package that will hash it.
	exact := strings.Repeat("x", users.MinPasswordLength)
	if _, err := readPassword(strings.NewReader(exact)); err != nil {
		t.Errorf("a password of exactly the minimum was refused: %v", err)
	}
}

// Bounded, so a pipe that never closes cannot make this allocate without limit.
func TestStdinIsBounded(t *testing.T) {
	got, err := readPassword(strings.NewReader(strings.Repeat("x", 100_000)))
	if err != nil {
		t.Fatalf("readPassword: %v", err)
	}
	if len(got) > 4096 {
		t.Errorf("read %d bytes from stdin; it must be bounded", len(got))
	}
}
