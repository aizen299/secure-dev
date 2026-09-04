package auth

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The placeholders in .env.example must actually parse.
//
// They did not: the second secret was 31 characters against a 32-character
// minimum, so copying the file verbatim produced an API in a restart loop --
// the exact failure the file exists to prevent. Read from the real file rather
// than a copy of it, so the two cannot drift apart again.
func TestEnvExampleTokensParse(t *testing.T) {
	raw, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Skipf("no .env.example: %v", err)
	}

	line := regexp.MustCompile(`(?m)^SECUREOPS_API_TOKENS=(.+)$`).FindSubmatch(raw)
	if line == nil {
		t.Fatal("SECUREOPS_API_TOKENS is not set in .env.example")
	}

	if _, err := New(strings.Split(string(line[1]), ",")); err != nil {
		t.Fatalf(".env.example token format rejected: %v", err)
	}
}
