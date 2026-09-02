package auth_test

import (
	"testing"

	"github.com/aizen299/secure-dev/internal/auth"
)

func TestRoleRankOrdering(t *testing.T) {
	for _, tc := range []struct {
		held, required auth.Role
		want           bool
	}{
		{auth.RoleAdmin, auth.RoleAdmin, true},
		{auth.RoleAdmin, auth.RoleService, true},
		{auth.RoleAdmin, auth.RoleViewer, true},
		{auth.RoleService, auth.RoleAdmin, false},
		{auth.RoleService, auth.RoleService, true},
		{auth.RoleService, auth.RoleViewer, true},
		{auth.RoleViewer, auth.RoleAdmin, false},
		{auth.RoleViewer, auth.RoleService, false},
		{auth.RoleViewer, auth.RoleViewer, true},
	} {
		if got := tc.held.Allows(tc.required); got != tc.want {
			t.Errorf("%q.Allows(%q) = %v, want %v", tc.held, tc.required, got, tc.want)
		}
	}
}

// The defensive branch that the HTTP tests cannot reach, because ParseRole
// rejects unknown roles at startup. It is exactly the case where being wrong
// is expensive, so it is tested directly rather than assumed.
func TestAnUnknownRoleGrantsNothing(t *testing.T) {
	for _, bogus := range []auth.Role{"", "root", "Admin ", "superuser", "administrator"} {
		if bogus.Valid() {
			t.Errorf("%q reports itself valid", bogus)
		}
		for _, required := range []auth.Role{auth.RoleViewer, auth.RoleService, auth.RoleAdmin} {
			if bogus.Allows(required) {
				t.Errorf("%q was allowed to act as %q", bogus, required)
			}
		}
	}
}

// A typo in configuration must not silently change what a credential can do.
func TestParseRoleRejectsAnythingUnrecognised(t *testing.T) {
	for _, raw := range []string{"admin", "ADMIN", " service ", "Viewer"} {
		if _, ok := auth.ParseRole(raw); !ok {
			t.Errorf("ParseRole(%q) rejected a valid role", raw)
		}
	}
	for _, raw := range []string{"", "adminn", "read-only", "owner", "svc"} {
		if role, ok := auth.ParseRole(raw); ok {
			t.Errorf("ParseRole(%q) accepted it as %q", raw, role)
		}
	}
}

// The format change is breaking on purpose: an un-roled token must fail loudly
// rather than be treated as anything.
func TestPreviousTokenFormatIsRejected(t *testing.T) {
	if _, err := auth.New([]string{"ci:" + validSecret}); err == nil {
		t.Fatal("a label:secret token was accepted; an un-roled credential must not start the server")
	}
	if _, err := auth.New([]string{"ci:owner:" + validSecret}); err == nil {
		t.Fatal("an unknown role was accepted")
	}
}

// The error names the label and the permitted roles, never the secret.
func TestRoleErrorDoesNotLeakTheSecret(t *testing.T) {
	_, err := auth.New([]string{"ci:owner:" + validSecret})
	if err == nil {
		t.Fatal("expected an error")
	}
	if contains(err.Error(), validSecret) {
		t.Errorf("the error echoed the secret: %v", err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
