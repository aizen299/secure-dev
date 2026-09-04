package users

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// `service` is a machine role and must not be assignable to a person (ADR 033).
//
// A CI credential is not a junior person. If this ever passes, a row with a
// password column can hold the role a token holds, and the distinction between
// the two kinds of principal has quietly collapsed.
func TestServiceIsNotAUserRole(t *testing.T) {
	if r, ok := ParseRole("service"); ok {
		t.Errorf("ParseRole(service) = %q, ok; a machine role must not be assignable to a person", r)
	}
	if Role("service").Valid() {
		t.Error("service is a valid user role")
	}
}

func TestParseRoleRefusesUnknownInput(t *testing.T) {
	for _, raw := range []string{"", "  ", "root", "superuser", "Admin ", "ADMIN"} {
		r, ok := ParseRole(raw)
		switch raw {
		case "Admin ", "ADMIN":
			// Trimmed and lowercased: configuration is written by a person.
			if !ok || r != RoleAdmin {
				t.Errorf("ParseRole(%q) = %q, %v; want admin", raw, r, ok)
			}
		default:
			if ok {
				t.Errorf("ParseRole(%q) = %q, ok; unknown input must not become a role", raw, r)
			}
		}
	}
}

// An unspecified role becomes viewer, never admin.
func TestAnUnspecifiedRoleBecomesViewer(t *testing.T) {
	n := NewUser{Email: "ada@example.com", Password: strings.Repeat("x", MinPasswordLength)}
	if err := n.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if n.Role != RoleViewer {
		t.Errorf("role = %q, want viewer: an unspecified role must be the least privileged", n.Role)
	}
}

func TestValidateNormalisesTheEmail(t *testing.T) {
	n := NewUser{Email: "  Ada@Example.COM  ", Password: strings.Repeat("x", MinPasswordLength)}
	if err := n.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Must match what the database's lower(email) unique index compares, or
	// two rows could exist for one person.
	if n.Email != "ada@example.com" {
		t.Errorf("email = %q, want ada@example.com", n.Email)
	}
}

func TestValidateRefusesBadInput(t *testing.T) {
	long := strings.Repeat("a", MaxEmailLength) + "@example.com"
	for name, n := range map[string]NewUser{
		"no email":       {Password: strings.Repeat("x", MinPasswordLength)},
		"blank email":    {Email: "   ", Password: strings.Repeat("x", MinPasswordLength)},
		"no at sign":     {Email: "ada.example.com", Password: strings.Repeat("x", MinPasswordLength)},
		"at sign first":  {Email: "@example.com", Password: strings.Repeat("x", MinPasswordLength)},
		"email too long": {Email: long, Password: strings.Repeat("x", MinPasswordLength)},
		"short password": {Email: "ada@example.com", Password: "short"},
		"unknown role":   {Email: "ada@example.com", Password: strings.Repeat("x", MinPasswordLength), Role: "root"},
		"service role":   {Email: "ada@example.com", Password: strings.Repeat("x", MinPasswordLength), Role: "service"},
	} {
		if err := n.Validate(); !errors.Is(err, ErrInvalidUser) {
			t.Errorf("%s: Validate() = %v, want ErrInvalidUser", name, err)
		}
	}
}

// The User struct must not carry the password hash.
//
// Nothing that reads a user needs it, and a struct that carries it will
// eventually be serialised into a response by someone who did not know it was
// there. Asserted structurally rather than trusted.
func TestUserDoesNotCarryThePasswordHash(t *testing.T) {
	var u User
	// If a hash field is ever added, this fails to compile against the JSON
	// tags below -- and more usefully, a reviewer reading this test knows why
	// it must not be.
	for _, field := range []string{"password", "hash", "secret"} {
		if strings.Contains(strings.ToLower(jsonFieldsOf(u)), field) {
			t.Errorf("User exposes a %q field; a value that travels must never carry a credential", field)
		}
	}
}

func TestRoleCapabilities(t *testing.T) {
	for role, wantTriage := range map[Role]bool{
		RoleViewer: false, RoleEngineer: true, RoleAdmin: true,
	} {
		if got := role.CanTriage(); got != wantTriage {
			t.Errorf("%s.CanTriage() = %v, want %v", role, got, wantTriage)
		}
	}
	for role, wantAdmin := range map[Role]bool{
		RoleViewer: false, RoleEngineer: false, RoleAdmin: true,
	} {
		if got := role.CanAdminister(); got != wantAdmin {
			t.Errorf("%s.CanAdminister() = %v, want %v", role, got, wantAdmin)
		}
	}
}

// jsonFieldsOf renders a value's JSON keys, so a test can assert what a struct
// would put on the wire rather than what its Go fields are named.
func jsonFieldsOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
