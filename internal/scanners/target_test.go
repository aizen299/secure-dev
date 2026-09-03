package scanners

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/netguard"
)

type fakeResolver struct{ ip string }

func (f fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP(f.ip)}}, nil
}

func testValidator(t *testing.T) Validator {
	t.Helper()
	return Validator{
		WorkspaceRoot: t.TempDir(),
		Resolver:      fakeResolver{ip: "93.184.216.34"},
	}
}

func TestKindValid(t *testing.T) {
	for _, k := range Kinds() {
		if !k.Valid() {
			t.Errorf("%q reported invalid", k)
		}
	}
	for _, k := range []Kind{"", "Repository", "exec", "unknown"} {
		if k.Valid() {
			t.Errorf("%q reported valid", k)
		}
	}
}

func TestValidateRejectsUnknownKind(t *testing.T) {
	_, err := testValidator(t).Validate(t.Context(), Target{Kind: "shell"})
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("err = %v, want ErrInvalidTarget", err)
	}
}

func TestValidateRepository(t *testing.T) {
	v := testValidator(t)

	got, err := v.Validate(t.Context(), Target{
		Kind:          KindRepository,
		RepositoryURL: "https://github.com/aizen299/secure-dev.git",
		Ref:           "main",
	})
	if err != nil {
		t.Fatalf("valid repository rejected: %v", err)
	}
	if got.Kind != KindRepository || got.Ref != "main" {
		t.Errorf("unexpected normalised target: %+v", got)
	}
}

func TestValidateRepositoryRejects(t *testing.T) {
	v := testValidator(t)

	tests := []struct {
		name   string
		target Target
	}{
		{"empty url", Target{Kind: KindRepository}},
		{"file scheme reads the worker filesystem", Target{Kind: KindRepository, RepositoryURL: "file:///etc/passwd"}},
		{"git scheme is unauthenticated", Target{Kind: KindRepository, RepositoryURL: "git://github.com/x/y"}},
		{"http scheme", Target{Kind: KindRepository, RepositoryURL: "http://github.com/x/y"}},
		{"no host", Target{Kind: KindRepository, RepositoryURL: "https:///x/y"}},
		{"ref with semicolon", Target{Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "main;rm -rf /"}},
		{"ref with space", Target{Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "main branch"}},
		{"ref with traversal", Target{Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "../../etc"}},
		{"ref with backtick", Target{Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "main`id`"}},
		{"ref with newline", Target{Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "main\nrm"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Validate(t.Context(), tc.target); !errors.Is(err, ErrInvalidTarget) {
				t.Errorf("err = %v, want ErrInvalidTarget", err)
			}
		})
	}
}

// A ref beginning with "-" would be read by git as a flag, not a ref. This is
// the argument-injection case that a naive "no shell metacharacters" check
// misses entirely.
func TestValidateRejectsLeadingDashArguments(t *testing.T) {
	v := testValidator(t)

	cases := []struct {
		name   string
		target Target
	}{
		{"ref as flag", Target{Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "--upload-pack=touch /tmp/pwned"}},
		{"short ref flag", Target{Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "-o"}},
		{"image as flag", Target{Kind: KindImage, Image: "--config=/etc/shadow"}},
		{"short image flag", Target{Kind: KindImage, Image: "-v"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Validate(t.Context(), tc.target); !errors.Is(err, ErrInvalidTarget) {
				t.Errorf("leading-dash value accepted: err = %v", err)
			}
		})
	}
}

// Validation errors are logged, so they must not echo attacker-controlled text.
func TestValidationErrorsDoNotEchoInput(t *testing.T) {
	v := testValidator(t)
	marker := "CANARY-a1b2c3-payload"

	_, err := v.Validate(t.Context(), Target{
		Kind: KindRepository, RepositoryURL: "https://github.com/x/y", Ref: "main;" + marker,
	})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("error echoed attacker input: %q", err.Error())
	}
}

func TestValidateRepositorySSRF(t *testing.T) {
	v := Validator{WorkspaceRoot: t.TempDir(), Resolver: fakeResolver{ip: "169.254.169.254"}}

	_, err := v.Validate(t.Context(), Target{
		Kind: KindRepository, RepositoryURL: "https://evil.example/repo.git",
	})
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("err = %v, want ErrInvalidTarget", err)
	}
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Errorf("error does not wrap ErrBlockedAddress: %v", err)
	}
}

func TestValidateEndpointSSRF(t *testing.T) {
	blocked := Validator{WorkspaceRoot: t.TempDir(), Resolver: fakeResolver{ip: "127.0.0.1"}}
	if _, err := blocked.Validate(t.Context(), Target{
		Kind: KindEndpoint, EndpointURL: "http://localtest.me/api",
	}); !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("loopback endpoint accepted: %v", err)
	}

	// Self-hosted deployments may legitimately scan internal endpoints, but
	// only when that is switched on deliberately.
	allowed := Validator{
		WorkspaceRoot: t.TempDir(),
		Resolver:      fakeResolver{ip: "10.0.0.5"},
		NetworkPolicy: netguard.Policy{AllowPrivate: true},
	}
	if _, err := allowed.Validate(t.Context(), Target{
		Kind: KindEndpoint, EndpointURL: "https://internal.corp/api",
	}); err != nil {
		t.Errorf("AllowPrivate endpoint rejected: %v", err)
	}
}

func TestValidateEndpointRejects(t *testing.T) {
	v := testValidator(t)
	for _, raw := range []string{"", "ftp://example.com", "file:///etc/passwd", "https:///nohost", "gopher://example.com"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := v.Validate(t.Context(), Target{Kind: KindEndpoint, EndpointURL: raw}); !errors.Is(err, ErrInvalidTarget) {
				t.Errorf("err = %v, want ErrInvalidTarget", err)
			}
		})
	}
}

func TestValidateFilesystemContainment(t *testing.T) {
	root := t.TempDir()
	v := Validator{WorkspaceRoot: root}

	got, err := v.Validate(t.Context(), Target{Kind: KindFilesystem, Path: "repo/src"})
	if err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
	want := filepath.Join(root, "repo", "src")
	if got.Path != want {
		t.Errorf("path = %q, want %q", got.Path, want)
	}
}

// Every one of these must resolve inside the workspace or be refused. Escaping
// the workspace would let a scan read the worker's own filesystem (§14.5).
func TestValidateFilesystemRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	v := Validator{WorkspaceRoot: root}

	for _, p := range []string{
		"../etc/passwd",
		"../../../../etc/passwd",
		"repo/../../outside",
		"/etc/passwd",
		"./../../secrets",
		"repo/./../../..",
	} {
		t.Run(p, func(t *testing.T) {
			got, err := v.Validate(t.Context(), Target{Kind: KindFilesystem, Path: p})
			if err != nil {
				return // rejected outright, which is fine
			}
			// If it was accepted, it must have been clamped inside the root.
			rel, relErr := filepath.Rel(root, got.Path)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Errorf("path %q escaped the workspace: %q", p, got.Path)
			}
		})
	}
}

func TestValidateFilesystemRequiresRoot(t *testing.T) {
	if _, err := (Validator{}).Validate(t.Context(), Target{Kind: KindFilesystem, Path: "x"}); !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("missing workspace root accepted: %v", err)
	}
	if _, err := (Validator{WorkspaceRoot: t.TempDir()}).Validate(t.Context(), Target{Kind: KindFilesystem}); !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("empty path accepted: %v", err)
	}
}

func TestValidateImage(t *testing.T) {
	v := testValidator(t)

	for _, img := range []string{
		"alpine:3.20",
		"ghcr.io/aizen299/secureops-api:v1.2.3",
		"postgres@sha256:abc123",
	} {
		t.Run("valid/"+img, func(t *testing.T) {
			if _, err := v.Validate(t.Context(), Target{Kind: KindImage, Image: img}); err != nil {
				t.Errorf("valid image rejected: %v", err)
			}
		})
	}

	for _, img := range []string{
		"", "alpine; rm -rf /", "alpine$(id)", "alpine`id`", "alpine|cat", "alpine\nrm", "alpine 3.20",
	} {
		t.Run("invalid/"+img, func(t *testing.T) {
			if _, err := v.Validate(t.Context(), Target{Kind: KindImage, Image: img}); !errors.Is(err, ErrInvalidTarget) {
				t.Errorf("err = %v, want ErrInvalidTarget", err)
			}
		})
	}
}

// An image reference names a host to connect to, exactly as a repository URL
// does. Until an adapter served this kind the omission was inert; ADR 025 makes
// it reachable, and §14.6 requires the check.
func TestValidateImageBlocksInternalRegistries(t *testing.T) {
	// Every literal here is an address the policy blocks on sight, so no
	// resolution is involved and the resolver's answer is irrelevant.
	v := Validator{WorkspaceRoot: t.TempDir(), Resolver: fakeResolver{ip: "93.184.216.34"}}

	for _, img := range []string{
		"127.0.0.1:5000/app:1",
		"10.0.0.5:5000/app",
		"192.168.1.10/app:latest",
		"172.16.0.1:443/app",
		// The cloud metadata endpoint, which is the reason link-local is
		// blocked rather than merely discouraged.
		"169.254.169.254/latest/meta-data",
	} {
		t.Run(img, func(t *testing.T) {
			_, err := v.Validate(t.Context(), Target{Kind: KindImage, Image: img})
			if !errors.Is(err, ErrInvalidTarget) {
				t.Errorf("err = %v, want ErrInvalidTarget for an internal registry", err)
			}
		})
	}

	// A name is no safer than a literal: what matters is where it resolves.
	loopback := Validator{WorkspaceRoot: t.TempDir(), Resolver: fakeResolver{ip: "127.0.0.1"}}
	for _, img := range []string{"registry.internal/app:1", "localhost:5000/app"} {
		t.Run("resolves-to-loopback/"+img, func(t *testing.T) {
			_, err := loopback.Validate(t.Context(), Target{Kind: KindImage, Image: img})
			if !errors.Is(err, ErrInvalidTarget) {
				t.Errorf("err = %v, want ErrInvalidTarget", err)
			}
		})
	}
}

// The default registry still reaches the network, so a reference naming no host
// is checked against the host it will actually use.
func TestValidateImageChecksTheDefaultRegistry(t *testing.T) {
	blocked := Validator{WorkspaceRoot: t.TempDir(), Resolver: fakeResolver{ip: "127.0.0.1"}}
	if _, err := blocked.Validate(t.Context(), Target{Kind: KindImage, Image: "alpine:3.20"}); !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("err = %v: a bare reference must still be checked against %s",
			err, DefaultRegistryHost)
	}
}

func TestRegistryHost(t *testing.T) {
	cases := map[string]string{
		// No registry component: these are all on the default registry, and
		// "library" is a path rather than a host because it has no dot.
		"alpine":             DefaultRegistryHost,
		"alpine:3.9":         DefaultRegistryHost,
		"library/alpine:3.9": DefaultRegistryHost,
		"org/app@sha256:abc": DefaultRegistryHost,
		// A dot, a colon, or the literal "localhost" makes it a registry.
		"ghcr.io/org/app:1":    "ghcr.io",
		"registry.io:5000/app": "registry.io",
		"localhost:5000/app":   "localhost",
		"localhost/app":        "localhost",
		"127.0.0.1:5000/app":   "127.0.0.1",
	}
	for in, want := range cases {
		got, err := RegistryHost(in)
		if err != nil {
			t.Errorf("RegistryHost(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("RegistryHost(%q) = %q, want %q", in, got, want)
		}
	}

	if _, err := RegistryHost("   "); !errors.Is(err, ErrUnparseableImage) {
		t.Errorf("err = %v, want ErrUnparseableImage", err)
	}
}

// A ".." in an image reference is malformed rather than merely unusual, and the
// repository half of a reference ends up in a fingerprint.
func TestValidateImageRejectsDotDot(t *testing.T) {
	v := testValidator(t)
	if _, err := v.Validate(t.Context(), Target{Kind: KindImage, Image: "ghcr.io/org/../app"}); !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("err = %v, want ErrInvalidTarget", err)
	}
}
