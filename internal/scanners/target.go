// Package scanners defines the SecureOps scanner contract.
//
// This root package holds the abstraction only: the Scanner interface, the
// Target model, the registry, and the safe-execution helpers every adapter
// uses. Scanner-specific knowledge lives exclusively in the adapter
// subpackages (CLAUDE.md §7). Nothing here may import an adapter, and nothing
// here may branch on a scanner's name.
package scanners

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aizen299/secure-dev/internal/netguard"
)

// ErrInvalidTarget reports that a target failed validation.
var ErrInvalidTarget = errors.New("invalid target")

// Kind enumerates what a scan can point at. Adapters declare which kinds they
// support through capabilities, so the core never asks "which scanner is this?"
type Kind string

const (
	KindRepository Kind = "repository" // a git repository
	KindFilesystem Kind = "filesystem" // a directory inside the worker workspace
	KindImage      Kind = "image"      // a container image reference
	KindEndpoint   Kind = "endpoint"   // an HTTP endpoint, for DAST
)

// Kinds lists every valid target kind.
func Kinds() []Kind {
	return []Kind{KindRepository, KindFilesystem, KindImage, KindEndpoint}
}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	for _, known := range Kinds() {
		if k == known {
			return true
		}
	}
	return false
}

// Target describes what to scan. It is serialised into queue payloads, so it
// must stay plain data: no commands, no scripts, nothing executable.
type Target struct {
	Kind Kind `json:"kind"`

	// Repository
	RepositoryURL string `json:"repository_url,omitempty"`
	Ref           string `json:"ref,omitempty"`

	// Filesystem: always relative to the worker's workspace root.
	Path string `json:"path,omitempty"`

	// Image
	Image string `json:"image,omitempty"`

	// Endpoint
	EndpointURL string `json:"endpoint_url,omitempty"`
}

// Every one of these values is passed to a scanner as an argv element. A value
// beginning with "-" would be parsed by the scanner as a flag rather than as
// data, which turns a target string into attacker-controlled scanner options.
// Rejecting leading dashes is what closes that hole; see also ExecOptions,
// which forbids shell invocation entirely.
var (
	refPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/\-]{0,254}$`)
	imagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@\-]{0,254}$`)
)

// Validator checks targets against deployment policy.
type Validator struct {
	// WorkspaceRoot bounds every filesystem target. Required.
	WorkspaceRoot string
	// NetworkPolicy governs SSRF checks for repository and endpoint targets.
	NetworkPolicy netguard.Policy
	// Resolver performs DNS lookups. Defaults to the system resolver.
	Resolver netguard.Resolver
}

// Validate checks t and returns a normalised copy.
//
// Validation is deliberately allow-list based: anything not explicitly
// permitted is rejected, because the input is attacker-controlled (§15.7).
func (v Validator) Validate(ctx context.Context, t Target) (Target, error) {
	if !t.Kind.Valid() {
		return Target{}, fmt.Errorf("%w: unknown kind %q", ErrInvalidTarget, t.Kind)
	}

	switch t.Kind {
	case KindRepository:
		return v.validateRepository(ctx, t)
	case KindFilesystem:
		return v.validateFilesystem(t)
	case KindImage:
		return v.validateImage(t)
	case KindEndpoint:
		return v.validateEndpoint(ctx, t)
	default:
		return Target{}, fmt.Errorf("%w: unhandled kind %q", ErrInvalidTarget, t.Kind)
	}
}

func (v Validator) validateRepository(ctx context.Context, t Target) (Target, error) {
	if t.RepositoryURL == "" {
		return Target{}, fmt.Errorf("%w: repository_url is required", ErrInvalidTarget)
	}

	u, err := url.Parse(t.RepositoryURL)
	if err != nil {
		return Target{}, fmt.Errorf("%w: repository_url is not a valid URL", ErrInvalidTarget)
	}
	// Only https and ssh. Notably absent: file:// (would read the worker's own
	// filesystem) and git:// (unauthenticated and unencrypted).
	switch u.Scheme {
	case "https", "ssh":
	default:
		return Target{}, fmt.Errorf("%w: repository_url scheme must be https or ssh, got %q", ErrInvalidTarget, u.Scheme)
	}
	if u.Hostname() == "" {
		return Target{}, fmt.Errorf("%w: repository_url is missing a host", ErrInvalidTarget)
	}
	if err := v.checkHost(ctx, u.Hostname()); err != nil {
		return Target{}, err
	}

	if t.Ref != "" && !refPattern.MatchString(t.Ref) {
		// The message must not echo the value: it is attacker-controlled and
		// ends up in logs.
		return Target{}, fmt.Errorf("%w: ref contains characters that are not permitted", ErrInvalidTarget)
	}
	// ".." in a ref would escape the checkout path when used as a directory
	// component, and is never valid in a git ref name anyway.
	if strings.Contains(t.Ref, "..") {
		return Target{}, fmt.Errorf("%w: ref must not contain '..'", ErrInvalidTarget)
	}

	return Target{Kind: KindRepository, RepositoryURL: u.String(), Ref: t.Ref}, nil
}

func (v Validator) validateFilesystem(t Target) (Target, error) {
	if v.WorkspaceRoot == "" {
		return Target{}, fmt.Errorf("%w: validator has no workspace root configured", ErrInvalidTarget)
	}
	if t.Path == "" {
		return Target{}, fmt.Errorf("%w: path is required", ErrInvalidTarget)
	}

	root, err := filepath.Abs(v.WorkspaceRoot)
	if err != nil {
		return Target{}, fmt.Errorf("%w: workspace root is not resolvable", ErrInvalidTarget)
	}

	// Join cleans the path, collapsing any "..", so traversal cannot escape by
	// construction. The containment check below is belt and braces.
	joined := filepath.Join(root, filepath.Clean("/"+t.Path))

	rel, err := filepath.Rel(root, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return Target{}, fmt.Errorf("%w: path escapes the workspace", ErrInvalidTarget)
	}

	return Target{Kind: KindFilesystem, Path: joined}, nil
}

func (v Validator) validateImage(t Target) (Target, error) {
	if t.Image == "" {
		return Target{}, fmt.Errorf("%w: image is required", ErrInvalidTarget)
	}
	if !imagePattern.MatchString(t.Image) {
		return Target{}, fmt.Errorf("%w: image reference contains characters that are not permitted", ErrInvalidTarget)
	}
	return Target{Kind: KindImage, Image: t.Image}, nil
}

func (v Validator) validateEndpoint(ctx context.Context, t Target) (Target, error) {
	if t.EndpointURL == "" {
		return Target{}, fmt.Errorf("%w: endpoint_url is required", ErrInvalidTarget)
	}

	u, err := url.Parse(t.EndpointURL)
	if err != nil {
		return Target{}, fmt.Errorf("%w: endpoint_url is not a valid URL", ErrInvalidTarget)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return Target{}, fmt.Errorf("%w: endpoint_url scheme must be http or https, got %q", ErrInvalidTarget, u.Scheme)
	}
	if u.Hostname() == "" {
		return Target{}, fmt.Errorf("%w: endpoint_url is missing a host", ErrInvalidTarget)
	}
	if err := v.checkHost(ctx, u.Hostname()); err != nil {
		return Target{}, err
	}

	return Target{Kind: KindEndpoint, EndpointURL: u.String()}, nil
}

func (v Validator) checkHost(ctx context.Context, host string) error {
	resolver := v.Resolver
	if resolver == nil {
		resolver = defaultResolver{}
	}
	if err := v.NetworkPolicy.CheckHost(ctx, resolver, host); err != nil {
		// Wrap both sentinels: callers distinguish "bad input" from "blocked
		// destination", and the second is what an operator needs to see.
		return fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	return nil
}
