// Package projects owns the project entity.
//
// A project is the unit of security context. Its environment, criticality, and
// internet exposure are inputs to the risk engine (CLAUDE.md §10), which is why
// they are first-class validated fields rather than free-form metadata: a risk
// multiplier derived from an unvalidated string is a risk multiplier nobody can
// reason about.
package projects

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ErrInvalidProject reports that a project failed validation.
var ErrInvalidProject = errors.New("invalid project")

// ErrNotFound reports that no project matched.
var ErrNotFound = errors.New("project not found")

// ErrSlugTaken reports a collision on the unique slug.
var ErrSlugTaken = errors.New("project slug is already in use")

// Environment is the deployment context. A finding in production is not
// equivalent to the same finding in a sandbox (§10).
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// Environments lists every valid environment.
func Environments() []Environment {
	return []Environment{EnvDevelopment, EnvStaging, EnvProduction}
}

// Valid reports whether e is a known environment.
func (e Environment) Valid() bool {
	for _, known := range Environments() {
		if e == known {
			return true
		}
	}
	return false
}

// Criticality is the asset criticality multiplier input (§10).
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// Criticalities lists every valid criticality.
func Criticalities() []Criticality {
	return []Criticality{CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical}
}

// Valid reports whether c is a known criticality.
func (c Criticality) Valid() bool {
	for _, known := range Criticalities() {
		if c == known {
			return true
		}
	}
	return false
}

// Field bounds. Every external input is size-capped before it reaches the
// database (§15.8); the database constraints are the second line, not the
// first, so that a rejection is a 400 with a clear message rather than a 500
// from a constraint violation.
const (
	MaxNameLength        = 128
	MaxSlugLength        = 64
	MaxDescriptionLength = 1024
)

// slugPattern mirrors the projects_slug_format CHECK constraint in
// migration 0001. The two must agree; the test asserts the shared cases.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Project is a durable project record.
type Project struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Slug           string      `json:"slug"`
	Description    string      `json:"description"`
	Environment    Environment `json:"environment"`
	Criticality    Criticality `json:"criticality"`
	InternetFacing bool        `json:"internet_facing"`
	// Archived hides the project from lists. Its scans, findings and history
	// remain readable -- archiving is not deleting (ADR 033 §6, §17).
	Archived bool `json:"archived"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewProject is the validated input for creating a project.
//
// It is a separate type from Project on purpose: the fields a client may set
// are not the fields a project has. Server-assigned values (id, timestamps)
// have no place in a request body.
type NewProject struct {
	Name           string
	Slug           string
	Description    string
	Environment    Environment
	Criticality    Criticality
	InternetFacing bool
}

// Normalize validates the input and returns a canonical copy.
//
// Defaults are applied here rather than in the database so that the value the
// API echoes back is the value that was stored.
func (n NewProject) Normalize() (NewProject, error) {
	out := NewProject{
		Name:           strings.TrimSpace(n.Name),
		Slug:           strings.TrimSpace(n.Slug),
		Description:    strings.TrimSpace(n.Description),
		Environment:    n.Environment,
		Criticality:    n.Criticality,
		InternetFacing: n.InternetFacing,
	}

	if out.Name == "" {
		return NewProject{}, fmt.Errorf("%w: name is required", ErrInvalidProject)
	}
	if len(out.Name) > MaxNameLength {
		return NewProject{}, fmt.Errorf("%w: name must be at most %d characters", ErrInvalidProject, MaxNameLength)
	}
	if strings.ContainsAny(out.Name, "\x00\r\n") {
		// Control characters in a name end up in logs and reports, where a
		// newline can forge a second log line.
		return NewProject{}, fmt.Errorf("%w: name must not contain control characters", ErrInvalidProject)
	}
	if len(out.Description) > MaxDescriptionLength {
		return NewProject{}, fmt.Errorf(
			"%w: description must be at most %d characters", ErrInvalidProject, MaxDescriptionLength)
	}
	if strings.ContainsRune(out.Description, '\x00') {
		// PostgreSQL text cannot hold a NUL byte; rejecting it here turns a
		// driver-level failure into a clear validation error.
		return NewProject{}, fmt.Errorf("%w: description must not contain a NUL byte", ErrInvalidProject)
	}

	if out.Slug == "" {
		out.Slug = Slugify(out.Name)
	}
	if out.Slug == "" {
		// Reachable when the name is entirely non-alphanumeric, e.g. "***".
		return NewProject{}, fmt.Errorf(
			"%w: slug could not be derived from the name; supply one explicitly", ErrInvalidProject)
	}
	if len(out.Slug) > MaxSlugLength {
		return NewProject{}, fmt.Errorf("%w: slug must be at most %d characters", ErrInvalidProject, MaxSlugLength)
	}
	if !slugPattern.MatchString(out.Slug) {
		return NewProject{}, fmt.Errorf(
			"%w: slug must be lowercase alphanumeric words separated by single hyphens", ErrInvalidProject)
	}

	if out.Environment == "" {
		out.Environment = EnvDevelopment
	}
	if !out.Environment.Valid() {
		// The value is echoed because it is a closed enum: an invalid one is a
		// client mistake worth naming, and it cannot carry a payload past the
		// JSON encoder.
		return NewProject{}, fmt.Errorf(
			"%w: environment %q is not one of development, staging, production",
			ErrInvalidProject, out.Environment)
	}

	if out.Criticality == "" {
		out.Criticality = CriticalityMedium
	}
	if !out.Criticality.Valid() {
		return NewProject{}, fmt.Errorf(
			"%w: criticality %q is not one of low, medium, high, critical",
			ErrInvalidProject, out.Criticality)
	}

	return out, nil
}

// Slugify derives a URL-safe slug from a project name.
//
// It is deliberately lossy and ASCII-only: a slug appears in URLs and report
// filenames, so predictability matters more than fidelity. A name that reduces
// to nothing yields "", and the caller must then require an explicit slug.
func Slugify(name string) string {
	var b strings.Builder
	b.Grow(len(name))

	lastHyphen := true // leading hyphens are suppressed
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastHyphen = false
		case !lastHyphen:
			// Any run of other characters collapses to one hyphen.
			b.WriteByte('-')
			lastHyphen = true
		}
	}

	slug := strings.Trim(b.String(), "-")
	if len(slug) > MaxSlugLength {
		slug = strings.Trim(slug[:MaxSlugLength], "-")
	}
	return slug
}
