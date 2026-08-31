package projects_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/projects"
)

func TestNormalizeAppliesDefaults(t *testing.T) {
	got, err := projects.NewProject{Name: "Payments API"}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}

	if got.Slug != "payments-api" {
		t.Errorf("Slug = %q, want %q", got.Slug, "payments-api")
	}
	// The safe defaults are the low-risk ones: a project is assumed to be
	// development and not internet-facing until someone says otherwise.
	if got.Environment != projects.EnvDevelopment {
		t.Errorf("Environment = %q, want %q", got.Environment, projects.EnvDevelopment)
	}
	if got.Criticality != projects.CriticalityMedium {
		t.Errorf("Criticality = %q, want %q", got.Criticality, projects.CriticalityMedium)
	}
	if got.InternetFacing {
		t.Error("InternetFacing should default to false")
	}
}

func TestNormalizeTrimsAndPreservesExplicitValues(t *testing.T) {
	got, err := projects.NewProject{
		Name:           "  Billing  ",
		Slug:           "  billing-core  ",
		Description:    "  handles invoices  ",
		Environment:    projects.EnvProduction,
		Criticality:    projects.CriticalityCritical,
		InternetFacing: true,
	}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}

	if got.Name != "Billing" {
		t.Errorf("Name = %q, want %q", got.Name, "Billing")
	}
	if got.Slug != "billing-core" {
		t.Errorf("Slug = %q, want %q", got.Slug, "billing-core")
	}
	if got.Description != "handles invoices" {
		t.Errorf("Description = %q, want %q", got.Description, "handles invoices")
	}
	if got.Environment != projects.EnvProduction || got.Criticality != projects.CriticalityCritical {
		t.Errorf("explicit risk inputs were not preserved: %+v", got)
	}
	if !got.InternetFacing {
		t.Error("InternetFacing = false, want true")
	}
}

func TestNormalizeRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input projects.NewProject
	}{
		{"empty name", projects.NewProject{Name: ""}},
		{"whitespace name", projects.NewProject{Name: "   "}},
		{"name too long", projects.NewProject{Name: strings.Repeat("a", projects.MaxNameLength+1)}},
		{"name with newline", projects.NewProject{Name: "billing\nadmin"}},
		{"name with carriage return", projects.NewProject{Name: "billing\radmin"}},
		{"name with NUL", projects.NewProject{Name: "billing\x00"}},
		{"description too long", projects.NewProject{
			Name:        "ok",
			Description: strings.Repeat("a", projects.MaxDescriptionLength+1),
		}},
		{"description with NUL", projects.NewProject{Name: "ok", Description: "a\x00b"}},
		{"undeviable slug", projects.NewProject{Name: "***"}},
		{"uppercase slug", projects.NewProject{Name: "ok", Slug: "Billing"}},
		{"slug with underscore", projects.NewProject{Name: "ok", Slug: "billing_core"}},
		{"slug with double hyphen", projects.NewProject{Name: "ok", Slug: "billing--core"}},
		{"slug with leading hyphen", projects.NewProject{Name: "ok", Slug: "-billing"}},
		{"slug with trailing hyphen", projects.NewProject{Name: "ok", Slug: "billing-"}},
		{"slug with slash", projects.NewProject{Name: "ok", Slug: "billing/core"}},
		{"slug too long", projects.NewProject{
			Name: "ok",
			Slug: strings.Repeat("a", projects.MaxSlugLength+1),
		}},
		{"unknown environment", projects.NewProject{Name: "ok", Environment: "prod"}},
		{"unknown criticality", projects.NewProject{Name: "ok", Criticality: "extreme"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.input.Normalize(); !errors.Is(err, projects.ErrInvalidProject) {
				t.Fatalf("Normalize: error = %v, want ErrInvalidProject", err)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Payments API", "payments-api"},
		{"payments", "payments"},
		{"  Leading and trailing  ", "leading-and-trailing"},
		{"Multiple   spaces", "multiple-spaces"},
		{"under_scores", "under-scores"},
		{"dots.and/slashes", "dots-and-slashes"},
		{"Mixed-CASE-99", "mixed-case-99"},
		{"---hyphens---", "hyphens"},
		{"***", ""},
		{"", ""},
		// Non-ASCII reduces rather than transliterating: the result stays
		// predictable in a URL, and an empty result is caught by Normalize.
		{"café", "caf"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := projects.Slugify(tc.in); got != tc.want {
				t.Errorf("Slugify(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A derived slug must satisfy the same constraint an explicit one does,
// including the length cap, or Normalize would reject its own output.
func TestSlugifyOutputAlwaysSatisfiesNormalize(t *testing.T) {
	names := []string{
		"A very long project name that certainly exceeds the slug length limit by a wide margin indeed",
		"trailing hyphen at the cut point aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-",
		"...leading dots",
		"99 bottles",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			got, err := projects.NewProject{Name: name}.Normalize()
			if err != nil {
				t.Fatalf("Normalize(%q): unexpected error: %v", name, err)
			}
			if len(got.Slug) > projects.MaxSlugLength {
				t.Errorf("derived slug is %d characters, over the %d limit: %q",
					len(got.Slug), projects.MaxSlugLength, got.Slug)
			}
		})
	}
}

// The Go pattern and the projects_slug_format CHECK constraint in migration
// 0001 must agree. If they drift, a slug the API accepts becomes a 500 from a
// constraint violation instead of a 400.
func TestSlugPatternMatchesTheMigrationConstraint(t *testing.T) {
	// Copied verbatim from migrations/0001_init.up.sql.
	migrationPattern := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

	cases := []string{
		"billing", "billing-core", "a", "9", "a-9-b",
		"Billing", "billing_core", "billing--core", "-billing", "billing-",
		"billing core", "", "billing/core",
	}

	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			normalized, err := projects.NewProject{Name: "placeholder", Slug: c}.Normalize()
			accepted := err == nil && normalized.Slug == c
			// An empty slug is derived rather than rejected, so it is not a
			// meaningful comparison against the constraint.
			if c == "" {
				return
			}
			if accepted != migrationPattern.MatchString(c) {
				t.Errorf("slug %q: Normalize accepted=%v, migration constraint accepted=%v",
					c, accepted, migrationPattern.MatchString(c))
			}
		})
	}
}

func TestEnvironmentAndCriticalityValidity(t *testing.T) {
	for _, e := range projects.Environments() {
		if !e.Valid() {
			t.Errorf("Environment %q should be valid", e)
		}
	}
	for _, c := range projects.Criticalities() {
		if !c.Valid() {
			t.Errorf("Criticality %q should be valid", c)
		}
	}
	if projects.Environment("prod").Valid() {
		t.Error(`Environment("prod") should not be valid`)
	}
	if projects.Criticality("").Valid() {
		t.Error(`Criticality("") should not be valid`)
	}
}
