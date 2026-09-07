package sbom

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "syft", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// Every fixture Phase 3b captured, and what each must produce.
//
// Table-driven because the interesting property is the boundary between "this
// scan did not work" and "this project has no dependencies". Those look
// identical in a component count and must never be confused: one is an error
// and the other is a legitimate inventory (ADR 012's reasoning, applied to a
// bill of materials rather than a vulnerability database).
func TestParseAgainstEveryFixture(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		wantErr bool
		want    int
		why     string
	}{
		{"valid.json", false, 2, "normal output"},
		{"with-locations.json", false, 3, "real syft shape, including one component syft could not name"},
		{"no-components.json", false, 0, "a repository with no manifests is an empty inventory, not a failure"},
		{"empty.json", true, 0, "zero bytes is a scan that did not work"},
		{"malformed.json", true, 0, "not JSON at all"},
		{"truncated.json", true, 0, "cut mid-object by a size cap or a killed process"},
		{"spdx.json", true, 0, "a different format entirely"},
		{"wrong-format.json", true, 0, "valid JSON, wrong bomFormat -- the only thing that can reject it"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			got, err := Parse(fixture(t, tc.fixture))

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse succeeded on %s (%s); a malformed SBOM stored as-is "+
						"reads later as 'few dependencies' rather than 'this did not work'",
						tc.fixture, tc.why)
				}
				if !errors.Is(err, ErrMalformed) {
					t.Errorf("error = %v, want ErrMalformed so callers can tell it apart", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Parse(%s) = %v, want success (%s)", tc.fixture, err, tc.why)
			}
			if len(got.Components) != tc.want {
				t.Errorf("components = %d, want %d (%s)", len(got.Components), tc.want, tc.why)
			}
		})
	}
}

// An empty inventory is not an error, and this is the case that says so.
//
// Called out separately from the table because it is the one a future change is
// most likely to break: treating "no components" as malformed would fail every
// scan of a repository that declares no dependencies.
func TestNoComponentsIsAnAnswerNotAFailure(t *testing.T) {
	got, err := Parse(fixture(t, "no-components.json"))
	if err != nil {
		t.Fatalf("Parse = %v, want success", err)
	}
	if len(got.Components) != 0 {
		t.Errorf("components = %d, want 0", len(got.Components))
	}
	if len(got.Degradations) != 0 {
		t.Errorf("degradations = %v, want none: an empty inventory is complete, not partial",
			got.Degradations)
	}
}

// The fields a component carries, read from real syft output.
func TestParseReadsTheFieldsThatMatter(t *testing.T) {
	got, err := Parse(fixture(t, "with-locations.json"))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	byName := map[string]Component{}
	for _, c := range got.Components {
		byName[c.Name] = c
	}

	flask, ok := byName["flask"]
	if !ok {
		t.Fatal("flask is missing from the inventory")
	}
	if flask.PURL != "pkg:pypi/flask@3.0.0" {
		t.Errorf("purl = %q, want the identity Grype and Trivy both emit", flask.PURL)
	}
	if flask.Version != "3.0.0" {
		t.Errorf("version = %q, want 3.0.0", flask.Version)
	}
	if flask.Type != "library" {
		t.Errorf("type = %q, want library", flask.Type)
	}
	if !strings.HasPrefix(flask.CPE, "cpe:2.3:") {
		t.Errorf("cpe = %q, want the CPE syft derived: some advisory sources key on it", flask.CPE)
	}
	// The question anybody asks about an unexpected dependency.
	if flask.Location != "/requirements.txt" {
		t.Errorf("location = %q, want /requirements.txt", flask.Location)
	}

	// One component, one location, even when syft found it twice. A row per
	// location would multiply the table for a detail nothing queries.
	mux, ok := byName["github.com/gorilla/mux"]
	if !ok {
		t.Fatal("gorilla/mux is missing")
	}
	if mux.Location != "/go.mod" {
		t.Errorf("location = %q, want the first: /go.mod", mux.Location)
	}
}

// A component syft could not name is still evidence of something present.
//
// Dropping it would make the inventory quietly incomplete, which is the failure
// this whole package exists to avoid.
func TestAComponentWithNoPURLIsStillStored(t *testing.T) {
	got, err := Parse(fixture(t, "with-locations.json"))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	for _, c := range got.Components {
		if c.Name == "a-package-syft-could-not-identify" {
			if c.PURL != "" {
				t.Errorf("purl = %q, want empty", c.PURL)
			}
			return
		}
	}
	t.Error("a component with no purl was dropped; an inventory that omits what it could not name is incomplete without saying so")
}

// Over the cap is a degradation, never a silent truncation.
func TestTooManyComponentsDegradesRatherThanLies(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","components":[`)
	for i := range MaxComponents + 50 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":"library","name":"pkg-%d","version":"1.0.0"}`, i)
	}
	b.WriteString(`]}`)

	got, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("Parse = %v, want a bounded success rather than a failure", err)
	}
	if len(got.Components) != MaxComponents {
		t.Errorf("components = %d, want the cap %d", len(got.Components), MaxComponents)
	}
	// The half that matters. A truncated inventory that does not say so is a
	// lie about what a project contains.
	if len(got.Degradations) == 0 {
		t.Fatal("truncated silently: the caller cannot tell a bounded inventory from a complete one")
	}
	if got.Degradations[0] != scanners.DegradedSBOMTruncated {
		t.Errorf("degradation = %q, want %q", got.Degradations[0], scanners.DegradedSBOMTruncated)
	}
}

// Hostile values are bounded here as well as in the database.
//
// Every string in an SBOM comes from a manifest inside an untrusted repository
// (§15.8). Clamping here means an absurd value is a truncated field rather than
// a failed INSERT that loses the whole scan's inventory.
func TestOverlongValuesAreClampedNotRejected(t *testing.T) {
	huge := strings.Repeat("a", MaxNameLength*3)
	doc := fmt.Sprintf(
		`{"bomFormat":"CycloneDX","components":[{"type":"library","name":%q,"version":%q,"purl":%q}]}`,
		huge, huge, huge)

	got, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse = %v, want a clamped success", err)
	}
	if len(got.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(got.Components))
	}
	c := got.Components[0]
	if len(c.Name) > MaxNameLength {
		t.Errorf("name is %d bytes, over the %d the database will accept", len(c.Name), MaxNameLength)
	}
	if len(c.Version) > MaxVersionLength {
		t.Errorf("version is %d bytes, over the %d limit", len(c.Version), MaxVersionLength)
	}
	if len(c.PURL) > MaxPURLLength {
		t.Errorf("purl is %d bytes, over the %d limit", len(c.PURL), MaxPURLLength)
	}
}

// A component with no name cannot be reported, queried or matched.
//
// Skipped rather than stored blank, and skipped rather than failing: one
// unnamed entry does not make the rest of the inventory untrustworthy.
func TestAnUnnamedComponentIsSkipped(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","components":[
		{"type":"library","name":"","version":"1.0.0"},
		{"type":"library","name":"  ","version":"1.0.0"},
		{"type":"library","name":"real","version":"1.0.0"}]}`

	got, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	if len(got.Components) != 1 || got.Components[0].Name != "real" {
		t.Errorf("components = %+v, want only the named one", got.Components)
	}
}

// Parsing is pure: the same bytes give the same components, always.
//
// The property that makes fixture testing meaningful (§8). Without it a
// component's identity could vary between two reads of one scan's output.
func TestParseIsDeterministic(t *testing.T) {
	data := fixture(t, "with-locations.json")

	first, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	for range 5 {
		again, err := Parse(data)
		if err != nil {
			t.Fatalf("Parse = %v", err)
		}
		if len(again.Components) != len(first.Components) {
			t.Fatalf("component count changed between reads: %d then %d",
				len(first.Components), len(again.Components))
		}
		for i := range first.Components {
			if again.Components[i] != first.Components[i] {
				t.Fatalf("component %d differs between reads:\n first: %+v\n again: %+v",
					i, first.Components[i], again.Components[i])
			}
		}
	}
}

// The workspace path stays the adapter's problem, and this records why.
//
// This parser cannot check for one: it never learns the workspace path, so it
// has nothing to compare against. The syft adapter does know it and fails the
// scan before any of this runs (ADR 008) -- which is why the fixture parses
// cleanly here. Asserting that it parses is not endorsing the content; it
// documents where the control actually lives, so a later reader does not add a
// guess-based path check here and believe it is the defence.
func TestTheWorkspaceLeakGuardIsNotThisPackages(t *testing.T) {
	got, err := Parse(fixture(t, "workspace-path-leak.json"))
	if err != nil {
		t.Fatalf("Parse = %v: this fixture is structurally valid CycloneDX", err)
	}
	if len(got.Components) == 0 {
		t.Fatal("expected the components to parse; the adapter is what rejects them")
	}
}
