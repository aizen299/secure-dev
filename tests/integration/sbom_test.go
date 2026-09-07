//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/aizen299/secure-dev/internal/sbom"
	sbomstore "github.com/aizen299/secure-dev/internal/sbom/store"
)

// An inventory round-trips through the real schema.
//
// Against a live database rather than a fake, because everything interesting
// here is the schema's: the CHECK constraints that bound attacker-influenced
// text, the CopyFrom path that a loop of INSERTs would have hidden, and the
// cascade that ties a component's lifetime to its scan.
func TestComponentsRoundTrip(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	scanID, projectID := seedScan(t, pool)
	store := sbomstore.New(pool)

	components := []sbom.Component{
		{PURL: "pkg:pypi/flask@3.0.0", Name: "flask", Version: "3.0.0",
			Type: "library", CPE: "cpe:2.3:a:x:x:3.0.0:*:*:*:*:*:*:*", Location: "/requirements.txt"},
		{PURL: "pkg:golang/github.com/gorilla/mux@v1.8.1", Name: "github.com/gorilla/mux",
			Version: "v1.8.1", Type: "library", Location: "/go.mod"},
		// The one syft could not name. Stored rather than dropped: an inventory
		// that omits what it could not identify is incomplete without saying so.
		{Name: "unidentified", Type: "library"},
	}

	if err := store.RecordScan(ctx, scanID, projectID, "syft", components); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	got, hasMore, err := store.ByScan(ctx, scanID, sbom.Page{Limit: 50})
	if err != nil {
		t.Fatalf("ByScan: %v", err)
	}
	if hasMore {
		t.Error("hasMore = true for three components in a page of fifty")
	}
	if len(got) != 3 {
		t.Fatalf("components = %d, want 3", len(got))
	}

	byName := map[string]sbom.Record{}
	for _, c := range got {
		byName[c.Name] = c
	}

	flask := byName["flask"]
	if flask.PURL != "pkg:pypi/flask@3.0.0" {
		t.Errorf("purl = %q, want it preserved byte for byte: it is the correlation key", flask.PURL)
	}
	if flask.Location != "/requirements.txt" {
		t.Errorf("location = %q, want /requirements.txt", flask.Location)
	}
	if flask.Scanner != "syft" {
		t.Errorf("scanner = %q, want syft: an inventory that cannot say where a component came from cannot be reconciled", flask.Scanner)
	}
	if byName["unidentified"].PURL != "" {
		t.Errorf("purl = %q, want empty for a component with none", byName["unidentified"].PURL)
	}
}

// Re-recording a scan replaces its inventory rather than appending to it.
//
// The property that makes reprocessing safe. Without it, replaying a scan's
// stored output would double every component and describe a project that never
// existed.
func TestRecordingAScanTwiceReplacesTheInventory(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	scanID, projectID := seedScan(t, pool)
	store := sbomstore.New(pool)

	first := []sbom.Component{
		{PURL: "pkg:pypi/one@1.0.0", Name: "one", Version: "1.0.0"},
		{PURL: "pkg:pypi/two@2.0.0", Name: "two", Version: "2.0.0"},
	}
	if err := store.RecordScan(ctx, scanID, projectID, "syft", first); err != nil {
		t.Fatalf("first RecordScan: %v", err)
	}

	second := []sbom.Component{{PURL: "pkg:pypi/three@3.0.0", Name: "three", Version: "3.0.0"}}
	if err := store.RecordScan(ctx, scanID, projectID, "syft", second); err != nil {
		t.Fatalf("second RecordScan: %v", err)
	}

	got, _, err := store.ByScan(ctx, scanID, sbom.Page{Limit: 50})
	if err != nil {
		t.Fatalf("ByScan: %v", err)
	}
	if len(got) != 1 || got[0].Name != "three" {
		names := make([]string, 0, len(got))
		for _, c := range got {
			names = append(names, c.Name)
		}
		t.Errorf("components = %v, want only the second recording: an inventory that grows on replay describes no real build", names)
	}
}

// A project's inventory is its latest scan's, and a scan with no components
// does not become the answer.
//
// The case this guards: an endpoint scan runs only ZAP and produces no SBOM.
// If "latest scan" meant "latest scan of any kind", scanning a project's
// website would erase the inventory its repository scan built.
func TestAProjectsInventoryIsItsLatestScanWithComponents(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	store := sbomstore.New(pool)

	firstScan, projectID := seedScan(t, pool)
	if err := store.RecordScan(ctx, firstScan, projectID, "syft", []sbom.Component{
		{PURL: "pkg:pypi/old@1.0.0", Name: "old", Version: "1.0.0"},
	}); err != nil {
		t.Fatalf("first RecordScan: %v", err)
	}

	// A later scan of the same project that produced nothing -- a website scan.
	laterScan := seedScanFor(t, pool, projectID)
	if err := store.RecordScan(ctx, laterScan, projectID, "syft", nil); err != nil {
		t.Fatalf("empty RecordScan: %v", err)
	}

	got, _, err := store.ByProject(ctx, projectID, sbom.Page{Limit: 50})
	if err != nil {
		t.Fatalf("ByProject: %v", err)
	}
	if len(got) != 1 || got[0].Name != "old" {
		t.Errorf("components = %+v, want the last scan that actually produced an inventory", got)
	}
}

// Deleting a scan takes its inventory with it.
//
// The cascade is deliberate and differs from audit_logs, which survives what it
// describes: an audit record is evidence about an action, while an inventory of
// a scan that no longer exists describes nothing.
func TestComponentsDieWithTheirScan(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	scanID, projectID := seedScan(t, pool)
	store := sbomstore.New(pool)

	if err := store.RecordScan(ctx, scanID, projectID, "syft", []sbom.Component{
		{PURL: "pkg:pypi/doomed@1.0.0", Name: "doomed", Version: "1.0.0"},
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM scans WHERE id = $1`, scanID); err != nil {
		t.Fatalf("delete scan: %v", err)
	}

	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM sbom_components WHERE scan_id = $1`, scanID).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 0 {
		t.Errorf("components = %d, want 0: an inventory must not outlive its scan", remaining)
	}
}

// The database bounds what the parser clamps.
//
// Both layers exist on purpose (ADR 035 §4): the parser truncates so a strange
// manifest does not lose a whole inventory, and the constraint is the backstop
// for anything that reaches the store another way.
func TestTheSchemaRefusesAnOverlongName(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	scanID, projectID := seedScan(t, pool)

	huge := make([]byte, sbom.MaxNameLength+1)
	for i := range huge {
		huge[i] = 'a'
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO sbom_components (scan_id, project_id, name, scanner)
		VALUES ($1, $2, $3, 'syft')`, scanID, projectID, string(huge))
	if err == nil {
		t.Error("the schema accepted a name past its CHECK constraint; the parser's clamp would be the only bound")
	}
}
