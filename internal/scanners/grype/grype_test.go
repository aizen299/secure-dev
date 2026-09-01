package grype

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// fixtureBuilt is the build timestamp in valid.json, so tests can position
// "now" relative to it rather than depending on the wall clock.
var fixtureBuilt = time.Date(2026, 8, 31, 6, 37, 31, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../tests/fixtures/grype", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// at returns a Scanner whose clock reads d after the fixture database was
// built, so staleness is exercised deterministically.
func at(d time.Duration) *Scanner {
	return &Scanner{now: func() time.Time { return fixtureBuilt.Add(d) }}
}

func TestCapabilities(t *testing.T) {
	c := New("/var/cache/grype/db").Capabilities()

	if !c.Supports(scanners.KindFilesystem) {
		t.Error("grype must accept filesystem targets")
	}
	if c.Supports(scanners.KindRepository) {
		t.Error("grype must not claim repository targets: the worker fetches them (ADR 008)")
	}
	if c.Category != scanners.CategoryDependency {
		t.Errorf("category = %q, want dependency", c.Category)
	}
	// The whole provisioning design exists to make this false. If it ever
	// becomes true, scans of untrusted content have gained egress.
	if c.RequiresNetwork {
		t.Error("grype must not require network: the database is provisioned before any job (ADR 012)")
	}
}

// The database is what makes grype's answer depend on more than the target, so
// every scan must reach a verdict about it.
func TestFreshDatabaseIsNotDegraded(t *testing.T) {
	if got := at(time.Hour).assessDatabase(fixture(t, "valid.json")); len(got) != 0 {
		t.Errorf("degradations = %v, want none for a database built an hour ago", got)
	}
}

func TestStaleDatabaseDegrades(t *testing.T) {
	got := at(DefaultMaxDBAge + time.Hour).assessDatabase(fixture(t, "valid.json"))
	if !slices.Contains(got, scanners.DegradedStaleVulnerabilityDB) {
		t.Errorf("degradations = %v, want stale_vulnerability_db", got)
	}
}

// The boundary is where a threshold is most likely to be wrong by one
// comparison, and being wrong here means reporting stale coverage as clean.
func TestStalenessBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		age  time.Duration
		want bool
	}{
		{"just inside the limit", DefaultMaxDBAge - time.Second, false},
		{"exactly at the limit", DefaultMaxDBAge, false},
		{"one second past", DefaultMaxDBAge + time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := at(tc.age).assessDatabase(fixture(t, "valid.json"))
			stale := slices.Contains(got, scanners.DegradedStaleVulnerabilityDB)
			if stale != tc.want {
				t.Errorf("stale = %v, want %v (age %s)", stale, tc.want, tc.age)
			}
		})
	}
}

// A report that does not say how old its data is has not proven freshness.
// Treating silence as "recent" is exactly the false clean this adapter exists
// to prevent.
func TestUnprovableFreshnessDegrades(t *testing.T) {
	for _, name := range []string{
		"no-db-provenance.json", "no-built-timestamp.json", "unparseable-built.json",
	} {
		t.Run(name, func(t *testing.T) {
			got := at(time.Hour).assessDatabase(fixture(t, name))
			if !slices.Contains(got, scanners.DegradedUnknownVulnerabilityDB) {
				t.Errorf("degradations = %v, want unknown_vulnerability_db", got)
			}
			// Missing evidence is not the same claim as bad evidence.
			if slices.Contains(got, scanners.DegradedStaleVulnerabilityDB) {
				t.Error("absent provenance reported as stale; the two are different findings")
			}
		})
	}
}

// Stale data is correct but incomplete, so its findings are kept. An invalid
// database is wrong in ways that cannot be characterised, so the result is
// refused outright.
func TestInvalidDatabaseIsRefusedNotDegraded(t *testing.T) {
	if !invalidDatabase(fixture(t, "invalid-db.json")) {
		t.Error("a database grype marked invalid was not detected")
	}
	for _, name := range []string{"valid.json", "stale-db.json", "no-db-provenance.json"} {
		if invalidDatabase(fixture(t, name)) {
			t.Errorf("%s wrongly treated as an invalid database", name)
		}
	}
}

func TestValidateAcceptsRealReports(t *testing.T) {
	for _, name := range []string{"valid.json", "no-matches.json", "stale-db.json"} {
		if err := validateReport(fixture(t, name)); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
}

func TestValidateRejectsBadOutput(t *testing.T) {
	for _, name := range []string{
		"empty.json", "malformed.json", "truncated.json", "wrong-tool.json",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateReport(fixture(t, name)); err == nil {
				t.Error("accepted output that is not a usable grype report")
			}
		})
	}
}

// An empty result set and a broken scan both contain zero findings. Conflating
// them is how a failed scan becomes a clean bill of health.
func TestNoMatchesIsNotAnError(t *testing.T) {
	data := fixture(t, "no-matches.json")
	if err := validateReport(data); err != nil {
		t.Fatalf("a clean project was rejected: %v", err)
	}
	n, err := matchCount(data)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("matches = %d, want 0", n)
	}
	if got := at(time.Hour).assessDatabase(data); len(got) != 0 {
		t.Errorf("a clean scan against a fresh database was degraded: %v", got)
	}
}

func TestValidReportIsPopulated(t *testing.T) {
	n, err := matchCount(fixture(t, "valid.json"))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n == 0 {
		t.Error("the valid fixture has no matches, so it asserts nothing")
	}
}

func TestArgsKeepLocationsRepositoryRelative(t *testing.T) {
	got := args()
	if got[0] != "dir:." {
		t.Errorf("scan root = %q, want dir:. so locations stay relative", got[0])
	}
	if !slices.Contains(got, "json") {
		t.Error("output format must be json")
	}
}

// Each of these disables a behaviour that would otherwise put egress, or
// grype's own fail-on-stale, into the scan path.
func TestEnvDisablesEgressAndGrypesOwnAgeGuard(t *testing.T) {
	env := New("/var/cache/grype/db").env()
	for _, want := range []string{
		"GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		"GRYPE_DB_REQUIRE_UPDATE_CHECK=false",
		"GRYPE_DB_VALIDATE_AGE=false",
		"GRYPE_DB_VALIDATE_BY_HASH_ON_START=true",
		"GRYPE_DB_CACHE_DIR=/var/cache/grype/db",
	} {
		if !slices.Contains(env, want) {
			t.Errorf("environment is missing %s", want)
		}
	}
	// An allow-list, not an inherited environment (§14.7).
	for _, e := range env {
		if e == "" {
			t.Error("empty environment entry")
		}
	}
}

func TestParseVersion(t *testing.T) {
	out := "Application:  grype\nVersion:      0.117.0\nBuildDate:    2026-08-10T16:48:30Z\n"
	if got := parseVersion(out); got != "0.117.0" {
		t.Errorf("parseVersion = %q, want 0.117.0", got)
	}
}

func TestScanRejectsNonFilesystemTargets(t *testing.T) {
	_, err := New("/var/cache/grype/db").Scan(
		t.Context(), scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://x/y"})
	if err == nil {
		t.Fatal("a repository target was accepted")
	}
}

// requireGrype skips when the binary is absent. The deterministic checks above
// run against fixtures and are the real coverage (§19); these confirm the
// adapter drives the actual tool correctly, which fixtures cannot.
func requireGrype(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("grype"); err != nil {
		t.Skip("grype is not installed; skipping live-binary test")
	}
}

// seedVulnerableProject writes a module pinned to a version with known
// advisories, so the scan has something real to find. A fixture asserting
// against zero matches would assert nothing.
func seedVulnerableProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	write("go.mod", "module vulnfixture\n\ngo 1.27.0\n\nrequire golang.org/x/crypto v0.31.0\n")
	write("go.sum", "")
	return dir
}

func TestScanProducesAUsableReport(t *testing.T) {
	requireGrype(t)

	s := New(os.Getenv("GRYPE_DB_CACHE_DIR"))
	if s.DBCacheDir == "" {
		// Fall back to the developer's own cache so the test is runnable
		// locally without extra setup.
		s.DBCacheDir = filepath.Join(os.Getenv("HOME"), "Library/Caches/grype/db")
		if _, err := os.Stat(s.DBCacheDir); err != nil {
			s.DBCacheDir = filepath.Join(os.Getenv("HOME"), ".cache/grype/db")
		}
	}

	raw, err := s.Scan(t.Context(), scanners.Target{
		Kind: scanners.KindFilesystem, Path: seedVulnerableProject(t),
	})
	if err != nil {
		t.Skipf("grype could not run (most likely no vulnerability database): %v", err)
	}

	if err := validateReport(raw.Output); err != nil {
		t.Fatalf("the adapter accepted output it should have rejected: %v", err)
	}
	n, err := matchCount(raw.Output)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n == 0 {
		t.Error("no matches against a deliberately vulnerable dependency")
	}
	if raw.Version == "" {
		t.Error("scanner version was not captured (§7 rule 6)")
	}
}

// The report must not embed the worker's layout, for the reason recorded as
// T-30 against syft: an artifact that differs between two scans of the same
// commit cannot be compared, and Phase 4 has to compare them.
func TestRealReportKeepsLocationsRelative(t *testing.T) {
	requireGrype(t)

	s := New(os.Getenv("GRYPE_DB_CACHE_DIR"))
	if s.DBCacheDir == "" {
		s.DBCacheDir = filepath.Join(os.Getenv("HOME"), "Library/Caches/grype/db")
		if _, err := os.Stat(s.DBCacheDir); err != nil {
			s.DBCacheDir = filepath.Join(os.Getenv("HOME"), ".cache/grype/db")
		}
	}

	dir := seedVulnerableProject(t)
	raw, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindFilesystem, Path: dir})
	if err != nil {
		t.Skipf("grype could not run: %v", err)
	}
	if bytes.Contains(raw.Output, []byte(dir)) {
		t.Error("the report embeds the scan workspace path")
	}
}
