package trivy

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// DefaultMaxDBAge is how old trivy's vulnerability data may be before an image
// scan is reported as degraded.
//
// Matched to grype's threshold rather than chosen independently: a scan that
// consults two vulnerability databases should not call one stale and the other
// fresh at the same age, because a reader comparing the two results has no way
// to know the thresholds differed.
const DefaultMaxDBAge = 7 * 24 * time.Hour

// assessDatabase reports what is wrong with trivy's vulnerability data, if
// anything.
//
// It exists because ADR 040 moved that data into the image. Provisioned at
// startup it was as old as the worker's uptime and nothing measured it; baked
// into an image it is as old as the last rebuild, and a rebuild cadence that
// quietly lapses would reproduce exactly the failure ADR 012 refused — a scan
// that succeeds, reports fewer vulnerabilities than exist, and signals nothing
// (T-31).
//
// Only image targets consult this database. A filesystem scan runs
// `--scanners misconfig` against the checks bundle and never touches it, so
// calling this there would attach a degradation to a result the data played no
// part in.
//
// Unlike grype, trivy does not put the database's build date in its scan
// report, so this asks the tool directly. That is a second subprocess per image
// scan, against an image pull that already dominates the cost.
func (s *Scanner) assessDatabase(ctx context.Context) []scanners.Degradation {
	res, err := scanners.Run(ctx, scanners.ExecOptions{
		Timeout:        s.Timeout,
		MaxOutputBytes: 1 << 20,
		Env:            s.env(),
	}, "trivy", "--cache-dir", s.cacheDir(), "version", "--format", "json")
	if err != nil {
		// Silence is not evidence of freshness. The same reasoning grype's
		// adapter applies: unknown and stale are different operator problems,
		// so they are different degradations.
		return []scanners.Degradation{scanners.DegradedUnknownVulnerabilityDB}
	}

	built, ok := dbUpdatedAt(res.Stdout)
	if !ok {
		return []scanners.Degradation{scanners.DegradedUnknownVulnerabilityDB}
	}
	if s.clock().Sub(built) > s.maxDBAge() {
		return []scanners.Degradation{scanners.DegradedStaleVulnerabilityDB}
	}
	return nil
}

// dbUpdatedAt reads the vulnerability database's build time from
// `trivy version --format json`.
//
// A tolerant read: a missing or unparseable field means "unknown", never
// "fresh". Trivy's version output is not part of any stability guarantee, so
// this must degrade rather than fail if the shape changes under it.
func dbUpdatedAt(data []byte) (time.Time, bool) {
	var doc struct {
		VulnerabilityDB struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false
	}
	if doc.VulnerabilityDB.UpdatedAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, doc.VulnerabilityDB.UpdatedAt)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func (s *Scanner) maxDBAge() time.Duration {
	if s.MaxDBAge > 0 {
		return s.MaxDBAge
	}
	return DefaultMaxDBAge
}

func (s *Scanner) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UTC()
}
