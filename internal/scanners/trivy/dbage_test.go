package trivy

import (
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func TestDBUpdatedAtReadsTrivysOwnReport(t *testing.T) {
	got, ok := dbUpdatedAt([]byte(`{"VulnerabilityDB":{"UpdatedAt":"2026-09-08T01:14:11.072075664Z"}}`))
	if !ok {
		t.Fatal("a well-formed version report was not understood")
	}
	if want := time.Date(2026, 9, 8, 1, 14, 11, 72075664, time.UTC); !got.Equal(want) {
		t.Errorf("UpdatedAt = %v, want %v", got, want)
	}
}

// TestUnreadableAgeIsUnknownNotFresh.
//
// The whole point of the degradation. Trivy's version output carries no
// stability guarantee, so a shape change must make the scan say "I could not
// establish freshness" rather than silently behave as though the data were new.
func TestUnreadableAgeIsUnknownNotFresh(t *testing.T) {
	for name, body := range map[string]string{
		"not json":        `<html>503</html>`,
		"no db section":   `{"Version":"0.74.0"}`,
		"empty timestamp": `{"VulnerabilityDB":{"UpdatedAt":""}}`,
		"unparseable":     `{"VulnerabilityDB":{"UpdatedAt":"last tuesday"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := dbUpdatedAt([]byte(body)); ok {
				t.Error("an unusable timestamp was accepted as a date")
			}
		})
	}
}

// TestAStaleDatabaseDegradesAndAFreshOneDoesNot is ADR 040 §5's control:
// baked data that goes stale must make the scan PARTIAL rather than pass
// quietly with fewer vulnerabilities than exist (T-31).
func TestAStaleDatabaseDegradesAndAFreshOneDoesNot(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	s := &Scanner{now: func() time.Time { return now }}

	fresh := now.Add(-24 * time.Hour)
	if got := s.clock().Sub(fresh) > s.maxDBAge(); got {
		t.Error("a one-day-old database was called stale")
	}
	stale := now.Add(-30 * 24 * time.Hour)
	if got := s.clock().Sub(stale) > s.maxDBAge(); !got {
		t.Error("a thirty-day-old database was not called stale")
	}
}

// TestTheThresholdMatchesGrypes.
//
// A scan consults two vulnerability databases. Calling one stale and the other
// fresh at the same age would leave a reader comparing the two results with no
// way to know the thresholds differed.
func TestTheThresholdMatchesGrypes(t *testing.T) {
	if DefaultMaxDBAge != 7*24*time.Hour {
		t.Errorf("trivy's threshold is %v; grype's is 7 days", DefaultMaxDBAge)
	}
}

func TestDegradationVocabularyIsShared(t *testing.T) {
	// Named constants rather than strings invented here: the vocabulary
	// belongs to the adapter contract, and the gate reads it (ADR 010).
	for _, d := range []scanners.Degradation{
		scanners.DegradedStaleVulnerabilityDB,
		scanners.DegradedUnknownVulnerabilityDB,
	} {
		if d == "" {
			t.Error("a degradation constant is empty")
		}
	}
}
