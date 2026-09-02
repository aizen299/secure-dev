package worker

import (
	"errors"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/risk"
)

// The score reaches storage, carrying the configuration it was computed under.
// A persisted number with no digest cannot be compared against a later one
// across a re-tuning, which is the whole reason the column exists.
func TestAScanPersistsItsRiskScore(t *testing.T) {
	fs := &fakeFindingStore{
		riskContext: risk.Context{
			Environment: projects.EnvProduction,
			Criticality: projects.CriticalityHigh,
		},
		riskSubjects: []risk.Subject{{
			Finding: normalization.Finding{
				Fingerprint: "fp-1",
				Scanner:     "grype",
				Severity:    normalization.SeverityCritical,
				Confidence:  normalization.ConfidenceHigh,
				Status:      normalization.StatusOpen,
			},
			Sources: []string{"grype"},
		}},
	}
	dep, sast := crossDomainScanners()
	r := runnerWithFindings(t, fs, dep, sast)

	r.executeJob(t.Context(), repoJob("scan-risk"))

	if fs.riskScore.Score <= 0 {
		t.Errorf("score = %v, want a positive score for an open critical", fs.riskScore.Score)
	}
	if fs.riskScore.Live != 1 {
		t.Errorf("live findings = %d, want 1", fs.riskScore.Live)
	}
	if fs.riskDigest != risk.DefaultWeights().Digest() {
		t.Errorf("digest = %q, want the default weights' digest", fs.riskDigest)
	}
}

// Risk is a derived view. Losing it must not cost the observations the scan
// actually made -- the same rule correlation follows, for the same reason.
func TestRiskFailureDoesNotFailTheScan(t *testing.T) {
	for name, fs := range map[string]*fakeFindingStore{
		"read fails":  {riskListErr: errors.New("db down")},
		"write fails": {riskSaveErr: errors.New("db down")},
	} {
		t.Run(name, func(t *testing.T) {
			dep, sast := crossDomainScanners()
			r := runnerWithFindings(t, fs, dep, sast)
			store := r.opts.Store.(*fakeStore)

			r.executeJob(t.Context(), repoJob("scan-risk-degraded"))

			if got := store.finalStatus("scan-risk-degraded"); got != "completed" {
				t.Errorf("status = %q, want completed: a derived number failing is not a scan failing", got)
			}
			// And the findings it did record are still correlated: one derived
			// view failing must not take the other down with it.
			if len(fs.persisted.Issues) == 0 {
				t.Error("correlation was lost when risk failed")
			}
		})
	}
}
