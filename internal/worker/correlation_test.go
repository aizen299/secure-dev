package worker

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/correlation"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/risk"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// normalizingScanner is a scripted scanner that also implements
// normalization.Normalizer, so the worker's findings path actually runs.
type normalizingScanner struct {
	scriptedScanner
	findings []normalization.Finding
	// file is where this scanner saw its findings. Distinct per scanner,
	// because a dependency finding lives in a lockfile and a SAST finding
	// lives in source -- sharing one path would form a file issue too and
	// make this test about the wrong rule.
	file string
}

func (n *normalizingScanner) Normalize(_ []byte, scanID string) (normalization.Result, error) {
	res := normalization.Result{Findings: n.findings}
	for _, f := range n.findings {
		res.Occurrences = append(res.Occurrences, normalization.Occurrence{
			Fingerprint: f.Fingerprint, ScanID: scanID,
			File: n.file, StartLine: 1, EndLine: 1, Scanner: n.name,
		})
	}
	return res, nil
}

// fakeFindingStore records the order of calls, which is the property under
// test: correlation has to run on what was just written, not before it.
type fakeFindingStore struct {
	mu        sync.Mutex
	calls     []string
	subjects  []correlation.Subject
	persisted correlation.Result
	listErr   error
	replErr   error

	riskSubjects []risk.Subject
	riskContext  risk.Context
	riskScore    risk.Assessment
	riskDigest   string
	riskListErr  error
	riskSaveErr  error
}

func (f *fakeFindingStore) RecordScan(
	_ context.Context, _, _ string, result normalization.DedupResult,
	_ []string, _ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "record")
	for _, m := range result.Findings {
		files := []string{}
		for _, o := range result.Occurrences {
			if o.Fingerprint == m.Fingerprint && o.File != "" {
				files = append(files, o.File)
			}
		}
		f.subjects = append(f.subjects, correlation.Subject{Finding: m.Finding, Files: files})
	}
	return nil
}

func (f *fakeFindingStore) ListLiveForCorrelation(
	_ context.Context, _ string,
) ([]correlation.Subject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "list")
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.subjects, nil
}

func (f *fakeFindingStore) ReplaceCorrelation(
	_ context.Context, _ string, result correlation.Result,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "replace")
	if f.replErr != nil {
		return f.replErr
	}
	f.persisted = result
	return nil
}

func (f *fakeFindingStore) LoadRiskInputs(
	_ context.Context, _ string,
) ([]risk.Subject, risk.Context, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "risk-load")
	if f.riskListErr != nil {
		return nil, risk.Context{}, f.riskListErr
	}
	return f.riskSubjects, f.riskContext, nil
}

func (f *fakeFindingStore) SaveRiskScore(
	_ context.Context, _, _ string, assessment risk.Assessment, digest string, _ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "risk-save")
	if f.riskSaveErr != nil {
		return f.riskSaveErr
	}
	f.riskScore = assessment
	f.riskDigest = digest
	return nil
}

func (f *fakeFindingStore) order() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func crossDomainScanners() (*normalizingScanner, *normalizingScanner) {
	dep := &normalizingScanner{
		scriptedScanner: scriptedScanner{name: "grype"},
		file:            "package-lock.json",
		findings: []normalization.Finding{{
			Fingerprint: "aaaa", Scanner: "grype", Title: "Vulnerable dependency",
			Category: scanners.CategoryDependency, Severity: normalization.SeverityMedium,
			Confidence: normalization.ConfidenceHigh, CVE: "CVE-2026-1234",
		}},
	}
	sast := &normalizingScanner{
		scriptedScanner: scriptedScanner{name: "semgrep"},
		file:            "server.ts",
		findings: []normalization.Finding{{
			Fingerprint: "bbbb", Scanner: "semgrep", Title: "Unsafe call",
			Category: scanners.CategorySAST, Severity: normalization.SeverityMedium,
			Confidence: normalization.ConfidenceHigh, CVE: "CVE-2026-1234",
		}},
	}
	return dep, sast
}

func runnerWithFindings(t *testing.T, fs FindingStore, sc ...scanners.Scanner) *Runner {
	t.Helper()
	r := testRunner(t, newFakeStore(), sc...)
	r.opts.Findings = fs
	return r
}

// The wiring, end to end inside the worker: a scan that produces findings must
// leave the project correlated. Nothing else in the suite proves correlate is
// reached at all.
func TestAScanCorrelatesWhatItRecorded(t *testing.T) {
	fs := &fakeFindingStore{}
	dep, sast := crossDomainScanners()
	r := runnerWithFindings(t, fs, dep, sast)

	r.executeJob(t.Context(), repoJob("scan-corr"))

	// The pipeline order is load-bearing, not incidental. Correlation must run
	// on what persistence just wrote, and risk must run on what correlation
	// just decided -- scoring first would score yesterday's classification of
	// today's findings.
	want := []string{"record", "list", "replace", "risk-load", "risk-save"}
	got := fs.order()
	if !slices.Equal(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}

	if len(fs.persisted.Issues) != 1 {
		t.Fatalf("issues = %+v, want exactly the one CVE issue", fs.persisted.Issues)
	}
	issue := fs.persisted.Issues[0]
	if issue.Key.Kind != correlation.KindCVE || issue.Key.Value != "CVE-2026-1234" {
		t.Errorf("issue key = %s, want the shared CVE", issue.Key)
	}
	// Dependency plus SAST is cross-domain corroboration, so medium becomes
	// high. This is the §9 behaviour arriving through the real pipeline.
	if issue.Severity != normalization.SeverityHigh || !issue.Escalated {
		t.Errorf("severity = %q escalated = %v, want high and escalated",
			issue.Severity, issue.Escalated)
	}
}

// Correlation is a derived view. Losing it must not cost the observations the
// scan actually made -- the same reason persistFindings is not fatal.
func TestCorrelationFailureDoesNotFailTheScan(t *testing.T) {
	for name, fs := range map[string]*fakeFindingStore{
		"read fails":  {listErr: errors.New("db down")},
		"write fails": {replErr: errors.New("db down")},
	} {
		t.Run(name, func(t *testing.T) {
			dep, sast := crossDomainScanners()
			r := runnerWithFindings(t, fs, dep, sast)
			store := r.opts.Store.(*fakeStore)

			r.executeJob(t.Context(), repoJob("scan-degraded"))

			if got := store.finalStatus("scan-degraded"); got != "completed" {
				t.Errorf("status = %q, want completed: a derived view failing is not a scan failing", got)
			}
		})
	}
}

// A scan with no findings must not leave stale issues standing. Skipping the
// recompute would be the same class of error as a failed scanner resolving
// nothing: the absence of new data is not the absence of a change.
func TestAScanWithNoFindingsStillRecorrelates(t *testing.T) {
	fs := &fakeFindingStore{}
	// A scanner that normalizes to nothing.
	quiet := &normalizingScanner{scriptedScanner: scriptedScanner{name: "grype"}}
	r := runnerWithFindings(t, fs, quiet)

	r.executeJob(t.Context(), repoJob("scan-quiet"))

	got := fs.order()
	var sawReplace bool
	for _, c := range got {
		if c == "replace" {
			sawReplace = true
		}
	}
	if !sawReplace {
		t.Errorf("call order = %v, want a recompute: an empty scan can still resolve findings", got)
	}
}
