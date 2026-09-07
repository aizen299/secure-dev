package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeAPI serves the three endpoints the client uses.
//
// A real HTTP server rather than an injected interface: the client's job is to
// speak HTTP correctly, and a fake that skipped the wire would not exercise the
// status-code handling that decides whether a build passes.
type fakeAPI struct {
	scanStatus  string
	statusAfter string // status returned from the second poll onward
	polls       int
	gate        *Gate
	gateStatus  int
	scanStatus_ int
}

func (f *fakeAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		if f.scanStatus_ != 0 {
			w.WriteHeader(f.scanStatus_)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{"message": "this credential is not permitted"}})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "scan-1"})
	})

	mux.HandleFunc("GET /api/v1/scans/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.polls++
		status := f.scanStatus
		if f.polls > 1 && f.statusAfter != "" {
			status = f.statusAfter
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": status, "failure_reason": "the repository could not be fetched"})
	})

	mux.HandleFunc("GET /api/v1/scans/{id}/gate", func(w http.ResponseWriter, r *http.Request) {
		if f.gateStatus != 0 {
			w.WriteHeader(f.gateStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{"message": "no gate result for this scan"}})
			return
		}
		_ = json.NewEncoder(w).Encode(f.gate)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, f *fakeAPI) (Result, error) {
	t.Helper()
	srv := f.server(t)
	return Run(t.Context(), Options{
		BaseURL: srv.URL, Token: "tok", ProjectID: "proj",
		RepositoryURL: "https://github.com/acme/app", Timeout: 5 * time.Second,
		HTTPClient: srv.Client(),
	})
}

// The exit-code contract, which is the public interface of this whole binary.
//
// A pipeline branches on these, so the table is the specification: changing what
// a code means breaks every pipeline using it (ADR 036 §2).
func TestExitCodeContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  Result
		want int
		why  string
	}{
		{"pass", Result{Gate: &Gate{Verdict: "pass"}}, ExitOK,
			"a clean gate does not stop a build"},
		{"warn", Result{Gate: &Gate{Verdict: "warn"}}, ExitOK,
			"WARN exists because a team chose warn; blocking on it makes it a FAIL with a friendlier name"},
		{"fail", Result{Gate: &Gate{Verdict: "fail"}}, ExitGateFailed,
			"the gate blocked, and the code is the reason"},
		{"no gate", Result{Status: "failed"}, ExitCouldNotEvaluate,
			"the gate never ran; a build must not pass on a judgement nobody made"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.ExitCode(); got != tc.want {
				t.Errorf("ExitCode() = %d, want %d: %s", got, tc.want, tc.why)
			}
		})
	}
}

// A gate that passed exits 0 and carries its reasoning.
func TestAPassingGateRunsEndToEnd(t *testing.T) {
	got, err := run(t, &fakeAPI{
		scanStatus: "completed",
		gate: &Gate{Verdict: "pass", ScanID: "scan-1", Summary: "no rule breached",
			Coverage:   GateCoverage{Complete: true, ScanStatus: "completed"},
			Conditions: []GateCondition{{Kind: "severity_count", Selector: "critical", Max: 0, Level: "fail", Explanation: "0 critical findings, at most 0 allowed"}}},
	})
	if err != nil {
		t.Fatalf("Run = %v", err)
	}
	if got.ExitCode() != ExitOK {
		t.Errorf("exit = %d, want %d", got.ExitCode(), ExitOK)
	}
	if got.Gate == nil || len(got.Gate.Conditions) != 1 {
		t.Fatalf("conditions = %+v, want the rule that was evaluated", got.Gate)
	}
}

// The case the third exit code exists for.
//
// An unreachable API must not pass a build. This is the failure that would be
// invisible in production -- every pipeline green, nothing checked -- so it is
// asserted rather than assumed.
func TestAnUnreachableAPICannotPassABuild(t *testing.T) {
	// A port nothing is listening on, with a short timeout.
	got, err := Run(t.Context(), Options{
		BaseURL: "http://127.0.0.1:1", Token: "tok", ProjectID: "proj",
		RepositoryURL: "https://github.com/acme/app", Timeout: 2 * time.Second,
		HTTPClient: &http.Client{Timeout: time.Second},
	})

	if err == nil {
		t.Fatal("Run succeeded against an unreachable API")
	}
	if !errors.Is(err, ErrCouldNotEvaluate) {
		t.Errorf("error = %v, want ErrCouldNotEvaluate", err)
	}
	if got.ExitCode() != ExitCouldNotEvaluate {
		t.Errorf("exit = %d, want %d: a green build that checked nothing is worse than a red one",
			got.ExitCode(), ExitCouldNotEvaluate)
	}
}

// A refused credential is not a passing gate either.
func TestARefusedCredentialCannotPassABuild(t *testing.T) {
	got, err := run(t, &fakeAPI{scanStatus_: http.StatusForbidden})

	if err == nil {
		t.Fatal("Run succeeded with a refused credential")
	}
	if got.ExitCode() != ExitCouldNotEvaluate {
		t.Errorf("exit = %d, want %d", got.ExitCode(), ExitCouldNotEvaluate)
	}
	// The message names the cause, because "fix the pipeline" needs to be
	// distinguishable from "fix the code" at a glance.
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want the status that explains it", err)
	}
}

// A scan that failed outright is not a gate result.
func TestAFailedScanIsNotAVerdict(t *testing.T) {
	got, err := run(t, &fakeAPI{scanStatus: "failed"})

	if err == nil {
		t.Fatal("Run succeeded on a failed scan")
	}
	if got.ExitCode() != ExitCouldNotEvaluate {
		t.Errorf("exit = %d, want %d", got.ExitCode(), ExitCouldNotEvaluate)
	}
	// The API's own reason, forwarded rather than replaced: "the repository
	// could not be fetched" tells somebody what to do, "the scan failed" does
	// not.
	if !strings.Contains(err.Error(), "could not be fetched") {
		t.Errorf("error = %q, want the API's failure reason", err)
	}
}

// A scan that never finishes has not passed.
//
// Without this the client would pass every build that was merely slow, which is
// the same class of failure as passing on an outage.
func TestATimeoutCannotPassABuild(t *testing.T) {
	f := &fakeAPI{scanStatus: "running"}
	srv := f.server(t)

	got, err := Run(t.Context(), Options{
		BaseURL: srv.URL, Token: "tok", ProjectID: "proj",
		RepositoryURL: "https://github.com/acme/app",
		Timeout:       1500 * time.Millisecond,
		HTTPClient:    srv.Client(),
	})

	if err == nil {
		t.Fatal("Run succeeded on a scan that never finished")
	}
	if got.ExitCode() != ExitCouldNotEvaluate {
		t.Errorf("exit = %d, want %d", got.ExitCode(), ExitCouldNotEvaluate)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want it to name the timeout", err)
	}
}

// A PARTIAL scan reaches the gate rather than being refused by the client.
//
// The gate is what decides what degraded coverage means, and it already refuses
// to store a PASS for one (§12). Failing here would take that judgement away
// from the project's policy and put it in the client.
func TestAPartialScanIsJudgedByTheGateNotTheClient(t *testing.T) {
	got, err := run(t, &fakeAPI{
		scanStatus: "partial",
		gate: &Gate{Verdict: "warn", ScanID: "scan-1",
			Coverage: GateCoverage{Complete: false, ScanStatus: "partial", Downgraded: true}},
	})
	if err != nil {
		t.Fatalf("Run = %v: a partial scan is a result, not a failure", err)
	}
	if got.ExitCode() != ExitOK {
		t.Errorf("exit = %d, want %d: the gate said warn, and warn does not block",
			got.ExitCode(), ExitOK)
	}
	if !got.Gate.Coverage.Downgraded {
		t.Error("the downgrade was lost; a WARN from a crashed scanner must stay distinguishable from a WARN from a breached rule")
	}
}

// The client waits rather than reading the first status it sees.
func TestItWaitsForTheScanToSettle(t *testing.T) {
	f := &fakeAPI{
		scanStatus: "running", statusAfter: "completed",
		gate: &Gate{Verdict: "pass", ScanID: "scan-1"},
	}
	got, err := run(t, f)
	if err != nil {
		t.Fatalf("Run = %v", err)
	}
	if f.polls < 2 {
		t.Errorf("polled %d time(s); a client that reads one status judges a scan that has not run", f.polls)
	}
	if got.ExitCode() != ExitOK {
		t.Errorf("exit = %d, want %d", got.ExitCode(), ExitOK)
	}
}

// Missing configuration fails closed.
func TestMissingConfigurationCannotPassABuild(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"no token", Options{ProjectID: "p", RepositoryURL: "https://x/y"}, "SECUREOPS_API_TOKEN"},
		{"no project", Options{Token: "t", RepositoryURL: "https://x/y"}, "--project"},
		{"no repository", Options{Token: "t", ProjectID: "p"}, "--repo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Run(context.Background(), tc.opts)
			if err == nil {
				t.Fatal("Run succeeded with incomplete configuration")
			}
			if got.ExitCode() != ExitCouldNotEvaluate {
				t.Errorf("exit = %d, want %d", got.ExitCode(), ExitCouldNotEvaluate)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// Every rule is rendered, breached or not.
//
// A report listing only breaches makes "this project is clean" and "this policy
// checks nothing" look identical.
func TestRenderShowsEveryRule(t *testing.T) {
	var out strings.Builder
	Render(&out, Result{Gate: &Gate{
		Verdict: "fail", ScanID: "scan-1",
		Coverage: GateCoverage{Complete: true, ScanStatus: "completed"},
		Conditions: []GateCondition{
			{Kind: "severity_count", Selector: "critical", Level: "fail", Breached: true,
				Explanation: "2 critical findings, at most 0 allowed"},
			{Kind: "severity_count", Selector: "high", Level: "warn", Breached: false,
				Explanation: "1 high finding, at most 5 allowed"},
		},
	}})

	got := out.String()
	if !strings.Contains(got, "2 critical findings") {
		t.Error("the breached rule is missing")
	}
	if !strings.Contains(got, "1 high finding") {
		t.Error("the rule that passed is missing; without it, a clean project and an empty policy look the same")
	}
	if !strings.Contains(got, "FAIL") {
		t.Error("the verdict is missing")
	}
}

// Degraded coverage is reported, not hidden behind the verdict.
func TestRenderSaysWhenCoverageWasIncomplete(t *testing.T) {
	var out strings.Builder
	Render(&out, Result{Gate: &Gate{
		Verdict:  "warn",
		Coverage: GateCoverage{Complete: false, ScanStatus: "partial", Downgraded: true},
	}})

	got := out.String()
	if !strings.Contains(got, "incomplete") {
		t.Error("incomplete coverage was not reported: fewer findings would read as fewer problems")
	}
	if !strings.Contains(got, "lowered the verdict") {
		t.Error("the downgrade was not reported")
	}
}

// The no-gate case says why the build stopped.
func TestRenderExplainsAMissingGate(t *testing.T) {
	var out strings.Builder
	Render(&out, Result{ScanID: "scan-1", Status: "failed"})

	got := out.String()
	if !strings.Contains(got, "NOT EVALUATED") {
		t.Error("a missing gate must not read like a verdict")
	}
	if !strings.Contains(got, "did not run") {
		t.Error("the reason the build stopped is missing")
	}
}

// The JSON carries the conditions, not a summary of them.
func TestJSONCarriesTheReasoning(t *testing.T) {
	var out strings.Builder
	err := RenderJSON(&out, Result{ScanID: "scan-1", Status: "completed",
		Gate: &Gate{Verdict: "fail", Conditions: []GateCondition{
			{Kind: "severity_count", Selector: "critical", Breached: true, Observed: 2}}}})
	if err != nil {
		t.Fatalf("RenderJSON = %v", err)
	}

	var back Result
	if err := json.Unmarshal([]byte(out.String()), &back); err != nil {
		t.Fatalf("the JSON does not parse: %v", err)
	}
	if back.Gate == nil || len(back.Gate.Conditions) != 1 {
		t.Fatal("conditions were lost; a consumer acting on a specific rule cannot re-derive it from prose")
	}
	if back.Gate.Conditions[0].Observed != 2 {
		t.Errorf("observed = %v, want it preserved", back.Gate.Conditions[0].Observed)
	}
}
