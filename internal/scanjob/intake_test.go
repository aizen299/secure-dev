package scanjob_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanjob"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
)

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// collector captures what the intake handed to the controller.
type collector struct {
	checkout [2]string
	results  []scanexec.Execution
}

func (c *collector) events() scanexec.Events {
	return scanexec.Events{
		Checkout: func(sha, branch string) { c.checkout = [2]string{sha, branch} },
		Scanner:  func(x scanexec.Execution) { c.results = append(c.results, x) },
	}
}

// harness wires an Intake behind a real HTTP server and a Reporter pointed at
// it -- the same two objects the Job and the controller use in production, with
// only the network between them shortened.
func harness(t *testing.T, limits scanjob.Limits) (*scanjob.Intake, *collector, string, string) {
	t.Helper()
	intake := scanjob.NewIntake(limits, discard())
	srv := httptest.NewServer(intake.Handler())
	t.Cleanup(srv.Close)

	c := &collector{}
	token, err := intake.Open("scan-1", c.events())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return intake, c, srv.URL, token
}

func succeeded(scanner string, output []byte) scanexec.Execution {
	started := time.Unix(1, 0).UTC()
	return scanexec.Execution{
		Result: scans.ScannerResult{
			Scanner: scanner, Status: scans.ScannerSucceeded,
			Version: "1.2.3", StartedAt: &started,
		},
		Raw: scanners.RawResult{Scanner: scanner, Version: "1.2.3", Output: output},
	}
}

// TestAResultMakesItAcrossIntact is the protocol's happy path.
func TestAResultMakesItAcrossIntact(t *testing.T) {
	_, c, url, token := harness(t, scanjob.DefaultLimits(1<<20))
	r := scanjob.NewReporter(url, token, "scan-1")

	output := []byte(`{"findings":[{"id":"x"}]}`)
	if err := r.Result(context.Background(), succeeded("gitleaks", output)); err != nil {
		t.Fatalf("Result: %v", err)
	}
	if len(c.results) != 1 {
		t.Fatalf("controller saw %d results, want 1", len(c.results))
	}
	got := c.results[0]
	if got.Result.Scanner != "gitleaks" || got.Result.Version != "1.2.3" {
		t.Errorf("metadata lost: %+v", got.Result)
	}
	if !bytes.Equal(got.Raw.Output, output) {
		t.Errorf("output = %q, want it byte-identical", got.Raw.Output)
	}
}

// TestTheCheckoutArrivesSeparately.
//
// Its own message because a scan can fetch successfully and then have every
// scanner fail, and the revision is still worth recording.
func TestTheCheckoutArrivesSeparately(t *testing.T) {
	_, c, url, token := harness(t, scanjob.DefaultLimits(1<<20))
	r := scanjob.NewReporter(url, token, "scan-1")

	if err := r.Checkout(context.Background(), "deadbeef", "main"); err != nil {
		t.Fatalf("Checkout: %v", err)
	}
	if c.checkout != [2]string{"deadbeef", "main"} {
		t.Errorf("checkout = %v, want deadbeef/main", c.checkout)
	}
}

// TestATokenIsUselessForAnotherScan.
//
// The property the whole design rests on: a compromised scanner reaches its own
// results and nothing else. If this fails, one hostile repository can write
// findings into another project's scan.
func TestATokenIsUselessForAnotherScan(t *testing.T) {
	intake, c, url, token := harness(t, scanjob.DefaultLimits(1<<20))

	other := &collector{}
	if _, err := intake.Open("scan-2", other.events()); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// scan-1's token, presented as scan-2.
	r := scanjob.NewReporter(url, token, "scan-2")
	err := r.Result(context.Background(), succeeded("gitleaks", nil))
	if err == nil {
		t.Fatal("scan-1's token was accepted for scan-2")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("refusal was %v, want 401", err)
	}
	if len(other.results) != 0 || len(c.results) != 0 {
		t.Error("a refused report still reached a controller")
	}
}

// TestAClosedScanAcceptsNothing.
//
// The token exists for exactly as long as the scan does. A Job that outlives
// its scan -- a straggler, a retry, a compromised pod kept alive -- must not be
// able to write into a scan that has already been judged.
func TestAClosedScanAcceptsNothing(t *testing.T) {
	intake, c, url, token := harness(t, scanjob.DefaultLimits(1<<20))
	intake.Close("scan-1")

	r := scanjob.NewReporter(url, token, "scan-1")
	if err := r.Result(context.Background(), succeeded("gitleaks", nil)); err == nil {
		t.Fatal("a closed scan accepted a result")
	}
	if len(c.results) != 0 {
		t.Error("a closed scan passed a result to the controller")
	}
}

// TestAnUnknownScanAndABadTokenAreIndistinguishable.
//
// Both 401 with no body. A distinct code or message would say whether a scan id
// exists, which turns this endpoint into an oracle for what the controller is
// running.
func TestAnUnknownScanAndABadTokenAreIndistinguishable(t *testing.T) {
	_, _, url, token := harness(t, scanjob.DefaultLimits(1<<20))

	cases := map[string]*scanjob.Reporter{
		"unknown scan": scanjob.NewReporter(url, token, "scan-does-not-exist"),
		"bad token":    scanjob.NewReporter(url, "not-the-token", "scan-1"),
		"no token":     scanjob.NewReporter(url, "", "scan-1"),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			err := r.Result(context.Background(), succeeded("gitleaks", nil))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "401 Unauthorized") {
				t.Errorf("refusal = %v, want a bare 401", err)
			}
		})
	}
}

// TestOversizedOutputIsRefusedRatherThanTruncated.
//
// Truncating would store a partial scanner result as a whole one, which is the
// "fewer findings does not mean fewer problems" failure the gate exists to
// catch (T-47). Refusing is loud; truncating is silent.
func TestOversizedOutputIsRefusedRatherThanTruncated(t *testing.T) {
	limits := scanjob.DefaultLimits(1 << 10)
	_, c, url, token := harness(t, limits)
	r := scanjob.NewReporter(url, token, "scan-1")

	big := bytes.Repeat([]byte("A"), 4<<10)
	if err := r.Result(context.Background(), succeeded("gitleaks", big)); err == nil {
		t.Fatal("oversized output was accepted")
	}
	if len(c.results) != 0 {
		t.Errorf("a truncated result reached the controller: %d bytes",
			len(c.results[0].Raw.Output))
	}
}

// TestAnUnknownPartIsRefused.
//
// Growing the protocol should be a decision. A handler that ignored unknown
// parts would silently accept whatever a compromised scanner chose to add.
func TestAnUnknownPartIsRefused(t *testing.T) {
	_, c, url, token := harness(t, scanjob.DefaultLimits(1<<20))

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	meta, _ := w.CreateFormField(scanjob.FieldMeta)
	_, _ = meta.Write([]byte(`{"result":{"scanner":"gitleaks","status":"succeeded"}}`))
	extra, _ := w.CreateFormField("surprise")
	_, _ = extra.Write([]byte("hello"))
	_ = w.Close()

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, url+scanjob.PathResult, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set(scanjob.HeaderScanID, "scan-1")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %s, want 400", resp.Status)
	}
	if len(c.results) != 0 {
		t.Error("a request with an unknown part still delivered a result")
	}
}

// TestAReportWithoutAScannerNameIsRefused.
//
// The controller looks the adapter up by name to normalize; a nameless result
// would be stored and never parsed.
func TestAReportWithoutAScannerNameIsRefused(t *testing.T) {
	_, c, url, token := harness(t, scanjob.DefaultLimits(1<<20))

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	meta, _ := w.CreateFormField(scanjob.FieldMeta)
	_, _ = meta.Write([]byte(`{"result":{"status":"succeeded"}}`))
	_ = w.Close()

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, url+scanjob.PathResult, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set(scanjob.HeaderScanID, "scan-1")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %s, want 400", resp.Status)
	}
	if len(c.results) != 0 {
		t.Error("a nameless result was delivered")
	}
}

// TestAnInventoryTravelsWhenThereIsOne.
//
// Adapters whose bill of materials comes from a separate run (ADR 037) carry it
// in a third part. Its absence must not be confused with an empty one.
func TestAnInventoryTravelsWhenThereIsOne(t *testing.T) {
	_, c, url, token := harness(t, scanjob.DefaultLimits(1<<20))
	r := scanjob.NewReporter(url, token, "scan-1")

	x := succeeded("trivy", []byte(`{"Results":[]}`))
	x.Inventory = []byte(`{"bomFormat":"CycloneDX"}`)
	if err := r.Result(context.Background(), x); err != nil {
		t.Fatalf("Result: %v", err)
	}
	if len(c.results) != 1 {
		t.Fatalf("got %d results", len(c.results))
	}
	if string(c.results[0].Inventory) != `{"bomFormat":"CycloneDX"}` {
		t.Errorf("inventory = %q, want it intact", c.results[0].Inventory)
	}

	// And a result without one carries none, rather than an empty artefact
	// that would be parsed as a malformed SBOM.
	if err := r.Result(context.Background(), succeeded("gitleaks", nil)); err != nil {
		t.Fatalf("Result: %v", err)
	}
	if len(c.results[1].Inventory) != 0 {
		t.Errorf("inventory = %q, want none", c.results[1].Inventory)
	}
}
