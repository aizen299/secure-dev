package scanjob

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/aizen299/secure-dev/internal/scanexec"
)

// Reporter posts a Job's progress back to the controller.
//
// It implements the other half of scanexec.Events: the in-process executor
// writes results to a database, and this writes them to a socket. That the same
// executor drives both is the whole reason PR 1 put the seam where it did.
type Reporter struct {
	BaseURL string
	Token   string
	ScanID  string
	Client  *http.Client
}

// NewReporter builds a Reporter with a bounded HTTP client.
func NewReporter(baseURL, token, scanID string) *Reporter {
	return &Reporter{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		ScanID:  scanID,
		Client: &http.Client{
			Timeout: 10 * time.Minute,
			// No redirects. The controller's address is configuration, and a
			// 30x pointing somewhere else is either a misconfiguration or an
			// attempt to make this Job post a scan's contents to a third
			// party -- neither of which should be followed silently.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Events adapts this Reporter to the executor's callbacks.
//
// Failures are returned through onError rather than swallowed. A Job that could
// not report a result must not exit zero: the controller would then see a
// successful scan with a scanner missing from it, which is exactly the
// "fewer findings does not mean fewer problems" failure the gate exists to
// catch (T-47).
func (r *Reporter) Events(onError func(error)) scanexec.Events {
	return scanexec.Events{
		Checkout: func(commitSHA, branch string) {
			if err := r.Checkout(context.Background(), commitSHA, branch); err != nil {
				onError(fmt.Errorf("reporting the checkout: %w", err))
			}
		},
		Scanner: func(x scanexec.Execution) {
			if err := r.Result(context.Background(), x); err != nil {
				onError(fmt.Errorf("reporting %s: %w", x.Result.Scanner, err))
			}
		},
	}
}

// Checkout reports the revision that was fetched.
func (r *Reporter) Checkout(ctx context.Context, commitSHA, branch string) error {
	body, err := json.Marshal(Checkout{CommitSHA: commitSHA, Branch: branch})
	if err != nil {
		return err
	}
	return r.post(ctx, PathCheckout, "application/json", bytes.NewReader(body))
}

// Result reports one scanner's outcome.
func (r *Reporter) Result(ctx context.Context, x scanexec.Execution) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	meta, err := json.Marshal(Report{Result: x.Result})
	if err != nil {
		return err
	}
	if err := writePart(w, FieldMeta, meta); err != nil {
		return err
	}
	// Output is written even when empty, so "the scanner produced nothing" and
	// "the part went missing" are distinguishable at the far end.
	if err := writePart(w, FieldOutput, x.Raw.Output); err != nil {
		return err
	}
	if len(x.Inventory) > 0 {
		if err := writePart(w, FieldInventory, x.Inventory); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	return r.post(ctx, PathResult, w.FormDataContentType(), &buf)
}

func writePart(w *multipart.Writer, field string, data []byte) error {
	part, err := w.CreateFormField(field)
	if err != nil {
		return err
	}
	_, err = part.Write(data)
	return err
}

func (r *Reporter) post(ctx context.Context, path, contentType string, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(HeaderScanID, r.ScanID)
	req.Header.Set("Authorization", "Bearer "+r.Token)

	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a bounded amount so the connection can be reused, and read no more
	// than that: the response comes from the controller, but a Job that read an
	// unbounded body would be one more place to exhaust.
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		// The status only. A response body could carry detail about the
		// controller that a compromised scanner has no business reading.
		return fmt.Errorf("controller rejected the report: %s", resp.Status)
	}
	return nil
}
