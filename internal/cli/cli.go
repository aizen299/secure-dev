// Package cli is the CI client: submit a scan, wait for it, apply the gate.
//
// It lives here rather than in cmd/cli so it can be tested without building a
// binary and without a CI provider, which is the whole argument for a
// standalone client (ADR 036 §1). cmd/cli is a thin main over this.
//
// Nothing here decides whether a build should fail. The gate did that, on the
// server, from a policy the project owns; this reports the decision and turns
// it into an exit code. A second opinion in the client would be a second place
// to configure severity, with the client's copy silently outranking the
// project's.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Exit codes. These are the public contract (ADR 036 §2): a pipeline branches
// on them, so changing what one means breaks every pipeline using it.
const (
	// ExitOK means the gate did not block: PASS, or WARN.
	ExitOK = 0

	// ExitGateFailed means the gate blocked. The code has a problem.
	ExitGateFailed = 1

	// ExitCouldNotEvaluate means the gate never ran -- unreachable, refused,
	// timed out, or a scan that failed outright.
	//
	// The code this whole design turns on. A client that exited 0 here would
	// turn an outage, or a network someone shaped deliberately, into a silent
	// and universal disabling of the gate: every build green, nothing checked.
	// Distinct from ExitGateFailed because the two demand different responses
	// -- fix the code, or fix the pipeline -- and a team that cannot tell them
	// apart learns to retry until green.
	ExitCouldNotEvaluate = 2
)

// pollInterval is how often the client asks whether a scan has settled.
//
// Two seconds rather than something cleverer: a scan takes tens of seconds at
// best, the API is not paginating anything here, and an exponential backoff
// would mostly add latency to the common case for no saving worth measuring.
const pollInterval = 2 * time.Second

// Options configures one run.
type Options struct {
	// BaseURL is where the API lives.
	BaseURL string
	// Token is a scoped `service` credential. Read from the environment by the
	// caller, never a flag: a flag is visible in `ps` and in CI logs
	// (ADR 036 §6).
	Token string

	// ProjectID names the project this build belongs to.
	//
	// Required, and deliberately not derived from the repository URL. The
	// dashboard derives a project from a URL and that lookup has produced three
	// separate defects -- a slug is globally unique while visibility is scoped,
	// so a target somebody else registered collides in ways that are hard to
	// explain. A pipeline knows its own project; asking for it once removes the
	// entire class.
	ProjectID string

	// RepositoryURL and Ref describe what to scan.
	RepositoryURL string
	Ref           string

	// Timeout bounds the whole run, including the wait. Exceeding it is
	// ExitCouldNotEvaluate: a scan that has not finished has not passed.
	Timeout time.Duration

	// HTTPClient is injectable so tests can drive the client without a server.
	HTTPClient *http.Client
}

// Gate is the verdict and the whole of its reasoning, as the API returns it.
//
// Mirrors the API's response rather than re-deriving anything. The client
// renders this; it does not recompute it.
type Gate struct {
	Verdict     string          `json:"verdict"`
	Conditions  []GateCondition `json:"conditions"`
	Coverage    GateCoverage    `json:"coverage"`
	Summary     string          `json:"summary"`
	ScanID      string          `json:"scan_id"`
	EvaluatedAt string          `json:"evaluated_at"`
}

// GateCondition is one rule and what it observed.
type GateCondition struct {
	Kind        string  `json:"kind"`
	Selector    string  `json:"selector,omitempty"`
	Max         float64 `json:"max"`
	Level       string  `json:"level"`
	Observed    float64 `json:"observed"`
	Breached    bool    `json:"breached"`
	Explanation string  `json:"explanation"`
}

// GateCoverage records whether the scan was complete.
type GateCoverage struct {
	Complete   bool   `json:"complete"`
	ScanStatus string `json:"scan_status"`
	// Downgraded records that incompleteness affected the verdict, so a WARN
	// caused by a crashed scanner is distinguishable from one caused by a
	// breached rule.
	Downgraded bool `json:"downgraded"`
}

// Result is everything one run produced.
type Result struct {
	ScanID string `json:"scan_id"`
	Gate   *Gate  `json:"gate,omitempty"`
	// Status is the scan's terminal status, kept even when no gate ran so a
	// caller can tell "failed to scan" from "scanned and was refused a gate".
	Status string `json:"scan_status"`
}

// ExitCode maps a result onto the contract.
//
// The only place that mapping exists. A caller that recomputed it from the
// verdict would be a second implementation of the rule that decides whether
// builds fail.
func (r Result) ExitCode() int {
	if r.Gate == nil {
		return ExitCouldNotEvaluate
	}
	if r.Gate.Verdict == "fail" {
		return ExitGateFailed
	}
	// PASS and WARN both pass. WARN exists because a team chose `warn` for that
	// rule; blocking on it would make it a FAIL with a friendlier name and
	// leave the policy engine's two levels indistinguishable to the only
	// consumer that acts on them (ADR 036 §2).
	return ExitOK
}

// ErrCouldNotEvaluate wraps every failure that is not a gate verdict.
//
// One error type for the whole class, because the caller's response is the same
// for all of them: exit 2 and say what happened. Distinguishing "DNS failed"
// from "401" matters to the human reading the message, not to the exit code.
var ErrCouldNotEvaluate = errors.New("the gate could not be evaluated")

// Run submits a scan, waits for it, and returns the gate result.
func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.Token == "" {
		return Result{}, fmt.Errorf("%w: no API token (set SECUREOPS_API_TOKEN)", ErrCouldNotEvaluate)
	}
	if opts.ProjectID == "" {
		return Result{}, fmt.Errorf("%w: no project (pass --project)", ErrCouldNotEvaluate)
	}
	if opts.RepositoryURL == "" {
		return Result{}, fmt.Errorf("%w: no repository URL (pass --repo)", ErrCouldNotEvaluate)
	}

	c := &client{
		base:  strings.TrimRight(opts.BaseURL, "/"),
		token: opts.Token,
		http:  opts.HTTPClient,
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	scanID, err := c.submit(ctx, opts)
	if err != nil {
		return Result{}, err
	}

	status, err := c.wait(ctx, scanID)
	result := Result{ScanID: scanID, Status: status}
	if err != nil {
		return result, err
	}

	gate, err := c.gate(ctx, scanID)
	if err != nil {
		return result, err
	}
	result.Gate = gate
	return result, nil
}

type client struct {
	base  string
	token string
	http  *http.Client
}

func (c *client) submit(ctx context.Context, opts Options) (string, error) {
	body := map[string]any{
		"project_id": opts.ProjectID,
		"target": map[string]any{
			"kind":           "repository",
			"repository_url": opts.RepositoryURL,
		},
	}
	if opts.Ref != "" {
		body["branch"] = opts.Ref
		body["target"].(map[string]any)["ref"] = opts.Ref
	}

	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/scans", body, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("%w: the API accepted the scan but returned no id", ErrCouldNotEvaluate)
	}
	return out.ID, nil
}

// wait polls until the scan reaches a terminal status.
//
// Polling rather than holding a request open, for the reason §13 gives: the
// HTTP request must never block on scanner execution, and a CI client is not an
// exception to that.
func (c *client) wait(ctx context.Context, scanID string) (string, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		var scan struct {
			Status        string `json:"status"`
			FailureReason string `json:"failure_reason"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/v1/scans/"+scanID, nil, &scan); err != nil {
			return "", err
		}

		switch scan.Status {
		case "completed", "partial":
			// PARTIAL settles here rather than failing: the gate is what
			// decides what degraded coverage means, and it already refuses to
			// store a PASS for one (§12). Failing here would take that
			// judgement away from the policy.
			return scan.Status, nil
		case "failed", "cancelled":
			reason := scan.FailureReason
			if reason == "" {
				reason = scan.Status
			}
			return scan.Status, fmt.Errorf("%w: the scan did not complete: %s", ErrCouldNotEvaluate, reason)
		}

		select {
		case <-ctx.Done():
			// A scan that has not finished has not passed. Exiting 0 here would
			// pass every build that was merely slow.
			return scan.Status, fmt.Errorf(
				"%w: timed out after waiting for the scan to finish (last status: %s)",
				ErrCouldNotEvaluate, scan.Status)
		case <-ticker.C:
		}
	}
}

func (c *client) gate(ctx context.Context, scanID string) (*Gate, error) {
	var gate Gate
	if err := c.do(ctx, http.MethodGet, "/api/v1/scans/"+scanID+"/gate", nil, &gate); err != nil {
		return nil, err
	}
	if gate.Verdict == "" {
		return nil, fmt.Errorf("%w: the API returned no verdict for this scan", ErrCouldNotEvaluate)
	}
	return &gate, nil
}

// do performs one request and decodes its result.
//
// Every failure becomes ErrCouldNotEvaluate. That is the point: a transport
// error, a refusal and a malformed response all mean the same thing to a
// pipeline -- the gate did not run -- and none of them may be mistaken for a
// verdict.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCouldNotEvaluate, err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCouldNotEvaluate, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s %s: %w", ErrCouldNotEvaluate, method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded, because this is an external response and §15.8 does not stop
	// applying because the peer is ours.
	limited := io.LimitReader(resp.Body, 8<<20)

	if resp.StatusCode >= 400 {
		var envelope struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		raw, _ := io.ReadAll(limited)
		_ = json.Unmarshal(raw, &envelope)
		message := envelope.Error.Message
		if message == "" {
			message = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("%w: %s %s returned %d: %s",
			ErrCouldNotEvaluate, method, path, resp.StatusCode, message)
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("%w: could not read the response to %s %s: %w",
			ErrCouldNotEvaluate, method, path, err)
	}
	return nil
}
