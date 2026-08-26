//go:build integration

// Package integration exercises SecureOps against real PostgreSQL and Redis.
//
// These tests are behind the `integration` build tag so the default `go test
// ./...` stays hermetic. Run them with `make test-integration`.
package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
	"github.com/aizen299/secure-dev/internal/worker"
)

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s is not set; skipping integration test", key)
	}
	return v
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), requireEnv(t, "SECUREOPS_DATABASE_URL"))
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testRedis(t *testing.T) *goredis.Client {
	t.Helper()
	opts, err := goredis.ParseURL(requireEnv(t, "SECUREOPS_REDIS_URL"))
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	client := goredis.NewClient(opts)
	if err := client.Ping(t.Context()).Err(); err != nil {
		t.Fatalf("ping redis: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// seedScan creates a project and a queued scan, returning the scan id.
func seedScan(t *testing.T, pool *pgxpool.Pool) (scanID, projectID string) {
	t.Helper()
	slug := "itest-" + uuid.NewString()[:8]

	err := pool.QueryRow(t.Context(),
		`INSERT INTO projects (name, slug) VALUES ($1, $2) RETURNING id`,
		"Integration Test", slug).Scan(&projectID)
	if err != nil {
		t.Fatalf("insert project: %v", err)
	}
	err = pool.QueryRow(t.Context(),
		`INSERT INTO scans (project_id, status) VALUES ($1, 'queued') RETURNING id`,
		projectID).Scan(&scanID)
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}

	t.Cleanup(func() {
		// Cascades to scans and their results.
		_, _ = pool.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, projectID)
	})
	return scanID, projectID
}

// echoScanner is a stand-in adapter that shells out through the real exec
// layer, so this test covers argv execution as well as the pipeline.
type echoScanner struct {
	name string
	fail bool
}

func (e echoScanner) Name() string { return e.name }
func (e echoScanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{Kinds: []scanners.Kind{scanners.KindFilesystem}, Category: scanners.CategorySAST}
}
func (e echoScanner) Version(ctx context.Context) (string, error) {
	return "0.0.1-test", nil
}
func (e echoScanner) Scan(ctx context.Context, target scanners.Target) (scanners.RawResult, error) {
	if e.fail {
		return scanners.RawResult{Scanner: e.name, ExitCode: 1}, errors.New("scanner failed on purpose")
	}
	res, err := scanners.Run(ctx, scanners.ExecOptions{Timeout: 10 * time.Second},
		"echo", `{"findings":[]}`)
	if err != nil {
		return scanners.RawResult{Scanner: e.name}, err
	}
	return scanners.RawResult{
		Scanner: e.name, Version: "0.0.1-test", Target: target,
		Output: res.Stdout, ExitCode: res.ExitCode, Duration: res.Duration,
	}, nil
}

func newRunner(t *testing.T, pool *pgxpool.Pool, client *goredis.Client, key string, sc ...scanners.Scanner) *worker.Runner {
	t.Helper()
	reg := scanners.NewRegistry()
	for _, s := range sc {
		if err := reg.Register(s); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	store := scans.NewStore(pool)
	root := t.TempDir()

	r, err := worker.New(worker.Options{
		Registry:       reg,
		Queue:          queue.NewRedis(client, key),
		Store:          store,
		Sink:           store,
		Validator:      scanners.Validator{WorkspaceRoot: root},
		WorkspaceRoot:  root,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Concurrency:    2,
		PollTimeout:    200 * time.Millisecond,
		ScannerTimeout: 10 * time.Second,
		JobTimeout:     30 * time.Second,
	})
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}
	return r
}

func drainQueue(t *testing.T, r *worker.Runner, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()
	<-done
}

func scanStatus(t *testing.T, pool *pgxpool.Pool, scanID string) string {
	t.Helper()
	var status string
	if err := pool.QueryRow(t.Context(),
		`SELECT status FROM scans WHERE id = $1`, scanID).Scan(&status); err != nil {
		t.Fatalf("read scan status: %v", err)
	}
	return status
}

// The full Phase 2 path: enqueue to real Redis, worker consumes, executes a
// scanner through the real exec layer, and persists results to PostgreSQL.
func TestScanPipelineEndToEnd(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)
	scanID, projectID := seedScan(t, pool)

	key := "secureops:itest:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	q := queue.NewRedis(client, key)
	if err := q.Enqueue(t.Context(), queue.Job{
		ScanID: scanID, ProjectID: projectID, Attempt: 1,
		Target: scanners.Target{Kind: scanners.KindFilesystem, Path: "repo"},
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if n, err := q.Len(t.Context()); err != nil || n != 1 {
		t.Fatalf("queue length = %d, %v; want 1", n, err)
	}

	drainQueue(t, newRunner(t, pool, client, key, echoScanner{name: "echo-sast"}), 8*time.Second)

	if got := scanStatus(t, pool, scanID); got != "completed" {
		t.Errorf("scan status = %q, want completed", got)
	}

	var scanner, status, version string
	var truncated bool
	err := pool.QueryRow(t.Context(), `
		SELECT scanner, status, scanner_version, truncated
		  FROM scan_scanner_results WHERE scan_id = $1`, scanID).
		Scan(&scanner, &status, &version, &truncated)
	if err != nil {
		t.Fatalf("read scanner result: %v", err)
	}
	if scanner != "echo-sast" || status != "succeeded" {
		t.Errorf("result = %s/%s, want echo-sast/succeeded", scanner, status)
	}
	// Scanner version must be captured: results are only reproducible
	// relative to it (CLAUDE.md §7 rule 6).
	if version != "0.0.1-test" {
		t.Errorf("scanner_version = %q, want 0.0.1-test", version)
	}
	if truncated {
		t.Error("result was marked truncated")
	}

	// Raw output is persisted verbatim for reprocessing (§8).
	var output []byte
	var outputBytes int64
	err = pool.QueryRow(t.Context(),
		`SELECT output, output_bytes FROM scan_raw_results WHERE scan_id = $1`, scanID).
		Scan(&output, &outputBytes)
	if err != nil {
		t.Fatalf("read raw result: %v", err)
	}
	if outputBytes == 0 || len(output) == 0 {
		t.Error("raw scanner output was not persisted")
	}
	if got := string(output); got == "" {
		t.Error("stored output is empty")
	}
}

// The §13 guarantee, against real infrastructure: one failing scanner yields
// PARTIAL, never COMPLETED, and the working scanner's result survives.
func TestPartialScanIsPersistedAsPartial(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)
	scanID, projectID := seedScan(t, pool)

	key := "secureops:itest:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	if err := queue.NewRedis(client, key).Enqueue(t.Context(), queue.Job{
		ScanID: scanID, ProjectID: projectID, Attempt: 1,
		Target: scanners.Target{Kind: scanners.KindFilesystem, Path: "repo"},
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	drainQueue(t, newRunner(t, pool, client, key,
		echoScanner{name: "good"}, echoScanner{name: "bad", fail: true}), 8*time.Second)

	if got := scanStatus(t, pool, scanID); got != "partial" {
		t.Fatalf("scan status = %q, want partial", got)
	}

	rows, err := pool.Query(t.Context(),
		`SELECT scanner, status FROM scan_scanner_results WHERE scan_id = $1 ORDER BY scanner`, scanID)
	if err != nil {
		t.Fatalf("query results: %v", err)
	}
	defer rows.Close()

	got := map[string]string{}
	for rows.Next() {
		var name, status string
		if err := rows.Scan(&name, &status); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		got[name] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if got["good"] != "succeeded" {
		t.Errorf("good scanner = %q, want succeeded", got["good"])
	}
	if got["bad"] != "failed" {
		t.Errorf("bad scanner = %q, want failed", got["bad"])
	}
}

// A finalized scan must not be rewritten by a late or duplicated delivery.
func TestFinalizeIsIdempotentAgainstReplay(t *testing.T) {
	pool := testPool(t)
	scanID, _ := seedScan(t, pool)
	store := scans.NewStore(pool)

	if err := store.MarkRunning(t.Context(), scanID, time.Now().UTC()); err != nil {
		t.Fatalf("MarkRunning: %v", err)
	}
	if err := store.Finalize(t.Context(), scanID, scans.StatusPartial, time.Now().UTC()); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// A replayed worker must not be able to upgrade partial to completed.
	if err := store.Finalize(t.Context(), scanID, scans.StatusCompleted, time.Now().UTC()); err == nil {
		t.Error("a terminal scan was re-finalized; a failure could be silently erased")
	}
	if got := scanStatus(t, pool, scanID); got != "partial" {
		t.Errorf("scan status = %q, want partial to be preserved", got)
	}

	// Likewise it must not be dragged back to running.
	if err := store.MarkRunning(t.Context(), scanID, time.Now().UTC()); err == nil {
		t.Error("a terminal scan was moved back to running")
	}
}

func TestRedisQueueRoundTrip(t *testing.T) {
	client := testRedis(t)
	key := "secureops:itest:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	q := queue.NewRedis(client, key)
	job := queue.Job{
		ScanID: "scan-x", ProjectID: "proj-x", Attempt: 1,
		Target:   scanners.Target{Kind: scanners.KindImage, Image: "alpine:3.20"},
		Scanners: []string{"trivy"},
	}
	if err := q.Enqueue(t.Context(), job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	got, err := q.Dequeue(t.Context(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if got.ScanID != job.ScanID || got.Target.Image != "alpine:3.20" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if got.EnqueuedAt.IsZero() {
		t.Error("EnqueuedAt was not preserved")
	}

	if _, err := q.Dequeue(t.Context(), 300*time.Millisecond); !errors.Is(err, queue.ErrEmpty) {
		t.Errorf("second Dequeue: err = %v, want ErrEmpty", err)
	}
}

// A malformed payload must be rejected rather than crashing the worker.
func TestRedisQueueRejectsMalformedPayload(t *testing.T) {
	client := testRedis(t)
	key := "secureops:itest:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	if err := client.RPush(t.Context(), key, "this is not json").Err(); err != nil {
		t.Fatalf("RPush: %v", err)
	}
	if _, err := queue.NewRedis(client, key).Dequeue(t.Context(), 2*time.Second); err == nil {
		t.Error("malformed payload was accepted")
	}
}
