// Command worker executes SecureOps scan jobs.
//
// This binary is the only component that touches untrusted target content
// (CLAUDE.md §14.2). It is also the composition root for scanner adapters:
// registration happens here, explicitly, so the wiring is visible in one place
// rather than hidden in package init side effects.
//
// No adapters are registered yet -- Phase 3 adds them, one scanner at a time.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/fetch"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/logging"
	"github.com/aizen299/secure-dev/internal/netguard"
	"github.com/aizen299/secure-dev/internal/policies"
	"github.com/aizen299/secure-dev/internal/queue"
	sbomstore "github.com/aizen299/secure-dev/internal/sbom/store"
	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/all"
	scanstore "github.com/aizen299/secure-dev/internal/scans/store"
	"github.com/aizen299/secure-dev/internal/storage/postgres"
	"github.com/aizen299/secure-dev/internal/storage/redis"
	"github.com/aizen299/secure-dev/internal/worker"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := logging.New(os.Stdout, logging.Options{
		Level:   cfg.LogLevel,
		Format:  cfg.LogFormat,
		Service: "secureops-worker",
		Version: version,
	})
	slog.SetDefault(logger)
	logger.Info("starting secureops worker", slog.Any("config", cfg))

	if cfg.AllowPrivateTargets {
		// Loud on purpose: this removes the SSRF guard.
		logger.Warn("private and loopback scan targets are permitted; SSRF protection is reduced")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	db, err := postgres.Connect(connectCtx, postgres.Config{URL: cfg.DatabaseURL, MaxConns: cfg.DBMaxConns})
	if err != nil {
		return err
	}
	defer db.Close()
	logger.Info("connected to postgres")

	cache, err := redis.Connect(connectCtx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := cache.Close(); err != nil {
			logger.Warn("close redis", slog.String("error", err.Error()))
		}
	}()
	logger.Info("connected to redis")

	// Every adapter, from the one list both binaries share (§7 rule 4).
	registry := all.New(cfg)

	// Adapters that need data in place get it now, before the queue is touched
	// and therefore before any untrusted repository exists on disk (§14.3).
	// A failure is logged and the adapter stays registered: a scan that needed
	// it then records a failed scanner and settles at PARTIAL, which is visible.
	// Dropping the adapter would hide the loss of coverage instead.
	for name, provisionErr := range registry.Provision(ctx) {
		logger.Error("scanner could not be provisioned; it will fail per scan",
			slog.String("scanner", name), slog.String("error", provisionErr.Error()))
	}

	if len(registry.Names()) == 0 {
		// Not fatal: the worker still drains the queue and records every job
		// as failed, which is a far clearer signal than silently idling.
		logger.Warn("no scanner adapters are registered; every job will fail")
	}

	store := scanstore.New(db.DB())

	// How scans execute (ADR 039). The default keeps them in this process,
	// which is what compose gets; "kubernetes" runs each in its own pod that
	// holds no credential of any kind.
	var executor scanexec.Executor
	if cfg.ScanExecutor == "kubernetes" {
		exec, shutdown, err := kubernetesExecutor(ctx, cfg, logger)
		if err != nil {
			return err
		}
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			if err := shutdown(shutCtx); err != nil {
				logger.Error("scan job intake did not shut down cleanly",
					slog.String("error", err.Error()))
			}
		}()
		executor = exec
		logger.Info("scans run as ephemeral kubernetes jobs",
			slog.String("namespace", cfg.JobNamespace))
	}

	opts := workerOptions(cfg, logger, db, cache, registry, store)
	opts.Executor = executor

	runner, err := worker.New(opts)
	if err != nil {
		return err
	}

	// Run blocks until ctx is cancelled, then drains in-flight jobs.
	if err := runner.Run(ctx); err != nil {
		return err
	}
	logger.Info("shutdown complete")
	return nil
}

// workerOptions assembles every dependency the scan pipeline needs.
//
// Extracted so a test can assert it, for the reason the API's equivalent was:
// worker.Options treats each store as optional -- a nil Policies makes the
// runner skip the gate silently rather than fail at startup -- and this call
// did not pass it. Phase 8's gate was therefore never evaluated by the real
// binary, and because the API could not serve a result either, the whole
// feature was unreachable from both ends at once.
//
// See TestWorkerOptionsWireEveryStore.
func workerOptions(
	cfg config.Config,
	logger *slog.Logger,
	db *postgres.Pool,
	cache *redis.Client,
	registry *scanners.Registry,
	store *scanstore.Store,
) worker.Options {
	return worker.Options{
		// How scans run (ADR 039). nil keeps the in-process executor the
		// Runner builds from the options below, which is what a compose
		// deployment gets: compose cannot create a Kubernetes Job, and a
		// change that improved production by breaking `make up` would not be
		// a good trade for a project this size.
		//
		// Written out rather than omitted because omitting it would make this
		// binary silent about how it executes untrusted content -- and because
		// the Kubernetes executor is selected exactly here when it lands.
		Executor: nil,
		Registry: registry,
		Queue:    queue.NewRedis(cache.Redis(), queue.DefaultKey),
		Store:    store,
		Sink:     store,
		Findings: findings.NewStore(db.DB()),
		// The bill of materials syft produces, made queryable (ADR 035).
		Components: sbomstore.New(db.DB()),
		// Without this the runner reaches no verdict and writes no result, so
		// GET /scans/{id}/gate answers 404 forever.
		Policies: policies.NewStore(db.DB()),
		Validator: scanners.Validator{
			WorkspaceRoot: cfg.WorkerWorkspaceRoot,
			NetworkPolicy: netguard.Policy{AllowPrivate: cfg.AllowPrivateTargets},
		},
		WorkspaceRoot: cfg.WorkerWorkspaceRoot,
		Fetch: fetch.Options{
			Timeout:  cfg.FetchTimeout,
			MaxBytes: cfg.FetchMaxBytes,
			MaxFiles: cfg.FetchMaxFiles,
		},
		Logger:         logger,
		Concurrency:    cfg.WorkerConcurrency,
		JobTimeout:     cfg.ScanJobTimeout,
		ScannerTimeout: cfg.ScannerTimeout,
		MaxOutputBytes: cfg.ScannerMaxOutputBytes,
	}
}
