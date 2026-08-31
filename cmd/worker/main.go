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
	"github.com/aizen299/secure-dev/internal/logging"
	"github.com/aizen299/secure-dev/internal/netguard"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/gitleaks"
	"github.com/aizen299/secure-dev/internal/scans"
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

	registry := scanners.NewRegistry()
	registerScanners(registry)

	if len(registry.Names()) == 0 {
		// Not fatal: the worker still drains the queue and records every job
		// as failed, which is a far clearer signal than silently idling.
		logger.Warn("no scanner adapters are registered; every job will fail")
	}

	store := scans.NewStore(db.DB())

	runner, err := worker.New(worker.Options{
		Registry: registry,
		Queue:    queue.NewRedis(cache.Redis(), queue.DefaultKey),
		Store:    store,
		Sink:     store,
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
	})
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

// registerScanners wires the scanner adapters.
//
// Adding a scanner is one line here plus its own package -- nothing else in the
// codebase changes (§7 rule 4). The remaining adapters land the same way:
//
//	registry.MustRegister(semgrep.New())
//	registry.MustRegister(syft.New())
func registerScanners(registry *scanners.Registry) {
	registry.MustRegister(gitleaks.New())
}
