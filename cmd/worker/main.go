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
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/gitleaks"
	"github.com/aizen299/secure-dev/internal/scanners/grype"
	"github.com/aizen299/secure-dev/internal/scanners/semgrep"
	"github.com/aizen299/secure-dev/internal/scanners/syft"
	"github.com/aizen299/secure-dev/internal/scanners/trivy"
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
	registerScanners(registry, cfg)

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

	store := scans.NewStore(db.DB())

	runner, err := worker.New(worker.Options{
		Registry: registry,
		Queue:    queue.NewRedis(cache.Redis(), queue.DefaultKey),
		Store:    store,
		Sink:     store,
		Findings: findings.NewStore(db.DB()),
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
// Grype takes a configured path rather than nothing, which is as far as the
// exception goes: what that path is for, how the database gets there, and what
// happens when it is stale are all inside the adapter. Provisioning is driven
// through the generic scanners.Provisioner hook, so this function does not know
// that grype needs a database at all.
func registerScanners(registry *scanners.Registry, cfg config.Config) {
	registry.MustRegister(gitleaks.New())
	registry.MustRegister(syft.New())
	registry.MustRegister(grype.New(cfg.GrypeDBCacheDir))
	registry.MustRegister(semgrep.New(cfg.SemgrepDir))
	registry.MustRegister(trivy.New(cfg.TrivyDir))
}
