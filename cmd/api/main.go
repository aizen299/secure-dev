// Command api runs the SecureOps HTTP API server.
//
// The API orchestrates; it never executes scanners or any other untrusted
// target content. That work belongs to isolated workers (CLAUDE.md §14).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aizen299/secure-dev/internal/auth"
	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/httpapi"
	"github.com/aizen299/secure-dev/internal/logging"
	"github.com/aizen299/secure-dev/internal/netguard"
	"github.com/aizen299/secure-dev/internal/policies"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scans"
	"github.com/aizen299/secure-dev/internal/storage/postgres"
	"github.com/aizen299/secure-dev/internal/storage/redis"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet, so fail loudly on stderr.
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
		Service: "secureops-api",
		Version: version,
	})
	slog.SetDefault(logger)

	// cfg implements slog.LogValuer, so the DSNs are redacted here.
	logger.Info("starting secureops api", slog.Any("config", cfg))

	// Built before any connection is opened: a credential problem should stop
	// startup immediately, not after the process has attached to a database.
	// auth.New refuses an empty or weak token set, so there is no path on
	// which this server comes up unauthenticated (ADR 006).
	authenticator, err := auth.New(cfg.APITokens)
	if err != nil {
		return err
	}
	logger.Info("api authentication configured",
		slog.Any("token_labels", authenticator.Labels()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	db, err := postgres.Connect(connectCtx, postgres.Config{
		URL:      cfg.DatabaseURL,
		MaxConns: cfg.DBMaxConns,
	})
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

	jobQueue := queue.NewRedis(cache.Redis(), queue.DefaultKey)

	// The same SSRF policy the worker uses. Validation happens at both ends:
	// here so a hostile target never reaches the queue, and again in the
	// worker because anything crossing the queue is untrusted (§15.7).
	validator := scanners.Validator{
		WorkspaceRoot: cfg.WorkerWorkspaceRoot,
		NetworkPolicy: netguard.Policy{AllowPrivate: cfg.AllowPrivateTargets},
	}

	handler, err := httpapi.New(apiOptions(cfg, logger, db, cache, jobQueue, validator, authenticator))
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("http server listening", slog.String("addr", cfg.HTTPAddr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("shutdown complete")
	return nil
}

// apiOptions assembles every dependency the API serves from.
//
// Extracted from the startup path so a test can assert it, which is not
// ceremony: the gate endpoints were unreachable for the whole of Phase 8
// because httpapi.Options treats each store as optional and this call simply
// did not pass Policies. The handler tests wired their own store and passed;
// nothing checked the binary. See TestAPIOptionsWireEveryStore.
func apiOptions(
	cfg config.Config,
	logger *slog.Logger,
	db *postgres.Pool,
	cache *redis.Client,
	jobQueue *queue.RedisQueue,
	validator scanners.Validator,
	authenticator *auth.Authenticator,
) httpapi.Options {
	return httpapi.Options{
		Service:       "secureops-api",
		Version:       version,
		Logger:        logger,
		Probes:        []httpapi.Probe{db, cache},
		Authenticator: authenticator,
		Projects:      projects.NewStore(db.DB()),
		Scans:         scans.NewStore(db.DB()),
		Queue:         jobQueue,
		Findings:      findings.NewStore(db.DB()),
		// Without this the policy and gate endpoints answer 503, which is how
		// Phase 8's gate shipped unreachable.
		Policies:        policies.NewStore(db.DB()),
		Validator:       validator,
		MaxRequestBytes: cfg.MaxRequestBytes,
	}
}
