// Command migrate applies and rolls back SecureOps database migrations.
//
// Migrations are a security-sensitive change (CLAUDE.md §17, §24): they run as a
// separate, explicitly invoked binary rather than implicitly at API startup, so
// that schema changes are a deliberate operational act.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/logging"
)

func main() {
	dir := flag.String("dir", "migrations", "directory containing migration files")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: migrate [-dir path] <up|down|version>\n\n")
		fmt.Fprintf(os.Stderr, "  up       apply all pending migrations\n")
		fmt.Fprintf(os.Stderr, "  down     roll back exactly one migration\n")
		fmt.Fprintf(os.Stderr, "  version  print the current schema version\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	logger := logging.New(os.Stdout, logging.Options{Level: slog.LevelInfo, Format: "text", Service: "secureops-migrate"})

	if err := run(logger, *dir, flag.Arg(0)); err != nil {
		logger.Error("migration failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger, dir, command string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	m, err := migrate.New("file://"+dir, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open migration source: %w", err)
	}
	defer func() {
		// Close returns a source error and a database error; report either.
		if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
			logger.Warn("close migrator",
				slog.Any("source_error", srcErr),
				slog.Any("database_error", dbErr),
			)
		}
	}()

	switch command {
	case "up":
		if err := m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				logger.Info("no pending migrations")
				return nil
			}
			return err
		}
		logger.Info("migrations applied")

	case "down":
		// Steps(-1) rolls back exactly one migration. A bare Down() would drop
		// the entire schema, which must never be a single-word command.
		if err := m.Steps(-1); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				logger.Info("no migrations to roll back")
				return nil
			}
			return err
		}
		logger.Info("rolled back one migration")

	case "version":
		v, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				logger.Info("no migrations applied yet")
				return nil
			}
			return err
		}
		logger.Info("schema version", slog.Uint64("version", uint64(v)), slog.Bool("dirty", dirty))

	default:
		flag.Usage()
		return fmt.Errorf("unknown command %q", command)
	}
	return nil
}
