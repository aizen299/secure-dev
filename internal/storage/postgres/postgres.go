// Package postgres provides the SecureOps PostgreSQL connection pool.
//
// Query construction rule (CLAUDE.md §15.9): every statement issued through this
// pool must use parameter placeholders. pgx rejects multi-statement text in the
// extended protocol, which is the mechanism that enforces it.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool wraps a pgx pool and exposes it as a health probe.
type Pool struct {
	pool *pgxpool.Pool
}

// Config holds the settings needed to open a pool.
type Config struct {
	URL      string
	MaxConns int32
}

// Connect opens a connection pool and verifies it with a ping.
func Connect(ctx context.Context, cfg Config) (*Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		// The DSN carries a password; never include it in the error.
		return nil, fmt.Errorf("parse postgres configuration: invalid DSN")
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Pool{pool: pool}, nil
}

// DB returns the underlying pool for query execution.
func (p *Pool) DB() *pgxpool.Pool { return p.pool }

// Name identifies this dependency in readiness output.
func (p *Pool) Name() string { return "postgres" }

// Check implements the readiness probe contract.
func (p *Pool) Check(ctx context.Context) error {
	if p == nil || p.pool == nil {
		return fmt.Errorf("postgres pool is not initialised")
	}
	return p.pool.Ping(ctx)
}

// Close releases all pooled connections.
func (p *Pool) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}
