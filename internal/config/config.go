// Package config loads SecureOps runtime configuration from the environment.
//
// Configuration values that carry credentials (database and Redis URLs) are
// treated as secrets: Config implements slog.LogValuer so that logging a Config
// can never leak a DSN. See CLAUDE.md §15.1-§15.3.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment names the deployment context. It is a risk-engine input later
// (production findings are weighted differently), so it is validated here.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// Config is the fully resolved configuration for a SecureOps process.
type Config struct {
	Env      Environment
	HTTPAddr string

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration

	LogLevel  slog.Level
	LogFormat string

	// DatabaseURL and RedisURL are secrets. Never log them directly.
	DatabaseURL string
	RedisURL    string

	// APITokens holds the interim bearer credentials as "label:secret" pairs
	// (ADR 006). These are secrets: LogValue reports only how many there are.
	// Their content is validated by internal/auth, which owns the rules, so
	// there is one place to change when Phase 11 replaces this.
	APITokens []string

	// MaxRequestBytes caps a request body before it is parsed (§15.8).
	MaxRequestBytes int64

	DBMaxConns int32

	// Worker settings. Every one is a resource limit (CLAUDE.md §14) and is
	// deliberately configurable rather than hardcoded.
	WorkerConcurrency     int
	WorkerWorkspaceRoot   string
	ScanJobTimeout        time.Duration
	ScannerTimeout        time.Duration
	ScannerMaxOutputBytes int64
	// AllowPrivateTargets permits scanning loopback and private addresses.
	// Off by default: turning it on removes the SSRF guard, so it must be a
	// deliberate choice for a self-hosted deployment (§14.6).
	AllowPrivateTargets bool
}

// Load reads configuration from the process environment and validates it.
func Load() (Config, error) {
	cfg := Config{
		Env:               Environment(getenv("SECUREOPS_ENV", string(EnvDevelopment))),
		HTTPAddr:          getenv("SECUREOPS_HTTP_ADDR", ":8080"),
		ReadHeaderTimeout: 5 * time.Second,
		LogFormat:         getenv("SECUREOPS_LOG_FORMAT", "json"),
		DatabaseURL:       os.Getenv("SECUREOPS_DATABASE_URL"),
		RedisURL:          os.Getenv("SECUREOPS_REDIS_URL"),
		APITokens:         splitList(os.Getenv("SECUREOPS_API_TOKENS")),
	}

	var errs []error
	var err error

	if cfg.ReadTimeout, err = durationEnv("SECUREOPS_HTTP_READ_TIMEOUT", 15*time.Second); err != nil {
		errs = append(errs, err)
	}
	if cfg.WriteTimeout, err = durationEnv("SECUREOPS_HTTP_WRITE_TIMEOUT", 30*time.Second); err != nil {
		errs = append(errs, err)
	}
	if cfg.IdleTimeout, err = durationEnv("SECUREOPS_HTTP_IDLE_TIMEOUT", 60*time.Second); err != nil {
		errs = append(errs, err)
	}
	if cfg.ShutdownTimeout, err = durationEnv("SECUREOPS_SHUTDOWN_TIMEOUT", 20*time.Second); err != nil {
		errs = append(errs, err)
	}
	if cfg.DBMaxConns, err = int32Env("SECUREOPS_DB_MAX_CONNS", 10); err != nil {
		errs = append(errs, err)
	}
	if cfg.LogLevel, err = levelEnv("SECUREOPS_LOG_LEVEL", slog.LevelInfo); err != nil {
		errs = append(errs, err)
	}
	if cfg.ScanJobTimeout, err = durationEnv("SECUREOPS_SCAN_JOB_TIMEOUT", 30*time.Minute); err != nil {
		errs = append(errs, err)
	}
	if cfg.ScannerTimeout, err = durationEnv("SECUREOPS_SCANNER_TIMEOUT", 10*time.Minute); err != nil {
		errs = append(errs, err)
	}
	if cfg.WorkerConcurrency, err = intEnv("SECUREOPS_WORKER_CONCURRENCY", 2); err != nil {
		errs = append(errs, err)
	}
	if cfg.ScannerMaxOutputBytes, err = int64Env("SECUREOPS_SCANNER_MAX_OUTPUT_BYTES", 64<<20); err != nil {
		errs = append(errs, err)
	}
	if cfg.MaxRequestBytes, err = int64Env("SECUREOPS_MAX_REQUEST_BYTES", 1<<20); err != nil {
		errs = append(errs, err)
	}
	if cfg.AllowPrivateTargets, err = boolEnv("SECUREOPS_ALLOW_PRIVATE_TARGETS", false); err != nil {
		errs = append(errs, err)
	}
	// Trim before validating: a whitespace-only value would otherwise pass the
	// non-empty check and create a directory literally named " ".
	cfg.WorkerWorkspaceRoot = strings.TrimSpace(getenv("SECUREOPS_WORKSPACE_ROOT", "/tmp/secureops-workspaces"))

	if err := cfg.validate(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

func (c Config) validate() error {
	var errs []error

	switch c.Env {
	case EnvDevelopment, EnvStaging, EnvProduction:
	default:
		errs = append(errs, fmt.Errorf("SECUREOPS_ENV: %q is not one of development, staging, production", c.Env))
	}

	if c.HTTPAddr == "" {
		errs = append(errs, errors.New("SECUREOPS_HTTP_ADDR: must not be empty"))
	}

	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("SECUREOPS_LOG_FORMAT: %q is not one of json, text", c.LogFormat))
	}

	// Validate the shape of the DSNs without ever echoing their contents:
	// an error message must not become a credential leak.
	if err := requireURL("SECUREOPS_DATABASE_URL", c.DatabaseURL, "postgres", "postgresql"); err != nil {
		errs = append(errs, err)
	}
	if err := requireURL("SECUREOPS_REDIS_URL", c.RedisURL, "redis", "rediss"); err != nil {
		errs = append(errs, err)
	}

	if c.DBMaxConns < 1 {
		errs = append(errs, fmt.Errorf("SECUREOPS_DB_MAX_CONNS: must be >= 1, got %d", c.DBMaxConns))
	}
	if c.WorkerConcurrency < 1 {
		errs = append(errs, fmt.Errorf("SECUREOPS_WORKER_CONCURRENCY: must be >= 1, got %d", c.WorkerConcurrency))
	}
	if c.ScannerMaxOutputBytes < 1 {
		errs = append(errs, fmt.Errorf("SECUREOPS_SCANNER_MAX_OUTPUT_BYTES: must be >= 1, got %d", c.ScannerMaxOutputBytes))
	}
	if c.MaxRequestBytes < 1 {
		errs = append(errs, fmt.Errorf("SECUREOPS_MAX_REQUEST_BYTES: must be >= 1, got %d", c.MaxRequestBytes))
	}
	// A scanner allowed to outlive its job would be killed mid-write, losing
	// the result and leaving the scan stuck.
	if c.ScannerTimeout > c.ScanJobTimeout {
		errs = append(errs, fmt.Errorf(
			"SECUREOPS_SCANNER_TIMEOUT (%s) must not exceed SECUREOPS_SCAN_JOB_TIMEOUT (%s)",
			c.ScannerTimeout, c.ScanJobTimeout))
	}
	if c.WorkerWorkspaceRoot == "" {
		errs = append(errs, errors.New("SECUREOPS_WORKSPACE_ROOT: must not be empty"))
	}
	// Refusing to boot production with the SSRF guard disabled is deliberate:
	// this is the setting most likely to be switched on locally and shipped
	// by accident.
	if c.Env == EnvProduction && c.AllowPrivateTargets {
		errs = append(errs, errors.New(
			"SECUREOPS_ALLOW_PRIVATE_TARGETS: must not be enabled in production"))
	}

	return errors.Join(errs...)
}

// IsProduction reports whether the process runs in the production environment.
func (c Config) IsProduction() bool { return c.Env == EnvProduction }

// LogValue implements slog.LogValuer so that a Config is always logged with its
// secrets redacted, even if someone logs the whole struct.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", string(c.Env)),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("log_level", c.LogLevel.String()),
		slog.String("log_format", c.LogFormat),
		slog.Int("db_max_conns", int(c.DBMaxConns)),
		slog.Int("worker_concurrency", c.WorkerConcurrency),
		slog.String("workspace_root", c.WorkerWorkspaceRoot),
		slog.Duration("scan_job_timeout", c.ScanJobTimeout),
		slog.Duration("scanner_timeout", c.ScannerTimeout),
		slog.Int64("scanner_max_output_bytes", c.ScannerMaxOutputBytes),
		slog.Int64("max_request_bytes", c.MaxRequestBytes),
		slog.Bool("allow_private_targets", c.AllowPrivateTargets),
		// Count only. The pairs contain secrets, so neither the labels nor the
		// values are logged from here (§15.3).
		slog.Int("api_tokens_configured", len(c.APITokens)),
		slog.String("database_url", RedactURL(c.DatabaseURL)),
		slog.String("redis_url", RedactURL(c.RedisURL)),
	)
}

// RedactURL returns a URL safe to log: scheme, host, and path are preserved so
// the value stays diagnosable, while userinfo and query parameters (which carry
// passwords and tokens) are removed.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable-redacted]"
	}
	if u.User != nil {
		u.User = url.User("redacted")
	}
	if u.RawQuery != "" {
		u.RawQuery = "redacted"
	}
	u.Fragment = ""
	return u.String()
}

func requireURL(key, raw string, schemes ...string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s: is required", key)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: is not a valid URL", key)
	}
	for _, s := range schemes {
		if u.Scheme == s {
			if u.Host == "" {
				return fmt.Errorf("%s: URL is missing a host", key)
			}
			return nil
		}
	}
	return fmt.Errorf("%s: scheme must be one of %s", key, strings.Join(schemes, ", "))
}

// splitList parses a comma-separated environment value, discarding empty
// entries so a trailing comma or an accidental double comma is not read as a
// credential with an empty label.
func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		// Only surrounding whitespace is trimmed. The secret inside a
		// label:secret pair keeps its exact value.
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid duration", key, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be greater than zero, got %q", key, raw)
	}
	return d, nil
}

func int32Env(key string, fallback int32) (int32, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid integer", key, raw)
	}
	return int32(n), nil
}

func levelEnv(key string, fallback slog.Level) (slog.Level, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(raw)); err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid log level (debug, info, warn, error)", key, raw)
	}
	return lvl, nil
}

func intEnv(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid integer", key, raw)
	}
	return n, nil
}

func int64Env(key string, fallback int64) (int64, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid integer", key, raw)
	}
	return n, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a valid boolean", key, raw)
	}
	return v, nil
}
