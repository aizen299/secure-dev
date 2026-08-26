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

	DBMaxConns int32
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
