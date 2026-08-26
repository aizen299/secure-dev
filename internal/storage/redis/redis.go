// Package redis provides the SecureOps Redis client.
//
// Redis is the scan job queue (CLAUDE.md §13). Phase 1 establishes connectivity
// and readiness only; queue semantics arrive in Phase 2.
package redis

import (
	"context"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
)

// Client wraps a go-redis client and exposes it as a health probe.
type Client struct {
	client *goredis.Client
}

// Connect opens a Redis client and verifies it with a ping.
func Connect(ctx context.Context, url string) (*Client, error) {
	opts, err := goredis.ParseURL(url)
	if err != nil {
		// The URL may carry a password; never include it in the error.
		return nil, fmt.Errorf("parse redis configuration: invalid URL")
	}

	client := goredis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return &Client{client: client}, nil
}

// Redis returns the underlying client for queue operations.
func (c *Client) Redis() *goredis.Client { return c.client }

// Name identifies this dependency in readiness output.
func (c *Client) Name() string { return "redis" }

// Check implements the readiness probe contract.
func (c *Client) Check(ctx context.Context) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("redis client is not initialised")
	}
	return c.client.Ping(ctx).Err()
}

// Close releases the client's connections.
func (c *Client) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}
