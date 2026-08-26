package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// DefaultKey is the Redis list holding pending scan jobs.
const DefaultKey = "secureops:scan_jobs"

// maxPayloadBytes caps a single job payload. The queue is an input boundary
// like any other, so it is size-bounded (§15.8).
const maxPayloadBytes = 1 << 20 // 1 MiB

// RedisQueue is a Redis list-backed Queue.
type RedisQueue struct {
	client *goredis.Client
	key    string
}

// NewRedis returns a queue backed by the given client.
func NewRedis(client *goredis.Client, key string) *RedisQueue {
	if key == "" {
		key = DefaultKey
	}
	return &RedisQueue{client: client, key: key}
}

// Enqueue appends a job to the queue.
func (q *RedisQueue) Enqueue(ctx context.Context, job Job) error {
	if err := job.Validate(); err != nil {
		return err
	}
	if job.EnqueuedAt.IsZero() {
		job.EnqueuedAt = time.Now().UTC()
	}

	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}
	if len(payload) > maxPayloadBytes {
		return fmt.Errorf("job payload is %d bytes, over the %d byte limit", len(payload), maxPayloadBytes)
	}

	if err := q.client.RPush(ctx, q.key, payload).Err(); err != nil {
		return fmt.Errorf("enqueue job: %w", err)
	}
	return nil
}

// Dequeue pops the oldest job, blocking up to timeout.
func (q *RedisQueue) Dequeue(ctx context.Context, timeout time.Duration) (Job, error) {
	res, err := q.client.BLPop(ctx, timeout, q.key).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return Job{}, ErrEmpty
		}
		return Job{}, fmt.Errorf("dequeue job: %w", err)
	}
	// BLPop returns [key, value].
	if len(res) != 2 {
		return Job{}, fmt.Errorf("dequeue job: unexpected reply shape")
	}

	payload := res[1]
	if len(payload) > maxPayloadBytes {
		return Job{}, fmt.Errorf("dequeue job: payload exceeds the size limit")
	}

	var job Job
	if err := json.Unmarshal([]byte(payload), &job); err != nil {
		// A malformed payload is dropped rather than retried: it will never
		// parse, and re-queueing it would block the worker forever. It is
		// logged by the caller as a structured failure.
		return Job{}, fmt.Errorf("dequeue job: payload is not valid JSON")
	}
	if err := job.Validate(); err != nil {
		return Job{}, fmt.Errorf("dequeue job: %w", err)
	}
	return job, nil
}

// Len reports how many jobs are waiting.
func (q *RedisQueue) Len(ctx context.Context) (int64, error) {
	n, err := q.client.LLen(ctx, q.key).Result()
	if err != nil {
		return 0, fmt.Errorf("queue length: %w", err)
	}
	return n, nil
}

var _ Queue = (*RedisQueue)(nil)
