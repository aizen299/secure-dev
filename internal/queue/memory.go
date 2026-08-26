package queue

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-process Queue for tests and local development.
//
// It is deliberately not exported as a production option: without Redis there
// is no durability and no cross-process delivery.
type Memory struct {
	mu   sync.Mutex
	jobs []Job
}

// NewMemory returns an empty in-memory queue.
func NewMemory() *Memory { return &Memory{} }

// Enqueue appends a job.
func (m *Memory) Enqueue(_ context.Context, job Job) error {
	if err := job.Validate(); err != nil {
		return err
	}
	if job.EnqueuedAt.IsZero() {
		job.EnqueuedAt = time.Now().UTC()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs = append(m.jobs, job)
	return nil
}

// Dequeue pops the oldest job, polling until timeout.
func (m *Memory) Dequeue(ctx context.Context, timeout time.Duration) (Job, error) {
	deadline := time.Now().Add(timeout)
	for {
		m.mu.Lock()
		if len(m.jobs) > 0 {
			job := m.jobs[0]
			m.jobs = m.jobs[1:]
			m.mu.Unlock()
			return job, nil
		}
		m.mu.Unlock()

		if time.Now().After(deadline) {
			return Job{}, ErrEmpty
		}
		select {
		case <-ctx.Done():
			return Job{}, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Len reports how many jobs are waiting.
func (m *Memory) Len(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.jobs)), nil
}

var _ Queue = (*Memory)(nil)
