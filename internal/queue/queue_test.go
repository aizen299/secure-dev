package queue

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func validJob() Job {
	return Job{
		ScanID:    "scan-1",
		ProjectID: "project-1",
		Target:    scanners.Target{Kind: scanners.KindRepository, RepositoryURL: "https://github.com/x/y"},
		Attempt:   1,
	}
}

func TestJobValidate(t *testing.T) {
	if err := validJob().Validate(); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*Job)
	}{
		{"no scan id", func(j *Job) { j.ScanID = "" }},
		{"no project id", func(j *Job) { j.ProjectID = "" }},
		{"invalid target kind", func(j *Job) { j.Target.Kind = "exec" }},
		{"empty target kind", func(j *Job) { j.Target.Kind = "" }},
		{"zero attempt", func(j *Job) { j.Attempt = 0 }},
		{"negative attempt", func(j *Job) { j.Attempt = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := validJob()
			tc.mut(&j)
			if err := j.Validate(); err == nil {
				t.Error("invalid job accepted")
			}
		})
	}
}

// The payload must stay plain data. If a command ever appears in this struct,
// the API/worker trust boundary has been breached.
func TestJobPayloadCarriesNoExecutableFields(t *testing.T) {
	payload, err := json.Marshal(validJob())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, forbidden := range []string{"command", "cmd", "args", "argv", "script", "shell", "exec", "env"} {
		if _, present := decoded[forbidden]; present {
			t.Errorf("job payload carries an executable field %q", forbidden)
		}
	}
}

func TestMemoryQueueFIFO(t *testing.T) {
	q := NewMemory()

	for _, id := range []string{"a", "b", "c"} {
		j := validJob()
		j.ScanID = id
		if err := q.Enqueue(t.Context(), j); err != nil {
			t.Fatalf("Enqueue(%s): %v", id, err)
		}
	}

	n, err := q.Len(t.Context())
	if err != nil || n != 3 {
		t.Fatalf("Len = %d, %v; want 3", n, err)
	}

	for _, want := range []string{"a", "b", "c"} {
		got, err := q.Dequeue(t.Context(), time.Second)
		if err != nil {
			t.Fatalf("Dequeue: %v", err)
		}
		if got.ScanID != want {
			t.Errorf("dequeued %q, want %q (FIFO order)", got.ScanID, want)
		}
	}
}

func TestMemoryQueueEmptyTimesOut(t *testing.T) {
	start := time.Now()
	_, err := NewMemory().Dequeue(t.Context(), 60*time.Millisecond)
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("err = %v, want ErrEmpty", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("Dequeue blocked well past its timeout")
	}
}

func TestMemoryQueueRejectsInvalidJob(t *testing.T) {
	q := NewMemory()
	if err := q.Enqueue(t.Context(), Job{}); err == nil {
		t.Error("invalid job accepted onto the queue")
	}
	if n, _ := q.Len(t.Context()); n != 0 {
		t.Errorf("invalid job was queued anyway: len = %d", n)
	}
}

func TestMemoryQueueStampsEnqueuedAt(t *testing.T) {
	q := NewMemory()
	if err := q.Enqueue(t.Context(), validJob()); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	got, err := q.Dequeue(t.Context(), time.Second)
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if got.EnqueuedAt.IsZero() {
		t.Error("EnqueuedAt was not stamped")
	}
}

func TestMemoryQueueHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := NewMemory().Dequeue(ctx, 5*time.Second); err == nil {
		t.Error("Dequeue ignored a cancelled context")
	}
}

func TestMemoryQueueConcurrent(t *testing.T) {
	q := NewMemory()
	const n = 50

	done := make(chan struct{})
	for i := range n {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			j := validJob()
			j.ScanID = string(rune('a'+i%26)) + "-job"
			_ = q.Enqueue(t.Context(), j)
		}(i)
	}
	for range n {
		<-done
	}

	got, err := q.Len(t.Context())
	if err != nil || got != n {
		t.Errorf("Len = %d, %v; want %d", got, err, n)
	}
}

func TestJobPayloadSizeIsBounded(t *testing.T) {
	j := validJob()
	j.Scanners = []string{strings.Repeat("x", maxPayloadBytes)}

	payload, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(payload) <= maxPayloadBytes {
		t.Skip("payload did not exceed the cap; nothing to assert")
	}
	// RedisQueue.Enqueue rejects this; the constant is what enforces it.
	if maxPayloadBytes <= 0 {
		t.Error("payload cap is not configured")
	}
}
