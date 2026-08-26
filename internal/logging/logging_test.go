package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewJSONIncludesServiceAttributes(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Level: slog.LevelInfo, Format: "json", Service: "api", Version: "test"})
	logger.Info("hello", "count", 1)

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("output is not JSON: %v (%s)", err, buf.String())
	}
	if payload["service"] != "api" {
		t.Errorf("service = %v, want api", payload["service"])
	}
	if payload["version"] != "test" {
		t.Errorf("version = %v, want test", payload["version"])
	}
	if payload["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", payload["msg"])
	}
}

func TestNewTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Level: slog.LevelInfo, Format: "text", Service: "api"})
	logger.Info("hello")

	out := buf.String()
	if !strings.Contains(out, "service=api") {
		t.Errorf("text output missing service attribute: %q", out)
	}
	if json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Errorf("expected text output, got JSON: %q", out)
	}
}

func TestNewRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, Options{Level: slog.LevelWarn, Format: "json"})
	logger.Info("suppressed")
	if buf.Len() != 0 {
		t.Errorf("info message was emitted at warn level: %q", buf.String())
	}
	logger.Warn("emitted")
	if buf.Len() == 0 {
		t.Error("warn message was suppressed at warn level")
	}
}
