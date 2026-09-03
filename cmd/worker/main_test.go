package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/worker"
)

// Every store worker.Options exposes must be wired by the binary.
//
// The sibling of cmd/api's test, and it exists because that one was not enough.
// Fixing the API's unwired policy store left the worker's identically unwired,
// so the gate stayed unreachable: the API could serve a verdict it never
// received, because the runner skipped evaluation silently whenever Policies
// was nil. A scan completed, findings were recorded, and no result was ever
// written.
//
// A nil store here is not a startup failure -- it is a stage the pipeline
// quietly does not run -- which is precisely why it needs a test rather than
// a panic.
func TestWorkerOptionsWireEveryStore(t *testing.T) {
	optsType := reflect.TypeOf(worker.Options{})

	// A dependency is an interface; a knob is a value.
	//
	// Deliberately not a hand-written list of exemptions: a list has to be
	// remembered when a field is added, which is the same failure mode as
	// forgetting the field itself. PollTimeout and MaxAttempts are durations
	// and counts with defaults, so nothing is skipped by leaving them unset --
	// whereas a nil store means a stage does not run.
	var stores []string
	for i := 0; i < optsType.NumField(); i++ {
		f := optsType.Field(i)
		if f.IsExported() && f.Type.Kind() == reflect.Interface {
			stores = append(stores, f.Name)
		}
	}
	if len(stores) == 0 {
		t.Fatal("no store fields found; this test has stopped asserting anything")
	}

	wired := wiredFields(t, "main.go", "return worker.Options{")
	for _, name := range stores {
		if !wired[name] {
			t.Errorf("workerOptions does not wire %s; that stage is skipped silently at runtime", name)
		}
	}
}

// wiredFields reports which fields a composite literal in the given file
// assigns.
//
// Reads the source rather than calling the function, because building real
// Options needs live database and Redis connections this test does not have.
// The assertion is about what the binary is written to pass, which is exactly
// where both of these bugs lived.
func wiredFields(t *testing.T, file, marker string) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	source := string(raw)

	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("%s no longer contains %q", file, marker)
	}
	body := source[start:]
	if end := strings.Index(body, "\n\t}\n"); end > 0 {
		body = body[:end]
	}

	fields := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && name != "" && !strings.HasPrefix(name, "//") {
			fields[name] = true
		}
	}
	return fields
}
