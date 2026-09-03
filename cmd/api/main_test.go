package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/httpapi"
)

// Every store httpapi.Options exposes must be wired by the binary.
//
// This exists because one was not. httpapi.Options treats each store as
// optional -- a nil Policies makes the policy and gate endpoints answer 503
// rather than failing at startup -- and cmd/api simply never passed it. The
// handler tests construct their own Options with a policy store and passed
// throughout, so Phase 8's entire gate shipped unreachable through the real
// binary and nothing noticed until the dashboard asked for it.
//
// Reflection rather than a hand-written list, deliberately: a list would have
// to be remembered when a store is added, which is the same failure again.
func TestAPIOptionsWireEveryStore(t *testing.T) {
	// Built with nil dependencies: this asserts which fields the binary
	// populates, not that they work. Their behaviour is tested where they live.
	opts := httpapi.Options{}
	optsType := reflect.TypeOf(opts)

	// Fields that are legitimately absent at this layer.
	exempt := map[string]string{
		"Logger":          "supplied at startup from config",
		"Service":         "a constant, not a dependency",
		"Version":         "a build stamp",
		"Probes":          "assembled from the live connections",
		"Authenticator":   "built from config before this call",
		"Validator":       "a value, not a store",
		"MaxRequestBytes": "a limit, not a dependency",
		"Queue":           "built from the redis client",
	}

	var storeFields []string
	for i := 0; i < optsType.NumField(); i++ {
		field := optsType.Field(i)
		if !field.IsExported() {
			continue
		}
		if _, ok := exempt[field.Name]; ok {
			continue
		}
		storeFields = append(storeFields, field.Name)
	}

	if len(storeFields) == 0 {
		t.Fatal("no store fields found; this test has stopped asserting anything")
	}

	// The source of truth is the function the binary actually calls. Reading
	// the file keeps the assertion honest even though the real call needs live
	// connections this test does not have.
	wired := wiredOptionFields(t)
	for _, name := range storeFields {
		if !wired[name] {
			t.Errorf("apiOptions does not wire %s; its endpoints will answer 503 at runtime", name)
		}
	}
}

// wiredOptionFields reports which httpapi.Options fields apiOptions assigns.
func wiredOptionFields(t *testing.T) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	source := string(raw)

	start := strings.Index(source, "return httpapi.Options{")
	if start < 0 {
		t.Fatal("apiOptions no longer returns an httpapi.Options literal")
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
