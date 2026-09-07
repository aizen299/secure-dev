package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheScanJobCannotSpeakToKubernetes.
//
// ADR 039's central claim is that the process running untrusted scanner
// binaries holds nothing -- no database credential, no queue credential, and no
// way to reach an API server. The pod spec sets
// automountServiceAccountToken: false, but a binary that LINKS a Kubernetes
// client is one mounted token away from using it, and mounting a token is a
// one-line change in a manifest nobody reads closely.
//
// So the boundary is asserted where it cannot drift: this binary must not
// depend on client-go at all. An import added anywhere in its tree fails here,
// including one added three packages deep by someone with no idea this rule
// exists.
func TestTheScanJobCannotSpeakToKubernetes(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(dep, "k8s.io/client-go") {
			t.Errorf("cmd/scanjob depends on %s; the scan job must not be able to reach an API server", dep)
		}
	}
}

// TestTheScanJobCarriesNoDatabaseDriver.
//
// The same argument one layer down. A pgx in this binary would mean the only
// thing standing between a compromised scanner and the findings database is an
// environment variable it does not currently have.
func TestTheScanJobCarriesNoDatabaseDriver(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(dep, "github.com/jackc/pgx") ||
			strings.HasPrefix(dep, "github.com/redis/go-redis") {
			t.Errorf("cmd/scanjob depends on %s; it has no business holding a data credential", dep)
		}
	}
}
