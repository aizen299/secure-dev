package kube_test

import (
	"context"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanexec/kube"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// adapter is a stand-in that declares exactly what a test needs it to.
type adapter struct {
	name    string
	kinds   []scanners.Kind
	network []scanners.Kind
}

func (a adapter) Name() string { return a.name }
func (a adapter) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{Kinds: a.kinds, NetworkKinds: a.network}
}

// The plan reads capabilities and never executes anything, so these two exist
// only to satisfy the interface. A plan that needed to run a scanner to decide
// what it may reach would be deciding too late.
func (a adapter) Version(context.Context) (string, error) { return "test", nil }
func (a adapter) Scan(context.Context, scanners.Target) (scanners.RawResult, error) {
	return scanners.RawResult{Scanner: a.name}, nil
}

func req(kind scanners.Kind, sc ...scanners.Scanner) scanexec.Request {
	return scanexec.Request{
		ScanID: "s1", ProjectID: "p1",
		Target:   scanners.Target{Kind: kind},
		Scanners: sc,
	}
}

// TestARepositoryScanRunsWithNoNetwork is the property ADR 039 exists for.
//
// gitleaks and semgrep run over an attacker's repository in a pod with no route
// off the node. If this ever reports true, a hostile repository has regained
// the ability to reach out during a scan.
func TestARepositoryScanRunsWithNoNetwork(t *testing.T) {
	p := kube.PlanFor(req(scanners.KindRepository,
		adapter{name: "gitleaks", kinds: []scanners.Kind{scanners.KindFilesystem}},
		adapter{name: "semgrep", kinds: []scanners.Kind{scanners.KindFilesystem}},
	))

	if len(p.Phases) != 2 || p.Phases[0] != kube.PhaseFetch || p.Phases[1] != kube.PhaseScan {
		t.Fatalf("phases = %v, want fetch then scan", p.Phases)
	}
	if !p.Egress[kube.PhaseFetch] {
		t.Error("the fetch cannot clone without egress")
	}
	if p.Egress[kube.PhaseScan] {
		t.Error("the scan pod was granted egress; the whole point of splitting it is that it has none")
	}
}

// TestAnImageScanKeepsTheEgressTrivyDeclared.
//
// Trivy performs its own registry pull, so this one cannot be split the way a
// repository can, and the plan must not pretend otherwise.
func TestAnImageScanKeepsTheEgressTrivyDeclared(t *testing.T) {
	p := kube.PlanFor(req(scanners.KindImage,
		adapter{
			name:    "trivy",
			kinds:   []scanners.Kind{scanners.KindImage},
			network: []scanners.Kind{scanners.KindImage},
		},
	))
	if len(p.Phases) != 1 || p.Phases[0] != kube.PhaseScan {
		t.Fatalf("phases = %v, want a single scan phase", p.Phases)
	}
	if !p.Egress[kube.PhaseScan] {
		t.Error("an image scan cannot pull without egress")
	}
}

// TestAnEndpointScanKeepsTheEgressZAPDeclared.
func TestAnEndpointScanKeepsTheEgressZAPDeclared(t *testing.T) {
	p := kube.PlanFor(req(scanners.KindEndpoint,
		adapter{
			name:    "zap",
			kinds:   []scanners.Kind{scanners.KindEndpoint},
			network: []scanners.Kind{scanners.KindEndpoint},
		},
	))
	if !p.Egress[kube.PhaseScan] {
		t.Error("DAST cannot reach its target without egress")
	}
}

// TestEgressComesFromTheAdaptersNotTheKind.
//
// The derivation asks Capabilities.NetworkKinds rather than switching on the
// target kind, which is what keeps §7 rule 2 intact -- and means an adapter
// that stops needing the network stops being granted it, with no core change.
func TestEgressComesFromTheAdaptersNotTheKind(t *testing.T) {
	// An image-kind scan whose adapter declares no network at all.
	p := kube.PlanFor(req(scanners.KindImage,
		adapter{name: "offline", kinds: []scanners.Kind{scanners.KindImage}},
	))
	if p.Egress[kube.PhaseScan] {
		t.Error("egress was granted for the kind rather than for what the adapter declared")
	}
}

// TestAnAdapterDeclaringAnotherKindGrantsNothing.
//
// Trivy declares network for images. Selected for an endpoint scan it must not
// carry that grant across -- NeedsNetwork is asked per kind for exactly this.
func TestAnAdapterDeclaringAnotherKindGrantsNothing(t *testing.T) {
	p := kube.PlanFor(req(scanners.KindEndpoint,
		adapter{
			name:    "trivy",
			kinds:   []scanners.Kind{scanners.KindEndpoint},
			network: []scanners.Kind{scanners.KindImage},
		},
	))
	if p.Egress[kube.PhaseScan] {
		t.Error("an image-kind network declaration leaked into an endpoint scan")
	}
}
