// Package kube runs a scan as one or two ephemeral Kubernetes Jobs (ADR 039).
//
// client-go lives here and nowhere else. cmd/scanjob must never link it: the
// process that runs untrusted scanner binaries has no business being able to
// speak to an API server, and keeping the dependency in one package is what
// makes that checkable rather than aspirational.
package kube

import (
	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Phase is one pod's worth of work.
type Phase string

const (
	// PhaseFetch clones a repository into the scan's volume. It needs egress
	// and carries no scanner binaries it has to run.
	PhaseFetch Phase = "fetch"
	// PhaseScan runs the adapters. For a repository it has NO egress at all,
	// which is the whole reason the fetch is a separate pod.
	PhaseScan Phase = "scan"
)

// Plan is how a scan will be executed: which pods, and what each may reach.
//
// Derived rather than configured. A deployment cannot widen a scan's egress by
// editing values, because the answer comes from what the target requires and
// what the selected adapters declared (`Capabilities.NetworkKinds`).
type Plan struct {
	// Phases in order. Two for a repository, one otherwise.
	Phases []Phase
	// Egress reports, per phase, whether that pod may reach the internet.
	Egress map[Phase]bool
}

// PlanFor derives the plan for a request.
//
// The rule, in one place so it can be read and tested as one thing:
//
//   - A repository must be fetched, and fetching needs the network. No adapter
//     does: once checked out, adapters are handed KindFilesystem (ADR 008) and
//     none of the six declares network for it. So the two halves are split, and
//     the half that touches the repository's contents gets nothing.
//   - An image or an endpoint cannot be split that way. Trivy performs its own
//     registry pull and ZAP talks to the target throughout, so their scan pod
//     needs the egress its adapters declared.
func PlanFor(req scanexec.Request) Plan {
	if req.Target.Kind == scanners.KindRepository {
		return Plan{
			Phases: []Phase{PhaseFetch, PhaseScan},
			Egress: map[Phase]bool{PhaseFetch: true, PhaseScan: false},
		}
	}
	return Plan{
		Phases: []Phase{PhaseScan},
		Egress: map[Phase]bool{PhaseScan: adaptersNeedNetwork(req)},
	}
}

// adaptersNeedNetwork asks the selected adapters, and nothing else.
//
// This is the call that turns Capabilities.NetworkKinds from honest metadata
// into a control. It had no non-test caller from Phase 2 until here.
func adaptersNeedNetwork(req scanexec.Request) bool {
	kind := scanners.EffectiveKind(req.Target.Kind)
	for _, s := range req.Scanners {
		if s.Capabilities().NeedsNetwork(kind) {
			return true
		}
	}
	return false
}
