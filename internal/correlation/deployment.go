package correlation

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Deployment states whether an issue's package reached the built artifact.
//
// Evidence, not a judgement. It changes no severity and no score (ADR 037):
// the useful direction is downward, and lowering a real vulnerability's
// standing because an inventory did not mention its package makes every way
// that inventory can be wrong into a way to under-report.
type Deployment string

const (
	// DeploymentUnknown means there is nothing to compare against: no image
	// scan for this project, or one whose inventory was truncated.
	//
	// The default, and a first-class value rather than a gap. Most projects
	// have no image scan, and a state that quietly meant "probably fine" would
	// be the same failure as an EPSS probability defaulting to zero (ADR 018).
	DeploymentUnknown Deployment = "unknown"

	// DeploymentPresent means the package is in the built artifact's inventory.
	DeploymentPresent Deployment = "deployed"

	// DeploymentAbsent means it is not, and the inventory it was compared
	// against was complete.
	//
	// The discriminating signal, and the one nothing else can produce: a
	// finding about a package nobody deployed. It is reported and never acted
	// on -- the engine cannot distinguish "not in the artifact" from "not in
	// the artifact we looked at" (ADR 037 §2).
	DeploymentAbsent Deployment = "not_deployed"
)

// Inventory is what a project's most recent image scan found installed.
//
// Passed in rather than read, exactly as Files are: the engine stays pure, and
// assembling this is the caller's job (§8, §10). A zero Inventory means no
// comparison is possible and every issue is DeploymentUnknown, which is the
// correct answer for the projects that have no image scan -- most of them.
type Inventory struct {
	// PURLs is the set of package URLs the artifact contains.
	PURLs map[string]struct{}

	// Complete is false when the inventory was truncated at the component cap.
	//
	// A truncated inventory can only prove presence, never absence: a package
	// missing from a prefix may be in the part that was dropped. So an
	// incomplete inventory yields `deployed` or `unknown`, never
	// `not_deployed`.
	Complete bool

	// ScanID and ScannedAt name what the comparison was made against, so the
	// evidence says which artifact and when rather than asserting a timeless
	// fact about the project.
	ScanID    string
	ScannedAt time.Time
}

// Empty reports whether there is anything to compare against.
func (i Inventory) Empty() bool { return len(i.PURLs) == 0 && i.ScanID == "" }

// deploymentOf classifies one issue against the artifact's inventory.
//
// Only `purl` issues are classified. A CVE issue can span several packages and
// a file issue names no package at all, so neither has a single presence to
// report -- and inventing one by checking every member would assert something
// about an issue that its key does not describe.
func deploymentOf(key Key, inv Inventory) Deployment {
	if key.Kind != KindComponent || inv.Empty() {
		return DeploymentUnknown
	}
	if _, ok := inv.PURLs[key.Value]; ok {
		return DeploymentPresent
	}
	if !inv.Complete {
		// Absent from a prefix is not absent.
		return DeploymentUnknown
	}
	return DeploymentAbsent
}

// deploymentEvidence renders the state as prose a person can act on.
//
// Names the scan and its date rather than asserting a timeless fact: "not in
// the image" is only ever true of a particular image, built at a particular
// time, and evidence that hides which one invites a reader to trust it further
// than it goes.
func deploymentEvidence(d Deployment, inv Inventory) string {
	switch d {
	case DeploymentPresent:
		return fmt.Sprintf("this package is installed in the image scanned on %s",
			inv.ScannedAt.UTC().Format("2006-01-02"))
	case DeploymentAbsent:
		return fmt.Sprintf(
			"this package is NOT installed in the image scanned on %s, so it appears to be "+
				"declared but not deployed — verify before dismissing",
			inv.ScannedAt.UTC().Format("2006-01-02"))
	default:
		return ""
	}
}

// purlsFrom builds an inventory's key set from component purls.
//
// A helper for callers, kept here so the normalisation of an empty purl lives
// beside the lookup that depends on it: a component syft could not name is
// stored with an empty purl (ADR 035), and letting "" into this set would make
// every unnamed component match every issue that also had no purl.
func purlsFrom(purls []string) map[string]struct{} {
	out := make(map[string]struct{}, len(purls))
	for _, p := range purls {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

// NewInventory assembles an Inventory from a scan's component purls.
func NewInventory(scanID string, scannedAt time.Time, purls []string, complete bool) Inventory {
	return Inventory{
		PURLs:     purlsFrom(purls),
		Complete:  complete,
		ScanID:    scanID,
		ScannedAt: scannedAt,
	}
}

// sortedPURLs is used only by tests and diagnostics, and exists so a set can be
// rendered deterministically without exposing map iteration order.
func sortedPURLs(inv Inventory) []string {
	out := make([]string, 0, len(inv.PURLs))
	for p := range inv.PURLs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
