package syft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// maxComponents bounds how many components are accepted from one SBOM.
//
// The document describes attacker-controlled content, so it is bounded like any
// other external input (§15.8). A repository crafted to catalog millions of
// packages must not exhaust the worker.
const maxComponents = 200_000

// document is the subset of CycloneDX this adapter validates.
//
// Adapter-local by design: nothing outside this package may import it (§7 rule
// 3). Phase 4 adds the mapping into the canonical model; Phase 3 needs the
// parsed form only to enforce the invariants below.
type document struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Components  []component `json:"components"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// validateSBOM checks that the output really is a CycloneDX document.
//
// A truncated or garbled SBOM is more dangerous than an obviously broken one:
// stored as-is, it later reads as "this project has few dependencies" rather
// than "this scan did not work". Failing closed keeps that distinction.
func validateSBOM(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		// Distinct from an empty component list, which is a legitimate result
		// for a repository with no recognised manifests.
		return fmt.Errorf("%w: output was empty", ErrMalformedSBOM)
	}

	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		// The error text quotes the offending bytes, which came from cataloging
		// untrusted content, so it is not wrapped into the returned message.
		return fmt.Errorf("%w: output is not valid JSON", ErrMalformedSBOM)
	}

	// Guards against a syft flag change silently switching format: an SPDX
	// document is valid JSON and would otherwise be stored as if it were
	// CycloneDX, breaking every consumer downstream.
	if !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return fmt.Errorf("%w: bomFormat is %q, want CycloneDX", ErrMalformedSBOM, doc.BOMFormat)
	}
	if doc.SpecVersion == "" {
		return fmt.Errorf("%w: specVersion is missing", ErrMalformedSBOM)
	}
	if len(doc.Components) > maxComponents {
		return fmt.Errorf("%w: more than %d components", ErrMalformedSBOM, maxComponents)
	}
	return nil
}

// assertNoWorkspacePaths verifies the SBOM does not embed the worker's
// filesystem layout.
//
// Syft's file cataloger names components by absolute path. Because a workspace
// directory is ephemeral and randomly suffixed, that would mean two scans of
// the identical commit produce different SBOMs -- so they could never be
// compared, and Phase 4 could not fingerprint a component's identity across
// scans. It also stores the worker's internal layout for no benefit.
//
// The cataloger is disabled in args(). This asserts the result, so a syft
// release that reintroduces the behaviour under a different cataloger fails the
// scan rather than quietly poisoning the artifact.
func assertNoWorkspacePaths(data []byte, workspacePath string) error {
	if workspacePath == "" {
		return nil
	}

	// Check the workspace itself and its parent. The parent matters because the
	// checkout sits inside the job workspace, and a leak of either reveals the
	// layout and breaks reproducibility.
	candidates := []string{workspacePath}
	if parent := filepath.Dir(workspacePath); parent != "" && parent != workspacePath && parent != "/" {
		candidates = append(candidates, parent)
	}

	for _, path := range candidates {
		if bytes.Contains(data, []byte(path)) {
			// The path is not echoed: it is an internal detail, and the point
			// is that it should not travel.
			return fmt.Errorf("%w: a component references the scan workspace", ErrWorkspacePathLeak)
		}
	}
	return nil
}

// componentCount reports how many components the document holds. Used by tests
// to confirm the adapter's output is not merely well-formed but populated.
func componentCount(data []byte) (int, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("%w: output is not valid JSON", ErrMalformedSBOM)
	}
	return len(doc.Components), nil
}
