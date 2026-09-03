package trivy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// resultBlock is the shape normalization reads. Kept separate from the
// validation types in parser.go, which deliberately keep Results opaque.
type resultBlock struct {
	// ArtifactName is the reference trivy was pointed at, and ArtifactType
	// says which of this adapter's two modes produced the report. Dispatching
	// on it keeps the two mappings apart without either one guessing.
	ArtifactName string `json:"ArtifactName"`
	ArtifactType string `json:"ArtifactType"`
	Results      []struct {
		Target            string          `json:"Target"`
		Class             string          `json:"Class"`
		Vulnerabilities   []vulnerability `json:"Vulnerabilities"`
		Misconfigurations []struct {
			ID          string `json:"ID"`
			Title       string `json:"Title"`
			Description string `json:"Description"`
			Message     string `json:"Message"`
			Resolution  string `json:"Resolution"`
			// References and PrimaryURL are where to read about the check.
			// They are references, not the fix: Resolution is the fix.
			References    []string `json:"References"`
			PrimaryURL    string   `json:"PrimaryURL"`
			Severity      string   `json:"Severity"`
			Status        string   `json:"Status"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

// Normalize converts trivy output into canonical findings.
//
// Pure: bytes in, findings out, no I/O (§8). Everything trivy-specific stops
// here.
//
// The input is the redacted document the adapter stored, not what trivy
// emitted, so no source content is available to leak into a finding even by
// accident (ADR 015).
func Normalize(data []byte, scanID string) (normalization.Result, error) {
	if err := validateReport(data); err != nil {
		return normalization.Result{}, err
	}
	// Checked again here, for the same reason the semgrep mapper checks its
	// own control: this is the last point before the database.
	if err := assertNoSourceContent(data); err != nil {
		return normalization.Result{}, err
	}

	var doc resultBlock
	if err := json.Unmarshal(data, &doc); err != nil {
		return normalization.Result{}, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	if doc.ArtifactType == artifactTypeImage {
		return normalizeImage(doc, scanID)
	}

	out := normalization.Result{}
	for _, r := range doc.Results {
		location := normalization.NormalizeLocation(r.Target)
		for i, m := range r.Misconfigurations {
			// Trivy reports passing checks too when asked; a finding is a
			// failure. Anything else would inflate every count downstream.
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}

			fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
				Category: scanners.CategoryIaC,
				RuleID:   m.ID,
				Location: location,
			})
			if err != nil {
				out.Errors = append(out.Errors, fmt.Sprintf("%s misconfiguration %d: %v", r.Target, i, err))
				continue
			}

			finding := normalization.Finding{
				Fingerprint:      fingerprint,
				Scanner:          Name,
				ScannerFindingID: m.ID,
				ScannerSeverity:  m.Severity,
				Category:         scanners.CategoryIaC,
				Severity:         normalization.MapSeverity(m.Severity),
				Confidence:       normalization.ConfidenceHigh,
				Title:            misconfigTitle(m.ID, m.Title),
				Description:      m.Description,
				Remediation:      m.Resolution,
				// Resolution is the vendor's fix and stays in Remediation.
				// These are where to read about the check, which is a
				// different thing and is modelled as such (ADR 020).
				Fix:    normalization.Fix{References: checkReferences(m.References, m.PrimaryURL)},
				Status: normalization.StatusOpen,
			}
			if err := finding.Validate(); err != nil {
				out.Errors = append(out.Errors, fmt.Sprintf("%s misconfiguration %d: %v", r.Target, i, err))
				continue
			}

			out.Findings = append(out.Findings, finding)
			out.Occurrences = append(out.Occurrences, normalization.Occurrence{
				Fingerprint: fingerprint,
				ScanID:      scanID,
				File:        location,
				StartLine:   m.CauseMetadata.StartLine,
				EndLine:     m.CauseMetadata.EndLine,
				Scanner:     Name,
			})
		}
	}
	return out, nil
}

func misconfigTitle(id, title string) string {
	if title != "" {
		return title
	}
	if id != "" {
		return "Misconfiguration " + id
	}
	return "Misconfiguration"
}

// Normalize implements normalization.Normalizer, so the worker can normalize
// this adapter's output without knowing which adapter it is (§7 rule 2).
func (s *Scanner) Normalize(raw []byte, scanID string) (normalization.Result, error) {
	return Normalize(raw, scanID)
}

// checkReferences collects a misconfiguration check's documentation links.
//
// Bounded: trivy output is untrusted input like any other (§15.7, §15.8).
func checkReferences(refs []string, primary string) []string {
	out := make([]string, 0, maxCheckReferences)
	add := func(v string) {
		if v = strings.TrimSpace(v); v != "" && len(out) < maxCheckReferences {
			out = append(out, v)
		}
	}
	add(primary)
	for _, r := range refs {
		add(r)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// maxCheckReferences caps how many links one finding may carry.
const maxCheckReferences = 10

// artifactTypeImage is the value trivy reports for a container image scan.
const artifactTypeImage = "container_image"

// vulnerability is trivy's per-finding shape for an image scan.
type vulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgIdentifier   struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Status           string   `json:"Status"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	CweIDs           []string `json:"CweIDs"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	DataSource       struct {
		URL string `json:"URL"`
	} `json:"DataSource"`
	CVSS map[string]struct {
		V3Score float64 `json:"V3Score"`
	} `json:"CVSS"`
}

// normalizeImage maps an image report onto canonical findings.
//
// Every finding is CategoryContainer, including the language packages trivy
// finds installed inside the image. Not CategoryDependency: grype owns declared
// dependencies, and the categories differing is exactly what makes a correlated
// issue cross-domain and lets correlation escalate it (ADR 025). Collapsing the
// two categories would silently disable the escalation image targets exist to
// enable.
func normalizeImage(doc resultBlock, scanID string) (normalization.Result, error) {
	// Identity comes from the reference trivy was given, not from
	// Result.Target, which is "alpine:3.9 (alpine 3.9.6)" for OS packages and
	// the literal "Node.js" for language ones -- neither usable, and the first
	// carrying a tag that would churn identity on every rebuild.
	repository := imageRepository(doc.ArtifactName)
	if repository == "" {
		return normalization.Result{}, fmt.Errorf("%w: image report names no artifact", ErrMalformedReport)
	}

	out := normalization.Result{}
	for _, r := range doc.Results {
		for i, v := range r.Vulnerabilities {
			pkg := canonicalPURL(v.PkgIdentifier.PURL)
			if pkg == "" && v.PkgName != "" {
				pkg = v.PkgName + "@" + v.InstalledVersion
			}

			// A vulnerability naming neither a component nor an identifier has
			// nothing to act on. Fingerprint would accept it, because the
			// repository alone is distinguishing input -- and every such entry
			// in one image would then collapse onto that single identity,
			// merging unrelated defects into one finding. Refused here
			// instead, which is the same judgement Fingerprint makes for a
			// finding carrying only a category.
			if pkg == "" && strings.TrimSpace(v.VulnerabilityID) == "" {
				out.Errors = append(out.Errors, fmt.Sprintf(
					"%s vulnerability %d: names neither a component nor an identifier", r.Class, i))
				continue
			}

			fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
				Category: scanners.CategoryContainer,
				// No RuleID: a CVE on a package is the same problem whichever
				// scanner reports it, which is what lets this finding and a
				// grype one agree.
				Location:        repository,
				Package:         pkg,
				VulnerabilityID: v.VulnerabilityID,
			})
			if err != nil {
				out.Errors = append(out.Errors, fmt.Sprintf("%s vulnerability %d: %v", r.Class, i, err))
				continue
			}

			finding := normalization.Finding{
				Fingerprint:      fingerprint,
				Scanner:          Name,
				ScannerFindingID: v.VulnerabilityID,
				ScannerSeverity:  v.Severity,
				Category:         scanners.CategoryContainer,
				Severity:         normalization.MapSeverity(v.Severity),
				Confidence:       normalization.ConfidenceHigh,
				Title:            vulnerabilityTitle(v),
				Description:      v.Description,
				Package:          v.PkgName,
				PackageVersion:   v.InstalledVersion,
				PURL:             pkg,
				Image:            repository,
				CVE:              v.VulnerabilityID,
				CWE:              firstCWE(v.CweIDs),
				CVSS:             cvssFor(v),
				Fix:              imageFix(v),
				Status:           normalization.StatusOpen,
			}
			if err := finding.Validate(); err != nil {
				out.Errors = append(out.Errors, fmt.Sprintf("%s vulnerability %d: %v", r.Class, i, err))
				continue
			}

			out.Findings = append(out.Findings, finding)
			// No file and no line: this is about a component in an image, not
			// a place in a checkout. The same shape grype's occurrences take.
			out.Occurrences = append(out.Occurrences, normalization.Occurrence{
				Fingerprint: fingerprint,
				ScanID:      scanID,
				Scanner:     Name,
			})
		}
	}
	return out, nil
}

// imageRepository reduces an image reference to the part that is stable across
// rebuilds: the repository, with any tag and digest removed.
//
// `ghcr.io/org/app:1.2.3@sha256:abc...` becomes `ghcr.io/org/app`. Including
// the tag would resolve every finding and open an identical set on every build,
// which is not an identity; see ADR 025.
func imageRepository(ref string) string {
	ref = strings.TrimSpace(ref)
	// The digest is always last.
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// A colon is a tag separator only when it follows the last slash.
	// "localhost:5000/app" has a colon in the registry's port, not a tag.
	if i := strings.LastIndex(ref, ":"); i >= 0 && i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	// Registry hosts are case-insensitive and repository paths are required to
	// be lowercase, so two spellings of one image must not become two findings.
	return strings.ToLower(strings.TrimSpace(ref))
}

// canonicalPURL strips a PURL's qualifiers.
//
// Trivy appends `?arch=x86_64&distro=3.9.6` to OS-package PURLs. The distro
// qualifier tracks the base image's patch level, so leaving it in would change
// a finding's identity when the base image was patched but the vulnerability
// was not -- and it would stop the PURL matching grype's, which is the key the
// repository/image correlation runs on.
//
// Stripped here rather than in normalization.normalizePackage: that this
// scanner adds qualifiers is trivy-specific knowledge (§7), and changing the
// shared normalizer would re-fingerprint every stored grype finding.
func canonicalPURL(purl string) string {
	purl = strings.TrimSpace(purl)
	if i := strings.Index(purl, "?"); i >= 0 {
		purl = purl[:i]
	}
	return purl
}

func vulnerabilityTitle(v vulnerability) string {
	name := v.PkgName
	if name == "" {
		name = "an unnamed component"
	}
	if v.VulnerabilityID == "" {
		return "Known vulnerability in " + name
	}
	return v.VulnerabilityID + " in " + name
}

// firstCWE takes one CWE from trivy's list, which is ordered most-specific
// first. Finding.CWE holds one value; the rest stay in the raw result, which is
// persisted, rather than being dropped silently.
func firstCWE(ids []string) string {
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			return id
		}
	}
	return ""
}

// cvssFor picks the one CVSS score that applies.
//
// Trivy reports a score per vendor and they disagree. NVD is preferred because
// it is the issuer of record; failing that the highest score wins, because
// under-reporting is the dangerous direction -- the same reasoning that makes
// deduplication keep the higher severity.
//
// Out-of-range values are dropped rather than clamped: a score outside 0-10 is
// a scanner saying something impossible, and Finding.Validate would reject the
// whole finding over it (§15.7).
func cvssFor(v vulnerability) float64 {
	if nvd, ok := v.CVSS["nvd"]; ok && inCVSSRange(nvd.V3Score) {
		return nvd.V3Score
	}
	best := 0.0
	for _, entry := range v.CVSS {
		if inCVSSRange(entry.V3Score) && entry.V3Score > best {
			best = entry.V3Score
		}
	}
	return best
}

func inCVSSRange(score float64) bool { return score >= 0 && score <= 10 }

// imageFix maps trivy's fix data onto the canonical Fix (§11, ADR 020).
//
// The state is mapped before the version is trusted, for the reason grype's
// equivalent gives: scanner output is untrusted (§15.7), and a version attached
// to "wont-fix" would otherwise become an upgrade recommendation for something
// that will never be fixed.
func imageFix(v vulnerability) normalization.Fix {
	f := normalization.Fix{State: normalization.MapFixState(v.Status)}

	if f.State == normalization.FixStateFixed {
		// Trivy reports several fixed versions as one comma-separated string.
		for _, part := range strings.Split(v.FixedVersion, ",") {
			if part = strings.TrimSpace(part); part != "" {
				f.FixedVersions = append(f.FixedVersions, part)
			}
		}
		// A "fixed" state naming no version cannot be acted on.
		if len(f.FixedVersions) == 0 {
			f.State = normalization.FixStateUnknown
		}
	}

	for _, u := range append([]string{v.PrimaryURL}, v.References...) {
		if u = strings.TrimSpace(u); u != "" && len(f.References) < maxCheckReferences {
			f.References = append(f.References, u)
		}
	}
	if src := strings.TrimSpace(v.DataSource.URL); src != "" && len(f.References) < maxCheckReferences {
		f.References = append(f.References, src)
	}
	return f
}
