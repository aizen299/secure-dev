package zap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// resultBlock is the shape normalization reads. Kept separate from the
// validation types in parser.go, which deliberately keep Site opaque.
type resultBlock struct {
	Site []struct {
		Alerts []alert `json:"alerts"`
	} `json:"site"`
}

// alert is ZAP's per-rule finding, with its instances.
type alert struct {
	// AlertRef is preferred over PluginID for identity: it is more specific,
	// distinguishing `10038-1` from `10038-2` where the plugin is one rule with
	// several distinct conditions.
	AlertRef   string `json:"alertRef"`
	PluginID   string `json:"pluginid"`
	Name       string `json:"name"`
	Alert      string `json:"alert"`
	RiskCode   string `json:"riskcode"`
	Confidence string `json:"confidence"`
	Desc       string `json:"desc"`
	Solution   string `json:"solution"`
	Reference  string `json:"reference"`
	CWEID      string `json:"cweid"`
	Instances  []struct {
		URI    string `json:"uri"`
		Method string `json:"method"`
		Param  string `json:"param"`
	} `json:"instances"`
}

// maxAlertInstances bounds how many instances of one alert are turned into
// findings. Scanner output is untrusted input and every parse is size-capped
// (§15.8); a spider that found ten thousand URLs must not produce ten thousand
// findings from one rule.
const maxAlertInstances = 1_000

// maxReferences caps how many links one finding may carry.
const maxReferences = 10

// Normalize converts ZAP output into canonical findings.
//
// Pure: bytes in, findings out, no I/O (§8). Everything ZAP-specific stops
// here.
//
// The input is the redacted document the adapter stored, not what ZAP emitted,
// so no application content is available to leak into a finding even by
// accident (ADR 026) -- the same property ADR 015 gives the trivy mapper.
func Normalize(data []byte, scanID string) (normalization.Result, error) {
	if err := validateReport(data); err != nil {
		return normalization.Result{}, err
	}
	// Checked again here, for the reason the trivy and semgrep mappers check
	// their own controls: this is the last point before the database.
	if err := assertNoTargetContent(data); err != nil {
		return normalization.Result{}, err
	}

	var doc resultBlock
	if err := json.Unmarshal(data, &doc); err != nil {
		return normalization.Result{}, fmt.Errorf("%w: output is not valid JSON", ErrMalformedReport)
	}

	out := normalization.Result{}
	for _, site := range doc.Site {
		for i, a := range site.Alerts {
			mapAlert(&out, a, i, scanID)
		}
	}
	return out, nil
}

// mapAlert turns one ZAP alert into one finding per distinct path it was seen
// at.
//
// Per path rather than per instance: ZAP reports an instance for every request
// that triggered the rule, and a rule firing on two parameters of one page is
// one problem fixed once. Per path rather than per alert, because a missing
// header on /login and on /admin are two endpoints to fix (ADR 026).
func mapAlert(out *normalization.Result, a alert, index int, scanID string) {
	rule := strings.TrimSpace(a.AlertRef)
	if rule == "" {
		rule = strings.TrimSpace(a.PluginID)
	}

	seen := map[string]bool{}
	for j, inst := range a.Instances {
		if j >= maxAlertInstances {
			out.Errors = append(out.Errors, fmt.Sprintf(
				"alert %d (%s): more than %d instances, the rest were not mapped",
				index, rule, maxAlertInstances))
			break
		}

		path := EndpointPath(inst.URI)
		if path == "" {
			out.Errors = append(out.Errors, fmt.Sprintf(
				"alert %d instance %d: no usable path in the reported location", index, j))
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true

		fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
			Category: scanners.CategoryDAST,
			RuleID:   rule,
			Location: path,
			// No package and no CVE: a DAST finding is about a place in a
			// running application, not a component or a named vulnerability.
		})
		if err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("alert %d instance %d: %v", index, j, err))
			continue
		}

		finding := normalization.Finding{
			Fingerprint:      fingerprint,
			Scanner:          Name,
			ScannerFindingID: rule,
			ScannerSeverity:  a.RiskCode,
			Category:         scanners.CategoryDAST,
			Severity:         normalization.MapZAPRisk(a.RiskCode),
			Confidence:       normalization.MapZAPConfidence(a.Confidence),
			Title:            alertTitle(a),
			Description:      a.Desc,
			Remediation:      a.Solution,
			Endpoint:         endpointLabel(inst.Method, path),
			CWE:              cweID(a.CWEID),
			// ZAP's own solution text is the vendor's fix and stays in
			// Remediation. The reference list is where to read about the rule,
			// which is a different thing and is modelled as such (ADR 020).
			Fix:    normalization.Fix{References: alertReferences(a.Reference)},
			Status: normalization.StatusOpen,
		}
		if err := finding.Validate(); err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("alert %d instance %d: %v", index, j, err))
			continue
		}

		out.Findings = append(out.Findings, finding)
		out.Occurrences = append(out.Occurrences, normalization.Occurrence{
			Fingerprint: fingerprint,
			ScanID:      scanID,
			// The path doubles as the occurrence's file. A DAST finding has no
			// line: it is about an endpoint, not a place in a text.
			File:    path,
			Scanner: Name,
		})
	}
}

// EndpointPath reduces a reported location to the part identity uses: the URL
// path, without origin, query, or fragment.
//
// Exported so the adapter and its tests derive it one way. `/` normalizes to
// the empty-but-meaningful root, which NormalizeLocation renders as "" -- so
// the site root is spelled "/" here to keep it distinguishable from "no path
// at all", which is what an unparseable location produces.
func EndpointPath(raw string) string {
	raw = StripQuery(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	// A location with no scheme and no host is already a path.
	path := u.Path
	if u.Scheme == "" && u.Host == "" {
		path = raw
	}
	if path == "" || path == "/" {
		return "/"
	}
	return normalization.NormalizeLocation(path)
}

// endpointLabel renders the human-facing locator: method and path.
//
// The method is here and not in the fingerprint. ZAP's passive rules are
// page-level -- headers, cookies, forms -- so GET and POST of one path are one
// problem to fix; recording the method still tells a reader which request
// surfaced it (ADR 026).
func endpointLabel(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return path
	}
	return method + " " + path
}

func alertTitle(a alert) string {
	for _, candidate := range []string{a.Name, a.Alert} {
		if t := strings.TrimSpace(candidate); t != "" {
			return t
		}
	}
	if ref := strings.TrimSpace(a.AlertRef); ref != "" {
		return "ZAP alert " + ref
	}
	return "ZAP alert"
}

// cweID renders ZAP's bare numeric CWE as the identifier everyone else writes.
//
// ZAP reports "352"; the canonical model, every other adapter, and every
// consumer expect "CWE-352". ZAP also uses "-1" and "0" to mean "no CWE
// applies", which must read as absence rather than as CWE-0.
func cweID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" || raw == "-1" {
		return ""
	}
	return "CWE-" + raw
}

// alertReferences splits ZAP's reference block into individual links.
//
// ZAP concatenates them into one string, usually newline-separated and often
// wrapped in <p> tags depending on the template. Bounded, because scanner
// output is untrusted input (§15.8).
func alertReferences(raw string) []string {
	cleaned := strings.NewReplacer("<p>", "\n", "</p>", "\n", "\r", "\n").Replace(raw)

	out := make([]string, 0, maxReferences)
	for _, line := range strings.Split(cleaned, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || len(out) >= maxReferences {
			continue
		}
		// Only actual links. ZAP's reference block sometimes carries prose,
		// and prose in a list of references is not a reference.
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Normalize implements normalization.Normalizer, so the worker can normalize
// this adapter's output without knowing which adapter it is (§7 rule 2).
func (s *Scanner) Normalize(raw []byte, scanID string) (normalization.Result, error) {
	return Normalize(raw, scanID)
}
