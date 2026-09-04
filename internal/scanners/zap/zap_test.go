package zap

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../tests/fixtures/zap", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestCapabilities(t *testing.T) {
	c := New("/var/cache/zap").Capabilities()

	if !c.Supports(scanners.KindEndpoint) {
		t.Error("zap must accept endpoint targets")
	}
	for _, k := range []scanners.Kind{scanners.KindFilesystem, scanners.KindImage, scanners.KindRepository} {
		if c.Supports(k) {
			t.Errorf("zap must not claim %s targets", k)
		}
	}
	if !c.Covers(scanners.CategoryDAST) || len(c.Categories) != 1 {
		t.Errorf("categories = %v, want dast only", c.Categories)
	}
	// The one adapter that cannot work without the network, and the per-kind
	// declaration must say so for the kind it actually serves.
	if !c.NeedsNetwork(scanners.KindEndpoint) {
		t.Error("an endpoint scan must declare the egress it needs")
	}
	if c.NeedsNetwork(scanners.KindFilesystem) {
		t.Error("zap must not declare egress for a kind it does not serve")
	}
}

// THE control this adapter's design turns on. Active scanning delivers crafted
// attack payloads to a live application: it changes state, and whether it is
// authorized is a fact about who owns the target that SecureOps cannot model.
//
// The job must be ABSENT rather than present-and-disabled, so that no
// configuration change can switch it on (ADR 026).
func TestPlanNeverRequestsAnActiveScan(t *testing.T) {
	plan := string(New("/var/cache/zap").plan("https://example.com", "/out"))

	for _, forbidden := range []string{"activeScan", "active-scan", "ascan", "attack", "fuzz"} {
		if strings.Contains(strings.ToLower(plan), strings.ToLower(forbidden)) {
			t.Errorf("plan mentions %q; SecureOps does not send attack traffic (ADR 026)\n%s", forbidden, plan)
		}
	}
	// The jobs it must have.
	for _, required := range []string{"spider", "passiveScan-wait", "report"} {
		if !strings.Contains(plan, required) {
			t.Errorf("plan is missing the %q job\n%s", required, plan)
		}
	}
	// -plus embeds full request and response bodies, which is the entire
	// application including anything it renders.
	if strings.Contains(plan, "traditional-json-plus") {
		t.Error("the -plus report template embeds request and response bodies")
	}
	if !strings.Contains(plan, "traditional-json") {
		t.Error("plan does not request the JSON report the parser reads")
	}
	// A scan that cannot reach its target must fail rather than report zero
	// findings (§13).
	if !strings.Contains(plan, "failOnError: true") {
		t.Error("plan does not fail on error; an unreachable target would read as a clean application")
	}
}

// The plan is a document built from a caller-supplied value. A value that could
// terminate the scalar would inject structure into it.
func TestPlanQuotesTheEndpoint(t *testing.T) {
	hostile := `https://example.com/"` + "\n" + `      - type: activeScan`
	plan := string(New("/var/cache/zap").plan(hostile, "/out"))

	// The value may legitimately contain the text -- it is quoted, so it is a
	// string. What must not happen is the text becoming plan STRUCTURE, so
	// that is what is asserted: no line of the document declares a job the
	// adapter did not write.
	for _, line := range strings.Split(plan, "\n") {
		if t2 := strings.TrimSpace(line); strings.HasPrefix(t2, "- type: ") {
			job := strings.TrimPrefix(t2, "- type: ")
			if job != "spider" && job != "passiveScan-wait" && job != "report" {
				t.Errorf("a crafted endpoint injected the job %q:\n%s", job, plan)
			}
		}
	}
	// And the endpoint stays one line: a newline that survived would end the
	// scalar whatever the quoting.
	urls := 0
	for _, line := range strings.Split(plan, "\n") {
		if strings.Contains(line, "urls:") {
			urls++
		}
	}
	if urls != 1 {
		t.Errorf("endpoint spans more than one line:\n%s", plan)
	}
}

// Telemetry is off for the reason ADR 014 gives for semgrep: a scan must not be
// conditional on a vendor endpoint being reachable, nor report our usage to one.
func TestArgsDisableTelemetryAndBindLoopback(t *testing.T) {
	args := New("/var/cache/zap").args("/tmp/plan.yaml")

	if !slices.Contains(args, "-silent") {
		t.Error("-silent missing; ZAP checks for add-on updates and calls home")
	}
	for _, want := range []string{"telemetry.enabled=false", "callhome.telemetryEnabled=false"} {
		if !slices.Contains(args, want) {
			t.Errorf("%s missing from %v", want, args)
		}
	}
	// ZAP needs a listener even headless. A wildcard bind would make the worker
	// an open proxy for the length of the scan.
	i := slices.Index(args, "-host")
	if i < 0 || args[i+1] != "127.0.0.1" {
		t.Errorf("-host = %v, want 127.0.0.1", args)
	}
	if !slices.Contains(args, "-cmd") {
		t.Error("-cmd missing; ZAP would start its GUI")
	}
}

func TestEnvCarriesNoCredentials(t *testing.T) {
	env := New("/var/cache/zap").env()

	for _, v := range env {
		name, _, _ := strings.Cut(v, "=")
		if slices.Contains([]string{"ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_VALUE", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID"}, name) {
			t.Errorf("%s reaches the zap subprocess (§14.7)", name)
		}
	}
	if !slices.Contains(env, "HOME=/nonexistent") {
		t.Error("HOME must not resolve")
	}
}

// Adding a scanner must require zero changes outside its own package plus one
// registration entry (§7 rule 4). This is that property, checked rather than
// assumed: the registry selects by target kind and knows nothing about DAST.
func TestRegistrySelectsZAPForEndpointTargets(t *testing.T) {
	r := scanners.NewRegistry()
	if err := r.Register(New("/var/cache/zap")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := r.SelectFor(scanners.KindEndpoint)
	if len(got) != 1 || got[0].Name() != Name {
		t.Fatalf("endpoint targets selected %v, want [zap]", got)
	}
	for _, kind := range []scanners.Kind{scanners.KindFilesystem, scanners.KindImage} {
		if sel := r.SelectFor(kind); len(sel) != 0 {
			t.Errorf("%s targets selected %v, want none", kind, sel)
		}
	}
}

func TestScanRejectsUnsupportedTargets(t *testing.T) {
	for _, kind := range []scanners.Kind{scanners.KindFilesystem, scanners.KindImage, scanners.KindRepository} {
		_, err := New("/var/cache/zap").Scan(t.Context(), scanners.Target{Kind: kind})
		if !errors.Is(err, scanners.ErrUnsupportedTarget) {
			t.Errorf("%s: err = %v, want ErrUnsupportedTarget", kind, err)
		}
	}
}

// The worker is on the far side of a queue from the validator, so it re-applies
// the scheme rule rather than trusting the payload.
func TestEndpointIsSafe(t *testing.T) {
	for _, bad := range []string{
		"", "-x", "--config=/etc/passwd",
		"file:///etc/passwd", "gopher://example.com",
		"https://example.com/\nnewline", "https://example.com/ space",
		"javascript:alert(1)", "http://",
		"https://example.com/" + strings.Repeat("a", maxEndpointLength),
	} {
		if endpointIsSafe(bad) {
			t.Errorf("endpointIsSafe(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{
		"http://example.com", "https://example.com/app",
		"https://example.com:8443/a/b?c=d",
	} {
		if !endpointIsSafe(good) {
			t.Errorf("endpointIsSafe(%q) = false, want true", good)
		}
	}
}

// --- redaction ------------------------------------------------------------

// The control this adapter exists for, on real output. ZAP puts the full
// request URL in every alert instance, and a query string is where an
// application carries credentials: this fixture is a captured scan of a target
// serving one link to `/search?api_key=…`, and the key appears seven times.
func TestRedactionRemovesTargetContent(t *testing.T) {
	raw := fixture(t, "unredacted.json")

	// The fixture must actually contain what redaction has to remove, or the
	// test proves nothing.
	if !strings.Contains(string(raw), "NOTAREALKEY") {
		t.Fatal("fixture no longer carries the planted query-string secret")
	}
	if !strings.Contains(string(raw), "NOTAREALTOKEN") {
		t.Fatal("fixture no longer carries the planted form token")
	}

	out, err := redactTargetContent(raw)
	if err != nil {
		t.Fatalf("redactTargetContent: %v", err)
	}
	for _, planted := range []string{"NOTAREALKEY", "NOTAREALTOKEN"} {
		if strings.Contains(string(out), planted) {
			t.Errorf("%s survived redaction", planted)
		}
	}
	if err := assertNoTargetContent(out); err != nil {
		t.Errorf("the adapter's own check rejected its own output: %v", err)
	}
}

// The digest is what distinguishes this from trivy's bare marker: §15.3 asks
// for a hash rather than the value, and a hash makes two scans comparable.
func TestRedactionStoresADigestRatherThanAMarker(t *testing.T) {
	out, err := redactTargetContent(fixture(t, "unredacted.json"))
	if err != nil {
		t.Fatalf("redactTargetContent: %v", err)
	}

	if !strings.Contains(string(out), redactedPrefix) {
		t.Fatal("nothing was redacted")
	}
	// Same content, same digest -- otherwise the comparison the digest exists
	// for does not work.
	a, b := redactedValue("some evidence"), redactedValue("some evidence")
	if a != b {
		t.Errorf("digest is not stable: %q vs %q", a, b)
	}
	if redactedValue("some evidence") == redactedValue("other evidence") {
		t.Error("two different values produced one digest")
	}
	if !strings.HasPrefix(a, redactedPrefix) || len(a) != len(redactedPrefix)+digestLength+1 {
		t.Errorf("redacted value %q is not the documented shape", a)
	}
}

// Fail-closed: the rewrite walks a decoded document, so a ZAP schema change
// that moved or renamed a field would make it silently miss content. The
// assertion checks the result rather than trusting the rewrite.
func TestAssertionCatchesWhatTheRewriteMisses(t *testing.T) {
	err := assertNoTargetContent(fixture(t, "unredacted-after-rewrite.json"))
	if !errors.Is(err, ErrTargetLeak) {
		t.Errorf("err = %v, want ErrTargetLeak", err)
	}
}

func TestStripQuery(t *testing.T) {
	cases := map[string]string{
		"http://h/search?api_key=secret": "http://h/search",
		"http://h/a#frag":                "http://h/a",
		"http://h/a?b=1#c":               "http://h/a",
		"http://h/a":                     "http://h/a",
		"not a url at all?x=1":           "not a url at all",
		"":                               "",
	}
	for in, want := range cases {
		if got := StripQuery(in); got != want {
			t.Errorf("StripQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- report validation ----------------------------------------------------

func TestValidateReport(t *testing.T) {
	if err := validateReport(fixture(t, "passive-scan.json")); err != nil {
		t.Errorf("a real report was rejected: %v", err)
	}
	// A clean application is not a failed scan, and must validate.
	if err := validateReport(fixture(t, "no-findings.json")); err != nil {
		t.Errorf("a clean report was rejected: %v", err)
	}
	for _, name := range []string{"empty.json", "malformed.json", "truncated.json", "wrong-tool.json"} {
		if err := validateReport(fixture(t, name)); !errors.Is(err, ErrMalformedReport) {
			t.Errorf("%s: err = %v, want ErrMalformedReport", name, err)
		}
	}
}

// --- mapping --------------------------------------------------------------

func TestNormalizeRedactedFixture(t *testing.T) {
	res, err := Normalize(fixture(t, "redacted.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("no findings from a report with alerts")
	}
	if len(res.Occurrences) != len(res.Findings) {
		t.Errorf("occurrences = %d, findings = %d", len(res.Occurrences), len(res.Findings))
	}

	for _, f := range res.Findings {
		if f.Category != scanners.CategoryDAST {
			t.Errorf("%s: category = %q, want dast", f.Title, f.Category)
		}
		if f.Endpoint == "" {
			t.Errorf("%s: no endpoint recorded", f.Title)
		}
		// The origin must never reach identity or the stored endpoint: it
		// churns per CI preview environment (ADR 026).
		if strings.Contains(f.Endpoint, "127.0.0.1") || strings.Contains(f.Endpoint, "http") {
			t.Errorf("endpoint %q carries an origin", f.Endpoint)
		}
		if strings.ContainsAny(f.Endpoint, "?#") {
			t.Errorf("endpoint %q carries a query string", f.Endpoint)
		}
		if f.Severity == normalization.SeverityCritical {
			t.Errorf("%s: ZAP's scale stops at high; critical must not be minted here", f.Title)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", f.Title, err)
		}
	}
}

// The mapper refuses unredacted input, because this is the last point before
// the database.
func TestNormalizeRefusesUnredactedInput(t *testing.T) {
	if _, err := Normalize(fixture(t, "unredacted.json"), "scan-1"); !errors.Is(err, ErrTargetLeak) {
		t.Errorf("err = %v, want ErrTargetLeak: the mapper must not accept raw ZAP output", err)
	}
}

func TestNormalizeCleanReport(t *testing.T) {
	res, err := Normalize(fixture(t, "no-findings.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(res.Findings) != 0 || len(res.Errors) != 0 {
		t.Errorf("findings = %d, errors = %v, want a clean report", len(res.Findings), res.Errors)
	}
}

// Identity survives the thing that changes every build: the hostname.
func TestFingerprintIgnoresOriginAndQuery(t *testing.T) {
	report := func(uri string) []byte {
		return []byte(`{"@programName":"ZAP","site":[{"alerts":[
		  {"alertRef":"10038-1","pluginid":"10038","name":"CSP header not set",
		   "riskcode":"2","confidence":"3","cweid":"693","desc":"d","solution":"s",
		   "instances":[{"uri":"` + uri + `","method":"GET","param":""}]}]}]}`)
	}
	fp := func(t *testing.T, uri string) string {
		t.Helper()
		// Through the real chain: the mapper only ever sees redacted output.
		redacted, err := redactTargetContent(report(uri))
		if err != nil {
			t.Fatalf("redact(%s): %v", uri, err)
		}
		res, err := Normalize(redacted, "scan-1")
		if err != nil {
			t.Fatalf("Normalize(%s): %v", uri, err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("Normalize(%s): findings = %d, want 1", uri, len(res.Findings))
		}
		return res.Findings[0].Fingerprint
	}

	base := fp(t, "https://app.example.com/login")
	for _, same := range []string{
		// A new CI preview host per pull request must not re-identify anything.
		"https://pr-4821.preview.example.com/login",
		"http://localhost:3000/login",
		"https://app.example.com/login#section",
	} {
		if got := fp(t, same); got != base {
			t.Errorf("%s: fingerprint changed; the origin must not be in identity", same)
		}
	}
	for _, different := range []string{"https://app.example.com/admin", "https://app.example.com/"} {
		if got := fp(t, different); got == base {
			t.Errorf("%s: fingerprint collided with /login", different)
		}
	}
}

func TestEndpointPath(t *testing.T) {
	cases := map[string]string{
		"http://h/login":          "login",
		"http://h/a/b/c?x=1":      "a/b/c",
		"http://h/":               "/",
		"http://h":                "/",
		"https://h:8443/app#frag": "app",
		"":                        "",
		"::::not a url":           "",
	}
	for in, want := range cases {
		if got := EndpointPath(in); got != want {
			t.Errorf("EndpointPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Hostile output is in the threat model (§15.7).
func TestNormalizeHostile(t *testing.T) {
	redacted, err := redactTargetContent(fixture(t, "hostile.json"))
	if err != nil {
		t.Fatalf("redactTargetContent: %v", err)
	}
	res, err := Normalize(redacted, "scan-1")
	if err != nil {
		t.Fatalf("Normalize must not fail the whole report over bad entries: %v", err)
	}

	byTitle := map[string]normalization.Finding{}
	for _, f := range res.Findings {
		byTitle[f.Title] = f
	}

	// A risk code ZAP does not define must not be guessed at.
	if f, ok := byTitle["Unknown risk level"]; !ok {
		t.Error("an unknown risk level discarded the finding")
	} else if f.Severity != normalization.SeverityUnknown {
		t.Errorf("severity = %q, want unknown for riskcode 9", f.Severity)
	}

	// Instances with no usable location cannot be given an identity.
	if _, ok := byTitle["No usable location"]; ok {
		t.Error("a finding with no usable path was accepted")
	}

	// Several instances of one rule on one path are one finding: the fix is one
	// change to that endpoint.
	dup := 0
	for _, f := range res.Findings {
		if f.Title == "Same path many times" {
			dup++
		}
	}
	if dup != 1 {
		t.Errorf("findings for one rule on one path = %d, want 1", dup)
	}

	// Traversal in a reported path must be cleaned, not stored or followed.
	for _, f := range res.Findings {
		if strings.Contains(f.Endpoint, "..") {
			t.Errorf("endpoint %q contains traversal", f.Endpoint)
		}
	}

	// ZAP's "no CWE applies" sentinels must read as absence.
	for _, f := range res.Findings {
		if f.CWE == "CWE-0" || f.CWE == "CWE--1" {
			t.Errorf("%s: cwe = %q, want empty", f.Title, f.CWE)
		}
	}

	// Prose in the reference block is not a reference.
	if f, ok := byTitle["Same path many times"]; ok {
		for _, ref := range f.Fix.References {
			if !strings.HasPrefix(ref, "http") {
				t.Errorf("reference %q is not a link", ref)
			}
		}
	}
	if len(res.Errors) == 0 {
		t.Error("errors = none, want the unusable instances recorded")
	}
}

func TestMapZAPRiskAndConfidence(t *testing.T) {
	risks := map[string]normalization.Severity{
		"3": normalization.SeverityHigh,
		"2": normalization.SeverityMedium,
		"1": normalization.SeverityLow,
		"0": normalization.SeverityInfo,
		"9": normalization.SeverityUnknown,
		"":  normalization.SeverityUnknown,
	}
	for in, want := range risks {
		if got := normalization.MapZAPRisk(in); got != want {
			t.Errorf("MapZAPRisk(%q) = %q, want %q", in, got, want)
		}
	}
	// ZAP's top is High. Promoting it to critical would fill the top of the
	// risk scale with findings nobody assessed for exposure.
	if normalization.MapZAPRisk("3") == normalization.SeverityCritical {
		t.Error("ZAP's High must not become critical")
	}

	confidences := map[string]normalization.Confidence{
		"4": normalization.ConfidenceHigh,
		"3": normalization.ConfidenceHigh,
		"2": normalization.ConfidenceMedium,
		"1": normalization.ConfidenceLow,
		"0": normalization.ConfidenceLow,
		"":  normalization.ConfidenceLow,
	}
	for in, want := range confidences {
		if got := normalization.MapZAPConfidence(in); got != want {
			t.Errorf("MapZAPConfidence(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	out := "Found Java version 17.0.17\nAvailable memory: 8192 MB\nUsing JVM args: -Xmx2048m\n2.17.0\n"
	if got := parseVersion([]byte(out)); got != "2.17.0" {
		t.Errorf("parseVersion = %q, want 2.17.0", got)
	}
	if got := parseVersion([]byte("no version here")); got != "" {
		t.Errorf("parseVersion = %q, want empty", got)
	}
}

// The deterministic checks above are the real coverage (§19). This confirms the
// adapter drives the actual tool, which fixtures cannot.
//
// Doubly gated: ZAP is not installed in the default local loop (§6), and a DAST
// scan sends HTTP requests to a host. It runs only against a target the operator
// names deliberately.
func TestScanAgainstRealZAP(t *testing.T) {
	command := os.Getenv("SECUREOPS_ZAP_COMMAND")
	if command == "" {
		t.Skip("SECUREOPS_ZAP_COMMAND is not set; zap is not on PATH in a default install")
	}
	endpoint := os.Getenv("SECUREOPS_ZAP_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("SECUREOPS_ZAP_TEST_ENDPOINT is not set; a DAST scan sends requests to a host")
	}

	s := &Scanner{Command: command, HomeDir: t.TempDir(), SpiderMinutes: 1}
	if err := s.Provision(t.Context()); err != nil {
		t.Fatalf("provision: %v", err)
	}

	raw, err := s.Scan(t.Context(), scanners.Target{Kind: scanners.KindEndpoint, EndpointURL: endpoint})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if raw.Version == "" {
		t.Error("scanner version was not captured (§7 rule 6)")
	}
	if err := validateReport(raw.Output); err != nil {
		t.Fatalf("the adapter accepted output it should have rejected: %v", err)
	}
	// The live run must satisfy the same controls the fixtures assert.
	if err := assertNoTargetContent(raw.Output); err != nil {
		t.Fatalf("live output was persisted unredacted: %v", err)
	}

	res, err := Normalize(raw.Output, "scan-live")
	if err != nil {
		t.Fatalf("normalize live output: %v", err)
	}
	for _, f := range res.Findings {
		if f.Category != scanners.CategoryDAST {
			t.Errorf("%s: category = %q, want dast", f.Title, f.Category)
		}
		if strings.ContainsAny(f.Endpoint, "?#") || strings.Contains(f.Endpoint, "://") {
			t.Errorf("endpoint %q carries an origin or a query", f.Endpoint)
		}
	}
	t.Logf("live scan produced %d findings", len(res.Findings))
}

// --- launching from the jar (ADR 030) ---------------------------------------

// In the worker image ZAP runs from its jar, because its launcher is bash and
// the container that executes untrusted content does not ship bash.
func TestJarModeRunsJavaWithADeclaredHeap(t *testing.T) {
	s := &Scanner{HomeDir: "/var/cache/zap", JarPath: "/opt/zap/zap.jar"}

	if got := s.command(); got != "java" {
		t.Errorf("command = %q, want java", got)
	}

	args := s.args("/tmp/plan.yaml")
	// The JVM's arguments must precede -jar, and -jar must precede ZAP's own
	// flags: java stops parsing its own options at -jar and hands the rest to
	// the application.
	jar := slices.Index(args, "-jar")
	if jar < 0 {
		t.Fatalf("-jar missing from %v", args)
	}
	if heap := slices.Index(args, "-Xmx"+DefaultMaxHeap); heap < 0 || heap > jar {
		t.Errorf("heap limit missing or after -jar: %v", args)
	}
	if args[jar+1] != "/opt/zap/zap.jar" {
		t.Errorf("-jar = %q, want /opt/zap/zap.jar", args[jar+1])
	}
	if cmd := slices.Index(args, "-cmd"); cmd < jar {
		t.Errorf("ZAP's flags precede -jar, so java would consume them: %v", args)
	}

	// An explicit heap overrides the default. The point of setting it at all is
	// that a scan's memory ceiling is configuration rather than a property of
	// whichever host the worker landed on (§14.3).
	s.MaxHeap = "2048m"
	if args := s.args("/tmp/plan.yaml"); !slices.Contains(args, "-Xmx2048m") {
		t.Errorf("configured heap ignored: %v", args)
	}
}

// Without a jar the adapter must behave exactly as it did before ADR 030: a
// developer's checkout points SECUREOPS_ZAP_COMMAND at a local install and
// expects the launcher, not a jar path that does not exist on their machine.
func TestWithoutAJarTheLauncherIsUnchanged(t *testing.T) {
	s := New("/var/cache/zap")

	if got := s.command(); got != DefaultCommand {
		t.Errorf("command = %q, want %q", got, DefaultCommand)
	}
	args := s.args("/tmp/plan.yaml")
	if slices.Contains(args, "-jar") {
		t.Errorf("launcher mode passed -jar: %v", args)
	}
	if args[0] != "-cmd" {
		t.Errorf("args start with %q, want -cmd", args[0])
	}
}

// Command names the executable; JarPath chooses the mode. Set together, a
// deployment is pointing at a specific JVM -- which must still run the jar.
func TestAnExplicitCommandStillRunsTheJar(t *testing.T) {
	s := &Scanner{HomeDir: "/var/cache/zap", JarPath: "/opt/zap/zap.jar", Command: "/usr/lib/jvm/bin/java"}

	if got := s.command(); got != "/usr/lib/jvm/bin/java" {
		t.Errorf("command = %q, want the configured JVM", got)
	}
	if args := s.args("/tmp/plan.yaml"); !slices.Contains(args, "-jar") {
		t.Errorf("explicit command dropped jar mode: %v", args)
	}
}

// The version is persisted per scan (§7 rule 6), and two things about this
// probe are easy to get wrong in ways that fail silently.
//
// Without the launch arguments it runs `java -version` and records the JVM's
// version as the scanner's. Without -dir, ZAP throws before printing anything:
// it creates its home first, and the subprocess environment sets
// HOME=/nonexistent on purpose (§14.7). Scan ignores this error by design, so
// either mistake leaves every ZAP result carrying an empty version rather than
// failing.
func TestTheVersionProbeAsksZAPAndNotTheJVM(t *testing.T) {
	s := &Scanner{HomeDir: "/var/cache/zap", JarPath: "/opt/zap/zap.jar"}

	args := append(s.launchArgs(), "-dir", s.baseDirUnchecked(), "-version")
	jar := slices.Index(args, "-jar")
	ver := slices.Index(args, "-version")
	if jar < 0 || ver < 0 || jar > ver {
		t.Fatalf("version probe would not reach ZAP: %v", args)
	}
	if d := slices.Index(args, "-dir"); d < 0 || args[d+1] != "/var/cache/zap" {
		t.Errorf("version probe omits -dir, so ZAP throws on $HOME/.ZAP: %v", args)
	}
}

// The worker image ships only the add-ons the plan uses (ADR 030), which makes
// the add-on list a contract between this adapter and that image: a job added
// to the plan whose add-on is not installed fails at ZAP startup in a deployed
// worker, and nowhere earlier.
//
// The cost of getting this wrong is not only a broken scan. What the trimmed
// set leaves out includes ascanrules -- ZAP's active scan rules -- and ADR 026's
// position is that SecureOps does not perform active scans. A careless "install
// everything to fix the build" would quietly put those payloads back.
//
// Read from the Dockerfile rather than duplicated here, in the same spirit as
// the OpenAPI contract test: two copies of a list are two things to forget.
func TestTheImageShipsTheAddOnsThePlanNeeds(t *testing.T) {
	const dockerfile = "../../../deployments/docker/worker.Dockerfile"
	data, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatalf("reading %s: %v", dockerfile, err)
	}

	installed := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "ARG ZAP_ADDONS=")
		if !ok {
			continue
		}
		for _, name := range strings.Fields(strings.Trim(rest, `"`)) {
			installed[name] = true
		}
	}
	if len(installed) == 0 {
		t.Fatal("no ARG ZAP_ADDONS in the worker Dockerfile; the trimmed add-on set has been removed")
	}

	// Each job the plan emits, and the add-on that provides it. Two entries are
	// not job types at all and were found by running rather than reading:
	// callhome is mandatory -- ZAP refuses to start without it even with its
	// telemetry disabled by config -- and commonlib and database are transitive
	// dependencies whose absence produces no message naming them.
	required := map[string]string{
		"spider":           "spider",
		"passiveScan-wait": "pscan",
		"report":           "reports",
		"":                 "automation", // the plan itself is an automation plan
	}
	mandatory := []string{"callhome", "commonlib", "database", "network", "pscanrules"}

	plan := string(New("/var/cache/zap").plan("https://example.test/", "/tmp/out"))
	for job, addon := range required {
		if job != "" && !strings.Contains(plan, "type: "+job) {
			t.Errorf("plan no longer emits the %q job; this mapping is stale", job)
			continue
		}
		if !installed[addon] {
			t.Errorf("plan uses job %q but the image does not install its add-on %q", job, addon)
		}
	}
	for _, addon := range mandatory {
		if !installed[addon] {
			t.Errorf("the image does not install %q, which ZAP requires to start", addon)
		}
	}

	// The control, stated as a test rather than only as a comment.
	for _, forbidden := range []string{"ascanrules", "ascanrulesAlpha", "ascanrulesBeta", "fuzz"} {
		if installed[forbidden] {
			t.Errorf("the image installs %q: SecureOps does not perform active scans (ADR 026)", forbidden)
		}
	}
}
