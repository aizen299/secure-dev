package cli

import (
	"os"
	"strings"
	"testing"
)

// actionYAML is the composite Action, read from disk.
//
// Read rather than duplicated, so the file and its test cannot drift apart --
// the same reason TestEnvExampleTokensParse reads the real .env.example. An
// Action is YAML that nothing type-checks, so what can be asserted about it is
// asserted here.
func actionYAML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../.github/actions/secureops-gate/action.yml")
	if err != nil {
		t.Fatalf("read the action: %v", err)
	}
	return string(data)
}

// The Action reports and does not block, by default.
//
// The project owner's requirement (ADR 036, amended). Asserted on the default
// rather than on the absence of the capability: blocking is one input away, so
// that "report-only" stays a setting rather than a property of the code.
func TestTheActionReportsByDefault(t *testing.T) {
	got := actionYAML(t)

	i := strings.Index(got, "fail-on-gate:")
	if i < 0 {
		t.Fatal("the action has no fail-on-gate input")
	}
	// The default lives in the input block that follows.
	block := got[i:]
	if end := strings.Index(block, "\n  comment:"); end > 0 {
		block = block[:end]
	}
	if !strings.Contains(block, "default: 'false'") {
		t.Errorf("fail-on-gate does not default to false; the Action would block, "+
			"and report-only is the requirement. Block:\n%s", block)
	}
}

// A gate that could not run always fails the step.
//
// The exception to report-only, and the one that must survive it. Exiting 0
// when the gate never ran would turn an outage -- or a network someone shaped
// deliberately -- into a silent, universal disabling of the gate: every build
// green, nothing checked. Report-only means "do not act on a verdict", not "do
// not notice that there was none".
func TestAGateThatDidNotRunAlwaysFails(t *testing.T) {
	got := actionYAML(t)

	i := strings.Index(got, "Apply the verdict")
	if i < 0 {
		t.Fatal("the action has no step that applies the verdict")
	}
	step := got[i:]

	// The exit-2 branch must be unconditional on fail-on-gate.
	two := strings.Index(step, `if [ "$CODE" = "2" ]`)
	if two < 0 {
		t.Fatal("nothing handles exit code 2; a gate that did not run would pass silently")
	}
	one := strings.Index(step, `if [ "$CODE" = "1" ]`)
	if one < 0 {
		t.Fatal("nothing handles exit code 1")
	}
	if two > one {
		t.Error("exit 2 is handled after exit 1; the branch that must never be skipped should come first")
	}
	// fail-on-gate must not appear before the exit-2 branch has exited.
	if strings.Contains(step[two:one], "fail-on-gate") {
		t.Error("the exit-2 branch consults fail-on-gate: a gate that could not run must fail regardless")
	}
}

// The token never reaches a fork pull request's comment step.
//
// §16: a fork PR that could read the token could exfiltrate it. The comment is
// skipped there rather than attempted and failed, because a failed comment must
// not be mistaken for a failed gate.
func TestForkPullRequestsSkipTheComment(t *testing.T) {
	got := actionYAML(t)

	if !strings.Contains(got, "head.repo.fork") {
		t.Error("nothing checks whether the pull request came from a fork")
	}
	if !strings.Contains(got, "github.token") {
		t.Error("the comment step does not use the workflow's own token")
	}
	// The scoped API credential must not be in the commenting step's env.
	i := strings.Index(got, "Comment on the pull request")
	if i < 0 {
		t.Fatal("no comment step")
	}
	end := strings.Index(got[i:], "Apply the verdict")
	if end < 0 {
		end = len(got) - i
	}
	if strings.Contains(got[i:i+end], "SECUREOPS_API_TOKEN") {
		t.Error("the SecureOps credential is exposed to the comment step, which runs on pull_request")
	}
}
