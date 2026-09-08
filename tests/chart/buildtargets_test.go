//go:build chart

package chart_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestEveryBuildSiteNamesItsTarget.
//
// worker.Dockerfile builds two images: the worker, and the scan job that
// carries the scanners' provisioned data. Docker builds the LAST stage when no
// target is given, so a build site that omits one silently produces the wrong
// image — and the failure names the wrong component entirely. A worker
// container started as cmd/scanjob exits 1 complaining about a missing scan id,
// which reads as a broken worker rather than a mis-built image.
//
// That has now happened twice: once in the local cluster deploy, once in
// docker-compose after the first was fixed. Two occurrences of one mistake is
// the point at which it stops being a mistake and becomes a missing test.
func TestEveryBuildSiteNamesItsTarget(t *testing.T) {
	stages := stageNames(t, "../../deployments/docker/worker.Dockerfile")
	if len(stages) < 2 {
		t.Skip("worker.Dockerfile no longer has multiple final stages; this guard is moot")
	}

	for _, site := range []struct{ path, why string }{
		{"../../docker-compose.yml", "the development stack"},
		{"../../Makefile", "make build-images"},
		{"../../scripts/kind-deploy.sh", "the local cluster deploy"},
	} {
		t.Run(site.path, func(t *testing.T) {
			body, err := os.ReadFile(site.path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			text := string(body)
			if !strings.Contains(text, "worker.Dockerfile") {
				t.Skipf("%s does not build from worker.Dockerfile", site.path)
			}
			// The DIRECTIVE, not the word. A first version of this matched
			// any line containing "target" and was satisfied by the comment
			// explaining why the target is needed -- so removing the directive
			// left the test green. Caught by running the control.
			for _, line := range nearby(text, "worker.Dockerfile", 6) {
				if directive.MatchString(line) {
					return
				}
			}
			t.Errorf("%s builds worker.Dockerfile without naming a target (%s); "+
				"the last stage is %q, so it would build that instead",
				site.path, site.why, stages[len(stages)-1])
		})
	}
}

// directive matches an actual build-target instruction: a YAML "target:" key
// or a "--target" flag. Deliberately not the bare word, which appears in prose.
var directive = regexp.MustCompile(`(^\s*target:\s*\S)|(--target[ =]\S)`)

// stageNames returns the named stages of a Dockerfile, in order.
func stageNames(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(`(?mi)^FROM\s+\S+\s+AS\s+(\S+)`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(body), -1) {
		out = append(out, m[1])
	}
	return out
}

// nearby returns the lines within n lines of each occurrence of needle.
func nearby(text, needle string, n int) []string {
	lines := strings.Split(text, "\n")
	var out []string
	for i, l := range lines {
		if !strings.Contains(l, needle) {
			continue
		}
		lo, hi := max(0, i-n), min(len(lines), i+n+1)
		out = append(out, lines[lo:hi]...)
	}
	return out
}
