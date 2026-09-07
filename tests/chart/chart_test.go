//go:build chart

// Package chart_test holds the Helm chart's security assertions.
//
// The chart grants privileges, and a misconfigured `securityContext` is a
// security defect in a file nobody thinks of as source (ADR 038). §15.12's
// rule -- never disable a control to make something pass -- only means
// anything if something checks, so these are tests rather than review notes.
//
// Behind a build tag because they shell out to `helm`, which `go test ./...`
// must not require. `make lint-chart` runs them; CI installs helm by pinned
// digest and runs the same target, so this is a gate and not a habit.
package chart_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

const chartPath = "../../deployments/kubernetes/secureops"

// A syntactically valid digest. Never a real image -- these tests render the
// chart and read the result; nothing is pulled.
const fakeDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

func baseArgs() []string {
	return []string{
		"template", "test", chartPath,
		"--set", "secrets.postgresPassword=p",
		"--set", "secrets.redisPassword=r",
		"--set", "secrets.apiTokens=ci:service:*:0123456789012345678901234567890123",
		"--set", "secrets.dashboardToken=0123456789012345678901234567890123",
		"--set", "images.api.digest=" + fakeDigest,
		"--set", "images.worker.digest=" + fakeDigest,
		"--set", "images.web.digest=" + fakeDigest,
		"--set", "images.postgres.digest=" + fakeDigest,
		"--set", "images.redis.digest=" + fakeDigest,
	}
}

func render(t *testing.T, extra ...string) []map[string]any {
	t.Helper()
	out, err := runHelm(t, append(baseArgs(), extra...)...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	var docs []map[string]any
	dec := yaml.NewDecoder(strings.NewReader(out))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if len(doc) > 0 {
			docs = append(docs, doc)
		}
	}
	if len(docs) == 0 {
		t.Fatal("chart rendered no objects")
	}
	return docs
}

func runHelm(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed; `make lint-chart` and CI provide it")
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("helm", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String() + stderr.String(), err
}

// podSpecs returns every pod template in the release, named for failure output.
func podSpecs(docs []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, d := range docs {
		kind, _ := d["kind"].(string)
		switch kind {
		case "Deployment", "StatefulSet", "Job":
		default:
			continue
		}
		meta, _ := d["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		spec, _ := d["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		ps, _ := tmpl["spec"].(map[string]any)
		if ps != nil {
			out[kind+"/"+name] = ps
		}
	}
	return out
}

// containers returns init containers as well as the main ones.
//
// Init containers deliberately included: they run with the same privileges in
// the same pod, and the migration one runs the API image inside the worker's
// pod. An assertion that skipped them would have passed the moment the
// migration moved out of its own Job and into here -- which is exactly what
// happened, and is why this comment exists.
func containers(ps map[string]any) []map[string]any {
	var out []map[string]any
	for _, key := range []string{"initContainers", "containers"} {
		raw, _ := ps[key].([]any)
		for _, c := range raw {
			if m, ok := c.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// TestEveryContainerIsHardened is the assertion the chart exists to satisfy.
//
// Every pod, not a sample: a workload that quietly omitted the context would
// otherwise be found by an auditor rather than by us.
func TestEveryContainerIsHardened(t *testing.T) {
	docs := render(t)
	specs := podSpecs(docs)
	if len(specs) < 5 {
		t.Fatalf("expected at least 5 workloads (api, worker, web, migrate, postgres, redis), got %d", len(specs))
	}

	for name, ps := range specs {
		pod, _ := ps["securityContext"].(map[string]any)
		if pod == nil {
			t.Errorf("%s: no pod securityContext", name)
			continue
		}
		if pod["runAsNonRoot"] != true {
			t.Errorf("%s: runAsNonRoot is not true", name)
		}
		if sec, _ := pod["seccompProfile"].(map[string]any); sec == nil || sec["type"] != "RuntimeDefault" {
			t.Errorf("%s: seccompProfile is not RuntimeDefault", name)
		}

		for _, c := range containers(ps) {
			cn := name + "/" + c["name"].(string)
			sc, _ := c["securityContext"].(map[string]any)
			if sc == nil {
				t.Errorf("%s: no container securityContext", cn)
				continue
			}
			if sc["allowPrivilegeEscalation"] != false {
				t.Errorf("%s: allowPrivilegeEscalation is not false", cn)
			}
			if sc["readOnlyRootFilesystem"] != true {
				t.Errorf("%s: readOnlyRootFilesystem is not true", cn)
			}
			caps, _ := sc["capabilities"].(map[string]any)
			drop, _ := caps["drop"].([]any)
			if len(drop) != 1 || drop[0] != "ALL" {
				t.Errorf("%s: capabilities are not dropped (got %v)", cn, drop)
			}
		}
	}
}

// TestEveryContainerHasResourceLimits enforces §14.3.
//
// A limit is a security bound here, not capacity planning: the worker unpacks
// attacker-supplied archives, and an unbounded container is how one scan takes
// down every other.
func TestEveryContainerHasResourceLimits(t *testing.T) {
	for name, ps := range podSpecs(render(t)) {
		for _, c := range containers(ps) {
			cn := name + "/" + c["name"].(string)
			res, _ := c["resources"].(map[string]any)
			lim, _ := res["limits"].(map[string]any)
			if lim["cpu"] == nil || lim["memory"] == nil {
				t.Errorf("%s: missing cpu or memory limit", cn)
			}
			req, _ := res["requests"].(map[string]any)
			if req["cpu"] == nil || req["memory"] == nil {
				t.Errorf("%s: missing cpu or memory request", cn)
			}
		}
	}
}

// TestEveryImageIsPinnedByDigest is the T-10 assertion.
func TestEveryImageIsPinnedByDigest(t *testing.T) {
	for name, ps := range podSpecs(render(t)) {
		for _, c := range containers(ps) {
			img, _ := c["image"].(string)
			if !strings.Contains(img, "@sha256:") {
				t.Errorf("%s/%s: image %q is not pinned by digest", name, c["name"], img)
			}
		}
	}
}

// TestTheChartRefusesATag is the control test for the above.
//
// An assertion that every image carries a digest proves nothing on its own if
// the template would happily accept a tag when one is offered -- the values
// file simply happens to hold digests today. This checks the refusal.
func TestTheChartRefusesATag(t *testing.T) {
	for _, tag := range []string{"latest", "v1.2.3", "sha256-notadigest"} {
		out, err := runHelm(t, append(baseArgs(), "--set", "images.api.digest="+tag)...)
		if err == nil {
			t.Errorf("rendering with tag %q succeeded; the digest requirement is not enforced", tag)
			continue
		}
		if !strings.Contains(out, "digest") {
			t.Errorf("tag %q was refused, but the error does not explain why: %s", tag, out)
		}
	}
}

// TestTheChartRefusesToRenderWithoutCredentials.
//
// The same line docker-compose.yml holds with `${VAR:?}`: a default password
// is a known-weak credential every deployment inherits and nobody notices.
func TestTheChartRefusesToRenderWithoutCredentials(t *testing.T) {
	args := []string{
		"template", "test", chartPath,
		"--set", "images.api.digest=" + fakeDigest,
		"--set", "images.worker.digest=" + fakeDigest,
		"--set", "images.web.digest=" + fakeDigest,
		"--set", "images.postgres.digest=" + fakeDigest,
		"--set", "images.redis.digest=" + fakeDigest,
	}
	out, err := runHelm(t, args...)
	if err == nil {
		t.Fatalf("the chart rendered with no credentials set:\n%s", out)
	}
}

// TestTheAPIHasNoEgressToTheInternet is the strongest claim in the chart.
//
// The API orchestrates and never reaches a target itself (§14.1). So the one
// component exposed to callers is the one that may open no outbound connection
// beyond PostgreSQL and Redis -- and if that ever stops being true, it is a
// trust-boundary change and should fail here rather than pass review.
func TestTheAPIHasNoEgressToTheInternet(t *testing.T) {
	docs := render(t)
	var found bool
	for _, d := range docs {
		if d["kind"] != "NetworkPolicy" {
			continue
		}
		meta, _ := d["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		if !strings.HasSuffix(name, "-api") {
			continue
		}
		found = true
		spec, _ := d["spec"].(map[string]any)
		egress, _ := spec["egress"].([]any)
		if len(egress) == 0 {
			t.Fatal("the api NetworkPolicy has no egress rules at all, which would also block PostgreSQL")
		}
		for _, r := range egress {
			rule, _ := r.(map[string]any)
			to, _ := rule["to"].([]any)
			for _, peer := range to {
				p, _ := peer.(map[string]any)
				if _, isIPBlock := p["ipBlock"]; isIPBlock {
					t.Errorf("the api may reach an ipBlock: %v — the API must not have internet egress", p)
				}
			}
		}
	}
	if !found {
		t.Fatal("no NetworkPolicy for the api was rendered")
	}
}

// TestTheWorkerCannotReachTheClusterNetwork.
//
// Defence in depth behind netguard, which refuses these ranges at validation
// time (T-04, T-49, T-56). Two independent controls, because the
// validation-time one has been wrong before: `validateImage` went without the
// address policy until an adapter served that kind.
func TestTheWorkerCannotReachTheClusterNetwork(t *testing.T) {
	mustExclude := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	for _, d := range render(t) {
		if d["kind"] != "NetworkPolicy" {
			continue
		}
		meta, _ := d["metadata"].(map[string]any)
		if name, _ := meta["name"].(string); !strings.HasSuffix(name, "-worker") {
			continue
		}
		spec, _ := d["spec"].(map[string]any)
		egress, _ := spec["egress"].([]any)
		for _, r := range egress {
			rule, _ := r.(map[string]any)
			for _, peer := range rule["to"].([]any) {
				p, _ := peer.(map[string]any)
				block, _ := p["ipBlock"].(map[string]any)
				if block == nil {
					continue
				}
				var excepted []string
				for _, e := range block["except"].([]any) {
					excepted = append(excepted, e.(string))
				}
				for _, want := range mustExclude {
					if !contains(excepted, want) {
						t.Errorf("the worker may reach %s — it must be excepted from its internet egress", want)
					}
				}
			}
		}
		return
	}
	t.Fatal("no NetworkPolicy for the worker was rendered")
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
