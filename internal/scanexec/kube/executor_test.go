package kube

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanjob"
	"github.com/aizen299/secure-dev/internal/scanners"
)

func testExecutor(t *testing.T) *Executor {
	t.Helper()
	e, err := New(Options{
		Client:            fake.NewSimpleClientset(),
		Namespace:         "secureops",
		Intake:            scanjob.NewIntake(scanjob.DefaultLimits(1<<20), discardLog()),
		JobImage:          "registry.example/secureops-worker@sha256:" + strings.Repeat("a", 64),
		JobServiceAccount: "secureops-scanjob",
		CallbackURL:       "http://secureops-api:8080",
		IntakePort:        8081,
		IntakeSelector:    map[string]string{"app.kubernetes.io/component": "worker"},
		WorkspaceSize:     "4Gi",
		TmpSize:           "256Mi",
		VulnDBClaim:       "secureops-vulndb",
		Logger:            discardLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func discardLog() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func request(kind scanners.Kind) scanexec.Request {
	return scanexec.Request{
		ScanID: "abc-123", ProjectID: "p1",
		Target:   scanners.Target{Kind: kind, RepositoryURL: "https://example.com/a/b"},
		Scanners: []scanners.Scanner{adapterStub{name: "gitleaks"}},
	}
}

type adapterStub struct{ name string }

func (a adapterStub) Name() string { return a.name }
func (a adapterStub) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{Kinds: []scanners.Kind{scanners.KindFilesystem}}
}
func (a adapterStub) Version(context.Context) (string, error) { return "1", nil }
func (a adapterStub) Scan(context.Context, scanners.Target) (scanners.RawResult, error) {
	return scanners.RawResult{}, nil
}

// TestTheScanPodCarriesNoCredentials is the property ADR 039 is named for.
//
// If a database or Redis URL ever reaches this pod, the process running
// attacker-supplied scanner binaries holds the password to every finding in the
// system -- which is the situation 12b exists to end.
func TestTheScanPodCarriesNoCredentials(t *testing.T) {
	e := testExecutor(t)
	job := e.job(request(scanners.KindRepository), PhaseScan, "tok", false)

	forbidden := []string{"SECUREOPS_DATABASE_URL", "SECUREOPS_REDIS_URL", "SECUREOPS_API_TOKENS"}
	for _, env := range job.Spec.Template.Spec.Containers[0].Env {
		for _, bad := range forbidden {
			if env.Name == bad {
				t.Errorf("the scan pod was given %s", bad)
			}
		}
	}
}

// TestTheScanPodCannotTalkToTheAPIServer.
//
// Without this a compromised scanner could ask what else is running, and with
// any RBAC at all could create pods of its own.
func TestTheScanPodCannotTalkToTheAPIServer(t *testing.T) {
	e := testExecutor(t)
	job := e.job(request(scanners.KindRepository), PhaseScan, "tok", false)

	mount := job.Spec.Template.Spec.AutomountServiceAccountToken
	if mount == nil || *mount {
		t.Error("automountServiceAccountToken is not false")
	}
}

// TestTheScanPodIsHardened mirrors the chart's assertion for pods the chart
// does not render -- these are created at runtime and no helm lint sees them.
func TestTheScanPodIsHardened(t *testing.T) {
	e := testExecutor(t)
	job := e.job(request(scanners.KindRepository), PhaseScan, "tok", false)
	pod := job.Spec.Template.Spec
	c := pod.Containers[0]

	if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Error("runAsNonRoot is not set")
	}
	if pod.SecurityContext.SeccompProfile == nil ||
		pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("seccompProfile is not RuntimeDefault")
	}
	if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		t.Error("readOnlyRootFilesystem is not true")
	}
	if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Error("allowPrivilegeEscalation is not false")
	}
	if len(c.SecurityContext.Capabilities.Drop) != 1 || c.SecurityContext.Capabilities.Drop[0] != "ALL" {
		t.Error("capabilities are not dropped")
	}
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 {
		t.Error("the job retries; an attacker's repository must not be run twice on a whim")
	}
}

// TestTheImageIsPinnedByDigest -- T-10 again, for a pod the chart never sees.
func TestTheImageIsPinnedByDigest(t *testing.T) {
	e := testExecutor(t)
	job := e.job(request(scanners.KindRepository), PhaseScan, "tok", false)
	if img := job.Spec.Template.Spec.Containers[0].Image; !strings.Contains(img, "@sha256:") {
		t.Errorf("job image %q is not pinned by digest", img)
	}
}

// TestAScanPolicyDeniesIngressAndAllowsOnlyDNSAndTheIntake.
//
// The scanning phase of a repository scan is the pod with no route off the
// node. It may resolve names and report results, and that is all.
func TestAScanPolicyDeniesIngressAndAllowsOnlyDNSAndTheIntake(t *testing.T) {
	e := testExecutor(t)
	np := e.networkPolicy(request(scanners.KindRepository), PhaseScan, false)

	if len(np.Spec.Ingress) != 0 {
		t.Error("the scan pod accepts ingress; nothing should ever connect to it")
	}
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("egress has %d rules, want exactly DNS and the intake", len(np.Spec.Egress))
	}
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				t.Errorf("the scan pod may reach %s; it must have no internet egress", peer.IPBlock.CIDR)
			}
		}
	}
}

// TestAFetchPolicyAllowsTheInternetButNotTheCluster.
func TestAFetchPolicyAllowsTheInternetButNotTheCluster(t *testing.T) {
	e := testExecutor(t)
	np := e.networkPolicy(request(scanners.KindRepository), PhaseFetch, true)

	var block *string
	var except []string
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				block = &peer.IPBlock.CIDR
				except = peer.IPBlock.Except
			}
		}
	}
	if block == nil {
		t.Fatal("the fetch pod has no internet egress and cannot clone")
	}
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"} {
		found := false
		for _, e := range except {
			if e == want {
				found = true
			}
		}
		if !found {
			t.Errorf("the fetch pod may reach %s; it must be excepted", want)
		}
	}
}

// TestTheVulnerabilityDatabaseIsMountedReadOnlyAndOnlyForScanning.
//
// The pod that runs untrusted binaries must not be able to edit the database
// every finding in the platform is derived from (ADR 039 §6).
func TestTheVulnerabilityDatabaseIsMountedReadOnlyAndOnlyForScanning(t *testing.T) {
	e := testExecutor(t)

	scan := e.job(request(scanners.KindRepository), PhaseScan, "tok", false)
	var found bool
	for _, m := range scan.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "vulndb" {
			found = true
			if !m.ReadOnly {
				t.Error("the vulnerability database is mounted writable")
			}
		}
	}
	if !found {
		t.Error("the scan pod has no vulnerability database")
	}

	fetch := e.job(request(scanners.KindRepository), PhaseFetch, "tok", true)
	for _, m := range fetch.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "vulndb" {
			t.Error("the fetch pod mounts the vulnerability database it has no use for")
		}
	}
}

// TestTheWorkspaceIsBounded -- T-51. A layer that decompresses past the limit
// fills a volume that dies with the scan, not the node's disk.
func TestTheWorkspaceIsBounded(t *testing.T) {
	e := testExecutor(t)
	pvc := e.workspacePVC(request(scanners.KindRepository))
	q := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	if q.IsZero() {
		t.Fatal("the workspace claim has no size; unbounded is what T-51 is about")
	}
	if got := q.String(); got != "4Gi" {
		t.Errorf("workspace size = %s, want the configured 4Gi", got)
	}
}

// TestAPolicyExistsBeforeItsJob.
//
// Creating the pod first would leave a window in which it is scheduled and
// unrestricted -- for the scanning phase, exactly the window this design exists
// to close. Proven by making Job creation fail: the policy must already be
// there, and runPhase must refuse rather than run the pod unrestricted.
func TestAPolicyExistsBeforeItsJob(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "jobs",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("the API server said no")
		})

	e := testExecutor(t)
	e.opts.Client = client

	err := e.runPhase(context.Background(), discardLog(),
		request(scanners.KindRepository), PhaseScan, "tok", false)
	if err == nil {
		t.Fatal("a job that could not be created was reported as fine")
	}

	nps, _ := client.NetworkingV1().NetworkPolicies("secureops").
		List(context.Background(), metav1.ListOptions{})
	if len(nps.Items) != 1 {
		t.Errorf("network policies present: %d, want the policy created before the job", len(nps.Items))
	}
}

// TestAPolicyThatCannotBeCreatedStopsTheScan.
//
// A scan is never worth more than the boundary around it. Running the pod
// anyway would run it unrestricted.
func TestAPolicyThatCannotBeCreatedStopsTheScan(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "networkpolicies",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("no policy for you")
		})

	e := testExecutor(t)
	e.opts.Client = client

	// Bounded, and that is not decoration. Removing the guard this test exists
	// for makes runPhase fall through to waiting on a Job that the fake never
	// completes -- so with context.Background() the control run HANGS instead
	// of failing, and a test that stalls reports nothing. Found by running the
	// control, not by reading it.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := e.runPhase(ctx, discardLog(),
		request(scanners.KindRepository), PhaseScan, "tok", false); err == nil {
		t.Fatal("the scan continued without a network policy")
	}
	jobs, _ := client.BatchV1().Jobs("secureops").List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Error("a pod was created despite having no policy to restrain it")
	}
}
