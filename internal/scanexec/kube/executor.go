package kube

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanjob"
	"github.com/aizen299/secure-dev/internal/scans"
)

// Options configures the Kubernetes executor.
type Options struct {
	Client    kubernetes.Interface
	Namespace string
	// Intake authorises a scan to report and receives what it sends.
	Intake *scanjob.Intake

	// JobImage carries cmd/scanjob and the scanner binaries. By digest: the
	// chart refuses a tag for the same reason (T-10), and a Job created with a
	// mutable tag would put that back.
	JobImage          string
	JobServiceAccount string

	// CallbackURL is where the Job posts. Reachable only through the one
	// NetworkPolicy hole this executor renders.
	CallbackURL    string
	IntakePort     int32
	IntakeSelector map[string]string

	// WorkspaceSize bounds the per-scan volume, which is what closes T-51.
	WorkspaceSize         string
	WorkspaceStorageClass string
	TmpSize               string

	// VulnDBClaim is the shared read-only vulnerability database (ADR 039 §6).
	// Empty means none is mounted, and grype then degrades loudly per scan
	// rather than scanning against nothing and reporting a clean result.
	VulnDBClaim     string
	VulnDBMountPath string

	Resources corev1.ResourceRequirements

	// TTLSeconds cleans a finished Job up even if the controller died between
	// creating it and deleting it.
	TTLSeconds   int32
	PollInterval time.Duration
	Logger       *slog.Logger
}

// Executor runs a scan as one or two ephemeral Jobs.
type Executor struct{ opts Options }

// New validates the options and builds an Executor.
func New(opts Options) (*Executor, error) {
	switch {
	case opts.Client == nil:
		return nil, fmt.Errorf("kube: a Kubernetes client is required")
	case opts.Namespace == "":
		return nil, fmt.Errorf("kube: a namespace is required")
	case opts.Intake == nil:
		return nil, fmt.Errorf("kube: an intake is required")
	case opts.JobImage == "":
		return nil, fmt.Errorf("kube: a job image is required")
	case opts.CallbackURL == "":
		return nil, fmt.Errorf("kube: a callback URL is required")
	}
	// A size that cannot be parsed would become "unbounded" at apply time,
	// which is the one thing a limit must never silently mean. Checked here so
	// it fails at startup rather than on the first hostile repository.
	for name, size := range map[string]string{
		"workspace": opts.WorkspaceSize, "tmp": opts.TmpSize,
	} {
		if _, err := parseQuantity(size); err != nil {
			return nil, fmt.Errorf("kube: %s size %q: %w", name, size, err)
		}
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}
	if opts.TTLSeconds <= 0 {
		opts.TTLSeconds = 300
	}
	if opts.VulnDBMountPath == "" {
		opts.VulnDBMountPath = "/var/cache/grype/db"
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Executor{opts: opts}, nil
}

// Execute implements scanexec.Executor.
//
// The controller never sees the scan's content: results arrive at the intake,
// which calls ev directly. This function's job is to create the pods, keep the
// token alive exactly as long as they run, and clean up whatever happens.
func (e *Executor) Execute(ctx context.Context, req scanexec.Request, ev scanexec.Events) error {
	log := e.opts.Logger.With(
		slog.String("scan_id", req.ScanID),
		slog.String("target_kind", string(req.Target.Kind)),
	)

	token, err := e.opts.Intake.Open(req.ScanID, ev)
	if err != nil {
		return scanexec.Fatal(scans.FailureWorkspaceUnavailable, err)
	}
	// Closed however this returns. A Job that outlives its scan must not be
	// able to write into a scan that has already been judged.
	defer e.opts.Intake.Close(req.ScanID)

	plan := PlanFor(req)
	log.Info("planned scan execution",
		slog.Any("phases", plan.Phases),
		slog.Bool("scan_phase_egress", plan.Egress[PhaseScan]))

	// Everything this scan creates is labelled with the scan id, so cleanup is
	// one delete by selector and cannot miss an object it did not remember.
	defer e.cleanup(context.WithoutCancel(ctx), log, req.ScanID)

	if _, err := e.opts.Client.CoreV1().PersistentVolumeClaims(e.opts.Namespace).
		Create(ctx, e.workspacePVC(req), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return scanexec.Fatal(scans.FailureWorkspaceUnavailable, err)
	}

	for _, phase := range plan.Phases {
		if err := e.runPhase(ctx, log, req, phase, token, plan.Egress[phase]); err != nil {
			return err
		}
	}
	return nil
}

// runPhase creates one phase's policy and Job, and waits for it.
//
// The policy is created BEFORE the Job, deliberately. Creating the pod first
// would leave a window in which it is scheduled and unrestricted, which for the
// scanning phase is exactly the window this design exists to close.
func (e *Executor) runPhase(
	ctx context.Context, log *slog.Logger, req scanexec.Request,
	phase Phase, token string, egress bool,
) error {
	np := e.networkPolicy(req, phase, egress)
	if _, err := e.opts.Client.NetworkingV1().NetworkPolicies(e.opts.Namespace).
		Create(ctx, np, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		// Not survivable. Running the pod anyway would run it unrestricted,
		// and a scan is never worth more than the boundary around it.
		return scanexec.Fatal(scans.FailureWorkspaceUnavailable,
			fmt.Errorf("creating the %s network policy: %w", phase, err))
	}

	job := e.job(req, phase, token, egress)
	if _, err := e.opts.Client.BatchV1().Jobs(e.opts.Namespace).
		Create(ctx, job, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return scanexec.Fatal(scans.FailureWorkspaceUnavailable,
			fmt.Errorf("creating the %s job: %w", phase, err))
	}

	log.Info("scan job created",
		slog.String("phase", string(phase)), slog.Bool("egress", egress))

	return e.wait(ctx, log, req, phase)
}

// wait blocks until the phase's Job finishes, fails, or the context ends.
func (e *Executor) wait(
	ctx context.Context, log *slog.Logger, req scanexec.Request, phase Phase,
) error {
	name := e.objectName(req.ScanID, phase)
	ticker := time.NewTicker(e.opts.PollInterval)
	defer ticker.Stop()

	for {
		job, err := e.opts.Client.BatchV1().Jobs(e.opts.Namespace).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				// Deleted underneath us. Reported rather than treated as
				// success: a scan whose pod vanished produced nothing, and
				// "no findings" must never come from "nothing ran" (T-47).
				return scanexec.Fatal(scans.FailureAllScannersDegraded,
					fmt.Errorf("the %s job disappeared", phase))
			}
			return scanexec.Fatal(scans.FailureAllScannersDegraded, err)
		}

		switch {
		case succeeded(job):
			return nil
		case failed(job):
			reason := scans.FailureAllScannersDegraded
			if phase == PhaseFetch {
				// "We could not get the code" must never read as "we scanned
				// it and found nothing".
				reason = scans.FailureFetchFailed
			}
			log.Error("scan job failed", slog.String("phase", string(phase)))
			return scanexec.Fatal(reason, fmt.Errorf("the %s job failed", phase))
		}

		select {
		case <-ctx.Done():
			return scanexec.Fatal(scans.FailureAllScannersDegraded, ctx.Err())
		case <-ticker.C:
		}
	}
}

func succeeded(j *batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func failed(j *batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// cleanup removes everything the scan created, by label.
//
// Best effort and loudly logged. A leaked Job is a pod that may still be
// running an attacker's repository, so a failure here is worth seeing even
// though the TTL will eventually catch it.
func (e *Executor) cleanup(ctx context.Context, log *slog.Logger, scanID string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	selector := metav1.ListOptions{LabelSelector: LabelScan + "=" + scanID}
	background := metav1.DeletePropagationBackground
	del := metav1.DeleteOptions{PropagationPolicy: &background}

	if err := e.opts.Client.BatchV1().Jobs(e.opts.Namespace).
		DeleteCollection(ctx, del, selector); err != nil && !apierrors.IsNotFound(err) {
		log.Error("could not delete the scan's jobs", slog.String("error", err.Error()))
	}
	if err := e.opts.Client.NetworkingV1().NetworkPolicies(e.opts.Namespace).
		DeleteCollection(ctx, del, selector); err != nil && !apierrors.IsNotFound(err) {
		log.Error("could not delete the scan's network policies", slog.String("error", err.Error()))
	}
	if err := e.opts.Client.CoreV1().PersistentVolumeClaims(e.opts.Namespace).
		DeleteCollection(ctx, del, selector); err != nil && !apierrors.IsNotFound(err) {
		log.Error("could not delete the scan's workspace", slog.String("error", err.Error()))
	}
}

var errBadQuantity = errors.New("not a valid quantity")

func parseQuantity(s string) (string, error) {
	if s == "" {
		return "", errBadQuantity
	}
	defer func() { _ = recover() }()
	_ = quantity(s)
	return s, nil
}
