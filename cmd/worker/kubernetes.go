package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanexec/kube"
	"github.com/aizen299/secure-dev/internal/scanjob"
)

// intakePort is where scan Jobs report. Fixed rather than configurable: it is
// referenced by the NetworkPolicy this process renders and by the chart's own
// policy, and a port that could drift between the two would mean a scan whose
// results are silently dropped.
const intakePort = 8081

// kubernetesExecutor builds the executor that runs each scan in its own pod,
// and starts the listener those pods report to.
//
// Returns a shutdown function rather than leaking the server: a worker that
// stopped consuming the queue while still accepting results would be accepting
// results for scans nothing is going to finish.
func kubernetesExecutor(
	ctx context.Context, cfg config.Config, logger *slog.Logger,
) (scanexec.Executor, func(context.Context) error, error) {
	// In-cluster only. There is deliberately no kubeconfig fallback: a
	// controller that could be pointed at an arbitrary cluster by a file on
	// disk is a wider blast radius than this needs, and the failure mode of
	// running outside a cluster should be a clear error rather than acting on
	// whatever context happened to be current.
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("kubernetes executor needs to run in a cluster: %w", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, err
	}

	intake := scanjob.NewIntake(
		scanjob.DefaultLimits(cfg.ScannerMaxOutputBytes), logger)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", intakePort),
		Handler: intake.Handler(),
		// The peer is the least trusted process in the system, so a slow or
		// silent one must not be able to hold a connection open indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
		// Generous: a 64 MB result over a busy node's network takes a while,
		// and a scan cut off mid-report loses a scanner's findings.
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 1 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	go func() {
		logger.Info("scan job intake listening", slog.Int("port", intakePort))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("scan job intake stopped", slog.String("error", err.Error()))
		}
	}()

	exec, err := kube.New(kube.Options{
		Client:            client,
		Namespace:         cfg.JobNamespace,
		Intake:            intake,
		JobImage:          cfg.JobImage,
		JobServiceAccount: cfg.JobServiceAccount,
		CallbackURL:       cfg.JobCallbackURL,
		IntakePort:        intakePort,
		IntakeSelector: map[string]string{
			"app.kubernetes.io/component": "worker",
		},
		WorkspaceSize:         cfg.JobWorkspaceSize,
		WorkspaceStorageClass: cfg.JobStorageClass,
		TmpSize:               cfg.JobTmpSize,
		ScannerDataInImage:    cfg.ScannerDataInImage,
		Resources:             jobResources(),
		Logger:                logger,
	})
	if err != nil {
		_ = srv.Close()
		return nil, nil, err
	}

	if !cfg.ScannerDataInImage {
		// Loud, because the alternative is a scan whose scanners cannot reach
		// their data from a pod with no egress -- three of five fail, the scan
		// is PARTIAL, and the gate refuses it. Safe, and not useful.
		logger.Warn("the job image is not declared to carry provisioned scanner data; " +
			"grype, semgrep and trivy will fail in a pod with no egress " +
			"(SECUREOPS_SCANNER_DATA_IN_IMAGE, ADR 040)")
	}

	return exec, srv.Shutdown, nil
}

// jobResources bounds a scan pod (§14.3).
//
// Generous on purpose: trivy extracts container layers and ZAP runs a JVM. An
// under-set limit here does not hide findings -- an OOM-killed scanner is a
// PARTIAL scan the gate refuses to pass (T-47) -- but it fails builds for the
// wrong reason.
func jobResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("4"),
			corev1.ResourceMemory: resource.MustParse("6Gi"),
		},
	}
}
