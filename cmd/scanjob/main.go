// Command scanjob runs one scan and reports it to the controller.
//
// This is the process that touches untrusted content, and it holds nothing:
// no database credential, no queue credential, no Kubernetes token (ADR 039).
// Everything it knows it is told through the environment, and everything it
// produces it posts back over one authenticated channel scoped to one scan.
//
// It is deliberately not a long-lived service. One scan, then exit -- which is
// what lets the pod carrying it have a filesystem quota and a network policy
// derived from what this scan's adapters declared.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/fetch"
	"github.com/aizen299/secure-dev/internal/logging"
	"github.com/aizen299/secure-dev/internal/scanjob"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/all"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scanjob: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{
		Level:   cfg.LogLevel,
		Format:  cfg.LogFormat,
		Service: "secureops-scanjob",
		Version: version,
	})
	slog.SetDefault(logger)

	jobCfg, err := jobConfig(cfg)
	if err != nil {
		return err
	}

	// SIGTERM is how Kubernetes asks a pod to stop. Honouring it lets the
	// in-flight scanner be cancelled and its result still reported, instead of
	// the pod being killed with the controller none the wiser.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry := all.New(cfg)
	// Provision before anything untrusted is on disk (§14.3). A failure leaves
	// the adapter registered so the scan records a failed scanner and settles
	// at PARTIAL, which is visible -- dropping it would hide lost coverage.
	for name, provisionErr := range registry.Provision(ctx) {
		logger.Error("scanner could not be provisioned; it will fail this scan",
			"scanner", name, "error", provisionErr.Error())
	}

	logger.Info("scan job starting",
		"scan_id", jobCfg.ScanID, "target_kind", string(jobCfg.Target.Kind),
		"scanners", jobCfg.Scanners)

	if err := scanjob.Run(ctx, jobCfg, registry, logger); err != nil {
		return err
	}
	logger.Info("scan job finished", "scan_id", jobCfg.ScanID)
	return nil
}

// jobConfig reads what this Job was told.
//
// The environment only. A flag carrying the token would put it in `ps` and in
// the pod spec that every `kubectl get` prints, which is the objection ADR 036
// already made to a --token flag on the CI client.
func jobConfig(cfg config.Config) (scanjob.Config, error) {
	target := scanners.Target{
		Kind:          scanners.Kind(os.Getenv("SECUREOPS_JOB_TARGET_KIND")),
		RepositoryURL: os.Getenv("SECUREOPS_JOB_TARGET_REPOSITORY_URL"),
		Ref:           os.Getenv("SECUREOPS_JOB_TARGET_REF"),
		Image:         os.Getenv("SECUREOPS_JOB_TARGET_IMAGE"),
		EndpointURL:   os.Getenv("SECUREOPS_JOB_TARGET_ENDPOINT_URL"),
	}
	// Path is deliberately absent: it is not a client-settable field on the
	// API and it is not one here either. The workspace is this process's own.

	out := scanjob.Config{
		ScanID:         os.Getenv("SECUREOPS_JOB_SCAN_ID"),
		ProjectID:      os.Getenv("SECUREOPS_JOB_PROJECT_ID"),
		CallbackURL:    os.Getenv("SECUREOPS_JOB_CALLBACK_URL"),
		Token:          os.Getenv("SECUREOPS_JOB_TOKEN"),
		Target:         target,
		Scanners:       splitList(os.Getenv("SECUREOPS_JOB_SCANNERS")),
		WorkspaceRoot:  cfg.WorkerWorkspaceRoot,
		ScannerTimeout: cfg.ScannerTimeout,
		Fetch: fetch.Options{
			Timeout:  cfg.FetchTimeout,
			MaxBytes: cfg.FetchMaxBytes,
			MaxFiles: cfg.FetchMaxFiles,
		},
	}
	if out.ScanID == "" || out.CallbackURL == "" || out.Token == "" {
		return scanjob.Config{}, fmt.Errorf(
			"SECUREOPS_JOB_SCAN_ID, SECUREOPS_JOB_CALLBACK_URL and SECUREOPS_JOB_TOKEN are required")
	}
	if target.Kind == "" {
		return scanjob.Config{}, fmt.Errorf("SECUREOPS_JOB_TARGET_KIND is required")
	}
	return out, nil
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
