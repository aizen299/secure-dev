// Command secureops is the CI client: it submits a scan, waits for it, and
// turns the gate's verdict into an exit code.
//
// A thin main over internal/cli, matching cmd/api over internal/httpapi. The
// logic lives there so it is testable without building a binary and without a
// CI provider (ADR 036 §1).
//
// Exit codes are the contract:
//
//	0  the gate did not block: PASS, or WARN
//	1  the gate blocked: FAIL
//	2  the gate did not run: unreachable, refused, timed out, scan failed
//
// The third exists so a broken client cannot pass a build. Exiting 0 when the
// API is unreachable would turn an outage into a silent, universal disabling of
// the gate.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aizen299/secure-dev/internal/cli"
)

func main() {
	var (
		apiURL    = flag.String("api", envOr("SECUREOPS_API_URL", "http://localhost:8090"), "SecureOps API base URL")
		projectID = flag.String("project", os.Getenv("SECUREOPS_PROJECT_ID"), "project id this build belongs to (required)")
		repoURL   = flag.String("repo", "", "https URL of the repository to scan (required)")
		ref       = flag.String("ref", "", "branch or tag to scan")
		timeout   = flag.Duration("timeout", 20*time.Minute, "how long to wait for the scan before giving up")
		format    = flag.String("format", "text", "output format: text or json")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: secureops [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Submits a scan, waits for it, and applies the project's security gate.\n\n")
		fmt.Fprintf(os.Stderr, "Exit codes:\n")
		fmt.Fprintf(os.Stderr, "  %d  the gate did not block (pass, or warn)\n", cli.ExitOK)
		fmt.Fprintf(os.Stderr, "  %d  the gate blocked (fail)\n", cli.ExitGateFailed)
		fmt.Fprintf(os.Stderr, "  %d  the gate did not run — unreachable, refused, timed out, or the scan failed\n",
			cli.ExitCouldNotEvaluate)
		fmt.Fprintf(os.Stderr, "\nThe token comes from SECUREOPS_API_TOKEN, never a flag: a flag is\n")
		fmt.Fprintf(os.Stderr, "visible in `ps` and in CI logs.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Interrupted is not passed. A pipeline cancelled mid-scan has not been
	// judged, and returning 0 for it would be the same lie as returning 0 for
	// an outage.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result, err := cli.Run(ctx, cli.Options{
		BaseURL: *apiURL,
		// Never a flag (ADR 036 §6).
		Token:         os.Getenv("SECUREOPS_API_TOKEN"),
		ProjectID:     *projectID,
		RepositoryURL: *repoURL,
		Ref:           *ref,
		Timeout:       *timeout,
	})

	if err != nil {
		// Written to stderr so a pipeline capturing stdout for the JSON still
		// sees why it stopped.
		fmt.Fprintf(os.Stderr, "secureops: %v\n", err)
		if !errors.Is(err, cli.ErrCouldNotEvaluate) {
			// Unreachable today -- Run wraps everything -- but stated rather
			// than assumed: an unclassified error must not fall through to a
			// passing exit code.
			os.Exit(cli.ExitCouldNotEvaluate)
		}
	}

	if *format == "json" {
		if err := cli.RenderJSON(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "secureops: could not write the result: %v\n", err)
			os.Exit(cli.ExitCouldNotEvaluate)
		}
	} else {
		cli.Render(os.Stdout, result)
	}

	os.Exit(result.ExitCode())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
