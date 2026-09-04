# SecureOps developer commands.
#
# CLAUDE.md §22 requires validation commands to be discoverable from the
# repository rather than invented, so this file is the single source of truth.

SHELL := /bin/bash
.DEFAULT_GOAL := help

WEB := apps/web
API_IMAGE ?= secureops-app:latest
WORKER_IMAGE ?= secureops-worker:latest
TRIVY_IGNORE ?= .trivyignore.yaml
# Pinned, not @latest: a gate whose version floats can start or stop failing
# without anything in this repository changing (§16).
GOVULNCHECK_VERSION ?= v1.7.0
VULN_BIN_DIR ?= bin/scanners
VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
SBOM ?= sbom.json

# Grype refreshes its vulnerability database before scanning. It documents an
# update-available timeout of 30s and a download timeout of 5m, yet a stalled
# refresh was observed running for over THIRTY MINUTES with a dead connection,
# no cache growth, and the database still reporting its previous build date --
# so those internal bounds cannot be relied on to terminate it. Since
# `make security` runs this, a hang there blocks all local validation.
#
# An external bound is what actually guarantees termination. scripts/with-timeout.sh
# rather than timeout(1): macOS does not ship coreutils, so depending on it
# would protect CI and leave developers unprotected -- backwards, since CI
# already has a job timeout and a developer has none.
GRYPE_TIMEOUT ?= 600

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- toolchain --

.PHONY: tools
tools: ## Report which required tools are available
	@for t in go gofmt golangci-lint node npm docker gitleaks semgrep syft grype trivy; do \
		if command -v $$t >/dev/null 2>&1; then printf "  %-16s ok\n" "$$t"; \
		else printf "  %-16s MISSING\n" "$$t"; fi; \
	done
	@printf "  %-16s " "docker daemon"; \
		if docker info >/dev/null 2>&1; then echo "running"; else echo "NOT RUNNING"; fi

# ---------------------------------------------------------------------- Go --

.PHONY: fmt
fmt: ## Format Go code
	gofmt -w cmd internal

.PHONY: fmt-check
fmt-check: ## Fail if Go code is not formatted
	@unformatted=$$(gofmt -l cmd internal); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi
	@echo "gofmt: clean"

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint-go
lint-go: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: build-go
build-go: ## Build the Go binaries into ./bin
	mkdir -p bin
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/api ./cmd/api
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/worker ./cmd/worker
	go build -trimpath -ldflags "-s -w" -o bin/migrate ./cmd/migrate

.PHONY: test-go
test-go: ## Run Go unit tests with the race detector
	go test ./... -race

.PHONY: lint-api
lint-api: ## Check the OpenAPI spec is valid and matches the handlers
	# §18 requires openapi.yaml to stay in sync with the handlers, and §25.17
	# forbids changing a public contract silently. Both were enforced by
	# discipline alone until this existed: a handler could change shape and
	# every check still passed.
	#
	# Pure `go test` on purpose -- no Node, no separate linter binary. The
	# candidates (Redocly, Spectral) both carry telemetry, and neither can do
	# the part that matters: comparing what we SEND against what we PUBLISHED.
	go test ./internal/httpapi/ -count=1 \
		-run 'TestOpenAPISpecIsValid|TestOpenAPIMatchesHandlers|TestEveryRouteIsDocumented'

.PHONY: test-integration
test-integration: ## Run integration tests against a running stack (make up first)
	# Behind a build tag so `go test ./...` stays hermetic. Requires PostgreSQL
	# and Redis; source .env for the connection URLs.
	set -a; . ./.env; set +a; go test -tags=integration ./tests/... -race -count=1 -v

.PHONY: cover
cover: ## Run Go tests and report coverage
	go test ./... -race -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

# --------------------------------------------------------------------- Web --

.PHONY: install-web
install-web: ## Install web dependencies from the lockfile
	npm --prefix $(WEB) ci --no-audit --no-fund

.PHONY: lint-web
lint-web: ## Lint the web app
	npm --prefix $(WEB) run lint

.PHONY: typecheck-web
typecheck-web: ## Type-check the web app
	npm --prefix $(WEB) run typecheck

.PHONY: test-web
test-web: ## Run the dashboard's unit tests (vitest)
	# ADR 031. The dashboard holds the session boundary and the mode-derived
	# UI, and both had defects that reached main because nothing here ran.
	npm --prefix $(WEB) run test

.PHONY: build-web
build-web: ## Build the web app
	npm --prefix $(WEB) run build

# ---------------------------------------------------------------- database --

.PHONY: migrate-up
migrate-up: ## Apply all pending migrations
	go run ./cmd/migrate -dir migrations up

.PHONY: migrate-down
migrate-down: ## Roll back exactly one migration
	go run ./cmd/migrate -dir migrations down

.PHONY: migrate-version
migrate-version: ## Print the current schema version
	go run ./cmd/migrate -dir migrations version

# --------------------------------------------------------------- local env --

.PHONY: build-images
build-images: ## Build the API and worker container images
	# `docker build`, not `docker compose build`: compose interpolates the
	# whole file before it builds anything, so it demands the Postgres and
	# Redis credentials that `${VAR:?}` makes mandatory -- credentials an image
	# build has no use for. That coupling is invisible on a machine with a
	# .env and fatal in CI, which has none. The compose guard stays as it is;
	# building simply stops depending on runtime configuration.
	docker build -f deployments/docker/api.Dockerfile -t $(API_IMAGE) .
	docker build -f deployments/docker/worker.Dockerfile -t $(WORKER_IMAGE) .

.PHONY: up
up: ## Start the local stack
	docker compose up -d --build

.PHONY: down
down: ## Stop the local stack
	docker compose down

.PHONY: logs
logs: ## Tail stack logs
	docker compose logs -f

.PHONY: ps
ps: ## Show stack status
	docker compose ps

# ---------------------------------------------------------------- security --
# SecureOps dogfoods itself (§16). These targets are the self-scan.

.PHONY: scan-secrets
scan-secrets: ## Scan for secrets (gitleaks: history + working tree)
	# .gitleaks.toml excludes local env files from the working-tree scan. That
	# is only sound while they are genuinely un-committable, so verify it here
	# rather than assuming it (CLAUDE.md §15.12).
	@for f in .env .env.local; do \
		if [ -e "$$f" ] && ! git check-ignore -q "$$f"; then \
			echo "FAIL: $$f exists but is NOT gitignored -- it could be committed."; \
			exit 1; \
		fi; \
	done
	@echo "guard: local env files are gitignored"
	gitleaks git --redact --config .gitleaks.toml
	gitleaks detect --no-git --redact --config .gitleaks.toml

.PHONY: scan-sast
scan-sast: ## Static analysis (semgrep)
	# Explicit rulesets, not --config auto: auto requires telemetry to be
	# enabled, and pinned rulesets make the scan reproducible.
	semgrep --error --metrics=off \
		--config p/golang --config p/typescript --config p/security-audit \
		--config p/secrets --config p/dockerfile \
		--exclude=node_modules --exclude=.next --exclude=bin .

.PHONY: scan-fs
scan-fs: ## Filesystem and dependency scan (trivy)
	trivy fs --exit-code 1 --severity HIGH,CRITICAL --scanners vuln,secret,misconfig .

.PHONY: scan-image
scan-image: build-images ## Scan the built container images (trivy)
	# Not part of `make security`: it needs the images built, which is slow,
	# and `security` is meant to be runnable before every commit. This gap is
	# how a worker image with 32 HIGH/CRITICAL CVEs went unnoticed until it was
	# scanned by hand, so run it whenever an image or its toolchain changes.
	# --ignorefile is passed explicitly rather than relying on auto-detection:
	# trivy 0.74 does not pick up .trivyignore.yaml on its own, and an ignore
	# file that is silently not applied is worse than none -- it would read as
	# "the exception is in place" while the build fails for reasons nobody
	# looks at. Every entry in it carries a justification and an expiry date
	# that trivy enforces.
	trivy image --exit-code 1 --severity HIGH,CRITICAL --scanners vuln \
		--ignorefile $(TRIVY_IGNORE) $(API_IMAGE)
	trivy image --exit-code 1 --severity HIGH,CRITICAL --scanners vuln \
		--ignorefile $(TRIVY_IGNORE) $(WORKER_IMAGE)

.PHONY: lint-vuln
lint-vuln: ## Check Go advisories in our code and the shipped scanner binaries
	# Two gates, not one. Trivy scans the images and reported TWO advisories in
	# the grype binary where govulncheck reported SIX -- govulncheck understands
	# Go specifically: which packages a binary links, and which symbols survived
	# the linker. Running both is coverage, not redundancy.
	#
	# Our own code is held to zero with no exceptions. The third-party scanner
	# binaries consult .govulnignore.yaml, where every accepted advisory carries
	# a reason and an expiry date this target enforces.
	# Installed at a pinned version rather than trusting whatever is on PATH,
	# so the gate cannot change behaviour without this file changing.
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@mkdir -p $(VULN_BIN_DIR)
	@# The scanner binaries only exist inside the worker image.
	docker create --name secureops-vulnextract $(WORKER_IMAGE) >/dev/null
	@for b in gitleaks syft grype trivy worker; do \
		docker cp secureops-vulnextract:/usr/local/bin/$$b $(VULN_BIN_DIR)/$$b >/dev/null; \
	done
	docker rm secureops-vulnextract >/dev/null
	SECUREOPS_BINARY_DIR=$(abspath $(VULN_BIN_DIR)) \
		PATH="$$PATH:$$(go env GOPATH)/bin" \
		go test -tags=vulncheck ./tests/vulnerability/ -count=1 -v

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM
	syft . -o cyclonedx-json=$(SBOM)

.PHONY: scan-deps
scan-deps: sbom ## Scan dependencies from the SBOM (grype)
	# The database refresh is deliberately NOT disabled. Scanning against stale
	# vulnerability data is a false clean -- it succeeds, reports fewer
	# vulnerabilities than exist, and signals nothing (ADR 010, ADR 012, T-31).
	# The refresh stays; only its ability to hang forever is removed.
	./scripts/with-timeout.sh $(GRYPE_TIMEOUT) grype sbom:$(SBOM) --fail-on high

.PHONY: security
security: scan-secrets scan-sast scan-fs scan-deps ## Run the full self-scan

# ------------------------------------------------------------- aggregates --

.PHONY: check
check: fmt-check vet lint-go test-go lint-api lint-web typecheck-web test-web ## Run all non-container checks

.PHONY: ci
ci: check build-go build-web ## What CI runs

.PHONY: clean
clean: ## Remove build output and scan artifacts
	rm -rf bin coverage.out coverage.html $(SBOM)
	rm -rf $(WEB)/.next
