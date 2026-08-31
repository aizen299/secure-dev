# SecureOps developer commands.
#
# CLAUDE.md §22 requires validation commands to be discoverable from the
# repository rather than invented, so this file is the single source of truth.

SHELL := /bin/bash
.DEFAULT_GOAL := help

WEB := apps/web
VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
SBOM ?= sbom.json

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
scan-image: ## Scan the built container images (trivy)
	# Not part of `make security`: it needs the images built, which is slow,
	# and `security` is meant to be runnable before every commit. This gap is
	# how a worker image with 32 HIGH/CRITICAL CVEs went unnoticed until it was
	# scanned by hand, so run it whenever an image or its toolchain changes.
	docker compose build api worker
	trivy image --exit-code 1 --severity HIGH,CRITICAL --scanners vuln secureops-app:latest
	trivy image --exit-code 1 --severity HIGH,CRITICAL --scanners vuln secureops-worker:latest

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM
	syft . -o cyclonedx-json=$(SBOM)

.PHONY: scan-deps
scan-deps: sbom ## Scan dependencies from the SBOM (grype)
	grype sbom:$(SBOM) --fail-on high

.PHONY: security
security: scan-secrets scan-sast scan-fs scan-deps ## Run the full self-scan

# ------------------------------------------------------------- aggregates --

.PHONY: check
check: fmt-check vet lint-go test-go lint-web typecheck-web ## Run all non-container checks

.PHONY: ci
ci: check build-go build-web ## What CI runs

.PHONY: clean
clean: ## Remove build output and scan artifacts
	rm -rf bin coverage.out coverage.html $(SBOM)
	rm -rf $(WEB)/.next
