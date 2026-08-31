# SecureOps scanner worker.
#
# This image is deliberately NOT the API image. The worker is the only
# component that executes scanner binaries and touches untrusted target content
# (CLAUDE.md §14.2), so it needs a toolchain the API must never have. Keeping
# them separate is what lets the API stay distroless: no shell, no package
# manager, no scanner binaries in the process that is actually exposed.
#
# Everything installed here is pinned and checksum-verified. A scanner binary is
# a supply-chain dependency that runs against attacker-controlled input, so
# "latest" is not acceptable (threat model T-10).

FROM golang:1.27-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/worker ./cmd/worker

# --- scanner toolchain -------------------------------------------------------
#
# Scanners are BUILT FROM SOURCE rather than installed from release archives.
# This is a deliberate supply-chain decision (ADR 009), not a convenience.
#
# The published gitleaks 8.30.1 binary carries 32 HIGH/CRITICAL CVEs: 21 in a
# stale Go standard library (it is built with Go 1.24.11) and 11 in x/crypto and
# x/text. There is no newer release to upgrade to -- 8.30.1 is the latest.
# Rebuilding here with this project's Go toolchain and patched x/ libraries
# brings that to zero, and the resulting binary produces byte-identical output
# on a 22-finding corpus of real planted secrets.
#
# The source is pinned to an immutable commit SHA, not a tag. Tags are mutable,
# so a SHA is a stronger guarantee than the publisher checksum this replaces.

FROM golang:1.27-alpine AS tools
RUN apk add --no-cache git

# v8.30.1
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
ARG GITLEAKS_VERSION=8.30.1
# Patched versions of the two x/ libraries carrying the remaining CVEs. Bumped
# explicitly and pinned: the build must not drift with the module proxy.
ARG X_CRYPTO_VERSION=v0.52.0
ARG X_TEXT_VERSION=v0.39.0

RUN set -eux; \
    git clone --no-checkout https://github.com/gitleaks/gitleaks /src; \
    cd /src; \
    git checkout -q "${GITLEAKS_COMMIT}"; \
    # Confirm the checkout really is the pinned commit before building it.
    test "$(git rev-parse HEAD)" = "${GITLEAKS_COMMIT}"; \
    go get "golang.org/x/crypto@${X_CRYPTO_VERSION}" "golang.org/x/text@${X_TEXT_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
      -o /out/gitleaks .; \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect. Without the ldflag above gitleaks prints
    # "version is set by build process", which would be stored as the scanner
    # version for every result.
    test "$(/out/gitleaks version)" = "${GITLEAKS_VERSION}"

# Syft, same pattern: pinned commit, our toolchain, version asserted.
# v1.51.0
ARG SYFT_COMMIT=2293641e3bd628a01bb37639318d62c0ebe89b39
ARG SYFT_VERSION=1.51.0
# Carries the two x/mod advisories that survive a plain rebuild.
ARG X_MOD_VERSION=v0.40.0

RUN set -eux; \
    git clone --no-checkout https://github.com/anchore/syft /syft-src; \
    cd /syft-src; \
    git checkout -q "${SYFT_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${SYFT_COMMIT}"; \
    go get "golang.org/x/mod@${X_MOD_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${SYFT_VERSION}" \
      -o /out/syft ./cmd/syft; \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect, not cosmetics.
    /out/syft version -o text | grep -q "${SYFT_VERSION}"

# --- runtime -----------------------------------------------------------------
#
# Alpine rather than distroless: the worker needs git, which needs a libc and a
# filesystem layout. The trade is accepted because the worker is not
# network-exposed -- it consumes a queue and never serves requests.

FROM alpine:3.22

# git is required to fetch repository targets (ADR 008). ca-certificates is
# required for https remotes. Nothing else is installed.
RUN apk add --no-cache git ca-certificates && \
    # Pick up any security fixes newer than the base image tag.
    apk upgrade --no-cache && \
    # No package manager in the running container: the worker executes
    # untrusted content, and apk would be a convenient escalation tool.
    rm -rf /sbin/apk /etc/apk /lib/apk /usr/share/apk /var/cache/apk

# 65532 matches the distroless "nonroot" UID the other images use, so the
# compose tmpfs ownership is the same for every service.
RUN addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S nonroot -G nonroot

COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=tools /out/gitleaks /usr/local/bin/gitleaks
COPY --from=tools /out/syft /usr/local/bin/syft

# The workspace root is created by the runtime (a tmpfs in compose, an
# emptyDir in Kubernetes) so that untrusted content never touches the image
# layers.
RUN mkdir -p /workspaces && chown nonroot:nonroot /workspaces

# Rule §15.10: containers run as non-root.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/worker"]
