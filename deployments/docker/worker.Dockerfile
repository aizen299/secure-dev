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
ARG X_CRYPTO_VERSION=v0.55.0
ARG X_TEXT_VERSION=v0.41.0
# Three archive-handling advisories that trivy does not report and govulncheck
# does. All three are in code that parses attacker-supplied archives, which is
# exactly the code path a secret scanner points at untrusted repositories.
#
# Bumped through mholt/archives rather than by pinning its dependencies
# underneath it: rardecode v2.2.0 changes an interface that archives v0.1.2
# implements against, so forcing the child alone fails to compile. v0.1.5
# already carries the fixed rardecode and xz. klauspost/compress still needs
# its own bump -- archives v0.1.5 pins v1.18.0 and the fix landed in v1.18.7.
ARG ARCHIVES_VERSION=v0.1.5
ARG COMPRESS_VERSION=v1.18.7

RUN set -eux; \
    git clone --no-checkout https://github.com/gitleaks/gitleaks /src; \
    cd /src; \
    git checkout -q "${GITLEAKS_COMMIT}"; \
    # Confirm the checkout really is the pinned commit before building it.
    test "$(git rev-parse HEAD)" = "${GITLEAKS_COMMIT}"; \
    go get "golang.org/x/crypto@${X_CRYPTO_VERSION}" "golang.org/x/text@${X_TEXT_VERSION}" \
           "github.com/mholt/archives@${ARCHIVES_VERSION}" \
           "github.com/klauspost/compress@${COMPRESS_VERSION}"; \
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
# The same OpenTelemetry advisory already pinned out of grype. Fixed here too:
# a fix applied to one scanner and not another is an accident waiting to be
# rediscovered.
ARG SYFT_OTEL_VERSION=v1.44.0

RUN set -eux; \
    git clone --no-checkout https://github.com/anchore/syft /syft-src; \
    cd /syft-src; \
    git checkout -q "${SYFT_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${SYFT_COMMIT}"; \
    go get "golang.org/x/mod@${X_MOD_VERSION}" \
           "go.opentelemetry.io/otel@${SYFT_OTEL_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${SYFT_VERSION}" \
      -o /out/syft ./cmd/syft; \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect, not cosmetics.
    /out/syft version -o text | grep -q "${SYFT_VERSION}"

# Grype, same pattern: pinned commit, our toolchain, version asserted.
#
# The binary only. Its 2 GB vulnerability database is NOT baked in -- it is
# provisioned into a volume at worker startup, before any job is claimed
# (ADR 012). A database in the image would be stale the moment it was built.
# v0.118.0
ARG GRYPE_COMMIT=756eb9a24f7beeafb6871a24e943e8a3ae210695
ARG GRYPE_VERSION=0.118.0
# Carries the two x/mod advisories that survive a plain rebuild, same as syft.
ARG GRYPE_X_MOD_VERSION=v0.40.0
# And an OpenTelemetry advisory that a plain rebuild also leaves behind.
ARG GRYPE_OTEL_VERSION=v1.44.0

RUN set -eux; \
    git clone --no-checkout https://github.com/anchore/grype /grype-src; \
    cd /grype-src; \
    git checkout -q "${GRYPE_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${GRYPE_COMMIT}"; \
    go get "golang.org/x/mod@${GRYPE_X_MOD_VERSION}" \
           "go.opentelemetry.io/otel@${GRYPE_OTEL_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${GRYPE_VERSION}" \
      -o /out/grype ./cmd/grype; \
    /out/grype version -o text | grep -q "${GRYPE_VERSION}"

# --- runtime -----------------------------------------------------------------
#
# Alpine rather than distroless: the worker needs git, which needs a libc and a
# filesystem layout. The trade is accepted because the worker is not
# network-exposed -- it consumes a queue and never serves requests.

FROM alpine:3.22

# Semgrep is Python, so unlike every other scanner here it cannot be built from
# source with our own toolchain (ADR 009 does not transfer; see ADR 014). It is
# installed from the musllinux wheel published on PyPI, with that wheel's
# SHA-256 verified against the digest PyPI publishes for it.
#
# Pinned per architecture because the digest differs: the build resolves
# TARGETARCH rather than trusting whichever wheel pip happens to pick.
ARG SEMGREP_VERSION=1.174.0
ARG SEMGREP_SHA256_AMD64=bbf20fdae8d6776a0afa3afe2aa20f07e8a24a86b3cd89b70b8b85a468e5dd24
ARG SEMGREP_SHA256_ARM64=4f916a51f71e2ac37852830f8003af0d0c484c53ce480e6ec96c7a60d092d536
ARG TARGETARCH

# git is required to fetch repository targets (ADR 008). ca-certificates is
# required for https remotes. python3 is required by semgrep. Nothing else is
# installed, and everything used only to install is removed again below.
RUN set -eux; \
    apk add --no-cache git ca-certificates python3; \
    apk add --no-cache --virtual .semgrep-install py3-pip; \
    \
    case "${TARGETARCH}" in \
      amd64) wheel_sha="${SEMGREP_SHA256_AMD64}" ;; \
      arm64) wheel_sha="${SEMGREP_SHA256_ARM64}" ;; \
      *) echo "no pinned semgrep wheel for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    pip download --no-deps --no-cache-dir -d /tmp semgrep=="${SEMGREP_VERSION}"; \
    # The artifact is verified before anything executes it. This is the whole
    # substitute for building from source: semgrep cannot be rebuilt with our
    # toolchain, so we at least refuse to install a wheel that is not the one
    # PyPI published (ADR 014).
    echo "${wheel_sha}  $(ls /tmp/semgrep-*.whl)" | sha256sum -c -; \
    \
    # Installed under its own prefix, not into the system site-packages.
    # Sharing that directory with apk means pip skips any dependency apk
    # already provides, and removing pip afterwards then takes those with it --
    # which is exactly how the first attempt produced a semgrep that could not
    # import `packaging`. A separate prefix has no such overlap.
    # --ignore-installed matters as much as --prefix. Without it pip treats any
    # dependency apk already provides as satisfied and does not place a copy in
    # the prefix; removing pip's apk package then takes those shared copies
    # away, leaving a semgrep that cannot import `packaging`.
    pip install --no-cache-dir --break-system-packages --ignore-installed \
        --prefix=/opt/semgrep /tmp/semgrep-*.whl; \
    rm -f /tmp/semgrep-*.whl; \
    \
    # pip is a strictly better escalation tool than apk -- it downloads and
    # executes arbitrary code by design -- so it leaves with everything else.
    apk del .semgrep-install; \
    \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect.
    #
    # Asserted AFTER the teardown above, deliberately. Run before it, this test
    # passes against a filesystem that does not ship: the first attempt checked
    # a working semgrep, then deleted the packages it depended on, and produced
    # a green build and a broken image.
    test "$(PATH=/opt/semgrep/bin:$PATH \
            PYTHONPATH=/opt/semgrep/lib/python3.12/site-packages \
            semgrep --version)" = "${SEMGREP_VERSION}"; \
    \
    # Pick up any security fixes newer than the base image tag.
    apk upgrade --no-cache; \
    # No package manager in the running container: the worker executes
    # untrusted content, and apk would be a convenient escalation tool.
    rm -rf /sbin/apk /etc/apk /lib/apk /usr/share/apk /var/cache/apk

# 65532 matches the distroless "nonroot" UID the other images use, so the
# compose tmpfs ownership is the same for every service.
RUN addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S nonroot -G nonroot

# semgrep lives under its own prefix, so neither its packages nor its helper
# executables are found by default. Both are needed: the `semgrep` entrypoint is
# an OCaml binary that execs a `pysemgrep` helper, which fails with a bare
# "execvp pysemgrep" if the prefix's bin is not on PATH.
ENV PATH=/opt/semgrep/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/opt/semgrep/lib/python3.12/site-packages

COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=tools /out/gitleaks /usr/local/bin/gitleaks
COPY --from=tools /out/syft /usr/local/bin/syft
COPY --from=tools /out/grype /usr/local/bin/grype

# The workspace root is created by the runtime (a tmpfs in compose, an
# emptyDir in Kubernetes) so that untrusted content never touches the image
# layers.
RUN mkdir -p /workspaces && chown nonroot:nonroot /workspaces
# The vulnerability database lives outside the workspace root on purpose: a
# workspace is ephemeral and destroyed after each job, while the database is
# long-lived and shared across them (ADR 012). Owned by the runtime user
# because provisioning writes to it as that user, not as root.
RUN mkdir -p /var/cache/grype/db /var/cache/semgrep && \
    chown -R nonroot:nonroot /var/cache/grype /var/cache/semgrep

# Rule §15.10: containers run as non-root.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/worker"]
