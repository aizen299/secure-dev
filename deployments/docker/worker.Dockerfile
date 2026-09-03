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
# GO-2026-6354 and GO-2026-6355 (CVE-2026-78662, CVE-2026-56855): two DoS
# advisories in golang.org/x/crypto/ssh, both fixed in v0.56.0. Every scanner
# below pulls x/crypto transitively, so every one is pinned past them.
ARG X_CRYPTO_VERSION=v0.56.0
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
# CVE-2026-84304 (HIGH): gRPC-Go. Fixed in 1.83.1, and every scanner below
# vendors an affected version -- syft and trivy at v1.82.1, grype at v1.83.0,
# measured with `go version -m` on the built binaries rather than inferred.
# Pinned per stage rather than globally: a fix applied to one scanner and not
# another is an accident waiting to be rediscovered.
ARG SYFT_GRPC_VERSION=v1.83.1

RUN set -eux; \
    git clone --no-checkout https://github.com/anchore/syft /syft-src; \
    cd /syft-src; \
    git checkout -q "${SYFT_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${SYFT_COMMIT}"; \
    go get "golang.org/x/mod@${X_MOD_VERSION}" \
           "golang.org/x/crypto@${X_CRYPTO_VERSION}" \
           "go.opentelemetry.io/otel@${SYFT_OTEL_VERSION}" \
           "google.golang.org/grpc@${SYFT_GRPC_VERSION}"; \
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
# CVE-2026-84304, the same gRPC-Go advisory pinned out of syft above.
ARG GRYPE_GRPC_VERSION=v1.83.1

RUN set -eux; \
    git clone --no-checkout https://github.com/anchore/grype /grype-src; \
    cd /grype-src; \
    git checkout -q "${GRYPE_COMMIT}"; \
    test "$(git rev-parse HEAD)" = "${GRYPE_COMMIT}"; \
    go get "golang.org/x/mod@${GRYPE_X_MOD_VERSION}" \
           "golang.org/x/crypto@${X_CRYPTO_VERSION}" \
           "go.opentelemetry.io/otel@${GRYPE_OTEL_VERSION}" \
           "google.golang.org/grpc@${GRYPE_GRPC_VERSION}"; \
    go mod tidy; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${GRYPE_VERSION}" \
      -o /out/grype ./cmd/grype; \
    /out/grype version -o text | grep -q "${GRYPE_VERSION}"

# Trivy needs its own build stage, on its own Go version.
#
# ADR 009 builds every scanner with this project's toolchain. Trivy is the first
# that cannot be: v0.74.0 targets Go 1.26.3 and uses encoding/json/v2, which is
# experimental and whose API is not stable across releases. `json.SkipFunc`
# exists in Go 1.26 and was removed in 1.27 -- checked in both, not inferred --
# so building it here with 1.27 fails outright with "undefined: json.SkipFunc".
#
# Pinning the toolchain the scanner targets is the more honest reading of ADR
# 009 than forcing a version its source does not compile against. The cost is
# that this binary misses Go 1.27's standard-library fixes, which is why trivy
# is in the govulncheck gate (ADR 013) and the image scan: if that costs us an
# advisory, both will say so rather than us finding out later.
FROM golang:1.26-alpine AS trivy-build
RUN apk add --no-cache git

# v0.74.0
ARG TRIVY_COMMIT=e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994
ARG TRIVY_VERSION=0.74.0
# CVE-2026-84304, the same gRPC-Go advisory pinned out of syft and grype.
ARG TRIVY_GRPC_VERSION=v1.83.1
# Redeclared rather than inherited: an ARG does not cross a FROM, and trivy
# builds in its own stage. GO-2026-6354 / GO-2026-6355 as above.
ARG TRIVY_X_CRYPTO_VERSION=v0.56.0

RUN set -eux; \
    # Shallow, at the tag, unlike the other scanners' full clones. Trivy's
    # repository is large enough that a full clone failed mid-transfer with an
    # SSL EOF; fetching one commit is far less to go wrong with.
    #
    # This does not weaken the pin. The assertion below still compares the
    # resolved HEAD against the commit SHA, so a tag repointed at different
    # code fails the build exactly as it would with a full clone.
    git clone --depth 1 --branch "v${TRIVY_VERSION}" \
        https://github.com/aquasecurity/trivy /trivy-src; \
    cd /trivy-src; \
    test "$(git rev-parse HEAD)" = "${TRIVY_COMMIT}"; \
    # GOEXPERIMENT is set on the module commands too, not just the build.
    # trivy's pkg/x/json imports encoding/json/v2, which only exists under the
    # experiment, so `go mod tidy` without it fails to load the package.
    GOEXPERIMENT=jsonv2 go get "google.golang.org/grpc@${TRIVY_GRPC_VERSION}" \
        "golang.org/x/crypto@${TRIVY_X_CRYPTO_VERSION}"; \
    GOEXPERIMENT=jsonv2 go mod tidy; \
    # GOEXPERIMENT=jsonv2 is not optional and not a tuning choice: trivy's
    # pkg/x/json calls into encoding/json/v2. This matches what trivy's own
    # release build sets, which is also what ADR 009's equivalence requirement
    # wants -- the same source, built the way upstream builds it.
    CGO_ENABLED=0 GOEXPERIMENT=jsonv2 go build -trimpath \
      -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" \
      -o /out/trivy ./cmd/trivy; \
    # The version is captured per scan and persisted (§7 rule 6), so a binary
    # that misreports it is a defect.
    /out/trivy --version | grep -q "${TRIVY_VERSION}"

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
COPY --from=trivy-build /out/trivy /usr/local/bin/trivy

# The workspace root is created by the runtime (a tmpfs in compose, an
# emptyDir in Kubernetes) so that untrusted content never touches the image
# layers.
RUN mkdir -p /workspaces && chown nonroot:nonroot /workspaces
# The vulnerability database lives outside the workspace root on purpose: a
# workspace is ephemeral and destroyed after each job, while the database is
# long-lived and shared across them (ADR 012). Owned by the runtime user
# because provisioning writes to it as that user, not as root.
RUN mkdir -p /var/cache/grype/db /var/cache/semgrep /var/cache/trivy && \
    chown -R nonroot:nonroot /var/cache/grype /var/cache/semgrep /var/cache/trivy

# Rule §15.10: containers run as non-root.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/worker"]
