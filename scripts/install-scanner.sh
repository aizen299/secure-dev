#!/usr/bin/env bash
#
# Install a pinned scanner binary into a directory, refusing to install one
# whose bytes we did not expect.
#
# CI previously piped a vendor's installer straight into a shell:
#
#     curl -sSfL https://get.anchore.io/syft | sh -s -- -b "$DIR" v1.51.0
#     curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- ...
#
# The TOOL version was pinned and the INSTALLER was not -- and trivy's came off
# the `main` branch, which is mutable by definition. So the thing granted
# arbitrary execution in our pipeline was whatever that URL served at the
# moment it was fetched. That is the same class of supply-chain problem
# SecureOps exists to find in other people's repositories (threat model T-19,
# T-10, §16), and a security tool that ships it in its own build has no
# standing to report it.
#
# What replaces it: a release archive at a pinned version, verified against a
# digest recorded in this file, extracted with no code from the vendor running
# at any point. A mismatch is fatal and loud -- never a warning, and never a
# fallback to installing it anyway, because an unverified scanner produces
# results that look exactly like verified ones (§15.12).
#
# The pins live here rather than in the workflow because a version without its
# digest is half a pin, and two files are two chances to update only one.
#
# Also installs helm, which is not a scanner. It is here rather than in a second
# script because the pinning discipline is the thing worth sharing, and two
# scripts would be two places for it to drift. helm renders the chart that
# grants privileges in a cluster; it deserves the same treatment.
#
# Usage: scripts/install-scanner.sh <syft|grype|trivy|helm> <bindir>

set -euo pipefail

TOOL="${1:?usage: install-scanner.sh <syft|grype|trivy|helm> <bindir>}"
BIN_DIR="${2:?usage: install-scanner.sh <syft|grype|trivy|helm> <bindir>}"

# linux/amd64 only, which is what CI runs on. A developer's machine installs
# these through its own package manager and `make tools` reports what is
# present; pinning every platform here would mean maintaining digests nothing
# verifies. Anything else fails rather than guessing.
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "install-scanner.sh: pinned for linux/amd64 only; this is $(uname -s)/$(uname -m)." >&2
  echo "Install $TOOL through your package manager -- 'make tools' reports what is on PATH." >&2
  exit 1
fi

case "$TOOL" in
  syft)
    VERSION=1.51.0
    URL="https://github.com/anchore/syft/releases/download/v${VERSION}/syft_${VERSION}_linux_amd64.tar.gz"
    SHA256=2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f
    ;;
  grype)
    VERSION=0.117.0
    URL="https://github.com/anchore/grype/releases/download/v${VERSION}/grype_${VERSION}_linux_amd64.tar.gz"
    SHA256=38525dab1e06f162ebaa02f94d82d1f807076b011a44180cf2777edf1a7b9c26
    ;;
  trivy)
    VERSION=0.74.0
    URL="https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz"
    SHA256=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
    ;;
  helm)
    VERSION=4.2.4
    URL="https://get.helm.sh/helm-v${VERSION}-linux-amd64.tar.gz"
    SHA256=c306b46f719b0a4da32d0f78ee21bf90ce8d602f15b22ab753f0674d1670a7f3
    # helm's archive nests the binary; the others put it at the root.
    MEMBER=linux-amd64/helm
    ;;
  *)
    echo "install-scanner.sh: unknown tool '$TOOL' (want syft, grype, trivy, or helm)" >&2
    exit 1
    ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ARCHIVE="$WORK/archive.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --max-time 300 --output "$ARCHIVE" "$URL"

# shasum on a developer's macOS, sha256sum on the Linux runner. Compared here
# rather than handed to `sha256sum -c`, so the expected value is visible in the
# failure message: "checksum mismatch" without the two values is a dead end.
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
fi

if [ "$ACTUAL" != "$SHA256" ]; then
  echo "install-scanner.sh: DIGEST MISMATCH for $TOOL $VERSION" >&2
  echo "  url:      $URL" >&2
  echo "  expected: $SHA256" >&2
  echo "  actual:   $ACTUAL" >&2
  echo "Refusing to install. Either the release was republished or the download was tampered with;" >&2
  echo "verify the new digest against the vendor's signed checksums before changing the pin." >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
# Only the binary. The archives also carry licences and completions, and
# extracting the whole thing into a directory that is about to go on PATH is
# more trust than this needs.
MEMBER="${MEMBER:-$TOOL}"
tar -xzf "$ARCHIVE" -C "$WORK" "$MEMBER"
install -m 0755 "$WORK/$MEMBER" "$BIN_DIR/$TOOL"

echo "install-scanner.sh: $TOOL $VERSION verified ($SHA256) -> $BIN_DIR/$TOOL"
