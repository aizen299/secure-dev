#!/usr/bin/env bash
#
# Stand up a local Kubernetes cluster for verifying the SecureOps chart.
#
# Why this exists, and why it runs a registry: the chart refuses to render an
# image that is not pinned by digest (threat model T-10), and a locally built
# image has no digest until something serves it. The tempting shortcut is an
# `allowTags` escape hatch used "just for local testing" -- which is how a
# control becomes optional, and is exactly what §15.12 forbids. So local
# development gets a real registry beside the cluster and satisfies the
# requirement honestly.
#
# The registry listens on 127.0.0.1 only. It holds development images and no
# credentials, and it is not something to expose.
#
# Usage: scripts/kind-up.sh [cluster-name]

set -euo pipefail

CLUSTER="${1:-secureops}"
# 5001, not 5000: macOS binds 5000 to AirPlay Receiver, and the failure is a
# 403 from something that is not a registry, which is a confusing way to spend
# twenty minutes.
REG_PORT=5001
REG_NAME=kind-registry

for t in kind kubectl helm docker; do
  command -v "$t" >/dev/null 2>&1 || { echo "kind-up: $t is not installed" >&2; exit 1; }
done

if [ "$(docker inspect -f '{{.State.Running}}' "$REG_NAME" 2>/dev/null || true)" != "true" ]; then
  echo "==> starting the local registry on 127.0.0.1:${REG_PORT}"
  docker run -d --restart=always \
    -p "127.0.0.1:${REG_PORT}:5000" \
    --name "$REG_NAME" registry:2 >/dev/null
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "==> cluster '${CLUSTER}' already exists"
else
  echo "==> creating cluster '${CLUSTER}'"
  cat <<EOF | kind create cluster --name "$CLUSTER" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
nodes:
  - role: control-plane
  - role: worker
EOF

  # Point containerd at the registry, per kind's documented local-registry
  # pattern.
  for node in $(kind get nodes --name "$CLUSTER"); do
    docker exec "$node" mkdir -p "/etc/containerd/certs.d/localhost:${REG_PORT}"
    docker exec -i "$node" sh -c \
      "cat > /etc/containerd/certs.d/localhost:${REG_PORT}/hosts.toml" <<EOF
[host."http://${REG_NAME}:5000"]
EOF
  done
fi

# The registry must share kind's network for the nodes to resolve it by name.
if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "$REG_NAME" 2>/dev/null || echo null)" = "null" ]; then
  echo "==> attaching the registry to the kind network"
  docker network connect kind "$REG_NAME" 2>/dev/null || true
fi

kubectl cluster-info --context "kind-${CLUSTER}" >/dev/null

cat <<EOF

Cluster '${CLUSTER}' is up, registry on localhost:${REG_PORT}.

  make kind-deploy      build, push by digest, and install the chart
  scripts/kind-down.sh  tear both down

EOF
