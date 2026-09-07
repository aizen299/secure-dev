#!/usr/bin/env bash
# Tear down the local verification cluster and its registry.
set -euo pipefail
CLUSTER="${1:-secureops}"
kind delete cluster --name "$CLUSTER" 2>/dev/null || true
docker rm -f kind-registry >/dev/null 2>&1 || true
echo "kind-down: cluster '${CLUSTER}' and its registry are gone"
