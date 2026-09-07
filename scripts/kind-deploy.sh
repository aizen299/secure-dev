#!/usr/bin/env bash
#
# Build, push, and install SecureOps into the local kind cluster -- BY DIGEST.
#
# The digest is read back from the registry after the push rather than computed
# locally, because the digest that matters is the one the cluster will resolve.
# A locally computed image ID is a different number and would satisfy the
# template while pinning nothing.
#
# Usage: scripts/kind-deploy.sh [cluster-name]

set -euo pipefail

CLUSTER="${1:-secureops}"
REG="localhost:5001"
NS="${NS:-secureops}"
RELEASE="${RELEASE:-secureops}"
CTX="kind-${CLUSTER}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

kubectl config use-context "$CTX" >/dev/null

echo "==> building images"
docker build -q -f "$ROOT/deployments/docker/api.Dockerfile"    -t "$REG/secureops-app:dev"    "$ROOT" >/dev/null
docker build -q -f "$ROOT/deployments/docker/worker.Dockerfile" -t "$REG/secureops-worker:dev" "$ROOT" >/dev/null
docker build -q -f "$ROOT/deployments/docker/web.Dockerfile"    -t "$REG/secureops-web:dev"    "$ROOT" >/dev/null

echo "==> pushing to $REG"
for i in secureops-app secureops-worker secureops-web; do
  docker push -q "$REG/$i:dev" >/dev/null
done

# Read the digest the registry actually stored.
digest_of() {
  docker inspect --format '{{index .RepoDigests 0}}' "$REG/$1:dev" | sed 's/.*@//'
}
API_DIGEST="$(digest_of secureops-app)"
WORKER_DIGEST="$(digest_of secureops-worker)"
WEB_DIGEST="$(digest_of secureops-web)"

# The dependencies come from Docker Hub, so their digests are whatever the
# registry serves for the tag this project already uses in compose. Resolved
# here rather than pinned in values.yaml because a chart that hardcoded one
# would go stale silently; a deployment pins them in ITS values file.
echo "==> resolving dependency digests"
docker pull -q postgres:17-alpine >/dev/null
docker pull -q redis:8-alpine >/dev/null
PG_DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' postgres:17-alpine | sed 's/.*@//')"
REDIS_DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' redis:8-alpine | sed 's/.*@//')"

echo "    api      $API_DIGEST"
echo "    worker   $WORKER_DIGEST"
echo "    web      $WEB_DIGEST"
echo "    postgres $PG_DIGEST"
echo "    redis    $REDIS_DIGEST"

# Development credentials, generated per deploy. Never a fixed string: a
# password committed to a script is a password (§15.1), even a local one.
#
# Read a finite chunk and slice it, rather than the obvious
# `tr -dc ... </dev/urandom | head -c 40`. That form makes `head` exit while
# `tr` is still writing, `tr` takes SIGPIPE, and `set -o pipefail` then kills
# this script -- silently, right before the install. Found by running it.
gen() {
  local s=""
  while [ "${#s}" -lt 40 ]; do
    s="${s}$(head -c 256 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  done
  printf '%s' "${s:0:40}"
}
PG_PASS="$(gen)"; REDIS_PASS="$(gen)"
ADMIN_SECRET="$(gen)"; DASH_SECRET="$(gen)"

# A values FILE rather than --set, for two reasons. `--set` splits on commas,
# and the token list is comma-separated -- so a second token silently became a
# malformed key. And a credential passed as an argument is visible in `ps`,
# which is the same objection the CI client already makes to a --token flag
# (ADR 036). The file is created 0600 and removed on exit.
VALUES="$(mktemp)"
chmod 600 "$VALUES"
trap 'rm -f "$VALUES"' EXIT

cat > "$VALUES" <<EOF
images:
  api:      { repository: "$REG/secureops-app",    digest: "$API_DIGEST" }
  worker:   { repository: "$REG/secureops-worker", digest: "$WORKER_DIGEST" }
  web:      { repository: "$REG/secureops-web",    digest: "$WEB_DIGEST" }
  postgres: { digest: "$PG_DIGEST" }
  redis:    { digest: "$REDIS_DIGEST" }
secrets:
  postgresPassword: "$PG_PASS"
  redisPassword: "$REDIS_PASS"
  apiTokens: "local:admin:*:${ADMIN_SECRET},dash:service:*:${DASH_SECRET}"
  dashboardToken: "$DASH_SECRET"
config:
  env: development
api:
  replicas: 1
web:
  replicas: 1
postgres:
  storage: 2Gi
worker:
  caches:
    storage: 4Gi
EOF

echo "==> installing release '$RELEASE' into namespace '$NS'"
helm upgrade --install "$RELEASE" "$ROOT/deployments/kubernetes/secureops" \
  --kube-context "$CTX" \
  --namespace "$NS" --create-namespace \
  -f "$VALUES" \
  --wait --timeout 10m

cat <<EOF

Installed. The admin token for this deployment is:

  local:admin:*:${ADMIN_SECRET}

Reach the API without exposing it:

  kubectl -n ${NS} port-forward svc/${RELEASE}-secureops-api 8080:8080

EOF
