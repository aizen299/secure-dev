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

# Not -q. These builds make four network fetches for the scan job's data, and
# -q swallows the step output -- so a failure leaves only the failing
# instruction and no reason, which cost a diagnosis once already.
echo "==> building images"
docker build -f "$ROOT/deployments/docker/api.Dockerfile"    -t "$REG/secureops-app:dev"    "$ROOT" >/dev/null
docker build --target worker -f "$ROOT/deployments/docker/worker.Dockerfile" -t "$REG/secureops-worker:dev" "$ROOT" >/dev/null
docker build -f "$ROOT/deployments/docker/web.Dockerfile"    -t "$REG/secureops-web:dev"    "$ROOT" >/dev/null
# The scan job carries the scanners' provisioned data (ADR 040), so it is a
# build TARGET of the worker Dockerfile rather than a file of its own -- the
# scanner builds above it must not be duplicated.
docker build --target scanjob \
  --build-arg SCANNER_DATA_BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -f "$ROOT/deployments/docker/worker.Dockerfile" -t "$REG/secureops-scanjob:dev" "$ROOT" >/dev/null

echo "==> pushing to $REG"
for i in secureops-app secureops-worker secureops-web secureops-scanjob; do
  docker push -q "$REG/$i:dev" >/dev/null
done

# Read the digest the registry actually stored.
digest_of() {
  docker inspect --format '{{index .RepoDigests 0}}' "$REG/$1:dev" | sed 's/.*@//'
}
API_DIGEST="$(digest_of secureops-app)"
WORKER_DIGEST="$(digest_of secureops-worker)"
WEB_DIGEST="$(digest_of secureops-web)"
SCANJOB_DIGEST="$(digest_of secureops-scanjob)"

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
echo "    scanjob  $SCANJOB_DIGEST"
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

# Reuse the credentials the release already has, if it has any.
#
# Generating fresh ones on every deploy looks harmless and is not: PostgreSQL's
# volume survives an upgrade and initdb only sets the password on FIRST init,
# so the Secret rotates, the database does not, and every pod crash-loops on
# "password authentication failed". Found by redeploying, which is the only way
# to find it -- a first install works perfectly.
existing() {
  kubectl --context "$CTX" -n "$NS" get secret "$RELEASE-secureops-secrets" \
    -o "jsonpath={.data.$1}" 2>/dev/null | base64 -d 2>/dev/null || true
}
PG_PASS="$(existing postgres-password)"; [ -n "$PG_PASS" ] || PG_PASS="$(gen)"
REDIS_PASS="$(existing redis-password)"; [ -n "$REDIS_PASS" ] || REDIS_PASS="$(gen)"
DASH_SECRET="$(existing dashboard-token)"; [ -n "$DASH_SECRET" ] || DASH_SECRET="$(gen)"

# The admin token is the third field of the first entry, when one exists.
ADMIN_SECRET="$(existing api-tokens | sed -n 's/^local:admin:\*:\([^,]*\).*/\1/p')"
[ -n "$ADMIN_SECRET" ] || ADMIN_SECRET="$(gen)"

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
  scanjob:  { repository: "$REG/secureops-scanjob", digest: "$SCANJOB_DIGEST" }
  postgres: { digest: "$PG_DIGEST" }
  redis:    { digest: "$REDIS_DIGEST" }
secrets:
  postgresPassword: "$PG_PASS"
  redisPassword: "$REDIS_PASS"
  apiTokens: "local:admin:*:${ADMIN_SECRET},dash:service:*:${DASH_SECRET}"
  dashboardToken: "$DASH_SECRET"
config:
  env: development
# Each scan in its own pod, holding nothing (ADR 039).
#
# vulnDB stays OFF here: it needs a multi-reader volume, and kind's default
# storage class (local-path) offers only ReadWriteOnce. Grype therefore
# degrades on every scan in this cluster, loudly, which is the behaviour a
# deployment without that storage should see -- and worth watching rather than
# papering over.
scanJobs:
  enabled: true
  workspaceSize: 2Gi
  dataInImage: true
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
