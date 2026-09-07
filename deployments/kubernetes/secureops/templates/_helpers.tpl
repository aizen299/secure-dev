{{/*
Chart helpers. The interesting one is `secureops.image`, which is a security
control rather than a convenience.
*/}}

{{- define "secureops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "secureops.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "secureops.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "secureops.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "secureops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: secureops
{{- end }}

{{- define "secureops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secureops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
secureops.image renders `repository@sha256:...` and REFUSES a tag.

This is the control that closes T-10, the project's only Open threat, so it is
enforced in the template rather than documented in a comment. The scanner
binaries inside the worker image are already built from source at pinned commit
SHAs (ADR 009, T-28); a digest is what carries that pin into the cluster. A tag
can be repointed at different bytes after review, which is the same objection
this project already made to tags in its Dockerfiles.

`required` fails the render. There is deliberately no `allowTags` escape hatch:
an escape hatch is how a control becomes optional, and local development
satisfies this honestly by pushing to a registry beside the kind cluster rather
than by switching it off (§15.12).

Usage: {{ include "secureops.image" (dict "img" .Values.images.api) }}
*/}}
{{- define "secureops.image" -}}
{{- $img := .img -}}
{{- $digest := required "every image needs an explicit digest: set images.<name>.digest to a sha256:... value. A tag does not pin which scanner binaries run (threat model T-10)." $img.digest -}}
{{- if not (hasPrefix "sha256:" $digest) -}}
{{- fail (printf "image digest %q must start with 'sha256:' — a tag is not a digest" $digest) -}}
{{- end -}}
{{- printf "%s@%s" (required "images.<name>.repository is required" $img.repository) $digest -}}
{{- end }}

{{/*
The Secret holding every credential, either created by this chart or supplied
out of band. Nothing is defaulted: see values.yaml.
*/}}
{{- define "secureops.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "secureops.fullname" .) -}}
{{- end -}}
{{- end }}

{{- define "secureops.postgresHost" -}}
{{- printf "%s-postgres" (include "secureops.fullname" .) -}}
{{- end }}

{{- define "secureops.redisHost" -}}
{{- printf "%s-redis" (include "secureops.fullname" .) -}}
{{- end }}

{{/*
Database and Redis URLs are assembled in the container from the password held
in a Secret, never templated into a ConfigMap or an env var value that would
appear in `kubectl get deploy -o yaml` and in every audit of it.
*/}}
{{- define "secureops.envCredentials" -}}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "secureops.secretName" . }}
      key: postgres-password
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "secureops.secretName" . }}
      key: redis-password
- name: SECUREOPS_DATABASE_URL
  value: "postgres://{{ .Values.postgres.user }}:$(POSTGRES_PASSWORD)@{{ include "secureops.postgresHost" . }}:5432/{{ .Values.postgres.database }}?sslmode=disable"
- name: SECUREOPS_REDIS_URL
  value: "redis://:$(REDIS_PASSWORD)@{{ include "secureops.redisHost" . }}:6379/0"
{{- end }}

{{- define "secureops.envCommon" -}}
- name: SECUREOPS_ENV
  value: {{ .Values.config.env | quote }}
- name: SECUREOPS_LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: SECUREOPS_LOG_FORMAT
  value: {{ .Values.config.logFormat | quote }}
- name: SECUREOPS_ALLOW_PRIVATE_TARGETS
  value: {{ .Values.config.allowPrivateTargets | quote }}
{{- end }}

{{/*
secureops.migrateInit runs migrations before the container that needs them.

This was a pre-install hook Job first, and that was wrong twice over -- both
found by deploying it rather than by reading it. Helm runs pre-install hooks
BEFORE every normal resource, so the Job started before the Secret holding its
credentials existed, and then, once that was fixed, before PostgreSQL existed
at all. A hook cannot depend on the release it precedes.

The objection to an initContainer was that two API replicas would migrate
concurrently. That objection was wrong: golang-migrate's postgres driver takes
`SELECT pg_advisory_lock($1)` around the migration -- checked in v4.19.1, the
version in go.mod, not assumed -- so concurrent runners serialise and the
losers find nothing to do. Concurrency is what this is designed for.

It also gives the dependency ordering for free: a pod cannot start until its
migration has connected to PostgreSQL and finished.

The API IMAGE, in the worker's pod: the migrate binary and the SQL live there,
and the worker image must never carry anything the API needs (§14.1) any more
than the reverse.
*/}}
{{- define "secureops.migrateInit" -}}
- name: migrate
  image: {{ include "secureops.image" (dict "img" .Values.images.api) }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  securityContext:
    {{- toYaml .Values.containerSecurityContext | nindent 4 }}
  command: ["/usr/local/bin/migrate", "-dir", "/migrations", "up"]
  env:
    {{- include "secureops.envCredentials" . | nindent 4 }}
  resources:
    requests: { cpu: 50m, memory: 64Mi }
    limits:   { cpu: 500m, memory: 256Mi }
  volumeMounts:
    - name: tmp
      mountPath: /tmp
{{- end }}
