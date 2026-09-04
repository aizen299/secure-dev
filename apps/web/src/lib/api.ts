/**
 * Typed client for the SecureOps API.
 *
 * Two rules govern this file.
 *
 * **Boundary (CLAUDE.md §18, §25.4).** The frontend consumes SecureOps domain
 * models only. Raw scanner JSON never appears here or anywhere downstream, and
 * no component may branch on which scanner produced a result. Every type below
 * mirrors a schema in docs/api/openapi.yaml; if one drifts, the spec is right.
 *
 * **Server-only (§15.4).** This module is imported exclusively by Server
 * Components and route handlers. The API credential is read from the server
 * environment and never reaches the browser -- there is no client-side fetch to
 * the API anywhere in this app, which is why no token is ever serialised into a
 * page payload. The `server-only` guard below turns a mistaken client import
 * into a build error rather than a credential leak.
 */
import "server-only";
import { sessionToken } from "./guard";

// --- primitives ------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type FindingStatus =
  | "open"
  | "acknowledged"
  | "in_progress"
  | "resolved"
  | "reopened"
  | "false_positive"
  | "ignored";
export type ScanStatus =
  | "queued"
  | "running"
  | "partial"
  | "completed"
  | "failed"
  | "cancelled";
export type Environment = "development" | "staging" | "production";
export type Criticality = "low" | "medium" | "high" | "critical";
export type TargetKind = "repository" | "image" | "endpoint";
export type Verdict = "pass" | "warn" | "fail";

export interface Pagination {
  limit: number;
  offset: number;
  has_more: boolean;
}

// --- projects --------------------------------------------------------------

export interface Project {
  id: string;
  name: string;
  slug: string;
  description?: string;
  environment: Environment;
  criticality: Criticality;
  internet_facing: boolean;
  created_at: string;
  updated_at: string;
}

export interface ProjectList {
  data: Project[];
  pagination: Pagination;
}

// --- scans -----------------------------------------------------------------

export interface Target {
  kind: TargetKind;
  repository_url?: string;
  ref?: string;
  path?: string;
  image?: string;
  endpoint_url?: string;
}

export interface ScannerResult {
  scanner: string;
  status: string;
  version?: string;
  exit_code?: number;
  duration_ms?: number;
  error?: string;
  degradations?: string[];
  started_at?: string;
}

export interface Scan {
  id: string;
  project_id: string;
  repository_id?: string;
  status: ScanStatus;
  target: Target;
  commit_sha?: string;
  branch?: string;
  requested_scanners?: string[];
  complete_coverage: boolean;
  degraded_scanners?: string[];
  failure_reason?: string;
  results?: ScannerResult[];
  queued_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface ScanList {
  data: Scan[];
  pagination: Pagination;
}

// --- findings --------------------------------------------------------------

export interface EPSS {
  probability: number;
  percentile: number;
  source: string;
  observed_at: string;
}

/**
 * Absent entirely when no signal is available, so a client cannot read a zero
 * and conclude "not exploited". Absence has to be handled as absence (ADR 018).
 */
export interface ThreatIntel {
  epss?: EPSS;
}

export interface Finding {
  id: string;
  fingerprint: string;
  category: string;
  severity: Severity;
  confidence: string;
  status: FindingStatus;
  title: string;
  description?: string;
  remediation?: string;
  scanner: string;
  sources?: string[];
  scanner_severity?: string;
  package?: string;
  package_version?: string;
  purl?: string;
  /** Container findings only: the image repository, never a tag (ADR 025). */
  image?: string;
  /** DAST findings only: method and path, never an origin (ADR 026). */
  endpoint?: string;
  cve?: string;
  cwe?: string;
  cvss?: number;
  threat?: ThreatIntel;
  occurrences: number;
  first_seen: string;
  last_seen: string;
}

export interface FindingList {
  findings: Finding[];
  has_more: boolean;
}

// --- issues ----------------------------------------------------------------

export interface IssueMember {
  finding_id: string;
  fingerprint: string;
  scanner: string;
  severity: Severity;
  title: string;
  evidence: string;
}

export interface Issue {
  id: string;
  key_kind: "cve" | "purl" | "file";
  key_value: string;
  severity: Severity;
  escalated: boolean;
  categories: string[];
  explanation: string;
  members: IssueMember[];
}

export interface IssueList {
  issues: Issue[];
  has_more: boolean;
}

// --- risk ------------------------------------------------------------------

export interface RiskPoint {
  scan_id: string;
  score: number;
  total: number;
  live_findings: number;
  scan_status: ScanStatus;
  complete: boolean;
  weights_digest: string;
  computed_at: string;
}

export interface Risk {
  score: number;
  total: number;
  live_findings: number;
  dismissed_findings: number;
  scan_id: string;
  scan_status: ScanStatus;
  /** False when the scan that produced this score had degraded coverage. */
  complete: boolean;
  computed_at: string;
  weights_digest: string;
  history?: RiskPoint[];
}

// --- remediation -----------------------------------------------------------

export interface RemediationStatement {
  /** "vendor" | "scanner" | "ai_explanation" -- never conflated (§11). */
  source: string;
  text: string;
}

export interface RemediationMember {
  fingerprint: string;
  scanner: string;
  severity: Severity;
  title: string;
  risk: number;
}

export interface RemediationAction {
  kind: string;
  key: string;
  component?: string;
  fixed_versions?: string[];
  references?: string[];
  /** Ranked by this: the risk the project sheds if this action is taken. */
  risk_removed: number;
  score_after: number;
  statements?: RemediationStatement[];
  members: RemediationMember[];
}

export interface RemediationPlan {
  score: number;
  addressable_findings: number;
  actions: RemediationAction[];
}

// --- policy and gate -------------------------------------------------------

export interface PolicyRule {
  kind: string;
  selector?: string;
  max: number;
  level: string;
}

export interface Policy {
  rules: PolicyRule[];
  incomplete_scan: string;
}

export interface GateCondition {
  kind: string;
  selector?: string;
  max: number;
  level: string;
  observed: number;
  breached: boolean;
  explanation: string;
}

export interface GateCoverage {
  complete: boolean;
  scan_status: ScanStatus;
  /** True when a PARTIAL scan downgraded the verdict (§12). */
  downgraded: boolean;
}

export interface GateResult {
  verdict: Verdict;
  conditions: GateCondition[];
  coverage: GateCoverage;
  summary: string;
  scan_id: string;
  evaluated_at: string;
}

// --- transitions -----------------------------------------------------------

export interface Transition {
  finding_id: string;
  from_status?: FindingStatus;
  to_status: FindingStatus;
  actor: string;
  reason: string;
  note?: string;
  changed_at: string;
}

export interface TransitionHistory {
  transitions: Transition[];
}

// --- health ----------------------------------------------------------------

export interface DependencyState {
  name: string;
  status: string;
  error?: string;
}

export interface ReadinessResponse {
  status: string;
  dependencies: DependencyState[];
}

// --- transport -------------------------------------------------------------

export interface ErrorEnvelope {
  error: { code: string; message: string; request_id?: string };
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }

  /** True when the resource is simply absent, which pages render as an empty
   *  state rather than as a failure. */
  get isNotFound() {
    return this.status === 404;
  }

  /** True when the dashboard's own credential was rejected. Distinct from a
   *  missing resource: this is a deployment problem, not a data one. */
  get isUnauthorized() {
    return this.status === 401 || this.status === 403;
  }
}

function apiBaseUrl(): string {
  return process.env.SECUREOPS_API_URL ?? "http://localhost:8090";
}

/**
 * The dashboard's own credential.
 *
 * A `service` token since ADR 029: enough to create projects and submit scans,
 * and deliberately not `admin`, so the dashboard still cannot edit the policy
 * that judges those scans (ADR 023). Dismissing findings stays out of reach
 * for the reason ADR 027 gives -- a judgement recorded against "the dashboard"
 * names nobody.
 *
 * A `viewer` token still works for a deployment that wants the read-only
 * behaviour; scan submission then fails with a clear 403 rather than silently
 * doing nothing.
 */
function apiToken(): string | undefined {
  const token = process.env.SECUREOPS_API_TOKEN;
  return token && token.trim() !== "" ? token.trim() : undefined;
}

/**
 * Signs a person in against the API.
 *
 * Uses the dashboard's own credential for the request itself, because the
 * caller has none yet -- that is what they are asking for. The API's login
 * endpoint is outside its authentication gate, so the header is incidental
 * here; it is sent only so this shares one request path with everything else.
 *
 * Returns a reason rather than an error message. Every failure the API can
 * report is the same 401, and narrowing it in the dashboard would tell somebody
 * which addresses are registered -- exactly what the API refuses to say.
 */
export async function login(
  email: string,
  password: string,
): Promise<{ ok: true; token: string } | { ok: false; reason: "invalid" | "unconfigured" | "unreachable" }> {
  try {
    const response = await fetch(`${apiBaseUrl()}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
      cache: "no-store",
    });

    if (response.status === 501) return { ok: false, reason: "unconfigured" };
    if (!response.ok) return { ok: false, reason: "invalid" };

    const body = (await response.json()) as { token?: string };
    if (!body.token) return { ok: false, reason: "invalid" };
    return { ok: true, token: body.token };
  } catch {
    return { ok: false, reason: "unreachable" };
  }
}

export class MissingCredentialError extends Error {
  constructor() {
    super("SECUREOPS_API_TOKEN is not configured");
    this.name = "MissingCredentialError";
  }
}

interface RequestOptions {
  /** Seconds to cache. Zero means never, which is the default for anything
   *  that reflects live security state. */
  revalidate?: number;
  /** Endpoints that do not require a credential (the probes). */
  anonymous?: boolean;
  /** Defaults to GET. */
  method?: "GET" | "POST" | "PUT";
  /** JSON body, for the two writes the dashboard performs. */
  body?: unknown;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };

  if (!opts.anonymous) {
    // A person's session in preference to the dashboard's own credential
    // (ADR 033 §5a). This is the line that makes identity mean anything: with
    // the dashboard's `*`-scoped token, a viewer would read the whole estate
    // and the audit trail would name the dashboard rather than them.
    //
    // The dashboard's credential remains the fallback, for the reads that
    // happen before anyone signs in.
    const token = (await sessionToken()) ?? apiToken();
    if (!token) throw new MissingCredentialError();
    headers.Authorization = `Bearer ${token}`;
  }

  if (opts.body !== undefined) headers["Content-Type"] = "application/json";

  const response = await fetch(`${apiBaseUrl()}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    // Security state is never served stale by default. A page that renders a
    // cached PASS after a FAIL landed is worse than a slow page.
    cache: opts.revalidate ? undefined : "no-store",
    next: opts.revalidate ? { revalidate: opts.revalidate } : undefined,
  });

  if (!response.ok) {
    let code = "unknown_error";
    let message = `request failed with status ${response.status}`;
    let requestId: string | undefined;
    try {
      const body = (await response.json()) as ErrorEnvelope;
      code = body.error.code;
      message = body.error.message;
      requestId = body.error.request_id;
    } catch {
      // A non-JSON error body is itself the diagnostic; keep the defaults.
    }
    throw new ApiError(response.status, code, message, requestId);
  }

  return (await response.json()) as T;
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
}

// --- operations ------------------------------------------------------------

export const getReadiness = () =>
  request<ReadinessResponse>("/readyz", { anonymous: true });

export const listProjects = (params: { limit?: number; offset?: number } = {}) =>
  request<ProjectList>(`/api/v1/projects${query(params)}`);

export const getProject = (id: string) =>
  request<Project>(`/api/v1/projects/${encodeURIComponent(id)}`);

export const listProjectScans = (
  id: string,
  params: { limit?: number; offset?: number } = {},
) => request<ScanList>(`/api/v1/projects/${encodeURIComponent(id)}/scans${query(params)}`);

export const listProjectFindings = (
  id: string,
  params: { limit?: number; offset?: number; severity?: string; status?: string; scanner?: string } = {},
) =>
  request<FindingList>(
    `/api/v1/projects/${encodeURIComponent(id)}/findings${query(params)}`,
  );

export const listProjectIssues = (
  id: string,
  params: { limit?: number; offset?: number } = {},
) => request<IssueList>(`/api/v1/projects/${encodeURIComponent(id)}/issues${query(params)}`);

/**
 * A project's current score, optionally with the scores before it.
 *
 * `history` asks the API for the previous scores of the same project, which is
 * the only source of a real trend on this dashboard -- there is no separate
 * metrics store, and a delta computed from anything else would be invented.
 */
export const getProjectRisk = (id: string, params: { history?: number } = {}) =>
  request<Risk>(`/api/v1/projects/${encodeURIComponent(id)}/risk${query(params)}`);

export const getProjectRemediation = (id: string) =>
  request<RemediationPlan>(`/api/v1/projects/${encodeURIComponent(id)}/remediation`);

export const getProjectPolicy = (id: string) =>
  request<Policy>(`/api/v1/projects/${encodeURIComponent(id)}/policy`);

export const getScan = (id: string) =>
  request<Scan>(`/api/v1/scans/${encodeURIComponent(id)}`);

export const listScanFindings = (
  id: string,
  params: { limit?: number; offset?: number } = {},
) => request<FindingList>(`/api/v1/scans/${encodeURIComponent(id)}/findings${query(params)}`);

export const getScanGate = (id: string) =>
  request<GateResult>(`/api/v1/scans/${encodeURIComponent(id)}/gate`);

export interface CreateProjectInput {
  name: string;
  slug: string;
  description?: string;
  environment?: Environment;
  criticality?: Criticality;
  internet_facing?: boolean;
}

export interface CreateScanInput {
  project_id: string;
  target: { kind: TargetKind; repository_url?: string; ref?: string; image?: string; endpoint_url?: string };
  branch?: string;
  commit_sha?: string;
  scanners?: string[];
}

/**
 * The two writes the dashboard performs, and the only two.
 *
 * Both are additive: they ask for work and reveal state. Nothing here changes
 * a security judgement -- no policy edit, no finding dismissal -- because those
 * would be recorded against the dashboard rather than a person (ADR 029).
 */
export const createProject = (input: CreateProjectInput) =>
  request<Project>("/api/v1/projects", { method: "POST", body: input });

/**
 * Asks the API whether a target would be accepted, before anything is created.
 *
 * Read-only on the API side: it creates nothing and enqueues nothing (ADR 032).
 * This is not a second copy of the address policy -- it is the same code path
 * the scan handler runs, reached earlier, which is the whole reason to call an
 * endpoint rather than shape-check the URL here.
 */
export const validateTarget = (target: CreateScanInput["target"]) =>
  request<{ target: CreateScanInput["target"] }>("/api/v1/targets/validate", {
    method: "POST",
    body: { target },
  });

export const createScan = (input: CreateScanInput) =>
  request<Scan>("/api/v1/scans", { method: "POST", body: input });

export const getFindingHistory = (id: string) =>
  request<TransitionHistory>(`/api/v1/findings/${encodeURIComponent(id)}/history`);

/** The API's maximum page size. Asking for more is a 400, not a larger page. */
export const MAX_PAGE = 100;

/**
 * Reads up to `maxPages` pages and reports whether more remained.
 *
 * The alternative -- ask for one page and treat it as the whole -- produces a
 * severity distribution that silently describes the first hundred findings
 * while looking like it describes the project. A bound is still a bound, so
 * `truncated` is returned rather than hidden, and the caller says so on screen.
 */
export async function collect<T>(
  page: (limit: number, offset: number) => Promise<{ items: T[]; hasMore: boolean }>,
  maxPages = 10,
): Promise<{ items: T[]; truncated: boolean }> {
  const items: T[] = [];
  for (let i = 0; i < maxPages; i++) {
    const { items: batch, hasMore } = await page(MAX_PAGE, i * MAX_PAGE);
    items.push(...batch);
    if (!hasMore) return { items, truncated: false };
  }
  return { items, truncated: true };
}

/**
 * Runs a loader and converts an expected absence into `null`.
 *
 * A project with no scans has no risk score, and that is a normal state rather
 * than an error -- the dashboard renders an empty state for it. Anything that
 * is not a 404 still throws, because a broken API must not render as an empty
 * project.
 */
export async function optional<T>(load: () => Promise<T>): Promise<T | null> {
  try {
    return await load();
  } catch (error) {
    if (error instanceof ApiError && error.isNotFound) return null;
    throw error;
  }
}
