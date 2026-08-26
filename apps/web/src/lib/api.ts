/**
 * Typed client for the SecureOps API.
 *
 * Boundary rule (CLAUDE.md §18): the frontend consumes SecureOps domain models
 * only. Raw scanner JSON never appears in this file or anywhere downstream of
 * it, and no component may branch on which scanner produced a result.
 */

/** Mirrors httpapi.LivenessResponse. */
export interface LivenessResponse {
  status: string;
  service: string;
  version: string;
}

/** Mirrors httpapi.DependencyState. */
export interface DependencyState {
  name: string;
  status: string;
  error?: string;
}

/** Mirrors httpapi.ReadinessResponse. */
export interface ReadinessResponse {
  status: string;
  dependencies: DependencyState[];
}

/** Mirrors httpapi.ErrorEnvelope. */
export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    request_id?: string;
  };
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
}

function apiBaseUrl(): string {
  return process.env.SECUREOPS_API_URL ?? "http://localhost:8080";
}

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
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

export function getLiveness(): Promise<LivenessResponse> {
  return request<LivenessResponse>("/healthz");
}

export function getReadiness(): Promise<ReadinessResponse> {
  return request<ReadinessResponse>("/readyz");
}
