// Package httpapi implements the SecureOps HTTP surface.
//
// Boundary rule (CLAUDE.md §14.1): this package validates input, reads and
// writes persisted state, and enqueues jobs. It never executes scanners, builds,
// package managers, or any other untrusted target content.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorCode is a stable, machine-readable error identifier. CI clients and the
// dashboard branch on these, so they are part of the API contract (§18).
type ErrorCode string

const (
	CodeNotFound      ErrorCode = "not_found"
	CodeMethodInvalid ErrorCode = "method_not_allowed"
	CodeInternal      ErrorCode = "internal_error"
	CodeUnavailable   ErrorCode = "service_unavailable"
)

// ErrorEnvelope is the single error shape returned by every endpoint.
type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody carries the details of a failure.
type ErrorBody struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id,omitempty"`
}

// writeJSON serialises v as the response body.
func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already sent, so this can only be logged.
		loggerFrom(r.Context()).Error("encode response body", slog.String("error", err.Error()))
	}
}

// writeError responds with the standard error envelope. The message must be a
// fixed, non-sensitive string: internal failure detail stays in the logs.
func writeError(w http.ResponseWriter, r *http.Request, status int, code ErrorCode, message string) {
	writeJSON(w, r, status, ErrorEnvelope{Error: ErrorBody{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFrom(r.Context()),
	}})
}
