package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Pagination bounds. Every list endpoint is paginated (§18): an unbounded list
// endpoint is a denial-of-service primitive as soon as the table is large.
const (
	DefaultPageLimit = 25
	MaxPageLimit     = 100
)

// uuidPattern validates a path parameter before it reaches the database.
//
// Without this, a malformed ID reaches pgx, which rejects it as invalid uuid
// syntax, and a client's typo becomes a 500. Validating here makes it the 400
// it actually is. A regexp avoids adding a UUID dependency for one check.
var uuidPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// errBadRequest carries a client-safe validation message.
type errBadRequest struct {
	code    ErrorCode
	status  int
	message string
}

func (e errBadRequest) Error() string { return e.message }

func badRequest(message string) error {
	return errBadRequest{code: CodeInvalidRequest, status: http.StatusBadRequest, message: message}
}

// decodeJSON reads and validates a JSON request body.
//
// Three bounds are applied before any parsing happens, because the body is
// attacker-controlled (§15.7, §15.8): the content type must be JSON, the body
// is hard-capped by MaxBytesReader, and unknown fields are refused so a typo
// in a field name fails loudly instead of being silently ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if err := requireJSONContentType(r); err != nil {
		return err
	}

	// MaxBytesReader also caps what the server will read from the socket, so
	// an oversized body is not buffered before being rejected.
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err, maxBytes)
	}

	// A second value in the stream means the client sent something other than
	// one JSON document, which is never what a correct client does.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return badRequest("request body must contain exactly one JSON object")
	}
	return nil
}

func requireJSONContentType(r *http.Request) error {
	raw := r.Header.Get("Content-Type")
	if raw == "" {
		return errBadRequest{
			code:    CodeUnsupportedMedia,
			status:  http.StatusUnsupportedMediaType,
			message: "Content-Type must be application/json",
		}
	}

	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errBadRequest{
			code:    CodeUnsupportedMedia,
			status:  http.StatusUnsupportedMediaType,
			message: "Content-Type must be application/json",
		}
	}
	return nil
}

// decodeError converts a decoder failure into a client-safe message.
//
// The underlying error is deliberately not surfaced: json.SyntaxError and
// friends quote the offending input, which would echo attacker-controlled
// bytes back to the caller and into the logs.
func decodeError(err error, maxBytes int64) error {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return errBadRequest{
			code:    CodePayloadTooLarge,
			status:  http.StatusRequestEntityTooLarge,
			message: fmt.Sprintf("request body must not exceed %d bytes", maxBytes),
		}
	}

	var unmarshalErr *json.UnmarshalTypeError
	if errors.As(err, &unmarshalErr) {
		// Only the field name is echoed, and only when it matches a field the
		// server declared, so nothing attacker-controlled reaches the client.
		return badRequest(fmt.Sprintf("field %q has the wrong type", unmarshalErr.Field))
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return badRequest("request body is not valid JSON")
	}

	if errors.Is(err, io.EOF) {
		return badRequest("request body is required")
	}

	// DisallowUnknownFields produces a plain error whose text names the field.
	// The name comes from the client, so it is not repeated back.
	if strings.HasPrefix(err.Error(), "json: unknown field") {
		return badRequest("request body contains an unrecognised field")
	}

	return badRequest("request body could not be parsed")
}

// pageFrom reads limit and offset from the query string.
func pageFrom(r *http.Request) (limit, offset int, err error) {
	limit, err = intQuery(r, "limit", DefaultPageLimit)
	if err != nil {
		return 0, 0, err
	}
	if limit < 1 {
		return 0, 0, badRequest("limit must be at least 1")
	}
	if limit > MaxPageLimit {
		// Clamping silently would mislead a client into thinking it had the
		// whole page. Rejecting says what the bound is.
		return 0, 0, badRequest(fmt.Sprintf("limit must not exceed %d", MaxPageLimit))
	}

	offset, err = intQuery(r, "offset", 0)
	if err != nil {
		return 0, 0, err
	}
	if offset < 0 {
		return 0, 0, badRequest("offset must not be negative")
	}
	return limit, offset, nil
}

func intQuery(r *http.Request, key string, fallback int) (int, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, badRequest(fmt.Sprintf("%s must be an integer", key))
	}
	return n, nil
}

// isUUID reports whether v is a syntactically valid UUID.
func isUUID(v string) bool { return uuidPattern.MatchString(v) }

// pathUUID reads and validates a UUID path parameter.
func pathUUID(r *http.Request, name string) (string, error) {
	value := chi.URLParam(r, name)
	if value == "" {
		return "", badRequest(fmt.Sprintf("%s is required", name))
	}
	if !isUUID(value) {
		// The value is not echoed: it is attacker-controlled and reaches logs.
		return "", badRequest(fmt.Sprintf("%s must be a UUID", name))
	}
	return value, nil
}

// Pagination is the page metadata returned with every list response.
type Pagination struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}

// listResponse is the envelope every list endpoint returns, so a client can
// page through any collection with the same code.
type listResponse[T any] struct {
	Data       []T        `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// writeListResponse serialises a page of results.
//
// data is normalised to an empty slice so an empty page encodes as [] rather
// than null, which a typed client would otherwise have to special-case.
func writeListResponse[T any](
	w http.ResponseWriter, r *http.Request, data []T, limit, offset int, hasMore bool,
) {
	if data == nil {
		data = []T{}
	}
	writeJSON(w, r, http.StatusOK, listResponse[T]{
		Data:       data,
		Pagination: Pagination{Limit: limit, Offset: offset, HasMore: hasMore},
	})
}

// writeRequestError renders a validation failure, falling back to a generic
// 400 for any error that did not carry a client-safe message.
func writeRequestError(w http.ResponseWriter, r *http.Request, err error) {
	var bad errBadRequest
	if errors.As(err, &bad) {
		writeError(w, r, bad.status, bad.code, bad.message)
		return
	}
	writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "request could not be processed")
}
