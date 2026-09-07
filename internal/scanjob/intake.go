package scanjob

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"

	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Intake receives what a Job reports and hands it to the controller.
//
// This is a listening surface on a component that previously listened on
// nothing, and the thing it listens to is the least trusted process in the
// system. So it is written the way the API is (§15.7, §15.8): bounded before a
// body is read, authenticated in constant time, scoped to one scan, and silent
// about why a request was refused.
type Intake struct {
	Limits Limits
	Logger *slog.Logger

	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	// tokenHash, never the token. The controller compares digests for the same
	// reason the API does: a credential at rest in memory is one core dump from
	// being a credential in a file.
	tokenHash [32]byte
	events    scanexec.Events
}

// NewIntake builds an Intake.
func NewIntake(limits Limits, logger *slog.Logger) *Intake {
	if logger == nil {
		logger = slog.Default()
	}
	return &Intake{Limits: limits, Logger: logger, sessions: map[string]*session{}}
}

// Open authorises one scan to report, and returns the token it must present.
//
// The token is generated here and handed to the Job, so it exists for exactly
// as long as the scan does. There is no standing credential to leak, rotate, or
// forget to revoke -- Close destroys it.
func (i *Intake) Open(scanID string, ev scanexec.Events) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)

	i.mu.Lock()
	defer i.mu.Unlock()
	i.sessions[scanID] = &session{tokenHash: sha256.Sum256([]byte(token)), events: ev}
	return token, nil
}

// Close revokes a scan's token. Safe to call more than once.
func (i *Intake) Close(scanID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.sessions, scanID)
}

// Handler routes the two endpoints a Job posts to.
func (i *Intake) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathCheckout, i.handleCheckout)
	mux.HandleFunc("POST "+PathResult, i.handleResult)
	return mux
}

// authorize resolves the reporting scan, or refuses.
//
// Every refusal is 401 with no body. A 403 or a distinct message would tell a
// caller whether the scan id exists, which turns this into an oracle for what
// the controller is running.
func (i *Intake) authorize(w http.ResponseWriter, r *http.Request) (*session, bool) {
	scanID := r.Header.Get(HeaderScanID)
	token, ok := bearer(r)
	if scanID == "" || !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}

	i.mu.RLock()
	s, known := i.sessions[scanID]
	i.mu.RUnlock()

	got := sha256.Sum256([]byte(token))
	// The digest is compared even when the scan is unknown, against a zero
	// value, so an unknown scan and a bad token take the same time. Without
	// this, timing distinguishes "no such scan" from "wrong token".
	var want [32]byte
	if known {
		want = s.tokenHash
	}
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 || !known {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	return s, true
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return h[len(prefix):], true
}

func (i *Intake) handleCheckout(w http.ResponseWriter, r *http.Request) {
	s, ok := i.authorize(w, r)
	if !ok {
		return
	}

	var c Checkout
	// Bounded before it is decoded, not after.
	dec := json.NewDecoder(io.LimitReader(r.Body, i.Limits.MaxMetaBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.events.Checkout != nil {
		s.events.Checkout(c.CommitSHA, c.Branch)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (i *Intake) handleResult(w http.ResponseWriter, r *http.Request) {
	s, ok := i.authorize(w, r)
	if !ok {
		return
	}

	boundary, err := boundaryOf(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The whole request is capped, so a stream that never ends cannot occupy
	// this handler indefinitely. Two outputs' worth of headroom over the
	// scanner cap, for the inventory part and the multipart framing.
	limited := io.LimitReader(r.Body, 2*i.Limits.MaxOutputBytes+i.Limits.MaxMetaBytes)
	mr := multipart.NewReader(limited, boundary)

	var (
		report    Report
		gotReport bool
		output    []byte
		inventory []byte
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case FieldMeta:
			body, err := io.ReadAll(io.LimitReader(part, i.Limits.MaxMetaBytes))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := json.Unmarshal(body, &report); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			gotReport = true
		case FieldOutput:
			if output, err = readCapped(part, i.Limits.MaxOutputBytes); err != nil {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
		case FieldInventory:
			if inventory, err = readCapped(part, i.Limits.MaxOutputBytes); err != nil {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
		default:
			// An unknown part is not tolerated. A handler that ignored them
			// would accept whatever a compromised scanner chose to add, and
			// growing the protocol should be a decision rather than a default.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = part.Close()
	}

	if !gotReport || report.Result.Scanner == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if s.events.Scanner != nil {
		s.events.Scanner(scanexec.Execution{
			Result: report.Result,
			Raw: scanners.RawResult{
				Scanner: report.Result.Scanner,
				Version: report.Result.Version,
				Output:  output,
			},
			Inventory: inventory,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// readCapped reads at most max bytes and refuses anything longer.
//
// Reads max+1 and checks: a reader that stopped at exactly the cap would
// silently truncate, and a truncated scanner result stored as a whole one is
// the "fewer findings does not mean fewer problems" failure again.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, io.ErrUnexpectedEOF
	}
	return body, nil
}

func boundaryOf(r *http.Request) (string, error) {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return "", err
	}
	b := params["boundary"]
	if b == "" {
		return "", http.ErrNotMultipart
	}
	return b, nil
}
