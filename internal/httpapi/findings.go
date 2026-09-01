package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
)

// findingResponse is the wire model for a finding.
//
// Converted explicitly from the domain model, so adding a field to the domain
// does not silently widen the public API contract (§18). Raw scanner output
// never reaches the client (§7 rule 5); everything here is canonical.
type findingResponse struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`

	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Status     string `json:"status"`

	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`

	// Scanner is the first reporter. Sources is every scanner that has
	// reported it, which is the more useful fact: two scanners agreeing is
	// independent corroboration.
	Scanner string   `json:"scanner"`
	Sources []string `json:"sources"`
	// ScannerSeverity is the original string, kept so a client can see what
	// the scanner said as well as what SecureOps concluded.
	ScannerSeverity string `json:"scanner_severity,omitempty"`

	Package        string  `json:"package,omitempty"`
	PackageVersion string  `json:"package_version,omitempty"`
	PURL           string  `json:"purl,omitempty"`
	CVE            string  `json:"cve,omitempty"`
	CWE            string  `json:"cwe,omitempty"`
	CVSS           float64 `json:"cvss,omitempty"`

	Occurrences int       `json:"occurrences"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type findingListResponse struct {
	Findings []findingResponse `json:"findings"`
	HasMore  bool              `json:"has_more"`
}

func toFindingResponse(r findings.Record) findingResponse {
	sources := r.Sources
	if sources == nil {
		sources = []string{}
	}
	return findingResponse{
		ID:              r.ID,
		Fingerprint:     r.Fingerprint,
		Category:        string(r.Category),
		Severity:        string(r.Severity),
		Confidence:      string(r.Confidence),
		Status:          string(r.Status),
		Title:           r.Title,
		Description:     r.Description,
		Remediation:     r.Remediation,
		Scanner:         r.Scanner,
		Sources:         sources,
		ScannerSeverity: r.ScannerSeverity,
		Package:         r.Package,
		PackageVersion:  r.PackageVersion,
		PURL:            r.PURL,
		CVE:             r.CVE,
		CWE:             r.CWE,
		CVSS:            r.CVSS,
		Occurrences:     r.Occurrences,
		FirstSeen:       r.FirstSeen,
		LastSeen:        r.LastSeen,
	}
}

func toFindingList(records []findings.Record, hasMore bool) findingListResponse {
	out := findingListResponse{Findings: make([]findingResponse, 0, len(records)), HasMore: hasMore}
	for _, r := range records {
		out.Findings = append(out.Findings, toFindingResponse(r))
	}
	return out
}

// handleListProjectFindings serves a project's findings, most severe first.
func (s *Server) handleListProjectFindings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.findings == nil {
			// An empty list would say "this project has no findings", which is
			// a different claim from "findings are not available here".
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"findings are not available on this server")
			return
		}

		projectID := chi.URLParam(r, "projectID")
		if !isUUID(projectID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "project id must be a uuid")
			return
		}
		if _, err := s.projects.Get(r.Context(), projectID); err != nil {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "project not found")
			return
		}

		filter := findings.Filter{
			Status:   r.URL.Query().Get("status"),
			Severity: r.URL.Query().Get("severity"),
			Scanner:  r.URL.Query().Get("scanner"),
		}
		// Filters are validated rather than passed through: an unknown value
		// would silently return nothing, which reads as "no findings" when it
		// means "you asked a question I did not understand".
		if filter.Status != "" && !normalization.Status(filter.Status).Valid() {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "unknown status filter")
			return
		}
		if filter.Severity != "" && !normalization.Severity(filter.Severity).Valid() {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "unknown severity filter")
			return
		}

		limit, offset, err := pageFrom(r)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		}

		records, hasMore, err := s.findings.ListByProject(
			r.Context(), projectID, filter, findings.Page{Limit: limit, Offset: offset})
		if err != nil {
			s.internalError(w, r, "list findings", err)
			return
		}
		writeJSON(w, r, http.StatusOK, toFindingList(records, hasMore))
	}
}

// handleListScanFindings serves the findings one scan reported.
func (s *Server) handleListScanFindings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.findings == nil {
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal,
				"findings are not available on this server")
			return
		}

		scanID := chi.URLParam(r, "scanID")
		if !isUUID(scanID) {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "scan id must be a uuid")
			return
		}
		if _, err := s.scans.Get(r.Context(), scanID); err != nil {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "scan not found")
			return
		}

		limit, offset, err := pageFrom(r)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
			return
		}

		records, hasMore, err := s.findings.ListByScan(
			r.Context(), scanID, findings.Page{Limit: limit, Offset: offset})
		if err != nil {
			s.internalError(w, r, "list scan findings", err)
			return
		}
		writeJSON(w, r, http.StatusOK, toFindingList(records, hasMore))
	}
}
