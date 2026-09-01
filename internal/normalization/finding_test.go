package normalization

import (
	"errors"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func valid() Finding {
	return Finding{
		Fingerprint: strings.Repeat("a", 64),
		Scanner:     "gitleaks",
		Title:       "Exposed credential",
		Category:    scanners.CategorySecrets,
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Status:      StatusOpen,
	}
}

func TestValidateAcceptsACompleteFinding(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Errorf("a complete finding was rejected: %v", err)
	}
}

// Enum fields reject unknown values rather than passing them through: a
// scanner that invents a severity must fail loudly, not store something
// nothing downstream understands (§8).
func TestValidateRejectsUnknownEnums(t *testing.T) {
	cases := map[string]func(*Finding){
		"unknown severity":   func(f *Finding) { f.Severity = "catastrophic" },
		"empty severity":     func(f *Finding) { f.Severity = "" },
		"unknown confidence": func(f *Finding) { f.Confidence = "certain" },
		"empty confidence":   func(f *Finding) { f.Confidence = "" },
		"unknown category":   func(f *Finding) { f.Category = "astrology" },
		"unknown status":     func(f *Finding) { f.Status = "pondering" },
		// An SBOM is an inventory; nothing in it is wrong, so no finding may
		// claim that category.
		"sbom category": func(f *Finding) { f.Category = scanners.CategorySBOM },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := valid()
			mutate(&f)
			if err := f.Validate(); !errors.Is(err, ErrInvalidFinding) {
				t.Errorf("err = %v, want ErrInvalidFinding", err)
			}
		})
	}
}

// A missing required field is an error, not a finding with an empty field:
// "we could not read this" and "there was nothing here" must not collapse.
func TestValidateRejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]func(*Finding){
		"no fingerprint":    func(f *Finding) { f.Fingerprint = "" },
		"blank fingerprint": func(f *Finding) { f.Fingerprint = "   " },
		"no scanner":        func(f *Finding) { f.Scanner = "" },
		"no title":          func(f *Finding) { f.Title = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := valid()
			mutate(&f)
			if err := f.Validate(); !errors.Is(err, ErrInvalidFinding) {
				t.Errorf("err = %v, want ErrInvalidFinding", err)
			}
		})
	}
}

func TestValidateBoundsCVSS(t *testing.T) {
	for _, bad := range []float64{-0.1, 10.1, 99} {
		f := valid()
		f.CVSS = bad
		if err := f.Validate(); !errors.Is(err, ErrInvalidFinding) {
			t.Errorf("CVSS %v was accepted", bad)
		}
	}
	for _, ok := range []float64{0, 5.5, 10} {
		f := valid()
		f.CVSS = ok
		if err := f.Validate(); err != nil {
			t.Errorf("CVSS %v was rejected: %v", ok, err)
		}
	}
}

// Unknown must outrank Info: an unassessed finding deserves more attention
// than one assessed as informational.
func TestSeverityRanking(t *testing.T) {
	if SeverityUnknown.Rank() <= SeverityInfo.Rank() {
		t.Error("unknown must rank above info: not knowing is worse than knowing it is minor")
	}
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Error("critical must outrank high")
	}
}

// A scanner adding a severity level is not a reason to discard its findings,
// but the result must be visibly Unknown rather than a wrong guess.
func TestUnrecognisedSeverityBecomesUnknown(t *testing.T) {
	if got := MapSeverity("catastrophic"); got != SeverityUnknown {
		t.Errorf("MapSeverity(catastrophic) = %q, want unknown", got)
	}
	if got := MapSeverity(""); got != SeverityUnknown {
		t.Errorf("MapSeverity(\"\") = %q, want unknown", got)
	}
}

// Semgrep's ERROR is its top level and is applied liberally. Mapping it to
// critical would fill the top of the risk scale before Phase 6 assesses
// anything.
func TestSemgrepErrorIsHighNotCritical(t *testing.T) {
	if got := MapSemgrepSeverity("ERROR"); got != SeverityHigh {
		t.Errorf("MapSemgrepSeverity(ERROR) = %q, want high (see normalization.md)", got)
	}
}
