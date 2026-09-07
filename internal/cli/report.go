package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Render writes a result for a person to read.
//
// Every condition is printed, breached or not. A report listing only breaches
// makes "this project is clean" and "this policy checks nothing" look
// identical, which is the bare verdict §12 forbids wearing a friendlier face.
//
// Rendered from the same conditions the JSON carries, so a terminal, a PR
// comment and a status check cannot disagree about why a build failed.
func Render(w io.Writer, result Result) {
	if result.Gate == nil {
		fmt.Fprintf(w, "GATE NOT EVALUATED  scan %s (%s)\n", result.ScanID, orDash(result.Status))
		fmt.Fprintln(w, "\nThe build is stopped because the gate did not run, not because it failed.")
		return
	}

	g := result.Gate
	fmt.Fprintf(w, "%s  scan %s\n", strings.ToUpper(g.Verdict), g.ScanID)
	if g.Summary != "" {
		fmt.Fprintf(w, "%s\n", g.Summary)
	}

	// Coverage before the rules, because it changes what the rules mean. A
	// scan that found less than it should have can breach fewer rules for the
	// wrong reason, and the verdict alone hides that.
	if !g.Coverage.Complete {
		fmt.Fprintf(w, "\nCoverage: incomplete (scan %s)", orDash(g.Coverage.ScanStatus))
		if g.Coverage.Downgraded {
			fmt.Fprint(w, " — this lowered the verdict")
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "A scanner did not report. Fewer findings here does not mean fewer problems.")
	}

	if len(g.Conditions) == 0 {
		fmt.Fprintln(w, "\nThis project's policy contains no rules, so nothing was checked.")
		return
	}

	fmt.Fprintln(w)
	for _, c := range g.Conditions {
		mark := "ok  "
		if c.Breached {
			mark = strings.ToUpper(c.Level) // "fail" or "warn"
			mark += strings.Repeat(" ", max(0, 4-len(mark)))
		}
		fmt.Fprintf(w, "  %s %s\n", mark, c.Explanation)
	}
}

// RenderJSON writes the machine-readable form.
//
// The gate result as the API returned it, not a summary of it: a consumer that
// wants to act on a specific condition needs the conditions, and re-deriving
// them from prose is how two renderings of one decision drift apart.
func RenderJSON(w io.Writer, result Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// Number formats a rule's threshold or observation for prose.
//
// Whole numbers print without a decimal point: "at most 0 critical" reads as a
// count, "at most 0.0 critical" reads as a measurement of something else.
func Number(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
