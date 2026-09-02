package risk

import (
	"strconv"
	"strings"
)

// Explain renders a score as the derivation that produced it.
//
// A score with no breakdown is an assertion. §12 has to explain a gate result
// in terms someone can dispute, §11 has to prioritise remediation from it, and
// neither is possible from a bare number. Factors that were neutral for lack of
// data say so explicitly, because "average" and "unknown" are different claims.
func (s Score) Explain() string {
	var b strings.Builder
	b.WriteString("risk ")
	b.WriteString(trim(s.Value))

	if s.Dismissed {
		b.WriteString(" = 0 (")
		if len(s.Factors) > 0 {
			b.WriteString(s.Factors[0].Reason)
		}
		b.WriteString(")")
		return b.String()
	}

	for i, f := range s.Factors {
		if i == 0 {
			b.WriteString(" = ")
		} else {
			b.WriteString("\n          × ")
		}
		b.WriteString(f.Name)
		b.WriteString(" ")
		b.WriteString(trim(f.Value))
		b.WriteString(" (")
		b.WriteString(f.Reason)
		if f.Neutral {
			b.WriteString("; neutral)")
		} else {
			b.WriteString(")")
		}
	}
	return b.String()
}

// trim formats a float without trailing zeroes, so an explanation reads as
// "1.5" rather than "1.500000".
func trim(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// join renders a list as prose: "grype and trivy", "grype, semgrep and trivy".
func join(in []string) string {
	switch len(in) {
	case 0:
		return ""
	case 1:
		return in[0]
	case 2:
		return in[0] + " and " + in[1]
	default:
		return strings.Join(in[:len(in)-1], ", ") + " and " + in[len(in)-1]
	}
}
