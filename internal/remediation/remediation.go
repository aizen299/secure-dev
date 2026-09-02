// Package remediation turns findings into ranked work (§11).
//
// The risk engine answers "how bad is this project". This one answers the only
// question that follows: what should I do first?
//
// Pure and deterministic, like the three engines before it: same findings, same
// plan, same order, with no I/O, no clock, and no network.
//
// Two rules shape everything here. Vendor and scanner data is authoritative and
// is never embellished -- §11 and §25.6 forbid presenting a generated fix as
// verified, so an action never names a version no scanner reported. And an
// action's kind comes from the finding's category, never from the scanner that
// reported it, because §7.2 and §25.3 keep scanner knowledge inside adapters.
//
// See docs/architecture/remediation.md and ADR 020.
package remediation

import (
	"sort"
	"strings"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/risk"
)

// Plan is a project's ranked remediation work.
type Plan struct {
	// Actions, most valuable first.
	Actions []Action
	// Score is the project's current risk score, so a reader can see what the
	// rankings are measured against.
	Score float64
	// Addressable counts the live findings that appear in some action. It
	// equals the live finding count -- every live finding produces work, even
	// if that work is "decide what to do about something with no fix".
	Addressable int
}

// Build produces a ranked plan from the same inputs the risk engine consumes.
//
// Deliberately the same inputs: remediation ranks by the risk an action would
// remove, so it must score the project exactly as the risk engine does or the
// two would disagree about what matters.
func Build(subjects []risk.Subject, ctx risk.Context) Plan {
	return BuildWith(subjects, ctx, risk.DefaultWeights())
}

// BuildWith produces a plan using caller-supplied risk weights.
func BuildWith(subjects []risk.Subject, ctx risk.Context, w risk.Weights) Plan {
	live := make([]risk.Subject, 0, len(subjects))
	for _, s := range subjects {
		// Dismissed findings are not work. A false positive appearing in a
		// remediation plan would mean a human decision never took effect --
		// the same rule the risk engine and correlation both follow.
		if isDismissed(s.Status) {
			continue
		}
		live = append(live, s)
	}

	baseline, _ := assess(live, ctx, w)
	plan := Plan{Score: baseline, Addressable: len(live)}
	if len(live) == 0 {
		plan.Actions = []Action{}
		return plan
	}

	// Per-finding risk, so a member can show which one dominates its action.
	perFinding := make(map[string]float64, len(live))
	_, scores := assess(live, ctx, w)
	for _, sc := range scores {
		perFinding[sc.Fingerprint] = sc.Value
	}

	grouped := group(live, perFinding)

	// Rank by what taking the action would actually remove, which needs the
	// score recomputed with that action's members withheld. O(actions x
	// findings), bounded by the same finding limits the other engines live in.
	for i := range grouped {
		remaining := without(live, grouped[i].Members)
		after, _ := assess(remaining, ctx, w)
		grouped[i].ScoreAfter = after
		grouped[i].RiskRemoved = baseline - after
		if grouped[i].RiskRemoved < 0 {
			// Unreachable while risk is monotonic, which ADR 019 proves.
			// Clamped rather than trusted, because a negative "risk removed"
			// would rank an action as actively harmful to take.
			grouped[i].RiskRemoved = 0
		}
	}

	sort.SliceStable(grouped, func(i, j int) bool {
		if grouped[i].RiskRemoved != grouped[j].RiskRemoved {
			return grouped[i].RiskRemoved > grouped[j].RiskRemoved
		}
		// Ties break by how much work one action closes, then by key, so the
		// order is total and the plan is byte-identical across runs.
		if len(grouped[i].Members) != len(grouped[j].Members) {
			return len(grouped[i].Members) > len(grouped[j].Members)
		}
		return grouped[i].Key < grouped[j].Key
	})

	plan.Actions = grouped
	return plan
}

// assess scores a set of subjects, returning the project score and the
// per-finding scores.
func assess(subjects []risk.Subject, ctx risk.Context, w risk.Weights) (float64, []risk.Score) {
	a, err := risk.AssessWith(subjects, ctx, w)
	if err != nil {
		// Only reachable with invalid weights, which the caller supplied. A
		// plan with no scoring is still better than none: the actions are
		// real, only the ranking is unavailable.
		return 0, nil
	}
	return a.Score, a.Findings
}

// without returns subjects excluding the given members.
func without(subjects []risk.Subject, members []Member) []risk.Subject {
	excluded := make(map[string]struct{}, len(members))
	for _, m := range members {
		excluded[m.Fingerprint] = struct{}{}
	}
	out := make([]risk.Subject, 0, len(subjects))
	for _, s := range subjects {
		if _, skip := excluded[s.Fingerprint]; skip {
			continue
		}
		out = append(out, s)
	}
	return out
}

// isDismissed mirrors the risk engine's set exactly. The engines must agree on
// which findings exist, or a plan recommends work on something the dashboard
// has already closed.
func isDismissed(s normalization.Status) bool {
	switch s {
	case normalization.StatusResolved, normalization.StatusFalsePositive, normalization.StatusIgnored:
		return true
	default:
		return false
	}
}

// dedupe returns the unique, sorted, non-blank entries of in, capped.
func dedupe(in []string, cap int) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}
