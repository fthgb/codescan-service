package discover

import (
	"context"

	"appsecgo/internal/contract"
	"appsecgo/internal/llm"
	"appsecgo/internal/report"
	"appsecgo/internal/slice"
)

// RunDiscovery mirrors appsec/discover_run.py:run_discovery: the Line B
// end-to-end orchestrator. A unified git diff -> changed functions (seeded by
// the diff itself, no SAST) -> discovery judge per unit -> an aggregated report.
//
// Discovery semantics differ from the SAST triage report (report.Report): a
// false_positive verdict here means "inspected this changed function, found no
// vulnerability" — the expected majority, NOT something needing review. So safe
// units are COUNTED, not listed; only true_positive and uncertain (incl.
// likely_tp, which VerdictOf maps to uncertain) findings go in details.
// Fail-open: an uncertain/likely_tp finding is always surfaced for human
// review, never dropped.
//
// When a RepositoryIndex is available, 1-hop callers of each changed function
// are pulled into the discovery set too (includeCallers=index!=nil, parity with
// Python) — a change can introduce a bug reachable only via its callers.
func RunDiscovery(ctx context.Context, diffText, repoRoot string, appContext map[string]any,
	provider llm.Provider, model string, extractor slice.FunctionExtractor,
	index *slice.RepositoryIndex, maxTokens int) *report.ReportOutput {

	includeCallers := index != nil
	units := ChangedFunctions(diffText, repoRoot, extractor, index, includeCallers)

	details := []contract.JudgeResult{}
	tp, uncertain, safe := 0, 0, 0
	severityCounts := map[string]int{}
	dispositions := map[string]int{}

	for _, unit := range units {
		res := DiscoverOne(ctx, unit, appContext, provider, model, index, maxTokens)

		// false_positive -> safe, counted NOT listed (no vuln in this changed fn).
		if res.Verdict == "false_positive" {
			safe++
			continue
		}
		// TP or uncertain (incl. likely_tp) -> listed + counted.
		if res.Verdict == "true_positive" {
			tp++
		} else {
			uncertain++
		}
		if res.Disposition != nil && *res.Disposition != "" {
			dispositions[*res.Disposition]++
		}
		if res.Severity != nil && *res.Severity != "" {
			severityCounts[*res.Severity]++
		}
		// vulnerability_type nil -> "unknown" (parity with Python
		// `d["vulnerability_type"] = res.vulnerability_type or "unknown"`).
		if res.VulnerabilityType == nil {
			vt := "unknown"
			res.VulnerabilityType = &vt
		}
		details = append(details, res)
	}

	summary := map[string]any{
		"units_scanned":       len(units),
		"findings":            len(details),
		"ai_true_positives":   tp,
		"ai_uncertain":        uncertain,
		"ai_safe":             safe,
		"severity_counts":     severityCounts,
		"dispositions":        dispositions,
		"human_review_needed": uncertain,
	}
	return &report.ReportOutput{Summary: summary, Details: details, Mode: "discovery"}
}
