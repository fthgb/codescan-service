package report

import (
	"sort"

	"appsecgo/internal/contract"
)

// report.go — port of appsec/nodes/report.py (aggregation only; store/checkpoint
// I/O side-effects removed — deferred to P5 callbacks). Deterministic.

var highRiskTypes = map[string]bool{
	"command_injection": true, "insecure_deserialization": true, "ssrf": true,
}

// ReportOutput mirrors Python report.py:108-137 {"report": {summary, details}}.
type ReportOutput struct {
	Summary map[string]any         `json:"summary"`
	Details []contract.JudgeResult `json:"details"`
	Mode    string                 `json:"mode,omitempty"`
	// SkippedByLanguage: 被 AllowedLanguages 过滤挡掉的非 Java alert 计数(按扩展名)。
	// runPipeline 在 pipeline.Run 后回填;nil→omitempty 不落 summary。非 Java alert 不
	// 进 judge fan-out(省 token),此处仅留可见性计数,不污染 verdict/details。
	SkippedByLanguage map[string]int `json:"skipped_by_language,omitempty"`
	// SkippedBySeverity: 被 MinSeverity 过滤挡掉的低危 alert 计数(按严重度)。
	// 同 SkippedByLanguage 模式：runPipeline 回填, nil→omitempty 不落 summary。
	SkippedBySeverity map[string]int `json:"skipped_by_severity,omitempty"`
}

// FPPattern ports report.py fp_patterns entry: {count, reasons}.
type FPPattern struct {
	Count   int      `json:"count"`
	Reasons []string `json:"reasons"` // first-occurrence order, dedup keep-first, cap 5, NOT sorted
}

// Report ports report_node (report.py:15-138). Pure aggregation over
// judgements. calibrate = IsCalibrated fn (injected to avoid hard-binding Registry).
func Report(judgements, inherited, excluded []contract.JudgeResult, calibrate func(string) bool) ReportOutput {
	counts := map[string]int{"ai_false_positives": 0, "ai_true_positives": 0, "ai_uncertain": 0}
	autoSuppressed := 0
	// Python report.py: dispositions/severity_counts = dict[str,int], fp_patterns =
	// dict[str,{"count","reasons"}]. Non-nil empty maps marshal to {} (parity); plain
	// map iteration order is irrelevant — JSON consumers parse to map before comparison,
	// and the report output uses sort_keys=True.
	dispositions := map[string]int{}
	sevCounts := map[string]int{}
	fpPatterns := map[string]FPPattern{}
	var inc21Total, inc21AgreedFp, inc21Overridden int
	humanReview := 0

	for _, j := range judgements {
		if j.ControlFlowMutex {
			inc21Total++
			if j.Verdict == "false_positive" {
				inc21AgreedFp++
			} else {
				inc21Overridden++
			}
		}
		if j.Disposition != nil {
			dispositions[*j.Disposition]++
		}
		if j.Severity != nil {
			sevCounts[*j.Severity]++
		}
		// FP-like aggregation
		disp := ptrStr(j.Disposition)
		isFPLike := disp == "false_positive" || disp == "likely_fp" ||
			(disp == "" && j.Verdict == "false_positive")
		if isFPLike {
			vt := ptrStrSafe(j.VulnerabilityType)
			if vt == "" {
				vt = "unknown"
			}
			p, ok := fpPatterns[vt]
			if !ok {
				p = FPPattern{Reasons: []string{}}
			}
			p.Count++
			why := ""
			if j.ExploitPath.PathBrokenAt != nil && *j.ExploitPath.PathBrokenAt != "" {
				why = *j.ExploitPath.PathBrokenAt
			} else if j.SanitizationFound != nil {
				why = *j.SanitizationFound
			}
			if why != "" {
				dup := false
				for _, r := range p.Reasons {
					if r == why {
						dup = true
						break
					}
				}
				if !dup && len(p.Reasons) < 5 {
					p.Reasons = append(p.Reasons, why)
				}
			}
			fpPatterns[vt] = p
		}
		switch j.Verdict {
		case "false_positive":
			counts["ai_false_positives"]++
			vt := ptrStrSafe(j.VulnerabilityType)
			highRisk := highRiskTypes[vt]
			calibrated := calibrate(vt)
			reclassified := len(j.TypeMismatchTypes) > 0 || len(j.BuriedTypes) > 0
			if j.Confidence >= 7 && !highRisk && calibrated && !reclassified {
				autoSuppressed++
			} else {
				humanReview++
			}
		case "true_positive":
			counts["ai_true_positives"]++
		default:
			counts["ai_uncertain"]++
		}
	}

	blindAlerts := 0
	for _, j := range judgements {
		if startsWith(ptrStr(j.FailReason), "empty_slice:") {
			blindAlerts++
		}
	}

	// sorted distinct (Python sorted(set(...))) — NOT first-occurrence (§6.4 例外)
	tmSet := map[string]bool{}
	for _, j := range judgements {
		for _, t := range j.TypeMismatchTypes {
			tmSet[t] = true
		}
	}
	typeMismatches := 0
	for _, j := range judgements {
		if len(j.TypeMismatchTypes) > 0 {
			typeMismatches++
		}
	}
	buriedSet := map[string]bool{}
	for _, j := range judgements {
		for _, t := range j.BuriedTypes {
			buriedSet[t] = true
		}
	}
	buriedCount := 0
	for _, j := range judgements {
		if len(j.BuriedTypes) > 0 {
			buriedCount++
		}
	}
	probeDowngrades := 0
	for _, j := range judgements {
		if j.Verification != nil && j.Verification["action"] == "downgraded_to_uncertain" {
			probeDowngrades++
		}
	}
	controlFlowPruned := 0
	for _, j := range judgements {
		if j.ModelUsed == "symbolic_cf_prefilter" {
			controlFlowPruned++
		}
	}

	tmSorted := sortedKeys(tmSet)
	buriedSorted := sortedKeys(buriedSet)

	funnel := map[string]any{
		"sast_in":             len(inherited) + len(excluded) + len(judgements),
		"bughash_inherited":   len(inherited),
		"hard_excluded":       len(excluded),
		"ai_judged":           len(judgements),
		"control_flow_pruned": controlFlowPruned,
		"auto_suppressed":     autoSuppressed,
	}

	summary := map[string]any{
		"bughash_cache_hits":      len(inherited),
		"hard_excluded":           len(excluded),
		"ai_processed":            len(judgements),
		"blind_alerts":            blindAlerts,
		"type_mismatches":         typeMismatches,
		"type_mismatch_types":     tmSorted,
		"buried_types":            buriedSorted,
		"buried_count":            buriedCount,
		"probe_downgrades":        probeDowngrades,
		"funnel":                  funnel,
		"dispositions":            dispositions,
		"severity_counts":         sevCounts,
		"fp_patterns":             fpPatterns,
		"inc21_total":             inc21Total,
		"inc21_agreed_fp":         inc21AgreedFp,
		"inc21_overridden_by_llm": inc21Overridden,
		"ai_false_positives":      counts["ai_false_positives"],
		"ai_true_positives":       counts["ai_true_positives"],
		"ai_uncertain":            counts["ai_uncertain"],
		"human_review_needed":     counts["ai_uncertain"] + humanReview,
	}
	return ReportOutput{Summary: summary, Details: append(append(append([]contract.JudgeResult{}, judgements...), inherited...), excluded...)}
}

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ptrStrSafe(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
