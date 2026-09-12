package discover

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"appsecgo/internal/bughash"
	"appsecgo/internal/contract"
	"appsecgo/internal/judge"
	"appsecgo/internal/llm"
	"appsecgo/internal/prompts"
	"appsecgo/internal/slice"
)

// DiscoverOne mirrors appsec/nodes/discover.py:discover_one: analyze one changed
// function for newly-introduced vulnerabilities (no SAST finding given).
// Provider-agnostic; fail-open to uncertain on any error/panic so a single bad
// unit never aborts the run. When index is non-nil the changed function is
// enriched with its in-repo callees (Tier 1.5) so the judge sees helpers like
// sanitizers.
//
// Reuses judge.ParseJudgeOutput + judge.VerdictOf + prompts.BuildRepairMessages
// (disposition->verdict mapping is the triage judge's single source of truth,
// 铁律 D — discovery only differs in prompt/task, not in verdict semantics).
func DiscoverOne(ctx context.Context, changed ChangedFunction, appContext map[string]any,
	provider llm.Provider, model string, index *slice.RepositoryIndex, maxTokens int) (result contract.JudgeResult) {

	file := changed.File
	fn := changed.Function
	body := changed.Body
	alertID := fmt.Sprintf("diff-%s:%s", file, fn)

	// bughashFn captures file/fn/body (mirrors Python's _bughash closure).
	bughashFn := func(vt string) string {
		return bughash.ComputeBughash(vt, "", file, fn, file, fn, body, "", 0, 0, "")
	}

	lr := changed.LineRange
	sliced := &contract.SlicedContext{
		AlertID:             alertID,
		Bughash:             bughashFn("unknown"),
		VulnerabilityType:   "unknown",
		EntryPointSignature: fn,
		Hops: []contract.HopSlice{{
			HopIndex:      0,
			FilePath:      file,
			FunctionName:  fn,
			FunctionBody:  body,
			TaintVariable: "",
			LineRange:     lr,
		}},
	}
	if index != nil {
		sliced = slice.EnrichSlice(sliced, index)
	}

	// Fail-open: any panic during the LLM/parse/repair flow -> uncertain, never
	// abort the run. Error returns hit the same failOpenResult explicitly.
	defer func() {
		if r := recover(); r != nil {
			result = failOpenResult(alertID, bughashFn, fn, model, fmt.Sprintf("discover: %v", r))
		}
	}()

	resp, err := provider.Complete(ctx, llm.Request{
		Messages:  BuildDiscoveryMessages(sliced, appContext),
		MaxTokens: maxTokens,
	})
	if err != nil {
		return failOpenResult(alertID, bughashFn, fn, model, fmt.Sprintf("discover: %v", err))
	}

	data, perr := judge.ParseJudgeOutput(resp.Text)
	if perr != nil { // ParseError -> repair retry (parity with triage P5)
		repairResp, rerr := provider.Complete(ctx, llm.Request{
			Messages:  prompts.BuildRepairMessages(resp.Text),
			MaxTokens: maxTokens,
		})
		if rerr != nil {
			return failOpenResult(alertID, bughashFn, fn, model, fmt.Sprintf("discover: %v", rerr))
		}
		data, perr = judge.ParseJudgeOutput(repairResp.Text)
		if perr != nil {
			return failOpenResult(alertID, bughashFn, fn, model, fmt.Sprintf("discover: %v", perr))
		}
	}

	// I6:provider 把工具参数框架吐进字符串值内部(见 contract.RecoverArgFraming)。
	// discovery 不经 NormalizeVerdictData,故在此显式收口 —— 否则 suggested_fix/
	// severity_rationale 会被吞进 reasoning,且原始标记印进报告。
	judge.RecoverArgFramingInto(data)

	return buildDiscoverResult(data, alertID, bughashFn, fn, model)
}

// buildDiscoverResult maps the parsed judge JSON into a JudgeResult. Mirrors
// discover.py:62-87. Key difference from triage BuildJudgeResult: disposition
// defaults to "false_positive" (skeptical — most code has no vuln), and there
// is no CWE registry / buried-type / decisive-check handling (discovery is
// open-ended, vt is an OUTPUT).
func buildDiscoverResult(data map[string]any, alertID string, bughashFn func(string) string,
	fn, model string) contract.JudgeResult {

	// disposition default "false_positive" (NOT "uncertain" like triage) —
	// skeptical: a missing disposition means no vuln found.
	disposition, _ := data["disposition"].(string)
	if disposition == "" {
		disposition = "false_positive"
	}

	// vt normalization: None/""/none/null/unknown -> nil (Python None).
	vt, _ := data["vulnerability_type"].(string)
	if vt == "" || vt == "none" || vt == "null" || vt == "unknown" {
		vt = ""
	}
	var vtPtr *string
	if vt != "" {
		vtPtr = &vt
	}

	// severity: lowercase, must be one of the 4 valid values, else nil.
	sev := strings.ToLower(strOr(data, "severity", ""))
	if sev != "critical" && sev != "high" && sev != "medium" && sev != "low" {
		sev = ""
	}
	var sevPtr *string
	if sev != "" {
		sevPtr = &sev
	}
	// severity_rationale only when severity present (Python `if sev else None`).
	// Uses type-assertion (not strOr) so a missing key -> nil (Python data.get
	// returns None -> null), not &"" (parity with discover.py:84).
	var sevRat *string
	if sev != "" {
		if r, ok := data["severity_rationale"].(string); ok {
			sevRat = &r
		}
	}

	var fixPtr *string
	if v, ok := data["suggested_fix"].(string); ok {
		fixPtr = &v
	}

	// bughash uses the normalized vt (or "unknown" when nil) — parity with
	// Python `_bughash(vt or "unknown")`.
	bh := vt
	if bh == "" {
		bh = "unknown"
	}
	disp := disposition
	return contract.JudgeResult{
		AlertID:           alertID,
		Bughash:           bughashFn(bh),
		Verdict:           judge.VerdictOf(disposition),
		Disposition:       &disp,
		VulnerabilityType: vtPtr,
		Confidence:        confidenceOf(data),
		ExploitPath:       exploitPath(asMap(data, "exploit_path"), fn),
		Reasoning:         strOr(data, "reasoning", ""),
		Severity:          sevPtr,
		SeverityRationale: sevRat,
		SuggestedFix:      fixPtr,
		ModelUsed:         model,
	}
}

// failOpenResult mirrors discover.py:88-98: verdict=uncertain, confidence=0,
// exploit_path anchored at fn, fail_reason="discover: <error>". Always surfaced
// for human review (never dropped).
func failOpenResult(alertID string, bughashFn func(string) string, fn, model, reason string) contract.JudgeResult {
	fr := reason
	return contract.JudgeResult{
		AlertID:     alertID,
		Bughash:     bughashFn("unknown"),
		Verdict:     "uncertain",
		Confidence:  0,
		ExploitPath: contract.ExploitPath{EntryPoint: fn, DataFlow: []string{}, AttackerControlAtSink: "none"},
		Reasoning:   "discovery fail-open",
		ModelUsed:   model,
		FailReason:  &fr,
	}
}

// exploitPath mirrors discover.py:_exploit_path. entry_point falls back to the
// changed fn; data_flow defaults to a non-nil empty slice (Python `or []` -> []
// not None -> JSON []); path_broken_at empty -> nil (parity with triage
// build.go so the shared ExploitPath contract renders consistently).
func exploitPath(ep map[string]any, entry string) contract.ExploitPath {
	if ep == nil {
		ep = map[string]any{}
	}
	entryPoint := strOr(ep, "entry_point", "")
	if entryPoint == "" {
		entryPoint = entry
	}
	var dataFlow []string
	if df, ok := ep["data_flow"].([]any); ok {
		for _, d := range df {
			if s, ok := d.(string); ok {
				dataFlow = append(dataFlow, s)
			}
		}
	}
	if dataFlow == nil {
		dataFlow = []string{} // Python `or []` -> [] (non-nil)
	}
	var pathBrokenAt *string
	if v, ok := ep["path_broken_at"].(string); ok && v != "" {
		pathBrokenAt = &v
	}
	return contract.ExploitPath{
		EntryPoint:            entryPoint,
		DataFlow:              dataFlow,
		SinkReached:           boolOr(ep, "sink_reached", false),
		AttackerControlAtSink: strOr(ep, "attacker_control_at_sink", "none"),
		PathBrokenAt:          pathBrokenAt,
	}
}

// --- map access helpers (mirror judge.build.go's strOr/anyList/boolVal) ---

func strOr(m map[string]any, k, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return def
}

func boolOr(m map[string]any, k string, def bool) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return def
}

func asMap(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return nil
}

// confidenceOf mirrors Python `int(data.get("confidence", 0))` with the same
// TypeError/ValueError -> 0 fallback: handles float64 (JSON default), int, and
// numeric strings; anything else -> 0.
func confidenceOf(data map[string]any) int {
	switch v := data["confidence"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}
