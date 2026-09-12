package judge

import (
	"fmt"
	"regexp"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
)

// dispositionToVerdict mirrors judge.py:_DISPOSITION_TO_VERDICT (canonical 3-value).
var dispositionToVerdict = map[string]string{
	"true_positive":  "true_positive",
	"false_positive": "false_positive",
	"likely_tp":      "uncertain",
	"likely_fp":      "uncertain",
	"out_of_scope":   "uncertain",
	"uncertain":      "uncertain",
}

func VerdictOf(disposition string) string {
	if v, ok := dispositionToVerdict[disposition]; ok {
		return v
	}
	return "uncertain"
}

// dispositionFragmentRe 提取被吞进某 string 值的 disposition(F1 A 类)。
// A 类成因:disposition 的值以 "disposition": "<枚举>" JSON 字段片段形态被吞进某字段值里,
// 但无 arg-frame 标记(不同于 microsyntax.RecoverArgFraming 的 :387 argFrameAnyRe 标记入场券),
// 故走独立路径,不放宽该类守卫纪律。
var dispositionFragmentRe = regexp.MustCompile(`"disposition":\s*"([^"]+)"`)

// recoverDispositionFromValues 扫 data 所有 string 值,提取被吞的 disposition(F1 A 类)。
// 枚举校验(复用 :12-19 dispositionToVerdict 的 6 值 map key)是防散文误切的唯一守卫:
// 非枚举值一律不采纳,原样返回 ""(交由调用方走 Disposition=nil 归因,见 BuildJudgeResult :37)。
func recoverDispositionFromValues(data map[string]any) string {
	for _, v := range data {
		s, ok := v.(string)
		if !ok {
			continue
		}
		m := dispositionFragmentRe.FindStringSubmatch(s)
		if len(m) < 2 {
			continue
		}
		if _, ok := dispositionToVerdict[m[1]]; ok { // 复用 :12-19 的 6 值枚举(map key)
			return m[1]
		}
	}
	return ""
}

// BuildJudgeResult mirrors judge.py:_build_judge_result: data (normalized) ->
// JudgeResult. Raises ErrParse (caller fail-opens) if data still has raw_arguments.
// cap = MAX_CONFIDENCE (10). llmRaw = the raw text/tool-args string (for buried scan).
func BuildJudgeResult(data map[string]any, sliced map[string]any, model string, cap int, llmRaw string, reg *cwereg.Registry) (contract.JudgeResult, error) {
	if _, ok := data["raw_arguments"]; ok {
		// Step-4 correction: wrap ErrParse so errors.Is(err, ErrParse) holds for
		// T9 JudgeOne.failReasonFor fail-open. Mirrors Python raising ParseError.
		return contract.JudgeResult{}, fmt.Errorf("%w: unparseable submit_verdict raw_arguments (model 返回残缺 JSON 包成 raw_arguments)", ErrParse)
	}
	disposition := strOr(data, "disposition", strOr(data, "verdict", ""))
	if disposition == "" {
		// F1 A 类回收:模型把 disposition 值吞进某 string 字段(无 arg-frame 标记),正则+枚举校验提取。
		disposition = recoverDispositionFromValues(data)
	}
	// 此处不静默缺省 uncertain。仍空 ⇒ Disposition=nil(contract.JudgeResult.Disposition:15,
	// 空指针 = 未判定,≠ uncertain);VerdictOf("")(:25 fallback)仍返回 uncertain ⇒ verdict 不变,
	// 只 Disposition 字段 null 化以供归因(B/C 类,见 spec 2026-09-01-f1 §3.2)。
	sev := strings.ToLower(strOr(data, "severity", ""))
	if sev != "" && sev != "critical" && sev != "high" && sev != "medium" && sev != "low" {
		sev = ""
	}
	declared := strings.ToLower(strOr(sliced, "vulnerability_type", ""))
	// actual_vulnerability_types: list, fallback legacy single.
	rawTypes := anyList(data, "actual_vulnerability_types")
	if rawTypes == nil {
		if single := strOr(data, "actual_vulnerability_type", ""); single != "" {
			rawTypes = []any{single}
		}
	}
	var actual []string
	for _, t := range rawTypes {
		s, ok := t.(string)
		if !ok {
			continue
		}
		// 原地内联的 nullish 判断已收口进 contract.IsNullish（微语法契约 I3 单一权威）：
		// 此处曾是全仓唯一做了该归一的字段，其余三个自由文本字段漏做 → 潜伏门洞。
		s = strings.TrimSpace(strings.ToLower(s))
		if contract.IsNullish(s) {
			continue
		}
		s = reg.NormalizeVulnType(s)
		if !contains(actual, s) {
			actual = append(actual, s)
		}
	}
	// buried: scan reasoning + llm_raw.
	buried := reg.DetectBuriedTypes(strOr(data, "reasoning", "")+" "+llmRaw, actual)
	// mismatch: actual NOT in loaded knowledge.
	loaded := reg.LoadedKnowledgeTypes(sliced, declared)
	var mismatch []string
	for _, t := range actual {
		if !loaded[t] {
			mismatch = append(mismatch, t)
		}
	}
	// decisive_checks: list, fallback single dict.
	var dc []map[string]any
	if v, ok := data["decisive_checks"].([]any); ok {
		for _, d := range v {
			if m, ok := d.(map[string]any); ok {
				dc = append(dc, m)
			}
		}
	}
	if len(dc) == 0 {
		if m, ok := data["decisive_check"].(map[string]any); ok {
			dc = []map[string]any{m}
		}
	}
	// exploit_path: entry_point fallback sliced.entry_point_signature or "?".
	epMap, _ := data["exploit_path"].(map[string]any)
	epEntry := strOr(epMap, "entry_point", strOr(sliced, "entry_point_signature", "?"))
	epDataFlow := anyList(epMap, "data_flow")
	var epDF []string
	for _, d := range epDataFlow {
		if s, ok := d.(string); ok {
			epDF = append(epDF, s)
		}
	}
	if epDF == nil {
		epDF = []string{}
	}
	// path_broken_at: mirror Python ExploitPath(**{**data["exploit_path"],...})
	// passthrough. Non-empty string -> *string; absent/empty -> nil (Python None -> null).
	// path_broken_at / sanitization_found / suggested_fix / exploit_payload：LLM 常在
	// 「该填 JSON null」处写字符串 "null"/"none"/"无"（2026-08-22 三 run 实测 39 处）。
	// 一律经 contract.NormalizeNullish 归一成真 nil（微语法契约 I3，单一解析器）。
	//
	// 这是**安全必需**而非洁癖：EnforceEvidenceOnTp（guard.go:145）判
	// `*ExploitPayload == ""`，字符串 "null" 非空 → 无结构化证据的高置信 TP 可绕过
	// hollow-TP 门。归一放在 build 层（判决门之前）→ 门本身不必改，少一处耦合。
	var pathBrokenAt *string
	if v, ok := epMap["path_broken_at"].(string); ok {
		pathBrokenAt = contract.NormalizeNullish(v)
	}
	// sink_evidence: LLM-emitted structured sink truth (arc ②). Present -> &map;
	// absent/null -> nil. Mirrors decisive_check map[string]any shape.
	var sinkEvidence *map[string]any
	if se, ok := epMap["sink_evidence"].(map[string]any); ok && len(se) > 0 {
		m := se
		sinkEvidence = &m
	}
	// taint_source: LLM-emitted structured taint-source truth（2026-09-07 根因报告 §8，
	// 治「data_flow 从入口调用链写起、真 source 藏在末步」）。同 sink_evidence 口径：
	// present -> &map; absent/nullish -> nil。
	var taintSource *map[string]any
	if ts, ok := epMap["taint_source"].(map[string]any); ok && len(ts) > 0 {
		m := ts
		taintSource = &m
	}
	conf := intVal(data, "confidence", 0)
	if conf > cap {
		conf = cap
	}
	var sevPtr *string
	if sev != "" {
		sevPtr = &sev
	}
	var sevRat *string
	if sev != "" {
		r := strOr(data, "severity_rationale", "")
		sevRat = &r
	}
	var actualFirst *string
	if len(actual) > 0 {
		a := actual[0]
		actualFirst = &a
	}
	var decisiveChecks []map[string]any
	if len(dc) > 0 {
		decisiveChecks = dc
	}
	var decisiveCheck map[string]any
	if len(dc) > 0 {
		decisiveCheck = dc[0]
	}
	// 三字段同走 NormalizeNullish（见上方 pathBrokenAt 处注释：I3 归一 + hollow-TP 门）。
	var san *string
	if v, ok := data["sanitization_found"].(string); ok {
		san = contract.NormalizeNullish(v)
	}
	var fix *string
	if v, ok := data["suggested_fix"].(string); ok {
		fix = contract.NormalizeNullish(v)
	}
	var payload *string
	if v, ok := data["exploit_payload"].(string); ok {
		payload = contract.NormalizeNullish(v)
	}
	// 开发者视角字段(B1)同走 NormalizeNullish:LLM 在该填 null 处写 "null"/"无" 是常态,
	// 不归一会让报告显出一段写着 null 的「给开发的说明」。
	var devSummary *string
	if v, ok := data["dev_summary"].(string); ok {
		devSummary = contract.NormalizeNullish(v)
	}
	var designNote *string
	if v, ok := data["design_note"].(string); ok {
		designNote = contract.NormalizeNullish(v)
	}
	result := contract.JudgeResult{
		AlertID:    strOr(sliced, "alert_id", ""),
		Bughash:    strOr(sliced, "bughash", ""),
		CweID:      strOr(sliced, "cwe_id", ""),
		Verdict:    VerdictOf(disposition),
		Reasoning:  strOr(data, "reasoning", ""),
		Confidence: conf,
		ExploitPath: contract.ExploitPath{
			EntryPoint:            epEntry,
			DataFlow:              epDF,
			SinkReached:           boolVal(epMap, "sink_reached", false),
			AttackerControlAtSink: strOr(epMap, "attacker_control_at_sink", "none"),
			PathBrokenAt:          pathBrokenAt,
			TaintSource:           taintSource,
			SinkEvidence:          sinkEvidence,
		},
		ModelUsed:                model,
		ControlFlowMutex:         boolVal(sliced, "control_flow_mutex", false),
		ActualVulnerabilityType:  actualFirst,
		ActualVulnerabilityTypes: actual,
		TypeMismatchTypes:        orNil(mismatch),
		BuriedTypes:              buried,
		Severity:                 sevPtr,
		SeverityRationale:        sevRat,
		DevSummary:               devSummary,
		DesignNote:               designNote,
		SanitizationFound:        san,
		SuggestedFix:             fix,
		ExploitPayload:           payload,
		DecisiveCheck:            decisiveCheck,
		DecisiveChecks:           decisiveChecks,
	}
	if disposition != "" {
		d := disposition
		result.Disposition = &d
	}
	return result, nil
}

// --- map access helpers (mirror Python data.get defaults) ---

func strOr(m map[string]any, k, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return def
}
func anyList(m map[string]any, k string) []any {
	if m == nil {
		return nil
	}
	if v, ok := m[k].([]any); ok {
		return v
	}
	return nil
}
func intVal(m map[string]any, k string, def int) int {
	if v, ok := m[k].(float64); ok {
		return int(v)
	}
	if v, ok := m[k].(int); ok {
		return v
	}
	return def
}
func boolVal(m map[string]any, k string, def bool) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return def
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
func orNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
