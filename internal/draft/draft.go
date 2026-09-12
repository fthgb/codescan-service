package draft

import (
	"encoding/json"
	"regexp"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/slice"
)

// draft.go — 移植自 appsec/draft.py（确定性 per-hop analysis drafts）+ appsec/nodes/draft.py（薄壳）。
//
// DRAFT_MODE cheap tier：每个 hop 产出一个结构化 draft（role + vuln_candidates + note + evidence_facts）。
// judge 把 draft 当线索（非判决），避免 Q5/Q7 过度信任守卫。
//
// 铁律 D：每个信号都从切片已有 ground truth 派生（Spring bindings / sanitizer-style names /
// extractable guards / sink APIs from CWE taint model）——ZERO LLM，zero cost。
// RC-A re-concat bypass 检测与 verifier 共享（slice.DetectGuardVariableBypass），无 drift。

// sourceMarkers mirrors draft.py:_SOURCE_MARKERS — Spring request-binding markers
// that make a function an attacker-facing source.
var sourceMarkers = []string{
	"@RequestParam", "@PathVariable", "@RequestBody", "MultipartFile",
	"getParameter", "@RequestPart", "getOriginalFilename",
}

// sinkTokenRe extracts bare API tokens from a taint_model sink phrase.
var sinkTokenRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_.]+`)

// excludedSinkTokens are too generic to be meaningful sink tokens.
var excludedSinkTokens = map[string]bool{
	"path": true, "file": true, "string": true, "name": true,
}

func isSource(body string) bool {
	for _, mk := range sourceMarkers {
		if strings.Contains(body, mk) {
			return true
		}
	}
	return false
}

func isSanitizer(name string, body string, guardSources map[string]bool) bool {
	low := strings.ToLower(name)
	// sanitizerHints 复用（slice 包导出的小写未导出，这里用本地副本对齐 draft.py:_SANITIZER_HINTS）
	for _, h := range sanitizerHintsLocal {
		if strings.Contains(low, h) {
			return true
		}
	}
	return guardSources[name]
}

// sanitizerHintsLocal mirrors slicer._SANITIZER_HINTS (draft.py imports it).
// Kept local to avoid exporting slice.sanitizerHints; values are identical.
var sanitizerHintsLocal = []string{
	"sanitize", "filter", "escape", "validate",
	"encode", "clean", "safe", "check",
}

func sinkAPIs(cweConfig contract.CweConfig) []string {
	if len(cweConfig.TaintModel) == 0 {
		return nil
	}
	var tm struct {
		Sinks []string `json:"sinks"`
	}
	if err := json.Unmarshal(cweConfig.TaintModel, &tm); err != nil {
		return nil
	}
	var toks []string
	for _, s := range tm.Sinks {
		for _, t := range sinkTokenRe.FindAllString(s, -1) {
			if len(t) >= 4 && !excludedSinkTokens[strings.ToLower(t)] {
				toks = append(toks, t)
			}
		}
	}
	return toks
}

func isSink(body string, sinkTokens []string) bool {
	for _, tok := range sinkTokens {
		if strings.Contains(body, tok) {
			return true
		}
	}
	return false
}

func firstSinkCall(body string, sinkTokens []string) string {
	for _, tok := range sinkTokens {
		if strings.Contains(body, tok) {
			return tok
		}
	}
	return ""
}

// DraftSlice produces one draft per hop. Pure & deterministic — safe to call on every alert.
//
// Role precedence: source (entry binding) > sanitizer (guard) > sink (dangerous API) > passthrough.
// vuln_candidates = declared type + its ADJACENCY (same-flow neighbour classes).
// RC-A re-concat bypass detection shared with the verifier (slice.DetectGuardVariableBypass).
func DraftSlice(sliced map[string]any, cweConfig contract.CweConfig) []contract.HopDraft {
	hops := hopsOf(sliced)
	if len(hops) == 0 {
		return []contract.HopDraft{}
	}

	declared := strings.TrimSpace(strVal(sliced, "vulnerability_type"))
	candidates := []string{}
	if declared != "" && declared != "unknown" {
		candidates = append(candidates, declared)
	}
	for _, t := range cweConfig.Adjacency {
		if t != "" {
			candidates = append(candidates, t)
		}
	}

	guardSources := map[string]bool{}
	for _, c := range slice.ExtractSanitizersFromSlice(sliced) {
		if s, ok := c["source"].(string); ok && s != "" {
			guardSources[s] = true
		}
	}
	sinkTokens := sinkAPIs(cweConfig)
	bypass := slice.DetectGuardVariableBypass(sliced)

	drafts := []contract.HopDraft{}
	for _, h := range hops {
		body, _ := h["function_body"].(string)
		name := strVal(h, "function_name")
		idx := intVal(h, "hop_index")

		var role, note string
		evidenceFacts := []map[string]any{}

		if isSource(body) {
			role = "source"
			note = "攻击者可控输入入口（请求参数/路径/上传）。"
		} else if isSanitizer(name, body, guardSources) {
			role = "sanitizer"
			note = "疑似净化/守卫 —— 其有效性不可仅凭存在就认定，须核实污点值确实流经它且无法绕过（关键判断见否证探针）。"
		} else if isSink(body, sinkTokens) {
			sinkCall := firstSinkCall(body, sinkTokens)
			role = "sink"
			note = "危险操作（函数体已完整展示）：污点值在此被使用；若本跳内无净化，污点直达 sink——确认到达此处的值是否仍可控。"
			if sinkCall != "" {
				evidenceFacts = append(evidenceFacts, map[string]any{
					"sink_call": sinkCall, "relation": "call",
				})
			}
		} else {
			role = "passthrough"
			note = "传递/辅助函数；核实是否在此重新引入或绕过净化。"
		}

		// RC-A re-concat: if this is the hop where the sanitizer assignment lives
		// and the raw taint is re-concatenated downstream, flag it.
		if bypass != nil {
			if by, _ := bypass["by"].(string); by == name {
				note += "（⚠ 净化后变量又与原始污点拼接/共用进 sink 喂值，守卫失效 —— 见否证探针）"
				san, _ := bypass["sanitizer"].(string)
				reason, _ := bypass["reason"].(string)
				evidenceFacts = append(evidenceFacts, map[string]any{
					"relation":  "bypass_guard",
					"sanitizer": san,
					"reason":    reason,
				})
			}
		}

		drafts = append(drafts, contract.HopDraft{
			HopIndex:       idx,
			FunctionName:   name,
			Role:           role,
			VulnCandidates: candidates,
			Note:           note,
			EvidenceFacts:  evidenceFacts,
		})
	}
	return drafts
}

// DraftForJudge mirrors nodes/draft.py:draft_for_judge.
// gate: draftMode=="off" → return sliced unchanged. "llm" → fallback deterministic.
// fail-open: any panic → sliced draft-less.
func DraftForJudge(sliced *contract.SlicedContext, cweConfig contract.CweConfig, draftMode string) *contract.SlicedContext {
	if draftMode == "off" {
		return sliced
	}
	// mode == "llm": July tool-model tier (placeholder) -> fall back to deterministic.
	defer func() {
		if r := recover(); r != nil {
			sliced.Drafts = []contract.HopDraft{}
		}
	}()
	slicedMap := slicedContextToMap(sliced)
	sliced.Drafts = DraftSlice(slicedMap, cweConfig)
	return sliced
}

// --- helpers ---

func strVal(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func intVal(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func slicedContextToMap(s *contract.SlicedContext) map[string]any {
	if s == nil {
		return nil
	}
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// hopsOf tolerates both []map[string]any (focused) and []any (JSON-roundtripped) shapes.
func hopsOf(sliced map[string]any) []map[string]any {
	switch v := sliced["hops"].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, h := range v {
			if m, ok := h.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}
