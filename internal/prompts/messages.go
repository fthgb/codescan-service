package prompts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"appsecgo/internal/contract"
)

// This file 1:1-mirrors the RENDERING helpers of appsec/prompts.py (safe_code_fence,
// lined_code, _fmt_evidence_facts, _cwe_layer, _secondary_cwe_layer, adjacency_layer,
// _render_app_context, _draft_layer). Chinese strings are byte-exact; the parity
// golden (testdata/golden/judge/*/prompt_golden.json) is the final gate.

var backtickRe = regexp.MustCompile("`+")

// safeCodeFence mirrors prompts.py:safe_code_fence: max(3, longest_run+1).
func safeCodeFence(text string) string {
	longest := 0
	for _, m := range backtickRe.FindAllString(text, -1) {
		if len(m) > longest {
			longest = len(m)
		}
	}
	n := 3
	if longest+1 > n {
		n = longest + 1
	}
	return strings.Repeat("`", n)
}

// SafeCodeFence 是 safeCodeFence 的导出别名，供 agentic 包复用（enrichUserPrompt 拼 code fence）。
func SafeCodeFence(s string) string { return safeCodeFence(s) }

// splitLines mirrors Python str.splitlines(): splits on \r\n, \r, \n (ASCII subset;
// \v\f\x1c\x1d\x1e\x85   omitted — not expected in code bodies, golden
// catches any divergence). A trailing line boundary does NOT yield a trailing empty
// element; a leading/middle boundary does (verified vs Python semantics). "" -> nil.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\r' {
			out = append(out, s[start:i])
			if c == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				i++ // consume the \n of a \r\n pair
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// linedCode mirrors prompts.py:lined_code.
func linedCode(body string) string {
	if body == "" {
		return ""
	}
	lines := splitLines(body)
	out := make([]string, len(lines))
	for i, ln := range lines {
		out[i] = fmt.Sprintf("%d. %s", i+1, ln)
	}
	return strings.Join(out, "\n")
}

// truthy mirrors Python's truthiness for the JSON-derived values _fmt_evidence_facts
// inspects (None->false, ""->false, 0/false->false, empty list/dict->false, else true).
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

// fmtEvidenceFacts mirrors prompts.py:_fmt_evidence_facts.
func fmtEvidenceFacts(facts []map[string]any) string {
	if len(facts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(facts))
	for _, f := range facts {
		rel, _ := f["relation"].(string)
		scVal, scHas := f["sink_call"]
		switch {
		case truthy(scVal):
			parts = append(parts, fmt.Sprintf("%s: %v", rel, scVal))
		case truthy(f["sanitized_var"]):
			parts = append(parts, fmt.Sprintf("%s: %v+%v->%v", rel,
				f["sanitized_var"], f["taint_var"], f["sink_var"]))
		case truthy(f["source_var"]) && (!scHas || scVal == nil):
			// Python: elif f.get("source_var") and f.get("sink_call") is None:
			parts = append(parts, fmt.Sprintf("%s: %v", rel, f["source_var"]))
		default:
			parts = append(parts, pyMarshal(f))
		}
	}
	return " 【事实：" + strings.Join(parts, "；") + "】"
}

// cweLayer mirrors prompts.py:_cwe_layer. taint_model via pyMarshal (Python
// json.dumps ensure_ascii=False, default separators) — TaintModel is json.RawMessage
// preserving the registry file's field order; nil -> "{}" matches Python's
// cfg.get('taint_model', {}) default.
func cweLayer(cfg contract.CweConfig) string {
	tm := cfg.TaintModel
	if len(tm) == 0 {
		tm = json.RawMessage("{}")
	}
	return fmt.Sprintf("## 漏洞专业知识：%s\n%s\n污点模型：%s\n过滤检查项：\n%s",
		cfg.CweID, cfg.LongDesc, pyMarshal(tm), cfg.FilterHints)
}

// unregisteredCweFallbackLayer is the ③-d 创可贴: when the filed CWE is not in the
// registry (ConfigForSlug returned a zero-value CweConfig, CweID==""), inject a
// first-principles full-class evaluation layer instead of cweLayer's empty shell
// ("## 漏洞专业知识：\n\n污点模型：{}\n"). Stops the LLM judging blind on unregistered
// or mislabelled CWEs (B2: CWE-915 actually IDOR). Vague nudge only — the prompt is
// taint-flow-only with no structural slot for access control; ③-e's signal-driven
// strategy key_questions is the structural fix. 创可贴, not a ③-e substitute.
func unregisteredCweFallbackLayer() string {
	return "## 漏洞专业知识：（声明类别未标定）\n" +
		"本告警声明的漏洞类别未在专家库登记（CweID 为空），可能因上游规则贴错 CWE 或类别未覆盖。" +
		"不要因专家层缺失就裸判——按第一性原理全类别评估这条数据流：\n" +
		"- 污点流：SQL 注入（#{} vs ${} / 拼接）、XSS、路径穿越、命令注入、反序列化、SSRF、" +
		"文件上传、XXE——检查 source→sink 是否存在可控数据流及有效守卫。\n" +
		"- 访问控制：若数据流涉及按标识符（id/订单号/文档号/资源键）查询或修改资源，" +
		"评估端点是否校验调用者对该资源的所有权/鉴权（@PreAuthorize/@Secured/owner 比对/" +
		"SecurityContext）；缺失即为 IDOR/越权（CWE-639/862/863）。\n" +
		"若声明类型不成立但另一类成立，在 reasoning 点名真实类别，并按 P6 设置 " +
		"actual_vulnerability_type（不在本层加载列表的类型会触发人工复核 banner）。\n"
}

// secondaryCweLayer mirrors prompts.py:_secondary_cwe_layer.
func secondaryCweLayer(cfg contract.CweConfig) string {
	return "## 同一 sink 还可能构成：" + cfg.CweID + "\n声明类型成立与否，这个 sink 同时可能造成下列漏洞 —— 一并评估；若成立，在 reasoning 点名、并按 P6 用 actual_vulnerability_type 标注最严重的真实类别。\n" +
		cweLayer(cfg)
}

// adjacencyLayer mirrors type_coverage.adjacency_layer(declared_cfg). allCfgs is
// reg.AllConfigs() (judge-resolved); the Go port does NOT touch cwereg. Verbatim
// header + per-neighbor adjacent_check, "- " prefixed, order = declared adjacency.
func adjacencyLayer(declared contract.CweConfig, allCfgs []contract.CweConfig) string {
	targets := declared.Adjacency
	if len(targets) == 0 {
		return ""
	}
	bySlug := map[string]contract.CweConfig{}
	for _, c := range allCfgs {
		if vt := strings.ToLower(c.VulnerabilityType); vt != "" {
			bySlug[vt] = c // last wins (Python dict comprehension)
		}
	}
	lines := []string{}
	for _, t := range targets {
		nc, ok := bySlug[strings.ToLower(t)]
		check := ""
		if ok {
			check = nc.AdjacentCheck
		}
		if check != "" {
			lines = append(lines, "- "+check)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "## 相邻漏洞类（同一条数据流）\n" +
		"若声明类型不成立，检查同一条污点流是否反而能造成下列之一 —— 若能，不要返回把它埋掉的裸 " +
		"false_positive；在 reasoning 中点名真实类别，并设置 actual_vulnerability_type（P6）。\n" +
		strings.Join(lines, "\n")
}

// renderAppContext mirrors prompts.py:_render_app_context. ctx is the raw
// app_context map. input.json is dumped sort_keys=True, so Python's dict insertion
// order == alphabetical; we sort scalar/trust_boundaries keys to match. (All current
// fixtures have empty app_context, rendering just "## 应用上下文".)
func RenderAppContext(ctx map[string]any) string {
	parts := []string{"## 应用上下文"}
	special := map[string]bool{
		"intended_behaviors": true, "not_a_vulnerability": true,
		"trust_boundaries": true, "requires_remote_trigger": true, "security_model": true,
	}
	var scalarKeys []string
	others := map[string]any{}
	for k, v := range ctx {
		if special[k] {
			continue
		}
		if _, isList := v.([]any); isList {
			others[k] = v
			continue
		}
		if _, isMap := v.(map[string]any); isMap {
			others[k] = v
			continue
		}
		scalarKeys = append(scalarKeys, k)
	}
	sort.Strings(scalarKeys)
	if len(scalarKeys) > 0 {
		kv := make([]string, len(scalarKeys))
		for i, k := range scalarKeys {
			kv[i] = fmt.Sprintf("%s=%v", k, ctx[k])
		}
		parts = append(parts, strings.Join(kv, ", "))
	}
	if len(others) > 0 {
		parts = append(parts, pyMarshal(others))
	}
	if ib, _ := ctx["intended_behaviors"].([]any); len(ib) > 0 {
		lines := make([]string, len(ib))
		for i, b := range ib {
			lines[i] = fmt.Sprintf("- %v", b)
		}
		parts = append(parts, "预期行为（设计使然的特性 features，不是漏洞）：\n"+strings.Join(lines, "\n"))
	}
	if nv, _ := ctx["not_a_vulnerability"].([]any); len(nv) > 0 {
		lines := make([]string, len(nv))
		for i, b := range nv {
			lines[i] = fmt.Sprintf("- %v", b)
		}
		parts = append(parts, "不要把以下当作漏洞（有意为之 / 超出范围）：\n"+strings.Join(lines, "\n"))
	}
	if tb, _ := ctx["trust_boundaries"].(map[string]any); len(tb) > 0 {
		keys := make([]string, 0, len(tb))
		for k := range tb {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		lines := make([]string, len(keys))
		for i, k := range keys {
			lines[i] = fmt.Sprintf("- %s: %v", k, tb[k])
		}
		parts = append(parts, "信任边界：\n"+strings.Join(lines, "\n"))
	}
	if exp, ok := ctx["exposure"].(string); ok && exp != "" {
		parts = append(parts, fmt.Sprintf("威胁模型：exposure=%s。据此判断可达性 —— 处于该暴露面的攻击者"+
			"够不到的真漏洞应判 out_of_scope，而不是给出自信的发现。", exp))
	}
	// requires_remote_trigger: Python `if ctx.get(...) is False:` — only literal False.
	if rt, ok := ctx["requires_remote_trigger"].(bool); ok && !rt {
		parts = append(parts, "注意：这是本地访问的工具/库 —— 只标远程（REMOTE）攻击者可利用的问题；"+
			"本地用户的文件/CLI/文件系统访问不是漏洞。")
	}
	if sm, ok := ctx["security_model"].(string); ok && sm != "" {
		parts = append(parts, fmt.Sprintf("安全模型：%s", sm))
	}
	return strings.Join(parts, "\n")
}

// draftLayer mirrors prompts.py:_draft_layer.
func draftLayer(drafts []map[string]any) string {
	if len(drafts) == 0 {
		return ""
	}
	roleCN := map[string]string{
		"source": "输入源", "sanitizer": "净化/守卫", "sink": "危险操作",
		"passthrough": "传递", "unknown": "未知",
	}
	lines := make([]string, 0, len(drafts))
	for _, d := range drafts {
		role, _ := d["role"].(string)
		role = orDefault(roleCN[role], role, role)
		cands, _ := d["vuln_candidates"].([]any)
		candStr := ""
		if len(cands) > 0 {
			cs := make([]string, len(cands))
			for i, c := range cands {
				cs[i] = fmt.Sprintf("%v", c)
			}
			candStr = fmt.Sprintf("（候选漏洞：%s）", strings.Join(cs, "/"))
		}
		facts, _ := d["evidence_facts"].([]any)
		factMaps := make([]map[string]any, 0, len(facts))
		for _, f := range facts {
			if fm, ok := f.(map[string]any); ok {
				factMaps = append(factMaps, fm)
			}
		}
		note, _ := d["note"].(string)
		hi, _ := d["hop_index"]
		fn, _ := d["function_name"].(string)
		lines = append(lines, fmt.Sprintf("- hop %v %v：%v%v —— %v%v", hi, fn, role, candStr, note, fmtEvidenceFacts(factMaps)))
	}
	return "## 数据流逐函数分析草稿（确定性推导，供参考、非判决）\n" +
		"下面是对每个函数在本数据流中所起作用的初步标注。它是线索，不是结论 —— 仍以第一性原理" +
		"和你引用的决定性事实为准；尤其对标为「净化/守卫」的函数，不要因为它存在就判安全，须核实可绕过性。\n" +
		strings.Join(lines, "\n")
}

func orDefault(mapped, fallback, def string) string {
	if mapped != "" {
		return mapped
	}
	if fallback != "" {
		return fallback
	}
	return def
}

// hopAsMap extracts a hop as a map, tolerating both []any (JSON-unmarshal path)
// and []map[string]any (Go-constructed path), mirroring cwereg.hopsOf's dual-shape
// tolerance without importing cwereg.
func hopMaps(sliced map[string]any) []map[string]any {
	raw, ok := sliced["hops"]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
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

// asMap extracts a map[string]any from a sliced field that may be nil/absent.
func asMap(sliced map[string]any, key string) map[string]any {
	if v, ok := sliced[key].(map[string]any); ok {
		return v
	}
	return nil
}

// forwardReachableLayer renders the §8.1 structured truncation contract as a
// prompt section: tells the judge structurally WHAT is missing (truncated /
// uncertain 1-hop frontier / method dispatch) so don't-demote-on-unknown
// (raptor reachability.py:3638-3642) is applied structurally — not by hoping
// the LLM reads the free-text enrichment_note prose. Returns "" when
// forward_reachable is absent or all-zero: the parity guard (the 4 SQLi
// fixtures carry no forward_reachable key in input.json → nil → "" → bytes
// unchanged). Augments (does not replace) enrichment_note — the prose stays
// as a human-readable supplement; deleting it is a later phase (needs corpus
// calibration) so existing byte assertions hold.
func forwardReachableLayer(sliced map[string]any) string {
	fr, ok := sliced["forward_reachable"].(map[string]any)
	if !ok || len(fr) == 0 {
		return ""
	}
	truncated, _ := fr["truncated"].(bool)
	hasDispatch, _ := fr["has_method_dispatch"].(bool)
	uncertainAny, _ := fr["uncertain"].([]any)
	var parts []string
	if truncated {
		parts = append(parts, "⚠ 切片因预算上限截断，确定可达集可能不完整；未展开的 callee 不等于不存在。")
	}
	if len(uncertainAny) > 0 {
		names := []string{}
		for _, u := range uncertainAny {
			if um, ok := u.(map[string]any); ok {
				if n, _ := um["name"].(string); n != "" {
					names = append(names, n)
				}
			}
		}
		sort.Strings(names)
		// 名单渲染截断（2026-09-07，与 slice/enrich.go 同口径 contract.MaxUnresolvedNoteNames）。
		// 70+ 名单会被 judge 读成逐个验证指令（探索翻倍驱动之一，2026-09-06 根因报告 §1.4）；
		// 截后点名「整体核实」。结构化 ForwardReachable.Uncertain 保持全量（守卫/rejudge 消费）。
		shown := names
		omitted := ""
		if len(names) > contract.MaxUnresolvedNoteNames {
			shown = names[:contract.MaxUnresolvedNoteNames]
			omitted = fmt.Sprintf("（其余 %d 个同类引用已略——与上同性质，整体核实即可，不必逐个验证。）", len(names)-contract.MaxUnresolvedNoteNames)
		}
		parts = append(parts, "⚠ 以下仓库内 callee 被引用但未解析入切片（不确定一跳前沿）："+strings.Join(shown, ", ")+
			omitted+
			"。\n**don't-demote 规则**：若确定可达前沿为空、而这些 Uncertain callee 可能位于利用路径，severity 不该降级——诚实判 uncertain（P3），不要因为没看见守卫就降 FP（那是切片缺口伪装的在场守卫）。")
	}
	if hasDispatch {
		parts = append(parts, "⚠ 源含方法分派（self.foo()/未解析名链），callee 集不完整；按不完全闭包处理。")
	}
	if len(parts) == 0 {
		return ""
	}
	return "## 切片可达性契约（结构化）\n" + strings.Join(parts, "\n")
}

// instanceLayer mirrors prompts.py:_instance_layer (:360-397). app_context +
// SAST 发现 header + 源类上下文 (json) + per-hop `### 跳 N ...` (safe_code_fence +
// lined_code) + degraded/enrichment_note/control_flow_mutex/drafts/decisive_facts.
func instanceLayer(sliced, appCtx map[string]any) string {
	parts := []string{
		RenderAppContext(appCtx),
	}
	vulnType, _ := sliced["vulnerability_type"].(string)
	entry, _ := sliced["entry_point_signature"].(string)
	parts = append(parts, fmt.Sprintf("## SAST 发现：%s entry=%s", vulnType, entry))
	if scc := asMap(sliced, "source_class_context"); len(scc) > 0 {
		// Python dict 插入序（= pydantic model_dump 声明序）：class_name, class_annotations,
		// parent_class, class_level_path。Go map 无序，用 pyMarshalKeys 固定顺序 byte-exact
		// 匹配 Python json.dumps（保插入序，无 sort_keys）。scan e2e trace golden 证实此序。
		parts = append(parts, "## 源类上下文\n"+pyMarshalKeys(scc, []string{"class_name", "class_annotations", "parent_class", "class_level_path"}))
	}
	for _, h := range hopMaps(sliced) {
		body, _ := h["function_body"].(string)
		fence := safeCodeFence(body)
		hi := h["hop_index"] // int (Go-constructed) or float64 (JSON)
		fp, _ := h["file_path"].(string)
		lineRange := h["line_range"] // []any or []float64-ish; first element
		fn, _ := h["function_name"].(string)
		tv, _ := h["taint_variable"].(string)
		parts = append(parts, fmt.Sprintf(
			"### 跳 %v %s:%v fn=%s taint_var=%v"+
				"（函数体已完整展示，请直接基于其逐行推理，不得声称未展示）\n"+
				"%sjava\n%s\n%s",
			hi, fp, firstLineRange(lineRange), fn, tv, fence, linedCode(body), fence))
	}
	if truthy(sliced["degraded"]) {
		parts = append(parts, "注意：上下文已降级（超出 token 预算）；confidence 上限取 7。")
	}
	if en, ok := sliced["enrichment_note"].(string); ok && en != "" {
		parts = append(parts, "注意："+en)
	}
	if fr := forwardReachableLayer(sliced); fr != "" {
		parts = append(parts, fr)
	}
	if cf, ok := sliced["control_flow_mutex"].(bool); ok && cf {
		parts = append(parts, ControlFlowMutexHint)
	}
	if drafts, _ := sliced["drafts"].([]any); len(drafts) > 0 {
		dms := make([]map[string]any, 0, len(drafts))
		for _, d := range drafts {
			if dm, ok := d.(map[string]any); ok {
				dms = append(dms, dm)
			}
		}
		if dl := draftLayer(dms); dl != "" {
			parts = append(parts, dl)
		}
	}
	// decisive_facts: sink_param_style hint (A1 adapter ground truth).
	df := asMap(sliced, "decisive_facts")
	if df != nil {
		if styleRaw, ok := df["sink_param_style"]; ok {
			style, _ := styleRaw.(string)
			hint := sinkParamStyleHint(style)
			if hint != "" {
				parts = append(parts, fmt.Sprintf(
					"## 决定性事实（适配器提取，ground truth）\n- sink 参数化形态: %s —— %s",
					style, hint))
			}
		}
	}
	return strings.Join(parts, "\n\n")
}

// sinkParamStyleHint mirrors the _hint dict in prompts.py:_instance_layer (:391-395).
func sinkParamStyleHint(style string) string {
	switch style {
	case "concat":
		return "${} 字符串替换或原生 Statement 拼接，值拼入 SQL 文本"
	case "parameterized":
		return "#{} 参数化绑定（MyBatis PreparedStatement，框架契约保证，执行器在 org.apache.ibatis 非切片可见但契约绑定），值不入 SQL 文本"
	case "unknown":
		return "执行器/占位符绑定不在切片，无法判定；须 read_file 核证 mapper 的 ${}/#{} 或判 uncertain，不得在证据缺失时自信判决"
	}
	return ""
}

// firstLineRange returns h['line_range'][0] rendered as Python would (int-like;
// float64 2 -> "2"). Absent/empty -> "?". Python raises IndexError if line_range
// is missing, but fixtures always carry it; the safe default avoids a panic.
func firstLineRange(v any) any {
	switch lr := v.(type) {
	case []any:
		if len(lr) > 0 {
			return lr[0]
		}
	case []float64:
		if len(lr) > 0 {
			return lr[0]
		}
	case []int:
		if len(lr) > 0 {
			return lr[0]
		}
	}
	return "?"
}

// perAxisGatePreamble 是评估视角段的判决闸前言（M2.1，spec §3.2 locus α，救 #26）。
// 仅在 ≥1 **非 AlwaysOn**（切片事实驱动，非 general 兜底）strategy 带 KeyQuestions 上桌时
// 渲染一次。闸语义：逼 LLM 对每个上桌视角的必答步骤给显式结论（带 file:line），任一视角
// 必答步骤未答完前不得以「声明类型不成立」为由下 likely_fp/false_positive——该视角若成立
// 则判 TP/uncertain，不成立要说清为什么。#26 的坑：prompt 已带 ## 评估视角：missing_auth
// + 必答步骤，LLM 忽略它只评 filed SQLi 轴 → likely_fp；缺的不是视角（已上桌）是逼评的闸。
//
// verdict 字符串（likely_fp/false_positive/TP）均为 5 值枚举真值（LESSONS:536 / runs 实证，
// 真值是 likely_tp 非 likely_true_positive），非翻译比较（铁律 E）。不动 constants.go:76
// 「二者并行」原则（taint-flow 精神，留原处）；闸落 perspective 段，分层清晰。
//
// **触发判定补 AlwaysOn 过滤（GR-8 核实 2026-08-27）**：spec §3.2 line 82 literal 写
// 「≥1 strategy 带 KeyQuestions」，但 general（data/strategies/general.json）是 AlwaysOn
// + 带 3 KeyQuestions，且 Select（registry.go:130-133）对每告警恒前置 general → SQLi-only
// 告警（general+taint_flow）也带 `## 评估视角：general` 段。若按 literal「≥1 KeyQuestions」
// 触发闸，SQLi-only 告警会被闸 → 违 spec line 83/187「SQLi-only 不变」+ 用户 endorsed
// 「SQLi-only 告警零影响」（α 优于 β 之理）。闸文本自身「切片事实驱动上桌」已排除 general
// （AlwaysOn 非切片驱动），故此处补 AlwaysOn 过滤使触发与闸文本 + scope claim + endorsed
// 理由一致。general 段仍渲染（KeyQuestions 作上下文），仅不触发闸。SQLi-only（无切片驱动
// 视角）→ 闸不出现 → prompt 字节不变（判据 2 on⊆off / GR-1）；#26（general+missing_auth）
// → missing_auth 非 AlwaysOn → 闸出现。
const perAxisGatePreamble = "**评估视角判决闸**：下列评估视角由切片事实驱动上桌。无论声明类型是否成立，你**必须**在 reasoning 中对每个视角的必答步骤给显式结论（成立 / 不成立，带 file:line 锚点）；任一视角的必答步骤未答完前，**不得以声明类型不成立为由下 likely_fp / false_positive**——该视角若成立则判 TP / uncertain，不成立要说清为什么。"

// strategyLayer 渲染选中的 strategy 评估视角段（perAxisGatePreamble + key_questions +
// prompt_addendum）。③-e：治 B2 错类漏报（filed CWE 贴错时专家层空壳）——评估视角由切片
// token 驱动竞争上桌，与 filed CWE 正交。parity 守卫（用户盯点：nil 传播不被吞成默认）：
//   - nil/空 strategies → 返空串（绝不默认填 general）→ 闸亦不出现。
//   - 无 key_questions 的 strategy（taint_flow）→ 跳过渲染（其评估本就是 constants.go:64
//     的 taint-flow 强制步骤，加槽位会破 4 SQLi parity fixture，plan §4.2）。
//   - 闸触发 = ≥1 **非 AlwaysOn** 带 key_questions 的 strategy（切片驱动视角，见
//     perAxisGatePreamble 头注 GR-8 核实）；general（AlwaysOn）虽带 KeyQuestions 但不触发闸，
//     其段仍渲染作上下文。闸在首个视角段前渲染一次（非逐视角重复）。
func strategyLayer(strategies []contract.Strategy) string {
	var b strings.Builder
	// 闸触发判定（M2.1 locus α）：仅当 ≥1 非 AlwaysOn（切片事实驱动）带 KeyQuestions
	// strategy 上桌时渲染闸。补 AlwaysOn 过滤使 SQLi-only（general+taint_flow）不被闸
	// （保 spec「SQLi-only 不变」+ 用户 endorsed「SQLi-only 告警零影响」）。
	hasSliceDrivenPerspective := false
	for _, s := range strategies {
		if len(s.KeyQuestions) == 0 || s.AlwaysOn {
			continue
		}
		hasSliceDrivenPerspective = true
		break
	}
	gateRendered := false
	for _, s := range strategies {
		if len(s.KeyQuestions) == 0 {
			continue
		}
		if hasSliceDrivenPerspective && !gateRendered {
			b.WriteString("\n\n" + perAxisGatePreamble)
			gateRendered = true
		}
		b.WriteString("\n\n## 评估视角：" + s.Name + "\n")
		b.WriteString(s.PromptAddendum + "\n\n必答步骤：\n")
		for i, q := range s.KeyQuestions {
			fmt.Fprintf(&b, "%d. %s\n", i+1, q)
		}
	}
	return b.String()
}

// BuildMessages mirrors prompts.py:build_messages (:505-532). Returns OpenAI-shape
// [system, user]. allCfgs = reg.AllConfigs() (judge-resolved); prompts does NOT
// touch cwereg. agentic drops the adjacency layer and appends _AGENTIC_SUFFIX.
// engineOn=true（engine 接入）时 agentic 分支额外追加 EngineToolsSuffix（appsecgo 专有，
// Python 无；列出 5 件 engine 工具 + 覆盖 AgenticSuffix 的 read_file-MyBatis 指令）。
// engineOn=false/off 时不追加 → off prompt 字节不变（判据2 on⊆off 安全；parity 守卫）。
func BuildMessages(sliced, appCtx map[string]any, cweConfig contract.CweConfig,
	secondary []contract.CweConfig, allCfgs []contract.CweConfig, strategies []contract.Strategy, agentic, engineOn bool) []map[string]any {
	declaredLayer := cweLayer(cweConfig)
	if cweConfig.CweID == "" {
		// ③-d: filed CWE 未在 registry 登记（ConfigForSlug 零值，CweID=""）→ 不渲染
		// cweLayer 的空壳 "## 漏洞专业知识：\n\n污点模型：{}\n"（LLM 无 taint model/filter
		// hints 裸判，B2 错类漏报诱因之一）。注入兜底层按第一性原理全类评估。③-e 的
		// signal-driven strategy key_questions 落地后接管（创可贴 vs 手术，不可互替）。
		declaredLayer = unregisteredCweFallbackLayer()
	}
	// 2026-09-07（spec §三.4）：agentic 模式用 SystemPromptBase（不含 JSON schema）——
	// submit_verdict 工具 schema 是输出契约的唯一权威版本，随 tools 数组每轮在场；
	// 非 agentic（text/single-turn tool）仍用 SystemPrompt（schema 必须在 system prompt）。
	basePrompt := SystemPrompt
	if agentic {
		basePrompt = SystemPromptBase
	}
	systemText := basePrompt + "\n\n" + declaredLayer
	for _, sec := range secondary {
		systemText += "\n\n" + secondaryCweLayer(sec)
	}
	if !agentic {
		if adj := adjacencyLayer(cweConfig, allCfgs); adj != "" {
			systemText += "\n\n" + adj
		}
	} else {
		systemText += AgenticSuffix
		// engine 接入时追加 engine 工具段（覆盖 AgenticSuffix 的 read_file-MyBatis 指令）。
		// off（engineOn=false）不追加 → off prompt 字节不变，判据2 on⊆off 安全。
		if engineOn {
			systemText += EngineToolsSuffix
		}
	}
	// ③-e: strategy 评估视角段 + M2.1 逐轴判决闸。parity 守卫——nil/空 strategies 或全无
	// key_questions（taint_flow）→ strategyLayer 返空串，systemText 字节不变（4 SQLi
	// fixture 路由 taint_flow，parity_test 传 nil）。生产 judge.go:362 调 sr.Select 取真
	// strategies 传入（Step 2b 已翻开，非 nil）→ perspective-bearing 告警上桌视角 + 闸。
	// Steer(F4a-Steer §1.3):按 sliced.authz_coverage.entry_nature 解析 effective
	// addendum。entry_nature 命中 strategy.AddendumOverrides 键 ⇒ 替换 PromptAddendum
	// 为 override(rpc_internal_facade→RPC 可达性框定);en==""/缺键/空值 → 默认 addendum
	// (fail-open:非 rpc 告警 + 未配 override 的 strategy 全走默认 ⇒ 4 SQLi parity 字节不变)。
	// resolved 拷贝 strategies 不污源数据;strategyLayer 签名保纯(渲染无 entry_nature 耦合,铁律 D)。
	en := ""
	if ac, _ := sliced["authz_coverage"].(map[string]any); ac != nil {
		en, _ = ac["entry_nature"].(string)
	}
	resolved := make([]contract.Strategy, len(strategies))
	for i, s := range strategies {
		resolved[i] = s
		if en != "" && s.AddendumOverrides != nil {
			if ov, ok := s.AddendumOverrides[en]; ok && ov != "" {
				resolved[i].PromptAddendum = ov
			}
		}
	}
	if sl := strategyLayer(resolved); sl != "" {
		systemText += sl
	}
	return []map[string]any{
		{"role": "system", "content": systemText},
		{"role": "user", "content": instanceLayer(sliced, appCtx)},
	}
}

// BuildRepairMessages mirrors prompts.py:build_repair_messages (:444-460).
// Truncation uses RuneCountInString (Python len(str) counts code points) and
// rune-slicing (Python raw_text[:8000] is code-point slicing, not byte slicing).
func BuildRepairMessages(rawText string) []map[string]any {
	snippet := rawText
	if n := utf8.RuneCountInString(rawText); n > 8000 {
		snippet = string([]rune(rawText)[:8000]) + "\n... [截断]"
	}
	user := "下面这段文本本应是一个符合此 schema 的 JSON 对象，但格式有误" +
		"（混入了散文、被截断，或有语法错误）。请抽取其本意数据，只返回符合 schema 的合法 JSON。\n\n" +
		"Schema：" + JudgeSchema + "\n\n" +
		"若某字段确实缺失，使用安全默认值（verdict 为 \"uncertain\"、confidence 为 0、" +
		"data_flow 为空）。不要 markdown、不要散文 —— 只要 JSON。\n\n" +
		"格式有误的响应：\n---\n" + snippet + "\n---"
	return []map[string]any{
		{"role": "system", "content": "你负责修复格式有误的 JSON。只输出一个 JSON 对象。"},
		{"role": "user", "content": user},
	}
}

// pyMarshal mirrors Python json.dumps(v, ensure_ascii=False) with default separators
// (', ', ': '). Three parity traps handled (same as internal/vcache.jsonMarshal):
//  1. Encoder.Encode appends '\n' -> TrimRight.
//  2. SetEscapeHTML(false) -> no <>& / U+2028 escaping.
//  3. Go compact has no spaces -> injectPythonSpaces adds ', '/': ' outside strings.
//
// For contract.CweConfig.TaintModel (json.RawMessage) the Encoder calls MarshalJSON,
// which returns the registry file's field-order bytes (compacted by the encoder), so
// the rendered taint_model byte-matches Python's field-order json.dumps.
func pyMarshal(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	return string(pyJSONFormat(b))
}

// pyMarshalKeys serializes a map with a FIXED key order (matching Python dict
// insertion order, which json.dumps preserves). Go map iteration is unordered,
// so for dicts where Python's insertion order matters for byte-shape parity
// (e.g. source_class_context), use this instead of pyMarshal.
func pyMarshalKeys(m map[string]any, keys []string) string {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, _ := json.Marshal(m[k])
		buf.Write(vb)
	}
	buf.WriteByte('}')
	// pyJSONFormat 统一加空格（", "/": "），避免此处手动加致双空格。
	return string(pyJSONFormat(buf.Bytes()))
}

// pyJSONFormat formats Go compact JSON to Python json.dumps default style:
// 1) spaces after structural ,/: outside strings (separators ", "/": ");
// 2) non-ASCII chars inside strings → \uXXXX (ensure_ascii=True).
// Stateful scan tracks in-string + escape to avoid mutating string content.
func pyJSONFormat(b []byte) []byte {
	var out bytes.Buffer
	inStr, escaped := false, false
	for _, r := range string(b) {
		if escaped {
			out.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			out.WriteRune(r)
			escaped = true
			continue
		}
		if r == '"' {
			inStr = !inStr
			out.WriteRune(r)
			continue
		}
		if inStr {
			if r > 127 {
				if r > 0xFFFF {
					r1, r2 := utf16.EncodeRune(r)
					fmt.Fprintf(&out, "\\u%04x\\u%04x", r1, r2)
				} else {
					fmt.Fprintf(&out, "\\u%04x", r)
				}
			} else {
				out.WriteRune(r)
			}
			continue
		}
		if r == ',' || r == ':' {
			out.WriteRune(r)
			out.WriteByte(' ')
			continue
		}
		out.WriteRune(r)
	}
	return out.Bytes()
}

// injectPythonSpaces adds a space after ':' and ',' OUTSIDE string literals,
// matching Python json.dumps default separators (', ', ': '). State machine
// tracking in-string + \" escapes. '{}' / empty unchanged. (Mirror of
// internal/vcache.injectPythonSpaces — duplicated here so internal/prompts stays
// dependency-free on internal/vcache per 铁律 A.)
func injectPythonSpaces(b []byte) []byte {
	var out bytes.Buffer
	inStr := false
	backslashes := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		out.WriteByte(c)
		if c == '\\' {
			backslashes++
			continue
		}
		if c == '"' {
			if backslashes%2 == 0 {
				inStr = !inStr
			}
			backslashes = 0
			continue
		}
		backslashes = 0
		if inStr {
			continue
		}
		if (c == ':' || c == ',') && i+1 < len(b) {
			out.WriteByte(' ')
		}
	}
	return out.Bytes()
}
