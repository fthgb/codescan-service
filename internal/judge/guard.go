package judge

import (
	"fmt"
	"log"
	"os"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
)

// EnforceDecisiveFactKnown mirrors judge.py:_enforce_decisive_fact_known (A1 contract
// guard, pure synchronous, NO LLM). For the declared type ∪ actual types, collect
// required_decisive_facts; if any is "unknown" and verdict != uncertain -> downgrade
// to uncertain + fail_reason="decisive_fact_unknown:<facts>" + missing_info. Only
// downgrades. _rejudge_* (extra LLM) is P3.
func EnforceDecisiveFactKnown(result contract.JudgeResult, sliced map[string]any, reg *cwereg.Registry) contract.JudgeResult {
	declared := strings.ToLower(strOr(sliced, "vulnerability_type", ""))
	required := requiredDecisiveFacts(reg, declared, result.ActualVulnerabilityTypes)
	if len(required) == 0 || result.Verdict == "uncertain" {
		return result
	}
	facts, _ := sliced["decisive_facts"].(map[string]any)
	var unknown []string
	for _, f := range required {
		if v, ok := facts[f].(string); ok && v == "unknown" {
			unknown = append(unknown, f)
		}
	}
	if len(unknown) == 0 {
		return result
	}
	factStr := strings.Join(unknown, ",")
	origDisp := strOr(map[string]any{"d": ptrStr(result.Disposition)}, "d", result.Verdict)
	result.Verdict = "uncertain"
	if result.Confidence > 4 {
		result.Confidence = 4
	}
	fr := "decisive_fact_unknown:" + factStr
	result.FailReason = &fr
	mi := "决定性事实未知（" + factStr + "），不能直接判 " + origDisp + "；须 read_file 核证 mapper 的 ${}/#{} 或降 uncertain（契约守卫：证据缺失时不得自信判决）"
	result.MissingInfo = &mi
	return result
}

// requiredDecisiveFacts 收 declared ∪ actual 类型的 required_decisive_facts（去重、小写、保序）。
// guard（EnforceDecisiveFactKnown）与 rejudge（rejudgeDecisiveFact）共用此函数——
// 同一 required 列表是契约一致性的前提（铁律 B 单一权威：守卫查的 = rejudge 须解决的；
// 两份复制会漂移 → rejudge 解决了守卫没查的 / 反之 → 闭环失灵）。declared 已小写则幂等。
//
// 行为对齐原 EnforceDecisiveFactKnown 内联收集（guard.go:20-47，2026-08-24 抽出）：
// declared 命中的 config + actual 里非 declared 的 config，各自 RequiredDecisiveFacts 去重并入。
func requiredDecisiveFacts(reg *cwereg.Registry, declared string, actualTypes []string) []string {
	if reg == nil {
		return nil // 防御：rejudge/guard 单测用 nil reg 验 fail-open（生产 judge.go:489/511 恒非 nil）
	}
	declared = strings.ToLower(declared)
	required := []string{}
	seen := map[string]bool{}
	addRequired := func(cfg contract.CweConfig) {
		for _, f := range cfg.RequiredDecisiveFacts {
			f = strings.TrimSpace(strings.ToLower(f))
			if f == "" || seen[f] {
				continue
			}
			seen[f] = true
			required = append(required, f)
		}
	}
	for _, c := range reg.AllConfigs() {
		if strings.ToLower(c.VulnerabilityType) == declared {
			addRequired(c)
		}
	}
	for _, t := range actualTypes {
		tl := strings.ToLower(t)
		if tl == declared {
			continue
		}
		for _, c := range reg.AllConfigs() {
			if strings.ToLower(c.VulnerabilityType) == tl {
				addRequired(c)
			}
		}
	}
	return required
}

// EnforceNoBareFp mirrors judge.py:_enforce_no_bare_fp (pure synchronous, NO LLM).
// verdict=false_positive + actual contains a loaded non-declared type -> downgrade
// to uncertain + fail_reason="bare_fp_buries_actual:<types>" + missing_info.
func EnforceNoBareFp(result contract.JudgeResult, sliced map[string]any, reg *cwereg.Registry) contract.JudgeResult {
	if result.Verdict != "false_positive" {
		return result
	}
	declared := strings.ToLower(strOr(sliced, "vulnerability_type", ""))
	mismatch := map[string]bool{}
	for _, t := range result.TypeMismatchTypes {
		mismatch[strings.ToLower(t)] = true
	}
	var otherLoaded []string
	for _, t := range result.ActualVulnerabilityTypes {
		tl := strings.ToLower(t)
		if tl == declared || mismatch[tl] {
			continue
		}
		otherLoaded = append(otherLoaded, t)
	}
	if len(otherLoaded) == 0 {
		return result
	}
	factStr := strings.Join(otherLoaded, ",")
	result.Verdict = "uncertain"
	if result.Confidence > 4 {
		result.Confidence = 4
	}
	fr := "bare_fp_buries_actual:" + factStr
	result.FailReason = &fr
	mi := "你判了 false_positive，但 actual_vulnerability_types 含 " + factStr + "（已加载类型、你自己在 reasoning 里指出的真漏洞）——不得用裸 FP 埋掉真漏洞（应返回 true_positive 或 uncertain）。请改判 TP 或核证为何不是该类。"
	result.MissingInfo = &mi
	return result
}

// EnforceParameterizedSqliTpContradiction (③ 守卫, 2026-08-31, pure synchronous, NO LLM)。
// ③ 把 MyBatis mapper-context #{} 从 "unknown" -> "parameterized"(SQLi-safe)后,
// EnforceDecisiveFactKnown 不再 fire 这些 alert。本守卫兜底**单面 SQLi-TP 与
// parameterized(safe) 矛盾**:verdict==TP 且 sink_param_style=="parameterized"
// 且 actual_vulnerability_types 非空且全为 SQLi 面 -> LLM 在 parameterized(值不入
// SQL 文本)的 sink 上判了 SQLi-TP = 矛盾(over-claim) -> 降 likely_tp(折 uncertain) conf6。
// 多面含非 SQLi 不 fire(TP 可能由非 SQLi 面驱动,blanket 降会压真 authz TP,见
// 2026-08-28-multiface-verdict-binding-wobble)。actual_types 空 不 fire(保守)。
// GREEN impl + 插入点 + §0 实证 见 spec 2026-08-31-sink-param-style-mybatis-semantic-fix-design.md §5。
func EnforceParameterizedSqliTpContradiction(result contract.JudgeResult, sliced map[string]any) contract.JudgeResult {
	if result.Verdict != "true_positive" {
		return result
	}
	facts, _ := sliced["decisive_facts"].(map[string]any)
	if facts == nil {
		return result
	}
	if style, _ := facts["sink_param_style"].(string); style != "parameterized" {
		return result
	}
	types := result.ActualVulnerabilityTypes
	if len(types) == 0 {
		return result // 无法确认单面 SQLi,保守不降(避免误压未知面 TP)
	}
	for _, t := range types {
		if !isSqlInjectionFace(t) {
			return result // 多面含非 SQLi,TP 可能由非 SQLi 驱动,不降(multiface-wobble 防护)
		}
	}
	d := "likely_tp"
	result.Disposition = &d
	result.Verdict = VerdictOf("likely_tp") // -> "uncertain" (5->3 fold, build.go:12-19)
	result.Confidence = 6
	fr := "parameterized_contradicts_sqli_tp"
	result.FailReason = &fr
	mi := "sink 参数化形态为 parameterized（#{} MyBatis PreparedStatement 绑定，值不入 SQL 文本），但 verdict=true_positive 且 actual_vulnerability_types 全为 SQLi 面 —— parameterized 与 SQLi-TP 矛盾（值不入 SQL 文本则无注入）。已降为 likely_tp（conf=6）。若确有注入，须核证 sink 实为 ${} 拼接或原生 Statement（改 sink_param_style）后重判。"
	result.MissingInfo = &mi
	return result
}

// isSqlInjectionFace 判 face 名是否为 SQLi 面。当前 corpus SQLi 面恒为
// "sql_injection"(CWE-89/566 vulnerability_type);若未来 LLM 用 cwe-89/cwe-566
// 命名 SQLi 面,扩此集(从 cwereg 单一权威取,勿硬编码漂移)。
func isSqlInjectionFace(t string) bool {
	return strings.EqualFold(t, "sql_injection")
}

// reachabilityBrokenClaimRe / EnforceReachableSinkClaim / definitiveCallees
// (Crack D guard) reverted on 2026-08-12 after 实证: guard misfired on first
// live run (regex "断裂" matched a legitimate sanitizer claim; naive
// strings.Contains matched the English word "insert"). Target class did not
// appear in the corpus. forward_reachable contract (PrejudgeCalleeReachability)
// retained for future use; the hard demote + rejudge remedy removed.
// See memory crack-d-reachable-callee-empirical.

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// EnforceEvidenceOnTp (根因1 代码兜底门, pure synchronous, NO LLM)。
//
// 3-run 实证(2026-08-19,见 memory judgment-stability-3run-0819-result):8a6fddf7
// 稳定 TP+Hollow×3 / b60300ea TP+hollow 2/3——LLM 稳达 TP 却稳拒填结构化证据
// (exploit_payload / decisive_checks),把证据写自由文本 reasoning。纯 prompt 挡不住
// 这种"稳态偷懒"(search_definitions nudge 被忽略同源,memory
// search-definitions-bypass-structural-lever),故上代码强制兜底(铁律 D 抗绑定)。
//
// 规则:verdict==true_positive 且 confidence>6 且 exploit_payload 与 decisive_checks
// 同时为空 -> 降为 likely_tp(经 VerdictOf 5->3 折成 uncertain,build.go:15) conf=6。
// 双通道:注入/上传/路径穿越类须 exploit_payload;缺失鉴权/IDOR/访问控制类须
// decisive_checks(缺失守卫清单);两者皆空=无结构化证据=不得自信判高置信 TP。
// 仅降不升;conf<=6 的 hollow TP 留作"已谦卑"不强行降(用户阈值:只杀 conf>6 的
// 高置信伪装——GR-8 无证据的高置信比低置信更危险,但低置信 hollow 已诚实)。
// fail_reason="hollow_tp_no_evidence" 不触 rejudge(contractRejected 只认
// decisive_fact_unknown:/bare_fp_buries_actual: 前缀);uncertain 经 cache 门排除
// (guard.go cache guard) -> 无"first-fail->cache->forever-fail"粘性,下跑重新判。
func EnforceEvidenceOnTp(result contract.JudgeResult) contract.JudgeResult {
	if result.Verdict != "true_positive" || result.Confidence <= 6 {
		return result
	}
	payloadEmpty := result.ExploitPayload == nil || *result.ExploitPayload == ""
	checksEmpty := len(result.DecisiveChecks) == 0
	if !payloadEmpty || !checksEmpty {
		return result
	}
	d := "likely_tp"
	result.Disposition = &d
	result.Verdict = VerdictOf("likely_tp") // -> "uncertain" (5->3 fold)
	result.Confidence = 6
	fr := "hollow_tp_no_evidence"
	result.FailReason = &fr
	mi := "你判了 true_positive（高置信），但 exploit_payload 与 decisive_checks 同时为空——不得用无结构化证据的高置信 TP 蒙混。注入/上传/路径穿越类须给 exploit_payload（可验证攻击输入，不得编造）；缺失鉴权/IDOR/访问控制类须给 decisive_checks（缺失守卫清单）至少其一。已降为 likely_tp（conf=6）。若确可证，请补具体证据后重判。"
	result.MissingInfo = &mi
	return result
}

// groundingGateMode reads APPSEC_GROUNDING_GATE（默认 "off" = 零回归；"monitor" =
// 只 log grounding 来源不改 verdict；"on" = enforce 降 uncertain）。监控先行
// （Crack-D 教训：模糊 verdict 门首轮易误判；2026-08-12 EnforceReachableSinkClaim
// 实证后回退）。off/monitor/on 三档让门先跑数据再绑定（GR-5）。
func groundingGateMode() string {
	if v := os.Getenv("APPSEC_GROUNDING_GATE"); v != "" {
		return v
	}
	// 2026-08-23 翻 on(用户拍板):收窄到「判据步」后,离线全量 monitor 复验
	// 263 条确认漏洞只降 2 条 = 0.8%(收窄前 71 条 = 27.0%),且余下 2 条经查是特定 run 里
	// 确无 grounded 判据的实例。0.8% 的代价换 GR-8「无真相不下判断」在判决层真正生效。
	return "on"
}

// EnforceGroundedDataFlow（报告去「未证实」arc Part D，pure synchronous，NO LLM）。
//
// 报告不再显「⚠ 无切片代码锚点·叙述未证实」标记（Part A）后，grounding 判定移到
// judge 层本门：verdict==true_positive 且 confidence>6 时，遍历 exploit_path.data_flow
// 每步，判该步是否有真实代码锚点（A/B 区分，用户 2026-08-20 关键洞察）：
//   - Case A（真幻觉 → 该 uncertain）：切片没切这代码 + 工具也没读过 → hop 不存在
//     且 tool_log 无探针 → 纯猜编步。不可接受 → 降 uncertain。
//   - Case B（AI 读了但没记录 → 修，不降）：切片没切这跳成 hop，但 LLM 用
//     code_at_line/read_function/read_file 真读过 → 代码在 tool_log → grounded，不降。
//
// grounding = hop 匹配（sliced.hops 词法）OR tool_log 探针匹配。cite 标记
// （contract.ParseStepCite）是确定性优先信号：hop cite [跳N] N∈[0,len(hops)) 有效；
// tool cite [工具:X@file] 在 tool_log 有对应条目有效；cite 越界/探针不存在 = Case A
// （cite 了假东西=真幻觉）。无 cite 退词法兜底（hop file basename/fn 子串 OR probe
// file basename 子串）。仅降不升；conf≤6 的 hollow TP 留作"已谦卑"不强行降（同
// EnforceEvidenceOnTp 阈值，GR-8 无证据的高置信比低置信更危险，但低置信 hollow 已诚实）。
// fail_reason 前缀 ungrounded_data_flow_step 不在 contractRejected → 不触 rejudge；
// uncertain 经 cache 门排除无粘性。off=零回归；monitor=只 log；on=降 likely_tp（折 uncertain）。
func EnforceGroundedDataFlow(result contract.JudgeResult, sliced map[string]any, toolLog []map[string]any) contract.JudgeResult {
	mode := groundingGateMode()
	if mode == "off" {
		return result
	}
	if result.Verdict != "true_positive" || result.Confidence <= 6 {
		return result
	}
	steps := result.ExploitPath.DataFlow
	if len(steps) == 0 {
		return result
	}
	hops := hopsFromSliced(sliced)
	probes := probesFromToolLog(toolLog)
	var ungrounded []int
	sources := make([]string, len(steps))
	for i, step := range steps {
		src, grounded := stepGrounding(step, hops, probes)
		sources[i] = src
		if !grounded {
			ungrounded = append(ungrounded, i)
		}
	}
	if mode == "monitor" {
		log.Printf("[grounding-gate monitor] alert=%s conf=%d steps=%d ungrounded=%v sources=%v",
			result.AlertID, result.Confidence, len(steps), ungrounded, sources)
		return result
	}
	// mode == "on"
	if len(ungrounded) == 0 {
		return result
	}
	// —— 收窄:判据步 vs 叙述步(2026-08-23 离线全量 monitor 后)——
	//
	// 离线重放 263 条确认漏洞:按旧口径(任一叙述步无锚点即降)会降级 **71 条 = 27.0%**,
	// 含已读源码核实为真的 probe-core createTask(SystemController.java:112 公网 POST
	// 端点确无任何 @PreAuthorize)。那是假降级,正是 Crack-D 的教训重演。
	//
	// 根因是判据粒度错了,不是阈值问题。GR-8 自己的落地红线写着:
	//   「missing-auth 的判据是入口零鉴权 + 改状态调用(hop0/hop1,切片内真值),
	//     **不是**没切到的深 sink。」
	// **叙述步 ≠ 判据步**:createTask 的判决建立在 hop0/hop1(均有切片真值),
	// 第 3 步「写入 ES」没切到,不影响判决成立 —— 那是展示缺口(该步无代码块),不是判决问题。
	//
	// 故:判决只要有**落在切片/工具真值上的判据**,叙述步无锚点一律不降。
	// 这是**严格弱化**(只降旧门会降的子集),不可能降得比旧门多。
	if hasGroundedDecisiveEvidence(result, hops, probes) {
		return result
	}
	d := "likely_tp"
	result.Disposition = &d
	result.Verdict = VerdictOf("likely_tp") // -> "uncertain" (5->3 fold)
	result.Confidence = 6
	fr := "ungrounded_data_flow_step"
	result.FailReason = &fr
	mi := fmt.Sprintf("exploit_path.data_flow 第 %v 步无切片 hop 锚点且无工具读过(tool_log)的代码——纯叙述步不得支撑高置信 TP（Case A 真幻觉）。已降为 likely_tp（conf=6）。要么补 cite [跳N]/[工具:...@file] 指向真实证据，要么改判 uncertain。grounding 来源:%v", ungrounded, sources)
	result.MissingInfo = &mi
	return result
}

// hopsFromSliced 提取 sliced["hops"] 为 []map[string]any（门只读 file_path/function_name/
// function_body 做词法兜底；不依赖 cwereg.hopsOf，避免跨包耦合）。
func hopsFromSliced(sliced map[string]any) []map[string]any {
	raw, ok := sliced["hops"]
	if !ok || raw == nil {
		return nil
	}
	if hs, ok := raw.([]map[string]any); ok {
		return hs
	}
	if ais, ok := raw.([]any); ok {
		out := make([]map[string]any, 0, len(ais))
		for _, h := range ais {
			if m, ok := h.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// probeEntry 是 tool_log 里 read_function/code_at_line/read_file 条目的 grounding 视图。
type probeEntry struct {
	tool string
	file string // 原始 file_path（args）
	base string // file_path basename（小写）
}

// probesFromToolLog 提取 tool_log 里 read_function/code_at_line/read_file 条目
// （有 file_path 即可做 grounding 匹配；code 内容非必需，门不展示代码块）。
func probesFromToolLog(toolLog []map[string]any) []probeEntry {
	var out []probeEntry
	for _, e := range toolLog {
		tool, _ := e["tool"].(string)
		if tool != "read_function" && tool != "read_file" && tool != "code_at_line" {
			continue
		}
		args, _ := e["args"].(map[string]any)
		fp, _ := args["file_path"].(string)
		if fp == "" {
			continue
		}
		out = append(out, probeEntry{tool: tool, file: fp, base: strings.ToLower(fileBasename(fp))})
	}
	return out
}

// fileBasename 取路径 basename（Windows/Unix 兼容）。
func fileBasename(fp string) string {
	fp = strings.ReplaceAll(fp, "\\", "/")
	if i := strings.LastIndex(fp, "/"); i >= 0 {
		fp = fp[i+1:]
	}
	return fp
}

// stepGrounding 判单步 grounding（cite 优先 → 词法兜底）。返回 (来源标签, 是否 grounded)。
// 来源标签: cite_hopN / cite_tool_<tool> / INVALID_CITE_hopN / INVALID_CITE_tool / lexeme_hop /
// lexeme_tool / none（none=Case A 真幻觉）。
func stepGrounding(step string, hops []map[string]any, probes []probeEntry) (string, bool) {
	hopCite, toolCite := contract.ParseStepCite(step)
	if hopCite != nil {
		if *hopCite >= 0 && *hopCite < len(hops) {
			return fmt.Sprintf("cite_hop%d", *hopCite), true
		}
		return fmt.Sprintf("INVALID_CITE_hop%d(len=%d)", *hopCite, len(hops)), false
	}
	if toolCite != nil {
		if probeExists(toolCite, probes) {
			return fmt.Sprintf("cite_tool_%s", toolCite.Tool), true
		}
		return fmt.Sprintf("INVALID_CITE_tool_%s", toolCite.Tool), false
	}
	// 无 cite → 词法兜底：步文提到某 hop 的 file basename 或 function name = grounded（Case B
	// 不要求 cite，LLM 叙述里提了真实 hop 标识即可）；否则看 tool_log 探针 file basename。
	stepLow := strings.ToLower(step)
	for _, h := range hops {
		if fn, _ := h["function_name"].(string); fn != "" && strings.Contains(stepLow, strings.ToLower(fn)) {
			return "lexeme_hop", true
		}
		if fp, _ := h["file_path"].(string); fp != "" {
			if base := strings.ToLower(fileBasename(fp)); base != "" && strings.Contains(stepLow, base) {
				return "lexeme_hop", true
			}
		}
	}
	for _, p := range probes {
		if p.base != "" && strings.Contains(stepLow, p.base) {
			return "lexeme_tool", true
		}
	}
	return "none", false
}

// probeExists 判 tool cite 是否在 tool_log 有对应条目（tool 相同 + file basename 匹配，
// 与渲染器 matchHopsToSteps Super Tier 同口径）。
func probeExists(cite *contract.ToolCite, probes []probeEntry) bool {
	citeBase := strings.ToLower(fileBasename(cite.File))
	citeFileLow := strings.ToLower(cite.File)
	for _, p := range probes {
		if p.tool != cite.Tool {
			continue
		}
		if citeBase != "" && p.base == citeBase {
			return true
		}
		if p.file != "" && strings.HasSuffix(strings.ToLower(p.file), citeFileLow) {
			return true
		}
	}
	return false
}

// hasGroundedDecisiveEvidence —— 判决是否有**落在切片/工具真值上**的判据。
//
// 判据来源两处(与 JudgeSchema 同源):decisive_checks[].location 与
// exploit_path.sink_evidence.sink_location。两者都要求 ① location 能解析出 file:line
// (contract.ParseLocation,散文/预计算标记如 `authz_coverage(预计算)` 不算锚点),
// ② 该文件在 sliced.hops 或 tool_log 探针里真实存在。
//
// GR-8:判据落点必须在切片可见的 hop 上 —— 本函数就是那句话的可执行版本。
func hasGroundedDecisiveEvidence(result contract.JudgeResult, hops []map[string]any, probes []probeEntry) bool {
	locs := make([]string, 0, len(result.DecisiveChecks)+1)
	for _, dc := range result.DecisiveChecks {
		if s, _ := dc["location"].(string); s != "" {
			locs = append(locs, s)
		}
	}
	if se := result.ExploitPath.SinkEvidence; se != nil {
		if s, _ := (*se)["sink_location"].(string); s != "" {
			locs = append(locs, s)
		}
	}
	for _, raw := range locs {
		loc := contract.ParseLocation(raw)
		if !loc.Anchored {
			continue // 散文/预计算标记不是锚点(GR-8 不把不可核实的当判据)
		}
		if fileInSliceOrTools(loc.File, hops, probes) {
			return true
		}
	}
	return false
}

// fileInSliceOrTools 判文件(按 basename)是否出现在切片 hop 或 tool_log 探针里。
func fileInSliceOrTools(file string, hops []map[string]any, probes []probeEntry) bool {
	base := strings.ToLower(fileBasename(file))
	if base == "" {
		return false
	}
	for _, h := range hops {
		if fp, _ := h["file_path"].(string); fp != "" && strings.ToLower(fileBasename(fp)) == base {
			return true
		}
	}
	for _, p := range probes {
		if p.base == base {
			return true
		}
	}
	return false
}
