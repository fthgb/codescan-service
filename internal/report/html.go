// html.go — 自包含暗色 HTML 审计报告渲染。纯函数无 IO（铁律：report 包只聚合/渲染，
// 不碰盘）。输入复用 runsread.GetRun 的返回形状 {meta, summary, details}。
// 样式 token 对齐 stitch_ Cyber-Sentinel 设计系统；html/template 默认上下文转义，
// PoC/reasoning 等不可信模型输出不做 template.HTML 白名单绕过。
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/vulntax"
)

// ---- view model ----

type htmlMeta struct {
	RunID, RepoKey, Adapter, Model, Timestamp string
	Mode                                      string // 扫描 / discovery
	DurationSeconds                           string
}

type htmlCard struct {
	Label string
	Value int
	Tone  string // danger | success | warn | info | muted
}

type sevBar struct {
	Name  string
	Count int
	Pct   int
	Class string
}

type typeRow struct {
	Name  string
	Count int
}

type sinkCheckVM struct {
	Code, Location, Kind, Asserts string
}

// impactLocVM — 影响位置表一行：角色 + 文件 + 行号。
// 从数据流步骤的 Hop 信息派生，按步序自动判定角色（入口/透传/Sink）。
type impactLocVM struct {
	Role string
	File string
	Line string
}

type hopVM struct {
	FunctionName, FilePath, LineRange string
	HopIdx                            int
	WinLines                          []lineVM
	FromProbe                         bool // true=代码来自 LLM read_function/read_file（tool_log），非切片器 hop
	FromEngineSink                    bool // true=代码来自 engine reachable_sinks.sql_text（MyBatis XML 真 SQL），非切片 hop 非 probe
	FromSinkEvidence                  bool // true=代码来自 LLM 直填的 exploit_path.sink_evidence.sink_code（arc ② 首类），非切片 hop 非 probe 非 engine 反查
	// ProbeStart —— 探针 read_file/code_at_line 的 executor 真值 range 首行（三轮第一级定位）；
	// 0=无（read_function 无行号）。切片 hop 不设（用 Taint 行更精确）。
	ProbeStart int
	// BlockNote —— 三轮第三级块级标注（无真值行号且词法无唯一命中时）。
	// 非空则模板在 hop-head 后渲染 block-note div，不带行号（GR-8 不编造）。
	BlockNote string
}

type lineVM struct {
	No string // 行号前缀（"573. "）；空=不显行号
	// Text —— 代码行原文。Note 非空时本行为注释行，Text 恒空。
	Text string
	// Taint —— 分析点定位标记（taint_line/decisive 兕底行），仅 annotateSteps 用于插注释，
	// 不再渲染背景高亮（2026-09-05 用户拍板：高亮语义不明，改行内注释）。
	Taint bool
	// Note —— 行内注释行（"// 🔴 分析点 L{n}：…"），插在 Taint 行后，非空则本行即注释行。
	Note string
}

type stepVM struct {
	Text string
	// Hop — 该步绑定的切片 hop 代码块;nil = 该步无对应代码(纯文字步)。
	// grounding 由 judge 层 EnforceGroundedDataFlow 门判,不在渲染层标「未证实」。
	Hop *hopVM
	// HopRef — 该步显式 cite 的 hop **真实存在但没被渲染**时的紧凑回指(函数名 @ 文件[:行范围])。
	// 两种来源:① hop 已被前一步绑走(一个函数体常覆盖数据流好几步,LLM 因此让多步 cite 同一
	// 个 [跳N]);② hop 被 recs 过滤([0,0] 且非 taint 的 XML 二次解析 hop)。
	// 三 run 实测 84 个有效 hop cite 中 28 个(33%)曾因此丢锚点。不重复整段代码(相邻大段重复
	// 更难读),只给可定位的回指;**仅显式 cite 适用**,词法命中不给(可能只是巧合,给了等于替
	// LLM 断言它没说过的话)。
	HopRef string
	// dedupedFromPrev —— 该步**有**锚点,只是与上一步同 hop 被去重(不重复整段代码)。
	// 与「从未有过锚点」必须区分:后者按 GR-8 收敛叙述丢弃,前者是可核实的,必须留。
	// anchored —— 该步有可核实的锚点(有效 cite 或词法命中切片/工具真值)。
	// **必须在剥离 cite 之前**算,否则文本里已无 cite 可判。
	anchored        bool
	dedupedFromPrev bool
	// NoAnchor —— 无任何可核实锚点(无 Hop/HopRef/dedup/词法命中)的步置位。
	// 2026-09-05 用户拍板:不再静默丢弃,显示步文并标「本步无独立代码锚点」——
	// 缺鉴权类漏洞的攻击面叙述本身就是交付物;judge 层 EnforceGroundedDataFlow 仍管
	// verdict 降级,此处只管展示。
	NoAnchor bool
}

// faceRowVM —— 面账一行（spec 2026-08-23 F5）。**待复核项，不是结论**。
type faceRowVM struct {
	Alert       string   // 展示用的 file:line
	Type        string   // 面族键
	Counterpart string   // 对照 alert 的 bughash 短码（判据可核实）
	Facts       []string // 支撑事实（人类可读）
	// Regressed —— 这条 alert **自己**上次被判过该面，本跑没判（FlagRegressedFromHistory）。
	//
	// 与「兄弟判了它没判」是**两种性质**：兄弟不一致可能只是两条本就不同；
	// 自我退化是同一条告警对同一份代码前后给出了不同答案 —— 其中必有一次是错的。
	// 首版把 flags 整个丢在渲染层，两类长得一模一样，最重的那类被埋在最轻的标题下
	// （2026-08-24 实测：probe-core 5 条真漏洞被判 FP，面账**全部正确标了** regressed，
	// 但报告上看不出分量）。
	Regressed bool
}

type fixVM struct {
	HasAnchor bool
	Loc       string
	// Paired —— 两侧都有内容**且不相同**,即这确实是一个可兑现的 before→after 补丁。
	// 只有 Paired 才允许用 `+`/`-` 渲染:那两个符号是对开发的**承诺**(「把红的换成绿的」),
	// 配不成对还照渲,仅有的那一侧会被当成推荐写法 —— 而它通常正是漏洞本体。
	Paired      bool
	BeforeLines []string
	AfterLines  []string
	// CodeLines —— 未配对时的中性代码块(不带 +/- 符号)。治法是去掉误导性的 diff 语义,
	// 不是删内容:代码仍要给开发看,只是不再声称「照这个改」。
	CodeLines []string
	Desc      string
}

type detailVM struct {
	Bughash         string
	VulnType        string
	Verdict         string
	VerdictClass    string
	Severity        string
	SevClass        string
	HasSeverity     bool
	Label           string
	LabelClass      string
	Confidence      int
	EntryPoint      string
	ShowEntryLine   bool   // 无 trace/step0 无 hop 时退回显独立源行（有 hop 时源代码已在 step0，不重复）
	TaintSourceCode string // exploit_path.taint_source.code —— 污点源代码（攻击者可控数据出生点，LLM 直填·须真读到）
	TaintSourceLoc  string // exploit_path.taint_source.location（file:line）
	HasTaintSource  bool   // code 或 loc 非空 → 数据流前渲染「污点源 Source」块（Source→数据流→Sink 三段式之首）
	DataFlow        []stepVM
	Reasoning       string
	AttackRequest   string
	ExploitPayload  string
	SuggestedFix    string
	Harm            string // severity_rationale
	HarmSummary     string // 由 severity/attacker_control/sink_reached 拼装的加粗一行摘要（开发可秒懂）
	AttackerControl string // exploit_path.attacker_control_at_sink（仅显于危害角标）
	SinkReached     string // exploit_path.sink_reached（仅显于 sink 区角标）
	SinkChecks      []sinkCheckVM
	HasHarm         bool   // Harm!="" || HasSeverity || AttackerControl!="" → 显危害区
	DowngradeNote   string // verification.action==downgraded_to_uncertain 时的简洁降级行（与前端否证卡口径一致），空则不显
	MissingInfo     string // verdict==uncertain 时「还缺什么才能定论」——把 uncertain 从死路变成待办
	DevSummary      string // 给不懂安全的开发的一句话：谁能通过哪个接口做成什么事(B1)
	DesignNote      string // 先承认原设计里对的部分、再指出缺的那一步(降低开发的防御心理)
	EvidenceBadge   string // 证据档位角标(只做正向:含 PoC / 有决定性检查;无正向证据留空)
	FlowSummary     string // 数据流一行摘要「源 → 中间 → sink」;凑不出两段则空(见 flowSummary)
	Editable        bool   // 单条报告(RenderAlertHTML)把修复区渲染成可编辑 textarea;主报告恒 false。
	// ImpactLocs — 影响位置表，从数据流步骤的 Hop 派生（入口/透传/Sink）。
	ImpactLocs    []impactLocVM
	HasImpactLocs bool
	// 放 VM 而非模板根:卡片被「确认漏洞」与「疑似真漏洞」两节共用同一个
	// 命名模板,模板里的 $ 会变成 VM 本身,$.EditableFix 取不到页面根。
	Fix fixVM
}

// planRow — 修复优先级建议的一行:排期档 + 条数 + 说明。
// 开发拿到报告的下一个问题是「先修哪个」,严重度分布本身回答不了。
type planRow struct {
	Tier  string
	Count int
	Note  string
}

// funnelRow — 审计漏斗的一级。Note 为空则不显副文。
type funnelRow struct {
	Label string
	Value int
	Note  string
}

// fpRow — 「已排除的误报」一行:类型 + 条数 + 排除理由(来自 summary.fp_patterns)。
type fpRow struct {
	Type    string
	Count   int
	Reasons []string
}

type htmlPage struct {
	Meta           htmlMeta
	Funnel         []funnelRow
	FPPatterns     []fpRow
	Cards          []htmlCard
	Severity       []sevBar
	HasSeverity    bool
	Types          []typeRow
	Details        []detailVM
	DetailCount    int
	Suspected      []detailVM
	SuspectedCount int
	FixPlan        []planRow
	Scope          []string
	ShowLegend     bool
	GeneratedNote  string
	EditableFix    bool        // 单条报告用：true 时修复渲染为可编辑 textarea（主报告恒 false）
	NeedsHardening bool        // 存在 needs-hardening 时显提示行
	NHCount        int         // needs-hardening 去重 bughash 数
	FaceRows       []faceRowVM // 确定性面账（F5）·兄弟不一致；空 → 该分节不出
	// RegressedRows —— 面账里**自我退化**那一类：这条 alert 自己上次判过该面，本跑没判。
	// 与 FaceRows 分开是因为性质不同(见 faceRowVM.Regressed)，且这一类必须排在前面。
	RegressedRows []faceRowVM
}

// ---- helpers (JSON numbers arrive as float64) ----

func hNum(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func hStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func hMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// hBoolCn — bool → 是/否，非 bool 返回空。
func hBoolCn(v any) string {
	b, ok := v.(bool)
	if !ok {
		return ""
	}
	if b {
		return "是"
	}
	return "否"
}

// assertsCn — decisive_check.asserts 中文断言，口径与前端 AlertDetail.tsx 一致。
func assertsCn(a string) string {
	switch a {
	case "blocks":
		return "拦得住"
	case "allows":
		return "拦不住"
	}
	return a
}

// isAbsenceCode — decisive_check.code 为空或字面 absence 标记（"（无）"/无/none/null/…）
// 时，描述的是「缺失守卫」而非真守卫。用于纠 assert=blocks 的误标渲染：:112 wobble 活体
// 在无守卫事实上吐 asserts=blocks code='（无）'，assertsCn 会渲染成"拦得住/安全"——面向
// 用户的报告正确性 bug（无守卫显示成安全）。真 blocks 恒带实质守卫/sink code（2423-alert
// 实证：#{}-param SQL / Workbook-不落盘 / enum 白名单 / 类型转换——asserts=blocks 下零
// absence 标记），故本谓词永不误吃真 block。Render-only：raw LLM asserts 仍存 trace/summary 供审计。
func isAbsenceCode(code string) bool {
	c := strings.TrimSpace(code)
	if c == "" {
		return true
	}
	switch c {
	case "（无）", "无":
		return true
	}
	switch strings.ToLower(c) {
	case "none", "null", "nil", "n/a":
		return true
	}
	return false
}

// severityCn — 严重度枚举 → 开发可懂的中文（与前端 severity 文案对齐）。
func severityCn(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info", "note":
		return "提示"
	}
	return ""
}

// attackerControlCn — exploit_path.attacker_control_at_sink 枚举 → 中文，去术语化。
func attackerControlCn(a string) string {
	switch strings.ToLower(a) {
	case "full":
		return "完全可控"
	case "partial":
		return "部分可控"
	case "none":
		return "不可控"
	}
	return ""
}

// joinNonEmpty — 用 sep 拼接非空段（构建 HarmSummary 用）。
func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// severityRank 越小越严重；缺失/未知排尾。
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info", "note":
		return 4
	}
	return 5
}

func severityClass(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	}
	return "sev-none"
}

func verdictClass(v string) string {
	switch v {
	case "true_positive":
		return "v-tp"
	case "false_positive":
		return "v-fp"
	}
	return "v-unc"
}

var verdictText = map[string]string{
	"true_positive":  "真漏洞",
	"false_positive": "误报",
	"uncertain":      "不确定",
}

// dispositionText — uncertain 的**分辨率**：VerdictOf 5→3 折叠（硬约束 build.go:12-19）
// 把「证据充分、只差一个渲染上下文」（likely_tp）和「sink 在三方 jar 里完全看不见」
// （真 uncertain）显示成同一个词「不确定」。判决语义没问题，是**展示**丢了分辨率。
//
// 2026-08-22 实证：三 run 9 项 uncertain 里只有 2 项是真不确定（ceshi 两个
// PluginController 上传，pluginOperator 来自 springboot-plugin-framework 三方 jar，
// 源码树确实无实现）；4 项是 likely_tp（missing_info 多为 None、sink_reached=true、
// attacker_control=full、decisive_checks 齐全）；1 项是探针误降。
//
// 故报告按 disposition 拆显 —— **纯渲染层，不动 VerdictOf**（硬约束）。
// 词表与前端 `web/src/components/DispositionBadge.tsx` 同源，两个展示面口径一致。
var dispositionText = map[string]string{
	"likely_tp":    "疑似真漏洞",
	"likely_fp":    "疑似误报",
	"out_of_scope": "不在范围内",
	"uncertain":    "无法确定",
}

// uncertainDetail — verdict==uncertain 时的细分标签 + 是否为「探针降级」。
//
// 探针降级时后端只改 verdict 不改 disposition（falsify.go），会出现
// disposition=false_positive 而 verdict=uncertain 打架 —— 此时以 uncertain 为准
// （与前端 DispositionBadge 同逻辑），避免报告显「误报」而列表显「不确定」。
func uncertainDetail(d map[string]any) (label string, downgraded bool) {
	if v := hMap(d["verification"]); hStr(v["action"]) == "downgraded_to_uncertain" {
		return dispositionText["uncertain"], true
	}
	disp := hStr(d["disposition"])
	if t, ok := dispositionText[disp]; ok {
		return t, false
	}
	return dispositionText["uncertain"], false
}

func labelClass(l string) string {
	switch l {
	case "true_positive":
		return "v-tp"
	case "false_positive":
		return "v-fp"
	case "needs-hardening":
		return "v-nh"
	}
	return "v-unc"
}

var labelText = map[string]string{
	"true_positive":   "人工·真漏洞",
	"false_positive":  "人工·误报",
	"uncertain":       "人工·不确定",
	"needs-hardening": "人工·需加固",
}

var sevOrder = []string{"critical", "high", "medium", "low"}

// parseFix — suggested_fix 锚点解析（[file:line] before → after \n 说明：…）。
// 解析本体在 contract.ParseFixAnchor（微语法契约单一解析器，GR-7 不造两份）——
// 本函数只做 view-model 适配（切行）。非锚点格式 → HasAnchor=false，调用方回退
// <pre> 原文（weak-model safe）。方括号可选：实测 47% 真实 fix 裸写 file:line。
func parseFix(s string) fixVM {
	fa := contract.ParseFixAnchor(s)
	if !fa.HasAnchor {
		return fixVM{}
	}
	b, a := strings.TrimSpace(fa.Before), strings.TrimSpace(fa.After)
	// 配对成立 = 两侧都有内容且不相同。缺一侧(模型常只摘了修改前就忘了写修改后)或两侧
	// 逐字相同,都不构成补丁 —— 此时退成中性代码块,不做 `+`/`-` 这个给不出的承诺。
	if b != "" && a != "" && b != a {
		return fixVM{HasAnchor: true, Loc: fa.Loc, Paired: true,
			BeforeLines: strings.Split(fa.Before, "\n"), AfterLines: strings.Split(fa.After, "\n"), Desc: fa.Desc}
	}
	var code []string
	switch {
	case b != "":
		code = strings.Split(fa.Before, "\n") // 含两侧逐字相同的情形:展示一份即可
	case a != "":
		code = strings.Split(fa.After, "\n")
	}
	return fixVM{HasAnchor: true, Loc: fa.Loc, CodeLines: code, Desc: fa.Desc}
}

// sliceOf — 取 []any(缺失/类型不符返 nil)。
func sliceOf(v any) []any {
	xs, _ := v.([]any)
	return xs
}

// flowSummary — 数据流的一行骨架「源 → 中间 → sink」。
//
// 数据流正文是若干段中文叙述,读者得逐段读完才知道这条链从哪来到哪去;先给骨架能省这一遍。
//
// GR-8:三段全部取**已有真值**,不新造 ——
//
//	源   = exploit_path.entry_point
//	中间 = 切片器 hop 的函数名(trace 真值;无 trace 则无中间段,不编)
//	sink = sink_checks 的 sink 代码
//
// 相邻同名段去重(入口函数常与 hop0 同名);凑不出至少两段就返回空 —— 一段不是摘要。
func flowSummary(vm *detailVM) string {
	segs := make([]string, 0, 4)
	push := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if n := len(segs); n > 0 && segs[n-1] == s {
			return
		}
		segs = append(segs, s)
	}
	push(vm.EntryPoint)
	for _, st := range vm.DataFlow {
		if st.Hop != nil {
			push(st.Hop.FunctionName)
		}
	}
	if len(vm.SinkChecks) > 0 {
		push(vm.SinkChecks[len(vm.SinkChecks)-1].Code)
	}
	if len(segs) < 2 {
		return ""
	}
	return strings.Join(segs, " → ")
}

// vulnTypeLabel — 明细卡标题与类型分布共用的类型标签。
//
// 形态「中文名 · 规范 slug」:中文名给不懂安全的开发看,slug 保留可追溯性与聚合键。
// 词表单一权威在 internal/vulntax/vuln_taxonomy.json(前端 import 同一文件,铁律 D)。
//
// 两个被治的缺陷(2026-08-22 三 run 实测):
//
//	D3 8/15 条 TP 的标题印着 `02000010070033` —— codesafe 适配器的内部规则码。这些条目
//	   的 cwe_id(CWE-915/CWE-338)不在 cwe_registry.json 的 19 条内,靠 registry 反查
//	   补不上,但 LLM 判出的 actual_vulnerability_types 是现成真值。
//	D4 同一类漏洞四种写法(missing_authorization / missing-authorization / missing-auth /
//	   broken-access-control)被算成四种类型,类型分布图把一类拆成几行。
//
// GR-8:内部规则码是实现细节不是给开发看的结论,认不出宁可显「未分类」也不吐码;但**非
// 数字**的未知 slug 原样保留(是信息,不是噪音)。
func vulnTypeLabel(d map[string]any) string {
	raw := hStr(d["vulnerability_type"])
	var actual []string
	if xs, ok := d["actual_vulnerability_types"].([]any); ok {
		for _, x := range xs {
			if s := hStr(x); s != "" {
				actual = append(actual, s)
			}
		}
	}
	cwe := hStr(d["cwe_id"])
	name := vulntax.Display(raw, actual, cwe)
	if name == "" {
		if raw != "" && isAllDigits(raw) {
			return "未分类"
		}
		return raw
	}
	// slug 段:优先该条自己的 slug,其次首个可识别的 actual type;只有 CWE 兜底时不带 slug。
	slug := ""
	if vulntax.DisplaySlug(raw) != "" {
		slug = vulntax.Canonical(raw)
	} else {
		for _, at := range actual {
			if vulntax.DisplaySlug(at) != "" {
				slug = vulntax.Canonical(at)
				break
			}
		}
	}
	if slug == "" {
		return name
	}
	return name + " · " + slug
}

// isAllDigits 判断字符串是否全为数字(适配器内部规则码的形态)。
func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// buildDetailVM — 单条 summary detail → 明细视图模型。纯函数，无 IO。
// 被主报告 RenderHTML（多条）与单条报告 RenderAlertHTML 复用，DRY。
func buildDetailVM(d map[string]any) detailVM {
	vm := detailVM{
		Bughash:      hStr(d["bughash"]),
		VulnType:     vulnTypeLabel(d),
		Verdict:      verdictText[hStr(d["verdict"])],
		VerdictClass: verdictClass(hStr(d["verdict"])),
		Confidence:   hNum(d["confidence"]),
		Reasoning:    hStr(d["reasoning"]),
	}
	if vm.VulnType == "" {
		vm.VulnType = "unknown"
	}
	if vm.Verdict == "" {
		vm.Verdict = hStr(d["verdict"])
	}
	// uncertain 拆显（分辨率，非语义）：likely_tp「疑似真漏洞」/ likely_fp「疑似误报」/
	// out_of_scope「不在范围内」/ 真 uncertain「无法确定」。见 dispositionText 注释。
	// verdict 本身不变（VerdictOf 折叠是硬约束），只是标签更准。
	if hStr(d["verdict"]) == "uncertain" {
		if label, _ := uncertainDetail(d); label != "" {
			vm.Verdict = label
		}
		// missing_info 是 LLM 自己写的「还缺什么才能定论」，实测写得很具体
		// （「需确认下载接口响应头是否 nosniff」）。显出来 uncertain 就从死路变成待办。
		vm.MissingInfo = hStr(d["missing_info"])
	}
	if sev := hStr(d["severity"]); sev != "" {
		vm.HasSeverity = true
		vm.Severity = sev
		vm.SevClass = severityClass(sev)
	}
	if l := hStr(d["label"]); l != "" {
		if t, ok := labelText[l]; ok {
			vm.Label = t
		} else {
			vm.Label = l
		}
		vm.LabelClass = labelClass(l)
	}
	ep := hMap(d["exploit_path"])
	vm.EntryPoint = hStr(ep["entry_point"])
	// taint_source（2026-09-07 根因报告 §8）：污点源三段式之首。LLM 直填、红线同
	// sink_evidence（须真读到，不编造）——渲染层信任直填并显式标注来源（GR-8 溯源）。
	if ts := hMap(ep["taint_source"]); ts != nil {
		vm.TaintSourceCode = hStr(ts["code"])
		vm.TaintSourceLoc = hStr(ts["location"])
		vm.HasTaintSource = vm.TaintSourceCode != "" || vm.TaintSourceLoc != ""
	}
	if df, ok := ep["data_flow"].([]any); ok {
		for _, step := range df {
			if s := hStr(step); s != "" {
				vm.DataFlow = append(vm.DataFlow, stepVM{Text: s})
			}
		}
	}
	// PoC 与利用载荷的 nullish 防线。报告读的是**已落盘的 summary.json**,历史 run 里
	// 字符串 "null" 原样躺着(judge 侧 build.go 的归一只对新跑生效),且当时 poc 拿到非空
	// "null" 生成了注入点是 null 的假 PoC(三 run 7/15 条 TP 中招)。
	//
	// 三态,不是两态 —— **载荷缺失 ≠ 载荷显式 nullish**:
	//   显式 nullish("null"/"无"/…) → 载荷块与 PoC 块都不渲染(PoC 是拿这个值拼的,
	//                                注入点是编的,GR-8 不展示编的锚点);
	//   缺失/空                     → 只是没这个字段,PoC 若在则**照常渲染**
	//                                (缺鉴权类的利用就是那条未认证请求本身,无需载荷);
	//   真载荷                       → 都渲染。
	// 判别器必须是**整值** nullish:真载荷里合法含 null 的 SQL UNION 不得被误伤
	// (锚点 1a004a2d,见 poc_nullish_render_test.go)。
	payload := hStr(d["exploit_payload"])
	payloadExplicitNullish := payload != "" && contract.IsNullish(payload)
	if !payloadExplicitNullish {
		vm.ExploitPayload = payload
		if ar := hStr(d["attack_request"]); !contract.IsNullish(ar) {
			vm.AttackRequest = ar
		}
	}
	// 证据档位角标 —— **只做正向**。
	// 2026-08-21 用户定的铁律级口径:dev 报告不得暴露「未证实」叙述(开发看到反手不修),
	// 证不了就判 uncertain 而非显黄标。加一个「未验证」角标 = 把那次移除的黄标换名放回来,
	// 故无正向证据时留空。
	switch {
	case vm.ExploitPayload != "" || vm.AttackRequest != "":
		vm.EvidenceBadge = "含 PoC"
	case len(sliceOf(d["decisive_checks"])) > 0:
		vm.EvidenceBadge = "有决定性检查"
	}
	vm.SuggestedFix = hStr(d["suggested_fix"])
	// 面向开发者的两段(B1)。同走 nullish 防线:LLM 在该填 null 处写 "null" 是常态。
	if v := hStr(d["dev_summary"]); !contract.IsNullish(v) {
		vm.DevSummary = contract.UnescapeLiteralEscapes(v)
	}
	if v := hStr(d["design_note"]); !contract.IsNullish(v) {
		vm.DesignNote = contract.UnescapeLiteralEscapes(v)
	}
	// I5 还原此前只接在 suggested_fix 解析里,这三个**直接展示**的散文字段没走过 ——
	// 实测 rt 报告里 dev_summary 出现 `文件名带 '..\'`(应为 `..\`),读者看到的是错字符。
	// UnescapeLiteralEscapes 自带判别器(含真换行则原样返回),不会篡改真值。
	vm.Harm = contract.UnescapeLiteralEscapes(hStr(d["severity_rationale"]))
	vm.AttackerControl = hStr(ep["attacker_control_at_sink"])
	vm.SinkReached = hBoolCn(ep["sink_reached"])
	// HarmSummary：由 severity/attacker_control/sink_reached 拼装的一行加粗摘要（不读盘，纯字段）。
	var reachedCN string
	if b, ok := ep["sink_reached"].(bool); ok {
		if b {
			reachedCN = "数据已到达危险操作"
		} else {
			reachedCN = "数据未到达危险操作"
		}
	}
	vm.HarmSummary = joinNonEmpty(" · ",
		severityCn(vm.Severity),
		joinNonEmpty("", "攻击者", attackerControlCn(vm.AttackerControl)),
		reachedCN,
	)
	if dc, ok := d["decisive_checks"].([]any); ok {
		for _, c := range dc {
			cm := hMap(c)
			code := hStr(cm["code"])
			a := hStr(cm["asserts"])
			// render override：LLM 标 asserts=blocks 但 code 为空/无守卫标记 → 实为 allows
			//（:112 wobble：无守卫事实被标 blocks 会渲染"拦得住/安全"=报告正确性 bug）。
			// raw LLM asserts 仍存 trace/summary 供审计；此处只纠渲染。isAbsenceCode 在
			// 2423-alert 实证上零假阳（真 blocks 恒带实质守卫/sink code）。
			if a == "blocks" && isAbsenceCode(code) {
				a = "allows"
			}
			vm.SinkChecks = append(vm.SinkChecks, sinkCheckVM{
				Code:     code,
				Location: hStr(cm["location"]),
				Kind:     hStr(cm["kind"]),
				Asserts:  assertsCn(a),
			})
		}
	}
	vm.HasHarm = vm.Harm != "" || vm.HarmSummary != "" || vm.HasSeverity || vm.AttackerControl != ""
	// DowngradeNote：仅当探针否证降级时显一行（与前端 ProbeCard 口径一致），
	// 点名原判 + 矛盾原因；守卫逐条详情不在 HTML 报告展开（前端详情页才有结构化卡）。
	if v := hMap(d["verification"]); v != nil {
		if hStr(v["action"]) == "downgraded_to_uncertain" {
			ov := hStr(v["original_verdict"])
			if ov == "" {
				ov = "?"
			}
			note := "已降级 uncertain：原判 " + ov
			if r := hStr(v["reason"]); r != "" {
				note += "。" + r
			}
			vm.DowngradeNote = note
		}
	}
	vm.ShowEntryLine = len(vm.DataFlow) == 0 || vm.DataFlow[0].Hop == nil
	vm.Fix = parseFix(vm.SuggestedFix)
	return vm
}

// recomputeEntryLine — matchHopsToSteps 后重算 ShowEntryLine：step0 已挂 hop（源代码在数据流）
// 则不显独立源行；否则退回显（避免无 trace 时丢失入口）。
func (vm *detailVM) recomputeEntryLine() {
	vm.ShowEntryLine = len(vm.DataFlow) == 0 || vm.DataFlow[0].Hop == nil
	vm.FlowSummary = flowSummary(vm)
	vm.computeImpactLocs()
}

// computeImpactLocs — 从数据流步骤的 Hop 派生影响位置表。
// 按步序自动判定角色：首步=入口接口，末步=Sink，中间步=参数透传。
// 无 Hop 的纯文字步跳过（无文件/行号真值，GR-8 不编造）。
func (vm *detailVM) computeImpactLocs() {
	vm.ImpactLocs = nil
	for i, step := range vm.DataFlow {
		if step.Hop == nil {
			continue
		}
		role := "参数透传"
		switch {
		case i == 0:
			role = "入口接口"
		case i == len(vm.DataFlow)-1:
			role = "Sink"
		}
		vm.ImpactLocs = append(vm.ImpactLocs, impactLocVM{
			Role: role,
			File: fileBase(step.Hop.FilePath),
			Line: step.Hop.LineRange,
		})
	}
	vm.HasImpactLocs = len(vm.ImpactLocs) > 0
}

var fileExtRe = regexp.MustCompile(`[\w./\\]+\.[A-Za-z]\w*`)

// hopRefLabel — hop 的紧凑回指标签「函数名 @ 文件:行范围」。
// 取 hop 真值,拿不到函数名/文件就退化为可拿到的那部分;全拿不到返回空(不编,GR-8)。
func hopRefLabel(h map[string]any) string {
	fn := hStr(h["function_name"])
	file := fileBase(hStr(h["file_path"]))
	rng := lineRangeStr(h["line_range"])
	loc := file
	if loc != "" && rng != "" {
		loc += ":" + rng
	}
	switch {
	case fn != "" && loc != "":
		return fn + " @ " + loc
	case fn != "":
		return fn
	default:
		return loc
	}
}

// hopLineMap — 从 trace.sliced.hops 建 {hop_index → 真实 line_range 串}。
// hop_index 经 slicealert.go 两次 reindex == 数组下标 == LLM 在「### 跳 N」看到的 N，
// 故可直接用下标反查 LLM 叙事里 跳N 的真实行号。rawHops(含 [0,0] dummy)全收,
// lineRangeStr 对 [0,0]/缺行返 "" → 不入 map → 该跳退化为剥行号(不编造真值,GR-8)。
func hopLineMap(trace map[string]any) map[int]string {
	sliced, _ := trace["sliced"].(map[string]any)
	if sliced == nil {
		return nil
	}
	rawHops, _ := sliced["hops"].([]any)
	if len(rawHops) == 0 {
		return nil
	}
	m := make(map[int]string, len(rawHops))
	for i, h := range rawHops {
		if hm := hMap(h); hm != nil {
			if r := lineRangeStr(hm["line_range"]); r != "" {
				m[i] = r
			}
		}
	}
	return m
}

// rewriteHopLines — 把 data_flow 步文里 LLM 自填的假行号回填/剥掉。
// 解析/回填本体在 contract.RewriteHopProseCites（微语法契约单一解析器，GR-7 不造两份）。
func rewriteHopLines(text string, lineMap map[int]string) string {
	return contract.RewriteHopProseCites(text, lineMap)
}

// fileBase — 取路径 basename（兼容 / 与 \）。
func fileBase(p string) string {
	if p == "" {
		return ""
	}
	if idx := strings.LastIndexAny(p, "/\\"); idx >= 0 {
		p = p[idx+1:]
	}
	return p
}

// mentionedFiles — 步文里出现的文件 basename 集合（小写归一）。
func mentionedFiles(text string) map[string]bool {
	m := map[string]bool{}
	for _, raw := range fileExtRe.FindAllString(text, -1) {
		if b := strings.ToLower(fileBase(raw)); b != "" {
			m[b] = true
		}
	}
	return m
}

// parseDecisiveLine — "StringUtil.java:366" → ("StringUtil.java", 366)；无行号→0。
func parseDecisiveLine(loc string) (base string, line int) {
	loc = fileBase(loc) // 去 dir，保留 :line
	i := strings.LastIndex(loc, ":")
	if i < 0 {
		return loc, 0
	}
	base = loc[:i]
	if n, err := strconv.Atoi(loc[i+1:]); err == nil {
		return base, n
	}
	return loc, 0
}

// resolveHighlight — hop 高亮行：taint_line 优先；无则 decisive_checks 落 range 内同文件行；都无 0。
func resolveHighlight(hop map[string]any, detail map[string]any) int {
	if tl, ok := hop["taint_line"].(float64); ok && tl > 0 {
		return int(tl)
	}
	lr, _ := hop["line_range"].([]any)
	lo, hi := 0, 0
	if len(lr) >= 2 {
		if a, ok := lr[0].(float64); ok {
			lo = int(a)
		}
		if b, ok := lr[1].(float64); ok {
			hi = int(b)
		}
	}
	hopBase := strings.ToLower(fileBase(hStr(hop["file_path"])))
	if lo > 0 && hopBase != "" {
		if dc, ok := detail["decisive_checks"].([]any); ok {
			for _, c := range dc {
				cm := hMap(c)
				loc := hStr(cm["location"])
				if loc == "" {
					continue
				}
				dbase, line := parseDecisiveLine(loc)
				if line > 0 && strings.ToLower(dbase) == hopBase && line >= lo && line <= hi {
					return line
				}
			}
		}
	}
	return 0
}

// buildHopVM — 单 hop → 代码视图模型（逐行 lineVM + 分析点标记）。纯函数无 IO。
// 折叠已移除（2026-09-05 用户拍板：PDF 对折叠不友好，全量展示）；
// highlightLine 为绝对行号，落在 body 内则该行 Taint 置位（供 annotateSteps 定位插注释，不再渲染背景色）。
func buildHopVM(hop map[string]any, highlightLine int) hopVM {
	body := hStr(hop["function_body"])
	start, hasRange := 0, false
	if lr, ok := hop["line_range"].([]any); ok && len(lr) >= 2 {
		if s, ok := lr[0].(float64); ok && s > 0 {
			start, hasRange = int(s), true
		}
	}
	// 类4:XML hop 视觉补回 statement-id 上下文。mapperxmlindex.go:35 正则捕组2内层,
	// 故意不含包裹 <select id="X"> 标签(忠实 Python)→ 报告只显内层 SQL 片段,dev 看不出
	// 属哪条语句。补一行 <!-- id="X" --> 前置上下文。仅对 [0,0] 合成 hop(无真实行号)补,
	// 有真实 line_range 的不补(避免错移行号/分析点定位)。不伪造包裹标签(GR-8)。
	if fp := hStr(hop["file_path"]); strings.HasSuffix(fp, ".xml") && !hasRange {
		if fn := hStr(hop["function_name"]); fn != "" {
			body = `<!-- id="` + fn + `" -->` + "\n" + body
		}
	}
	lines := strings.Split(body, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r") // CRLF 归一（§9.5 review carried fix）
	}
	hlIdx := -1
	if highlightLine > 0 && hasRange {
		if i := highlightLine - start; i >= 0 && i < len(lines) {
			hlIdx = i
		}
	}
	out := make([]lineVM, 0, len(lines))
	for i, ln := range lines {
		no := ""
		if hasRange {
			no = strconv.Itoa(start+i) + ". "
		}
		out = append(out, lineVM{
			No:    no,
			Text:  ln,
			Taint: hlIdx >= 0 && i == hlIdx,
		})
	}
	return hopVM{
		FunctionName: hStr(hop["function_name"]),
		FilePath:     hStr(hop["file_path"]),
		LineRange:    lineRangeStr(hop["line_range"]),
		WinLines:     out,
	}
}

// stemBeforeDot — 取首个 '.' 之前的子串（输入已小写归一）。
// TaskCreatingComponent.createTask → taskcreatingcomponent；taskcreatingcomponent.java → taskcreatingcomponent。
// 用于步文 Class.method 形 token 与 hop 文件 basename 的类名级收窄：mentionedFiles 取
// basename 得 class.method，与 hop 的 class.java 永不相等，必须比 stem 才能命中。
// （IP/版本号 192.168.1.1、v1.2 的 '.' 后非字母，根本进不了 mentionedFiles，故 stem 不会误命中。）
func stemBeforeDot(s string) string {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i]
	}
	return s
}

// roleWords — LLM 常把类名缩写成角色词（Service/Mapper/Controller…）。
// 这类 token（如「Service.getListWithStock」）stem 为「service」，与 hop 文件 stem
// 「materialservice」永不相等。改按后缀匹配：hop stem 以该角色词结尾即视为引用
// （materialservice ← service）。只对步文显式写出的角色词触发，不扫全词表，避免短 stem
// 误命中（如裸「c」永不入 roleStems，故 basic.java 不会被「c」误配）。
var roleWords = map[string]bool{
	"controller": true, "service": true, "serviceimpl": true, "mapper": true,
	"repository": true, "component": true, "dao": true, "impl": true,
	"util": true, "utils": true, "helper": true,
}

func isRoleWord(s string) bool { return roleWords[s] }

// wordBoundaryMatch reports whether token appears in text as a whole word
// (surrounded by non-identifier chars / string edges), NOT as a substring of
// a longer identifier. Used by the fn-name fallback so e.g. step text
// "taskService.cancelTask" matches hop fn "cancelTask" (token sits after a
// dot) but fn "lawsuitrevoke" does NOT match inside "taskLawsuitRevokeRequest"
// (no word boundary) — otherwise the source hop would steal every step that
// mentions a *Request type whose name embeds an entry fn. Real-data 3de4b5c0
// GR-8: step2 narrated taskService.cancelTask but matched the source hop via
// this substring leak; word-boundary routes it to the real cancelTask sink hop.
func wordBoundaryMatch(text, token string) bool {
	if token == "" {
		return false
	}
	start := 0
	for {
		i := strings.Index(text[start:], token)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !isIdentByte(text[i-1])
		end := i + len(token)
		afterOK := end == len(text) || !isIdentByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
		if start >= len(text) {
			return false
		}
	}
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// toolCodeField: tool → 候选字段链（首个非空胜出）。
// read_function: cache-miss/蒸馏off 命中 "code"(full body)；FUNC_DISTILL cache-hit 命中 "excerpt"
//
//	(真源码前60行，无 code——省 token 不重读)。fallback 到 excerpt 保 cache-hit 不丢块。
//
// read_file: "content"（无 distill 旁路）。
// code_at_line: "method_body"（engine 工具，CodeAtLineResult 字段名；非 code）。
var toolCodeField = map[string][]string{
	"read_function": {"code", "excerpt"},
	"read_file":     {"content"},
	"code_at_line":  {"method_body"},
}

// probeRec — tool_log 里 read_function/read_file 条目的精简视图，用于切片 hop 匹配不到时
// 给数据流步补一份「探针读取·非切片内」的代码块（c5f2e1：multipartFileToFile/
// inputStreamToFile 是真 sink callee，切片器未纳入 hop，LLM 靠 read_function 读到并
// 在 data_flow step2/step3 引用）。
type probeRec struct {
	tool     string // read_function / read_file / code_at_line
	code     string // 从 result_excerpt 抽出的函数体/文件片段
	fn       string // read_function 的 function_name（小写）
	fnOrig   string // 原始 function_name（渲染用）
	base     string // file_path basename（小写）
	stem     string // base 去扩展名 stem（小写）
	fileOrig string // 原始 file_path（渲染用）
	start    int    // read_file/code_at_line start_line（0=无）
	end      int
	hasLR    bool
}

// buildProbeRecs 从 trace.tool_log 构造 read_function/read_file 探针记录列表。
// 前置条件：em["result"] 必须经 JSON round-trip 成 map[string]any（hMap 的 v.(map[string]any)
// 严格断言，对未序列化的 readFileResult struct 返 nil）。当前安全是因为所有渲染调用方
// 消费 runsread.Trace（经 json.Unmarshal 成 map[string]any）；否则 read_file 块会静默丢失。
func buildProbeRecs(trace map[string]any) []probeRec {
	if trace == nil {
		return nil
	}
	tl, _ := trace["tool_log"].([]any)
	var recs []probeRec
	for _, e := range tl {
		em := hMap(e)
		if em == nil {
			continue
		}
		tool := hStr(em["tool"])
		if tool != "read_function" && tool != "read_file" && tool != "code_at_line" {
			continue
		}
		args := hMap(em["args"])
		fp := hStr(args["file_path"]) // file_path 仍从 args 取:输入参数,executor 不改,无 clamp 语义(spec §4.1)
		res := hMap(em["result"])     // trace JSON 读回为 map[string]any(struct 存进去再读也是 map)
		fields, ok := toolCodeField[tool]
		if !ok {
			continue // grep/search:无代码锚点,跳过(等价旧 :671-673 前置 continue)
		}
		code := ""
		for _, f := range fields {
			if c := hStr(res[f]); c != "" {
				code = c
				break
			}
		}
		if code == "" {
			continue // GR-8:无干净代码不编,不显(不变)
		}
		rec := probeRec{tool: tool, code: code, fileOrig: fp,
			base: strings.ToLower(fileBase(fp))}
		rec.stem = stemBeforeDot(rec.base)
		if tool == "read_function" {
			fn := hStr(args["function_name"])
			rec.fnOrig = fn
			rec.fn = strings.ToLower(fn)
		} else if tool == "code_at_line" {
			// code_at_line 无 function_name 入参；fn 留空，仅靠 file basename/stem 匹配。
			// line_range 从 result(executor 真值 start_line/end_line)，与 read_file 同构。
			s := hNum(res["start_line"])
			en := hNum(res["end_line"])
			if s > 0 {
				rec.start, rec.end, rec.hasLR = s, en, true
			}
		} else {
			// line_range 从 result 取(executor OOB clamp 后真值,GR-8);read_function 无此键→hNum 返 0→hasLR=false
			s := hNum(res["start_line"])
			en := hNum(res["end_line"])
			if s > 0 {
				rec.start, rec.end, rec.hasLR = s, en, true
			}
		}
		recs = append(recs, rec)
	}
	return recs
}

// sinkSqlRec — tool_log 里 reachable_sinks 回执的精简视图,给 sink 步补「engine 真值 SQL」代码块。
// 与 probeRec 区别:probeRec 是 read_function/read_file/code_at_line 读到的函数体/文件片段;
// sinkSqlRec 是 engine 从 MyBatis XML 解析出的真实 sink SQL 文本(含 ${}/#{} 与 <if> 动态标签原貌),
// GR-8 锚点最强——MyBatis 真 SQL 在 .xml 不在 .java 接口声明,reachable_sinks 做 java↔xml 跨文件
// 绑定才取到(切片器类4 缺口漏绑时,engine 在 judge 时补刀)。spec: 2026-08-21-render-sink-from-toollog-sqltext。
type sinkSqlRec struct {
	sqlText      string   // result.reachable_sinks[i].sql_text(engine 真值,原样渲染含 <if>)
	methodKey    string   // result.reachable_sinks[i].method_key("DepotItemMapperEx.getBillItemByParam(String)")
	method       string   // method_key 去签名后末段小写(getbillitembyparam),tier2/3 匹配用
	methodOrig   string   // 同上原 case(getBillItemByParam),渲染 header 用
	queryFn      string   // args.function_name(AI 查询入参,溯源/调试用)
	concatParams []string // result.reachable_sinks[i].concat_params(["barCodes"]),tier2 强信号
	cwe          string   // result.reachable_sinks[i].cwe
}

// buildSinkSqlRecs 从 trace.tool_log 构造 reachable_sinks 回执记录列表(多条调用取并集)。
// 仅消费 reachable_sinks 工具 result.reachable_sinks[] 每条的 sql_text(无 sql 跳过,GR-8 无真值不建)。
func buildSinkSqlRecs(trace map[string]any) []sinkSqlRec {
	if trace == nil {
		return nil
	}
	tl, _ := trace["tool_log"].([]any)
	var recs []sinkSqlRec
	for _, e := range tl {
		em := hMap(e)
		if em == nil || hStr(em["tool"]) != "reachable_sinks" {
			continue
		}
		args := hMap(em["args"])
		res := hMap(em["result"])
		arr, _ := res["reachable_sinks"].([]any)
		for _, s := range arr {
			sm := hMap(s)
			if sm == nil {
				continue
			}
			sql := hStr(sm["sql_text"])
			if sql == "" {
				continue // GR-8 无 sql 不建,不显
			}
			mk := hStr(sm["method_key"])
			orig := methodShort(mk)
			rec := sinkSqlRec{sqlText: sql, methodKey: mk, methodOrig: orig,
				method: strings.ToLower(orig), queryFn: hStr(args["function_name"]), cwe: hStr(sm["cwe"])}
			if cp, ok := sm["concat_params"].([]any); ok {
				for _, c := range cp {
					if cs := hStr(c); cs != "" {
						rec.concatParams = append(rec.concatParams, cs)
					}
				}
			}
			recs = append(recs, rec)
		}
	}
	return recs
}

// methodShort — method_key "DepotItemMapperEx.getBillItemByParam(String)" → "getBillItemByParam"。
// 去签名(括号前)+ 取末段(最后点后)。原 case(匹配前由调用方小写)。
func methodShort(mk string) string {
	if mk == "" {
		return ""
	}
	if i := strings.Index(mk, "("); i >= 0 {
		mk = mk[:i]
	}
	if i := strings.LastIndex(mk, "."); i >= 0 {
		mk = mk[i+1:]
	}
	return mk
}

// sinkConcatHit — 步文(小写)是否含某 concat_params 参名(如 "barCodes"→"barcodes")。
// tier2/tier3 收窄多 sink 歧义的方法短名匹配——步文出现 sink 的污染参名 = 强信号。
func sinkConcatHit(textLow string, params []string) bool {
	for _, p := range params {
		if p != "" && strings.Contains(textLow, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// 步无匹配 → Hop nil（仅文字）。HopIdx=步序号保证折叠 id 唯一。
// 不解析 data_flow 行号（AI 叙述幻觉）——只用文件名 + 函数名，行号以 hop line_range/taint_line 为准。
//
// 分配模型（2026-08-20 重设计，修弱信号偷强信号 sink / 同名 fn 碰撞丢块）：
// bipartite 信号强度优先 + hop 跨步唯一占用。每步算候选 hop 集及其信号 tier：
//
//	tier 0 = 步文显式 cite hop 文件 basename（X.java/X.xml，最具体，无 .java/.xml 歧义）；
//	tier 1 = 函数名词边界命中（仅当步无文件/stem cite 时的兜底）；
//	tier 2 = Class.method 类名 stem == hop 文件 stem（缩写歧义 .java/.xml，比 basename 弱）；
//	tier 3 = 角色词后缀命中（Service→MaterialService，兼容 LLM 缩写）；
//	tier 4 = 源步（@Request*/@Cookie*/@RequestHeader）无候选时的 entry_point 兜底。
//
// 步若有文件/stem/角色 cite（tier 0/2/3）则不再退回 fn 兜底——文件 cite 收窄候选，fn 兜底仅无 cite 时用，
// 防 step1 显式 cite SystemController 还被 fn=createTask 拉去其它同名 hop。
// fn-disagreement 收窄：步文提及某 fn 时，stem/角色候选里 fn 非空且不一致的 hop 排除——避免歧义 stem
// （materialmapperex 同名 .java/.xml）把步未提及的无关方法 hop 拉进来（2f2b371c step3 不偷 hop9/10）。
// 全部 (step,hop,tier) 边按 (tier, stepIdx, taint-first, hopIdx) 排序，贪心分配：每个 hop 给它
// 最强且最早的 claimant，弱 claimant 让位→无候选→探针回退→无则 nil。hop 跨步唯一占用，故旧"相邻同 hop
// 去重"被吸收（保留作安全网，防同 FilePath 不同 hop 的边界 case）。
//
// [0,0] 非 taint hop（XML 二次解析 dummy，非 sink——sink 有 taint_line）排除出候选：展示只会混淆。
func matchHopsToSteps(steps []stepVM, detail, trace map[string]any) []stepVM {
	if len(steps) == 0 {
		return steps
	}
	sliced, _ := trace["sliced"].(map[string]any)
	// 回填真实行号(用 hop_line_range 替换 LLM 假行号);无 trace → lineMap nil → 退化为剥行号。
	lm := hopLineMap(trace)
	for i := range steps {
		steps[i].Text = rewriteHopLines(steps[i].Text, lm)
	}
	if sliced == nil {
		// 无 trace:无 hop 可匹配,步仅文字。**但 cite 仍须剥** —— 早返回曾直接跳过函数末尾
		// 的 StripCites,于是任何拿不到 trace 的条目都把 `[跳0, 工具:…]` 这类内部锚点语法
		// 原样印进报告(2026-08-23 rt 实测)。剥离与 hop 匹配是两件事,不能被同一个早返回连坐。
		// **不丢弃**:sliced==nil 意味着「我们根本没加载 trace」,不是「这步无锚点」——
		// 没有 hop 数据就没有判定依据,一律丢等于把「我们没看」当成「它没有」。
		// GR-8「切不到 ≠ 代码不存在」的第四种成因:我们压根没去看。
		return stripStepCites(steps)
	}
	rawHops, _ := sliced["hops"].([]any)
	type hopRec struct {
		m     map[string]any
		fn    string
		base  string
		stem  string
		idx   int
		taint bool
	}
	var recs []hopRec
	for i, h := range rawHops {
		hm := hMap(h)
		if hm == nil || hStr(hm["function_body"]) == "" {
			continue
		}
		taint := false
		if tl, ok := hm["taint_line"].(float64); ok && tl > 0 {
			taint = true
		}
		// 跳过 [0,0] 非 taint 的 dummy hop（XML 二次解析，非 sink 非真方法代码，展示只混淆）。
		if !taint {
			lr, _ := hm["line_range"].([]any)
			if len(lr) < 1 {
				continue
			}
			if a, ok := lr[0].(float64); !ok || a <= 0 {
				continue
			}
		}
		base := strings.ToLower(fileBase(hStr(hm["file_path"])))
		recs = append(recs, hopRec{
			m: hm, fn: strings.ToLower(hStr(hm["function_name"])),
			base: base, stem: stemBeforeDot(base), idx: i, taint: taint,
		})
	}

	// entry_point 文件 basename（源步无候选时兜底匹配的 hop 文件）。用 parseDecisiveLine 去 :line。
	entryFile := ""
	sinkEvidence := hMap(nil)
	if epMap := hMap(detail["exploit_path"]); epMap != nil {
		if epBase, _ := parseDecisiveLine(hStr(epMap["entry_point"])); epBase != "" {
			entryFile = strings.ToLower(epBase)
		}
		// sink_evidence: LLM 直填的 sink 真值（arc ② 首类）。非空 map 时优先于 tool_log 反查。
		sinkEvidence = hMap(epMap["sink_evidence"])
	}

	isSourceStep := func(text string) bool {
		low := strings.ToLower(text)
		for _, m := range []string{"@requestmapping", "@requestparam", "@requestbody",
			"@pathvariable", "@cookievalue", "@requestheader"} {
			if strings.Contains(low, m) {
				return true
			}
		}
		return false
	}

	// hopTier: 步对 hop 的文件/stem/角色 cite tier（0 basename / 1 stem / 2 角色后缀）；无 cite 返 -1。
	// fn 词边界兜底是更弱信号（tier 3，仅在无 cite 时用），cite 比 fn 兜底更具体——防 step1 显式
	// cite SystemController 还被 fn=createTask 拉去其它同名 hop（ClassMethodStem/3de4b5c0）。
	hopTier := func(r hopRec, files map[string]bool, stepStems, roleStems map[string]bool) int {
		if r.base == "" {
			return -1
		}
		if files[r.base] { // (a) 直提完整 basename（最具体，无 .java/.xml 歧义）
			return 0
		}
		if r.stem != "" && stepStems[r.stem] { // (b) Class.method stem == hop stem
			return 1
		}
		if r.stem != "" {
			for rw := range roleStems { // (c) 角色词后缀
				if strings.HasSuffix(r.stem, rw) {
					return 2
				}
			}
		}
		return -1
	}

	// 分配模型（2026-08-20 重设计 + GR-8 守卫）：4 阶段信号强度优先 bipartite，hop 跨步唯一占用。
	// 关键变更：探针 cite 匹配(Phase 1b)优先于 hop fn 兜底(Phase 1c)——步若 cite 了具体类(即便
	// 无 hop 匹配),探针可能读过该类(真代码锚点,GR-8),不应被未 cite 文件的 hop fn 兜底抢走
	// (relation-trade b80c53c4 step4:步 cite RelateDocReportServiceImpl/OssUtils,hop fn=uploadFile
	// 的 RelateFileController 未被 cite,旧逻辑抢它→步显错代码)。hop fn 兜底仅在探针也没命中时用
	// (WordBoundaryFnNotSubstringLeak:无探针,fn cancelTask 唯一命中 hop7)。
	//
	//	tier 0 = 步文显式 cite hop 文件 basename（X.java/X.xml，最具体，无 .java/.xml 歧义）；
	//	tier 1 = Class.method 类名 stem == hop 文件 stem（缩写歧义 .java/.xml，比 basename 弱）；
	//	tier 2 = 角色词后缀命中（Service→MaterialService，兼容 LLM 缩写）；
	//	tier 3 = 函数名词边界命中（兜底，cite 比 fn 兜底更具体）；
	//	tier 4 = 源步（@Request*/@Cookie*/@RequestHeader）无候选时的 entry_point 兜底。
	//
	// fn-disagreement 收窄：步文提及某 fn 时,cite 候选里 fn 非空且不一致的 hop 排除——避免歧义 stem
	// （materialmapperex 同名 .java/.xml）把步未提及的无关方法 hop 拉进来（2f2b371c step3 不偷 hop9/10）。
	// [0,0] 非 taint hop（XML 二次解析 dummy，非 sink——sink 有 taint_line）排除出候选：展示只会混淆。
	// 注:未匹配 hop/探针的步=纯文字步(Hop nil),不渲染黄标——grounding 缺口由 judge 层
	// EnforceGroundedDataFlow 门(Case A 真幻觉→uncertain)收口,不在 dev 报告暴露「未证实」。
	type edge struct {
		si     int
		ri     int // recs 索引
		tier   int
		source bool
		taint  bool
		hidx   int
		// citeRank 同 tier 内的 cite 偏好序(仅箭头系多跳 cite 用):0=最优先。
		// 箭头 `[跳0:46 → 跳2]` 语义是"从源跳流到目标跳",目标跳才是这步该显的代码
		// (源跳通常已被上一步 `[跳0]` 占用),故目标跳 rank 0、源跳 rank 1。
		// 单跳 cite 恒 0 → 排序行为与加此字段前一致(零回归)。
		citeRank int
	}
	usedStep := make([]bool, len(steps))
	usedHop := make([]bool, len(recs))
	// 每步 cite 信号预计算(1a cite / 1c fn 兜底复用) + 显式 cite 标记(Super Tier)。
	type stepMeta struct {
		files        map[string]bool
		stepStems    map[string]bool
		roleStems    map[string]bool
		mentionedFns map[string]bool
		isSrc        bool
		hopCite      *int               // [跳N] 显式 cite 的首个跳号(Super Tier tier -1 直绑)
		hopCites     []int              // 该步 cite 到的全部跳号(箭头系 `[跳0:46 → 跳2]` 有两个)
		toolCite     *contract.ToolCite // [工具:...@file] 显式 cite
	}
	metas := make([]stepMeta, len(steps))
	for si := range steps {
		text := steps[si].Text
		if text == "" {
			continue
		}
		textLow := strings.ToLower(text)
		files := mentionedFiles(text)
		stepStems := map[string]bool{}
		roleStems := map[string]bool{}
		for f := range files {
			if s := stemBeforeDot(f); s != "" {
				stepStems[s] = true
				if isRoleWord(s) {
					roleStems[s] = true
				}
			}
		}
		mentionedFns := map[string]bool{}
		for _, r := range recs {
			if r.fn != "" && wordBoundaryMatch(textLow, r.fn) {
				mentionedFns[r.fn] = true
			}
		}
		hopCite, toolCite := contract.ParseStepCite(text)
		metas[si] = stepMeta{files: files, stepStems: stepStems, roleStems: roleStems,
			mentionedFns: mentionedFns, isSrc: isSourceStep(text),
			hopCite: hopCite, hopCites: contract.ParseStepCiteHops(text), toolCite: toolCite}
	}
	// Phase 1a0: reachable_sinks SQL 真值回执(Super Tier,显式 cite 驱动)——先于词法 1a。
	// sink 步 cite [工具:reachable_sinks@method] 时,LLM 声称"这步代码是引擎 reachable_sinks 取到的
	// 真 SQL"。reachable_sinks 回执的 sql_text 是 engine 从 MyBatis XML 解析的真值(GR-8 锚点最强),
	// 须优先于词法 stem 匹配——否则 mentionedFiles 把 cite 里的 "Class.method" 当文件提取,stem
	// 命中 .java 接口 hop(类4 缺口切的是 stub 非 SQL),sink 步会显接口声明冒充 SQL(语义错配比无码更糟)。
	// engineSinkClaimed:凡 cite reachable_sinks 的步,1a/1b/1c 一律跳过——匹配则显 sql_text,
	// 不匹配(AI 没调/无回执/wobble)则留 nil(未切片),绝不退回 .java stub(规则:接口 stub 不得冒充 SQL sink)。
	// 多 sink 歧义阶梯:tier1 method_key 全限定前缀 > tier2 method 短名+concat_params 参名;同 tier 仍
	// 多 rec → 留空(GR-8 宁缺毋错,防配错 SQL)。
	engineSinkClaimed := make([]bool, len(steps))
	for si := range steps {
		m := metas[si]
		if m.toolCite != nil && m.toolCite.Tool == "reachable_sinks" {
			engineSinkClaimed[si] = true
		}
	}
	// Phase 1a0-pre: LLM 直填的 sink_evidence.sink_code（arc ② 首类）优先于 tool_log 反查。
	// sink_evidence 是 exploit_path 上的单一结构化字段（非 per-step），绑到 sink 步——
	// 优先 cite reachable_sinks 的步（LLM 心中的 sink 步），否则最后一个非空步。绑后该步
	// usedStep=true，下面 sinkSqlRec 循环跳过它（首类 vs 兜底）。无 sink_code 则不绑走兜底链。
	if sinkEvidence != nil {
		if sc := hStr(sinkEvidence["sink_code"]); sc != "" {
			sinkStep := -1
			for si := range steps {
				if engineSinkClaimed[si] {
					sinkStep = si
					break
				}
			}
			if sinkStep < 0 {
				for si := len(steps) - 1; si >= 0; si-- {
					if steps[si].Text != "" {
						sinkStep = si
						break
					}
				}
			}
			if sinkStep >= 0 && !usedStep[sinkStep] {
				methodOrig := hStr(sinkEvidence["method_key"])
				if methodOrig == "" {
					methodOrig = hStr(sinkEvidence["sink_location"])
				}
				hop := map[string]any{
					"function_body": sc,
					"function_name": methodOrig,
					"file_path":     hStr(sinkEvidence["sink_location"]),
				}
				hv := buildHopVM(hop, 0)
				hv.HopIdx = sinkStep
				hv.FromSinkEvidence = true
				steps[sinkStep].Hop = &hv
				usedStep[sinkStep] = true
			}
		}
	}
	sinks := buildSinkSqlRecs(trace)
	usedSink := make([]bool, len(sinks))
	if len(sinks) > 0 {
		for si := range steps {
			if usedStep[si] || !engineSinkClaimed[si] {
				continue
			}
			m := metas[si]
			textLow := strings.ToLower(steps[si].Text)
			citeM := strings.ToLower(m.toolCite.File) // method_key(去签名) 或 method 短名
			type cand struct{ ri, tier int }
			var cands []cand
			for ri, s := range sinks {
				mkLow := strings.ToLower(s.methodKey)
				switch {
				case citeM != "" && mkLow != "" && strings.HasPrefix(mkLow, citeM):
					cands = append(cands, cand{ri, 1}) // tier1 全限定 method_key 前缀
				case citeM != "" && s.method != "" && citeM == s.method && sinkConcatHit(textLow, s.concatParams):
					cands = append(cands, cand{ri, 2}) // tier2 短名 + concat_params 参名
				}
			}
			if len(cands) == 0 {
				continue // cite 找不到回执(无码,Case A 类)→ 留 nil,1a/1c 跳过(claimed)
			}
			minT := cands[0].tier
			for _, c := range cands {
				if c.tier < minT {
					minT = c.tier
				}
			}
			var best []cand
			for _, c := range cands {
				if c.tier == minT {
					best = append(best, c)
				}
			}
			if len(best) != 1 {
				continue // 多 rec 同 tier 仍歧义 → 留空(GR-8 宁缺毋错)
			}
			ri := best[0].ri
			if usedSink[ri] {
				continue
			}
			s := sinks[ri]
			hop := map[string]any{
				"function_body": s.sqlText,
				"function_name": s.methodOrig,
				"file_path":     s.methodKey, // 诚实:method_key 作定位(engine 回执无 xml file:line)
			}
			hv := buildHopVM(hop, 0)
			hv.HopIdx = si
			hv.FromEngineSink = true
			steps[si].Hop = &hv
			usedStep[si] = true
			usedSink[ri] = true
		}
	}
	// citeRefFallback — 显式 cite 指向的 hop 被别的步绑走时登记的延后回指(stepIdx → 标签)。
	// 末尾统一落到仍无 Hop 的步上,详见 stepVM.HopRef。
	citeRefFallback := map[int]string{}

	// assignHopEdges: 按 (源步优先, tier, stepIdx, taint-first, hopIdx) 排序贪心分配 hop 边。
	assignHopEdges := func(edges []edge) {
		sort.SliceStable(edges, func(i, j int) bool {
			a, b := edges[i], edges[j]
			if a.source != b.source {
				return a.source && !b.source
			}
			if a.tier != b.tier {
				return a.tier < b.tier
			}
			if a.si != b.si {
				return a.si < b.si
			}
			// 同步内的多跳 cite:目标跳优先于源跳(见 edge.citeRank)。
			if a.citeRank != b.citeRank {
				return a.citeRank < b.citeRank
			}
			if a.taint != b.taint {
				return a.taint && !b.taint
			}
			return a.hidx < b.hidx
		})
		for _, e := range edges {
			if usedStep[e.si] || usedHop[e.ri] {
				// 显式 cite(tier -1)指向的 hop 已被前一步绑走 → **登记**一条延后回指,
				// 但**不消费该步**:它可能还有别的 cite 边或词法/探针候选,那些更值钱。
				// 真正落回指在本函数末尾,仅对最终仍两手空空的步(见 citeRefFallback)。
				if e.tier == -1 && !usedStep[e.si] && usedHop[e.ri] {
					if _, dup := citeRefFallback[e.si]; !dup {
						citeRefFallback[e.si] = hopRefLabel(recs[e.ri].m)
					}
				}
				continue
			}
			r := recs[e.ri]
			hv := buildHopVM(r.m, resolveHighlight(r.m, detail))
			hv.HopIdx = e.si
			steps[e.si].Hop = &hv
			usedStep[e.si] = true
			usedHop[e.ri] = true
		}
	}

	// Phase 1a: hop cite 边(tier 0/1/2,所有步) + 源步 fn 兜底(tier 3) + 源步 entry 兜底(tier 4)。
	// 源步 fn/entry 与 cite 同池分配,源步优先排序保入口稳显(ClassMethodStem step0 fn 兜底压过
	// step1 stem cite 同 hop0——源步是数据流入口,即便 fn 信号弱于 cite,也凭 source 优先拿 hop)。
	// 源步 fn 在 1a 而非 1c:源步 fn-hop 通常是入口 controller,须与 cite 步竞争同 hop 时凭 source
	// 优先拿到;非源步 fn 兜底延后到 1c(探针 1b 之后),让探针 cite 匹配优先于未 cite 的 hop fn。
	var citeEdges []edge
	for si := range steps {
		m := metas[si]
		if usedStep[si] || engineSinkClaimed[si] || steps[si].Text == "" {
			continue
		}
		textLow := strings.ToLower(steps[si].Text)
		hasCite := false
		// Super Tier(tier -1):显式 cite `[跳N]` 直绑 hop[N](N=hop 原始序号)——优先于
		// 一切词法 tier。cite 是 LLM 声称"这步就是这跳"的强信号,不让词法猜测覆盖。N 越界
		// (指向被过滤的 dummy hop)→ 找不到 rec → 无 cite 边,该步退词法;grounding 缺口由
		// judge 层 EnforceGroundedDataFlow 门(Case A→uncertain)收口。
		// 箭头系 cite（`[跳0:46 → 跳2]` / `[跳0→跳3]`）声明两个跳号,两者都是该步的合法
		// 锚点,但**目标跳优先**:箭头语义是"从这跳流到那跳",源跳通常已被上一步占用
		// (`[跳0]` 那步),这步该显的是被调进去的那个函数体。
		//
		// 实现:全部下 tier -1 边,用 citeRank 表达"目标跳优先"(倒序 → 最后一个跳号 rank 0)。
		// 单跳 cite 只产一条 rank 0 的边 → 排序与本改动前完全一致(零回归)。
		for i := len(m.hopCites) - 1; i >= 0; i-- {
			rank := len(m.hopCites) - 1 - i
			for ri, r := range recs {
				if r.idx == m.hopCites[i] {
					citeEdges = append(citeEdges, edge{si: si, ri: ri, tier: -1, source: m.isSrc,
						taint: r.taint, hidx: r.idx, citeRank: rank})
					hasCite = true
					break
				}
			}
		}
		if len(m.files) > 0 {
			for ri, r := range recs {
				t := hopTier(r, m.files, m.stepStems, m.roleStems)
				if t < 0 {
					continue
				}
				if len(m.mentionedFns) > 0 && r.fn != "" && !m.mentionedFns[r.fn] {
					continue
				}
				citeEdges = append(citeEdges, edge{si: si, ri: ri, tier: t, source: m.isSrc,
					taint: r.taint, hidx: r.idx})
				hasCite = true
			}
		}
		// 源步:无 cite 时加 fn 兜底(tier3)+ entry 兜底(tier4),与 cite 同池 source 优先分配。
		// 有 cite 的源步不再 fn 兜底(cite 更具体)。非源步 fn 兜底在 Phase 1c。
		if m.isSrc && !hasCite {
			for ri, r := range recs {
				if r.fn != "" && wordBoundaryMatch(textLow, r.fn) {
					citeEdges = append(citeEdges, edge{si: si, ri: ri, tier: 3, source: true,
						taint: r.taint, hidx: r.idx})
				}
			}
			if entryFile != "" {
				for ri, r := range recs {
					if r.base == entryFile {
						citeEdges = append(citeEdges, edge{si: si, ri: ri, tier: 4, source: true,
							taint: r.taint, hidx: r.idx})
					}
				}
			}
		}
	}
	assignHopEdges(citeEdges)

	// Phase 1b: tool_log 探针回退(read_function/read_file/code_at_line)——优先于 hop fn 兜底。
	// 切片 hop 未匹配的步从探针补代码块(c5f2e1 真 sink callee 不在切片 hop),标 FromProbe。
	// 同样 bipartite:每个探针跨步唯一占用,强信号优先。cite 匹配(tier 0/1/2)优先于 fn(tier 3)。
	probes := buildProbeRecs(trace)
	usedProbe := make([]bool, len(probes))
	if len(probes) > 0 {
		type pedge struct {
			si   int
			pi   int
			tier int
		}
		var pedges []pedge
		for si := range steps {
			if usedStep[si] || engineSinkClaimed[si] || steps[si].Text == "" {
				continue
			}
			m := metas[si]
			textLow := strings.ToLower(steps[si].Text)
			// Super Tier(tier -1):显式 cite `[工具:tool@file[:line]]` 直绑探针——LLM 声称
			// "这步代码是工具读过的"(Case B:切片没切但工具读到),优先于词法。cite 找不到
			// 匹配探针(tool_log 无该回执)→ 无 cite 边,该步不退词法(cite 显式,尊重:无码);
			// grounding 缺口由 judge 门(Case A→uncertain)收口。
			if m.toolCite != nil {
				citeFileLow := strings.ToLower(m.toolCite.File)
				citeBase := fileBase(citeFileLow)
				bestPi, fnMatched := -1, false
				for pi, p := range probes {
					if p.tool != m.toolCite.Tool {
						continue
					}
					match := false
					if citeBase != "" && p.base == citeBase {
						match = true
					} else if p.fileOrig != "" &&
						strings.HasSuffix(strings.ToLower(p.fileOrig), citeFileLow) {
						match = true
					}
					if !match {
						continue
					}
					// 优先级:覆盖 cite.Line 的探针 > **函数名在步文里出现**的探针 > 首个匹配。
					//
					// 函数名这一档是 2026-08-23 补的:cite 常只给文件名,而同一文件上可以有
					// 多个探针(活体 rt 429eb112:OssUtils.java 上有 download/checkFilePath/mkDir
					// 三个 read_function)。只取首个时,两步 cite 同文件 → 一步拿走、另一步没有
					// 备选边,于是「checkFilePath 实现仅做 replace…」这句话摆在报告里却没有代码可核。
					if m.toolCite.Line > 0 && p.hasLR &&
						m.toolCite.Line >= p.start && m.toolCite.Line <= p.end {
						bestPi = pi
						break
					}
					if p.fn != "" && strings.Contains(textLow, p.fn) {
						bestPi = pi
						fnMatched = true
						break
					}
					if bestPi < 0 && !fnMatched {
						bestPi = pi
					}
				}
				if bestPi >= 0 {
					pedges = append(pedges, pedge{si: si, pi: bestPi, tier: -1})
				}
				continue // cite 显式:不退词法探针边(无码则门收口)
			}
			for pi, p := range probes {
				t := -1
				if p.base != "" {
					switch {
					case m.files[p.base]: // (a) 直提 basename
						t = 0
					case p.stem != "" && m.stepStems[p.stem]: // (b) 类名 stem
						t = 1
					default:
						if p.stem != "" {
							for rw := range m.roleStems { // (c) 角色词后缀
								if strings.HasSuffix(p.stem, rw) {
									t = 2
									break
								}
							}
						}
					}
				}
				if t < 0 && p.fn != "" && wordBoundaryMatch(textLow, p.fn) { // 函数名词边界（最弱）
					t = 3
				}
				if t >= 0 {
					pedges = append(pedges, pedge{si: si, pi: pi, tier: t})
				}
			}
		}
		sort.SliceStable(pedges, func(i, j int) bool {
			a, b := pedges[i], pedges[j]
			if a.tier != b.tier {
				return a.tier < b.tier
			}
			if a.si != b.si {
				return a.si < b.si
			}
			return a.pi < b.pi
		})
		for _, e := range pedges {
			if usedStep[e.si] || usedProbe[e.pi] {
				continue
			}
			best := probes[e.pi]
			hop := map[string]any{
				"function_body": best.code,
				"function_name": best.fnOrig,
				"file_path":     best.fileOrig,
			}
			if best.hasLR {
				hop["line_range"] = []any{float64(best.start), float64(best.end)}
			}
			hv := buildHopVM(hop, 0) // 探针无 taint 行锚点，0=不高亮
			hv.HopIdx = e.si
			hv.FromProbe = true
			if best.hasLR {
				hv.ProbeStart = best.start // 三轮第一级：探针真值 range 首行用于注释定位
			}
			steps[e.si].Hop = &hv
			usedStep[e.si] = true
			usedProbe[e.pi] = true
		}
	}

	// Phase 1c: 非源步 hop fn 词边界兜底(tier 3,弱信号)。源步 fn 兜底已在 1a(须与 cite 竞争
	// source 优先)。1b 探针已先处理 cite 文件的步,此处仅命中探针也没覆盖的非源步(无探针或
	// 探针 fn 不匹配)——WordBoundaryFnNotSubstringLeak:无探针,fn cancelTask 唯一命中 hop7。
	var fnEdges []edge
	for si := range steps {
		if usedStep[si] || engineSinkClaimed[si] || steps[si].Text == "" {
			continue
		}
		m := metas[si]
		if m.isSrc {
			continue // 源步 fn 兜底已在 1a
		}
		textLow := strings.ToLower(steps[si].Text)
		for ri, r := range recs {
			if r.fn != "" && wordBoundaryMatch(textLow, r.fn) {
				fnEdges = append(fnEdges, edge{si: si, ri: ri, tier: 3, source: false,
					taint: r.taint, hidx: r.idx})
			}
		}
	}
	assignHopEdges(fnEdges)

	// Phase 1c5: reachable_sinks SQL 词法兜底(tier3,无 cite 的步)。步文 method 短名词边界 +
	// concat_params 参名双命中 → 绑 sql_text。仅填 1a/1b/1c 都未中的步(无 cite 老版 LLM 输出)。
	// cited 步已在 1a0 处理(claimed,跳过);要求 method+param 双信号防误绑(GR-8)。
	if len(sinks) > 0 {
		for si := range steps {
			if usedStep[si] || engineSinkClaimed[si] || steps[si].Text == "" {
				continue
			}
			textLow := strings.ToLower(steps[si].Text)
			var best []int
			for ri, s := range sinks {
				if s.method != "" && wordBoundaryMatch(textLow, s.method) && sinkConcatHit(textLow, s.concatParams) {
					best = append(best, ri)
				}
			}
			if len(best) != 1 {
				continue // 无命中/多歧义 → 留 nil(GR-8)
			}
			ri := best[0]
			if usedSink[ri] {
				continue
			}
			s := sinks[ri]
			hop := map[string]any{
				"function_body": s.sqlText,
				"function_name": s.methodOrig,
				"file_path":     s.methodKey,
			}
			hv := buildHopVM(hop, 0)
			hv.HopIdx = si
			hv.FromEngineSink = true
			steps[si].Hop = &hv
			usedStep[si] = true
			usedSink[ri] = true
		}
	}

	// 显式 cite 的延后回指:所有词法/探针阶段跑完后,仍两手空空的步若 cite 到一个**真实存在但
	// 没被渲染**的 hop,给一条紧凑回指(函数名 @ 文件[:行范围])。两种来源:
	//   ① hop 被前一步绑走(citeRefFallback)—— 不重复整段代码,相邻大段重复更难读,但读者
	//      至少知道「这步的代码在上面哪一块」。三 run 实测 84 个有效 cite 中 28 个(33%)因此丢锚点。
	//   ② hop 被 recs 过滤掉([0,0] 且非 taint 的 XML 二次解析 hop,见上方过滤注释)—— 不显
	//      代码是既定展示决定,但该 hop 是切片真值,说出它的名字不是编造(GR-8)。
	// 跳号在切片里压根不存在(真越界)则什么都不给 —— 不存在的东西编不出名字。
	for si := range steps {
		if steps[si].Hop != nil || steps[si].HopRef != "" {
			continue
		}
		if ref := citeRefFallback[si]; ref != "" {
			steps[si].HopRef = ref
			continue
		}
		for _, n := range metas[si].hopCites {
			if n < 0 || n >= len(rawHops) {
				continue
			}
			if hm := hMap(rawHops[n]); hm != nil {
				if ref := hopRefLabel(hm); ref != "" {
					steps[si].HopRef = ref
					break
				}
			}
		}
		if steps[si].HopRef != "" {
			continue
		}
		// ③ **探针**被兄弟步合法占用(2026-08-23 补)——与 ① 同一类:探针跨步唯一占用,
		// 后来的步 cite 同一文件就两手空空。活体 rt eb92a1d4:步3 绑走
		// RelateTradeManaComponent.java 的 read_file 探针,步4 cite 同文件 → 无码无锚,
		// 报告里剩一句「文件名由原始 getOriginalFilename 派生」没法核。
		// 探针是工具真读到的东西,说出它的名字不是编造(GR-8)。
		if tc := metas[si].toolCite; tc != nil {
			citeBase := fileBase(strings.ToLower(tc.File))
			for _, p := range probes {
				if p.tool != tc.Tool || (citeBase != "" && p.base != citeBase) {
					continue
				}
				if ref := probeRefLabel(p); ref != "" {
					steps[si].HopRef = ref
					break
				}
			}
		}
	}

	// 安全网去重：相邻两步命中同 FilePath+LineRange（含 FromProbe 的函数名）时后者转纯文字。
	// bipartite 已使 hop 跨步唯一占用，此分支理论上不再触发，保留防同 FilePath 不同 hop 的边界。
	prevKey := ""
	for si := range steps {
		h := steps[si].Hop
		if h == nil {
			prevKey = ""
			continue
		}
		key := h.FilePath + "|" + h.LineRange
		if h.FromProbe || h.FromEngineSink || h.FromSinkEvidence {
			key += "|" + h.FunctionName
		}
		if key == prevKey {
			steps[si].Hop = nil
			steps[si].dedupedFromPrev = true // 有锚点,只是不重复代码 —— 不得被当无锚点丢弃
		} else {
			prevKey = key
		}
	}
	// 未匹配 hop/探针的步保持 Hop=nil(纯文字步),不渲染标记——grounding 由 judge 层门收口。
	// cite 标记是内部锚点语法,从 dev 展示文本移除(开发报告只见干净步文 + 代码块)。
	// 锚定标记必须在**剥离 cite 之前**算 —— stripStepCites 之后文本里就没有 cite 了。
	// 有效 cite 也算锚定:`[工具:reachable_sinks@X]` 指向真读过的东西,只是候选歧义
	// 无法唯一渲染代码块(GR-8 宁缺毋错),那不等于它是幻觉。
	var hopFiles, probeFiles []string
	for _, r := range recs {
		hopFiles = append(hopFiles, r.base, r.fn)
	}
	for _, p := range probes {
		probeFiles = append(probeFiles, p.base, p.fn)
	}
	for si := range steps {
		if steps[si].anchored {
			continue
		}
		steps[si].anchored = stepHasValidCite(steps[si].Text, len(recs), probes, sinks) ||
			hasLexicalAnchor(steps[si].Text, hopFiles, probeFiles)
	}
	return annotateSteps(markUnanchoredSteps(stripStepCites(steps)))
}

// markUnanchoredSteps —— 无锚点步改为显示并标注（2026-09-05 用户拍板，取代丢弃）。
//
// 2026-08-23 曾按 GR-8「收敛叙述」拍板丢弃：既无 Hop(无代码块)又无 HopRef(非「同上」
// 去重)的一步不展示。但实测丢的多是缺鉴权类叙述（「该接口无任何鉴权」）——
// 那类漏洞**本身就没有代码可锚**（守卫不存在是缺失，不是某行代码），丢掉等于把
// 攻击面叙述从交付物里抹掉。改为置 NoAnchor 标记，模板渲染虚线框标注，
// 读者看得见「这里本应有代码，但属缺失型漏洞」。
// judge 层 EnforceGroundedDataFlow 仍管 verdict 降级（展示与判决分工不同）。
func markUnanchoredSteps(steps []stepVM) []stepVM {
	for i := range steps {
		if steps[i].Hop == nil && steps[i].HopRef == "" && !steps[i].dedupedFromPrev && !steps[i].anchored {
			steps[i].NoAnchor = true
		}
	}
	return steps
}

// annotateSteps —— 每个数据流代码块都插注释，三级定位（2026-09-05 用户拍板三轮）。
//
// 背景高亮被否掉后，注释是读者定位「这步的问题在哪行」的唯一信号。但无 taint_line 的
// 中转跳没有真值行号，启发式词法匹配有三个盲区（词不在场/一词多处/善意谎言），
// 不能强行插入带行号的注释——否则等于编造行号（违反 GR-8）。故分级：
//
//	第一级（真值行号）:切片 hop 的 taint 行 / 探针 read_file/code_at_line 的 range 首行。
//	  → 插该行后，带 L{n}（100% 置信）。
//	第二级（词法唯一命中）:步文调用形式 token（如 doSubmit(）或 hop function_name
//	  在代码行词边界**恰好命中一行**才用（多处冲突不取首个——那也是善意谎言）。
//	  → 插命中行后，带 L{n}。
//	第三级（块级标注兑底）:无真值无唯一命中 → hop-head 后 block-note div，
//	  不带行号。中转跳语义本就是「经过此地」非「案发此地」，诚实标注即可。
//
// 注释内容全量步文（去截断，pre-wrap 软折行 2-3 行；用户两轮反馈单薄）。换行/多空格归一单空格。
func annotateSteps(steps []stepVM) []stepVM {
	for si := range steps {
		h := steps[si].Hop
		if h == nil || steps[si].Text == "" {
			continue
		}
		stepNum := si + 1
		flat := flattenStepText(steps[si].Text)

		// 第一级 a:切片 hop 的 taint 行（最精确）。
		for li := range h.WinLines {
			if h.WinLines[li].Taint {
				note := "// 🔴 分析点 L" + strings.TrimRight(h.WinLines[li].No, ". ") + "：" + flat
				h.WinLines = insertBefore(h.WinLines, li, lineVM{Note: note})
				goto next
			}
		}
		// 第一级 b:探针 read_file/code_at_line 的真值 range 首行（executor 真值，GR-8 安全）。
		if h.ProbeStart > 0 {
			for li := range h.WinLines {
				if strings.TrimRight(h.WinLines[li].No, ". ") == strconv.Itoa(h.ProbeStart) {
					note := "// 🔴 分析点 L" + strconv.Itoa(h.ProbeStart) + "：" + flat
					h.WinLines = insertBefore(h.WinLines, li, lineVM{Note: note})
					goto next
				}
			}
		}
		// 第二级:词法唯一命中。
		if li := lexicalAnchorLine(h.WinLines, steps[si].Text, h.FunctionName); li >= 0 {
			note := "// 🔴 分析点 L" + strings.TrimRight(h.WinLines[li].No, ". ") + "：" + flat
			h.WinLines = insertBefore(h.WinLines, li, lineVM{Note: note})
			goto next
		}
		// 第三级:块级标注，不带行号。
		h.BlockNote = "🔴 [步骤 " + strconv.Itoa(stepNum) + " 中转]：" + flat
	next:
	}
	return steps
}

// insertBefore —— 在 lines[i] **前**插入一行（注释贴在目标代码行上方，读者先看分析再看代码；
// 2026-09-05 用户拍板：人下意识往下看，注释在上方更自然）。返回新切片，避免原 slice 容量别名副作用。
func insertBefore(lines []lineVM, i int, l lineVM) []lineVM {
	out := make([]lineVM, 0, len(lines)+1)
	out = append(out, lines[:i]...)
	out = append(out, l)
	out = append(out, lines[i:]...)
	return out
}

// flattenStepText —— 步文换行/多空格归一单空格（不截断，全量进注释）。
func flattenStepText(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// keywordBlacklist —— 词法定位 token 提取的黑名单（语言关键字与极通用控制词，
// 这些词在代码里高频多出现，命中会触发「多处冲突降级」白跑一趟；直接跳过）。
var keywordBlacklist = map[string]bool{
	"if": true, "for": true, "while": true, "do": true, "try": true, "catch": true,
	"finally": true, "return": true, "new": true, "throw": true, "switch": true,
	"case": true, "else": true, "synchronized": true, "lambda": true, "assert": true,
	"yield": true, "break": true, "continue": true, "default": true, "goto": true,
}

// callTokenRe —— 提取调用形式 ident（兼容半角/全角括号；用户微操 2）。
var callTokenRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*[\(（]`)

// lexicalAnchorLine —— 三轮第二级：步文调用 token / fn 名在代码行词边界**唯一**命中 → 返回该行索引；
// 无命中或多行冲突返 -1（降第三级）。case-sensitive 词边界匹配，防子串泄漏（lawsuitRevoke 不得命中
// taskLawsuitRevokeRequest）。token 提取优先调用形式（doSubmit(），次 hop fn；关键字黑名单 +
// 长度 <3 跳过（用户微操 3）。
func lexicalAnchorLine(winLines []lineVM, stepText, fnName string) int {
	var tokens []string
	for _, m := range callTokenRe.FindAllStringSubmatch(stepText, -1) {
		tok := m[1]
		if keywordBlacklist[tok] || len(tok) < 3 {
			continue
		}
		tokens = append(tokens, tok)
	}
	if fnName != "" && !keywordBlacklist[strings.ToLower(fnName)] && len(fnName) >= 3 {
		tokens = append(tokens, fnName)
	}
	for _, tok := range tokens {
		hit := -1
		for li, l := range winLines {
			if l.Taint || l.Note != "" {
				continue // 跳过注释/已标行
			}
			if wordBoundaryMatch(l.Text, tok) {
				if hit >= 0 {
					hit = -1 // 多处冲突 → 放弃该 token
					break
				}
				hit = li
			}
		}
		if hit >= 0 {
			return hit
		}
	}
	return -1
}

// hasLexicalAnchor 判步文是否提到切片 hop 或工具探针里真实存在的文件名/函数名。
func hasLexicalAnchor(text string, hopFiles, probeFiles []string) bool {
	low := strings.ToLower(text)
	for _, f := range hopFiles {
		if f != "" && strings.Contains(low, f) {
			return true
		}
	}
	for _, f := range probeFiles {
		if f != "" && strings.Contains(low, f) {
			return true
		}
	}
	return false
}

// stripStepCites —— cite 标记是内部锚点语法,从 dev 展示文本移除(开发报告只见干净步文
// + 代码块)。**两条返回路径必须都走这里**:早先无 trace 的早返回绕过了它,导致拿不到
// trace 的条目把内部语法印进报告。抽成函数就是为了让「漏走一条路径」在结构上不可能。
func stripStepCites(steps []stepVM) []stepVM {
	for si := range steps {
		if steps[si].Text != "" {
			steps[si].Text = contract.StripCites(steps[si].Text)
		}
	}
	return steps
}

func lineRangeStr(v any) string {
	lr, ok := v.([]any)
	if !ok || len(lr) < 2 {
		return ""
	}
	a, _ := lr[0].(float64)
	b, _ := lr[1].(float64)
	if a == 0 && b == 0 {
		return ""
	}
	if a == b {
		return strconv.Itoa(int(a))
	}
	return strconv.Itoa(int(a)) + "-" + strconv.Itoa(int(b))
}

// isConfirmed — 主报告明细过滤的唯一入口。
// 本期：AI 判定 verdict==true_positive 即确认。
// 后续扩展点（本期不实现）：或人工 label==true_positive；把人工确认的
// needs-hardening 接进主报告。改这里即可，调用方不动。
func isConfirmed(d map[string]any) bool {
	return hStr(d["verdict"]) == "true_positive"
}

// isSuspected — 「疑似真漏洞（待确认）」分节的准入(C1,2026-08-22 用户拍板)。
//
// VerdictOf 5→3 折叠(硬约束 judge/build.go:12-19)把 disposition=likely_tp 与真 uncertain
// 压成同一个 verdict="uncertain"。折叠本身正确不可动,但**展示**照搬 verdict 就把
// 「证据齐全、只差一个渲染上下文」和「sink 在三方 jar 里根本看不见」显示成同一件事,
// 于是一起被 isConfirmed 藏掉(三 run 9 项 uncertain:4 项 likely_tp / 2 项真不确定 / 1 项误降)。
//
// 只放 likely_tp:真 uncertain 没有可交付结论,放进来等于把「不知道」当「疑似有」卖;
// 探针误降(verification.action=downgraded_to_uncertain)是探针给出了反证,更不该进。
//
// **确认漏洞节的门槛不动**:isConfirmed 仍只认 true_positive,本函数是另一道独立的门。
func isSuspected(d map[string]any) bool {
	if hStr(d["verdict"]) != "uncertain" {
		return false
	}
	if v := hMap(d["verification"]); hStr(v["action"]) == "downgraded_to_uncertain" {
		return false
	}
	return hStr(d["disposition"]) == "likely_tp"
}

// RenderHTML 将 GetRun 返回数据渲染为自包含 HTML 报告（内联样式 + 打印适配）。
//
// 行为变更（2026-08-09）：本函数由"渲染所有 verdict 明细"改为"经 isConfirmed 过滤，
// 仅渲染 verdict==true_positive 的确认漏洞"。旧报告依赖者若需查看 FP/uncertain 全量
// 明细，后续可经 ?all=1 恢复全量渲染——本期不实现 ?all=1，仅留此注释标明恢复点。
//
// traces（2026-08-13 落地 spec §9.6 扩展点）：key=bughash 的 trace map，由 route 层
// 逐确认 detail 读 runsread.Trace 传入。存在则 matchHopsToSteps 注入 data_flow 步下
// 代码切片（同 RenderAlertHTML）；缺失（nil 或无对应 key）→ 该 detail 步仅文字。
func RenderHTML(data map[string]any, traces map[string]map[string]any) (string, error) {
	meta := hMap(data["meta"])
	summary := hMap(data["summary"])
	rawDetails, _ := data["details"].([]map[string]any)

	isDiscovery := hStr(meta["adapter"]) == "diff"
	mode := "扫描"
	if isDiscovery {
		mode = "discovery"
	}
	dur := ""
	if d, ok := meta["duration_seconds"].(float64); ok {
		dur = fmt.Sprintf("%.1fs", d)
	}

	page := htmlPage{
		Meta: htmlMeta{
			RunID: hStr(meta["run_id"]), RepoKey: hStr(meta["repo_key"]),
			Adapter: hStr(meta["adapter"]), Model: hStr(meta["model"]),
			Timestamp: hStr(meta["timestamp"]), Mode: mode, DurationSeconds: dur,
		},
	}

	// 明细 → VM + 类型分布（仅确认漏洞；isConfirmed 过滤，2026-08-09 行为变更）
	typeCounts := map[string]int{}
	confirmed := make([]map[string]any, 0, len(rawDetails))
	for _, d := range rawDetails {
		if isConfirmed(d) {
			confirmed = append(confirmed, d)
		}
	}
	details := make([]detailVM, 0, len(confirmed))
	for _, d := range confirmed {
		vm := buildDetailVM(d)
		// §9.6：注入 trace hop 代码到 data_flow 步（trace 由 route 层读入，nil 则步仅文字）。
		// 总调 matchHopsToSteps：nil trace 时它内部退化为剥假行号+剔评论步(无 hop 匹配)。
		vm.DataFlow = matchHopsToSteps(vm.DataFlow, d, traces[vm.Bughash])
		vm.recomputeEntryLine()
		typeCounts[vm.VulnType]++
		details = append(details, vm)
	}
	sort.SliceStable(details, func(i, j int) bool {
		return severityRank(details[i].Severity) < severityRank(details[j].Severity)
	})
	page.Details = details
	page.DetailCount = len(details)

	// 疑似真漏洞(待确认):独立分节,复用同一 VM 管线(代码块/数据流/缺口全同确认节)。
	// 不进类型分布与严重度分布 —— 那两处的口径是「确认漏洞」,混入会让数字口径漂移。
	sevCountsForPlan := map[string]int{}
	for _, vm := range details {
		if vm.HasSeverity {
			sevCountsForPlan[vm.Severity]++
		}
	}

	suspected := make([]detailVM, 0)
	for _, d := range rawDetails {
		if !isSuspected(d) {
			continue
		}
		vm := buildDetailVM(d)
		vm.DataFlow = matchHopsToSteps(vm.DataFlow, d, traces[vm.Bughash])
		vm.recomputeEntryLine()
		suspected = append(suspected, vm)
	}
	sort.SliceStable(suspected, func(i, j int) bool {
		return severityRank(suspected[i].Severity) < severityRank(suspected[j].Severity)
	})
	page.Suspected = suspected
	page.SuspectedCount = len(suspected)

	// 摘要：scan 模式单卡「确认漏洞 N」；discovery 模式保留原卡片（其卡片本就反映发现/真漏洞/安全，非 FP 仪表盘）
	if isDiscovery {
		page.Cards = []htmlCard{
			{"已审单元", hNum(summary["units_scanned"]), "info"},
			{"发现", hNum(summary["findings"]), "warn"},
			{"真漏洞", hNum(summary["ai_true_positives"]), "danger"},
			{"不确定", hNum(summary["ai_uncertain"]), "warn"},
			{"安全", hNum(summary["ai_safe"]), "success"},
		}
	} else {
		page.Cards = []htmlCard{{"确认漏洞", len(details), "danger"}}
	}

	// 审查范围与未覆盖面(B5):演示场景最容易被追问「覆盖了什么、漏了什么」。不写清楚,读者
	// 会默认「没报 = 没有」—— 而本系统覆盖面的**上限就是 SAST 告警集合**。
	// GR-8:只陈述可核实的事实(输入几条/判了几条/排除几条/空切片几条),不写「已覆盖全部风险」。
	{
		fn := hMap(summary["funnel"])
		sastIn := int(hNum(fn["sast_in"]))
		if sastIn == 0 {
			sastIn = len(rawDetails)
		}
		page.Scope = append(page.Scope,
			fmt.Sprintf("输入为 SAST（%s）报出的 %d 条告警，逐条切片后由模型判定；本报告的覆盖面上限即这批告警。",
				hStr(meta["adapter"]), sastIn))
		page.Scope = append(page.Scope,
			"未覆盖：SAST 未报出的位置不在本次判定范围内——「本报告没写」不等于「那里没有问题」。")
		if n := int(hNum(summary["blind_alerts"])); n > 0 {
			page.Scope = append(page.Scope,
				fmt.Sprintf("未覆盖：%d 条告警切片为空（空切片），判定环节没有看到任何代码，已按不确定处理而非默认安全。", n))
		}
		if n := int(hNum(fn["hard_excluded"])); n > 0 {
			page.Scope = append(page.Scope, fmt.Sprintf("按硬规则排除 %d 条（非 Java / 测试代码等），未送判定。", n))
		}
		if n := int(hNum(summary["human_review_needed"])); n > 0 {
			page.Scope = append(page.Scope, fmt.Sprintf("其中 %d 条建议人工复核。", n))
		}
		// 判定可靠性(2026-08-23):用户问「误报率是不是 0%」。报告**不给**这个数字 ——
		// 全仓只有 1 条人工标注,没有真值集就算不出准确率/误报率,写出来即编造(GR-8);
		// 且实测同输入三跑、报告分区层 50% 的条目会变动,任何「零误报」声称都会被第二次
		// 扫描当场证伪。能如实给的是**可核验性**:多少条确认漏洞的关键判据能回挂到具体
		// file:line。这是可算的事实,且正好替代「信不信模型」——读者自己翻那一行即可。
		if n := len(details); n > 0 {
			anchored := 0
			for _, vm := range details {
				for _, c := range vm.SinkChecks {
					if contract.ParseLocation(c.Location).Anchored {
						anchored++
						break
					}
				}
			}
			page.Scope = append(page.Scope,
				fmt.Sprintf("可核验性：%d 条确认漏洞中 %d 条的关键判据已锚定到具体 file:line，本报告随每条附上该处真实源码——不必采信模型结论，翻到那一行即可自行核实。",
					n, anchored))
			page.Scope = append(page.Scope,
				"判定由模型作出，是有源码证据支撑的判断而非形式化证明；本报告不声称零误报，请以上述锚点复核后再排期。")
		}
	}

	// 确定性面账（F5）：**并列的第三道独立门** —— `isConfirmed`/`isSuspected` 与
	// `html_test.go:100/105/110/118` 三处 load-bearing 锁一行不动（C1 已验证过的路数：
	// 「推翻旧决定」与「并列加一道门」代价差一个量级）。
	//
	// 这些是**未判定**的待复核项：同类兄弟在相同鉴权事实形态下被判定存在该面，本条未考虑它。
	// 措辞红线：不得写成「发现漏洞」—— authz 三态全空只证明「无鉴权守卫」，不等于漏洞
	// （登录接口、健康检查本就该公开）。替模型下判决会制造大批误报（GR-8）。
	for _, d := range rawDetails {
		for _, f := range sliceOf(d["faces"]) {
			fm := hMap(f)
			if fm == nil {
				continue
			}
			var facts []string
			for _, x := range sliceOf(fm["facts"]) {
				if s, ok := x.(string); ok {
					facts = append(facts, s)
				}
			}
			regressed := false
			for _, x := range sliceOf(fm["flags"]) {
				if s, ok := x.(string); ok && s == contract.FlagRegressedFromHistory {
					regressed = true
				}
			}
			row := faceRowVM{
				Alert:       fileBase(hStr(d["alert_id"])),
				Type:        vulnTypeLabel(map[string]any{"actual_vulnerability_types": []any{hStr(fm["type"])}}),
				Counterpart: shortHash(hStr(fm["counterpart_bughash"])),
				Facts:       facts,
				Regressed:   regressed,
			}
			// 分两张表：自我退化单独成节且排在前面 —— 它是「同一条告警对同一份代码
			// 前后给出不同答案」，比「兄弟不一致」重一档。
			if regressed {
				page.RegressedRows = append(page.RegressedRows, row)
			} else {
				page.FaceRows = append(page.FaceRows, row)
			}
		}
	}

	// 口径图例:有确认漏洞才显(没有数字就没有要解释的口径)。
	page.ShowLegend = len(details) > 0

	// 修复优先级建议:严重度计数 → 排期。只在有确认漏洞时给(没什么可排的就不给)。
	for _, t := range []struct{ sev, tier, note string }{
		{"critical", "立即修复", "远程可利用或影响面覆盖全站，建议当天处置"},
		{"high", "高优先级", "建议 1 周内修复"},
		{"medium", "计划修复", "建议纳入本迭代"},
		{"low", "择期修复", "可随重构一并处理"},
	} {
		if c := sevCountsForPlan[t.sev]; c > 0 {
			page.FixPlan = append(page.FixPlan, planRow{Tier: t.tier, Count: c, Note: t.note})
		}
	}

	// 审计漏斗:把「这 N 条是从多少条里筛出来的」摊开。数据全在 summary.funnel,纯展示。
	//
	// GR-8:只显**数据里真有**的级。缺失的键不补 0 —— 补 0 等于声称「这一级确实筛了 0 条」,
	// 而真相是这一级压根没跑(如 grounding 门默认 off 时)。键在但值为 0 则照显(跑了,筛了 0)。
	if fn := hMap(summary["funnel"]); len(fn) > 0 {
		for _, st := range []struct{ key, label string }{
			{"sast_in", "SAST 输入"},
			{"hard_excluded", "硬规则排除"},
			{"control_flow_pruned", "控制流剪枝"},
			{"bughash_inherited", "历史判定继承"},
			{"ai_judged", "AI 判定"},
			{"auto_suppressed", "自动抑制"},
		} {
			if v, ok := fn[st.key]; ok {
				page.Funnel = append(page.Funnel, funnelRow{Label: st.label, Value: int(hNum(v))})
			}
		}
		page.Funnel = append(page.Funnel, funnelRow{Label: "确认漏洞", Value: len(details)})
	}

	// 已排除的误报:证明系统在**主动排除**,而非只会报。理由直接来自判决,不二次加工。
	if fp := hMap(summary["fp_patterns"]); len(fp) > 0 {
		for t, raw := range fp {
			m := hMap(raw)
			if m == nil {
				continue
			}
			row := fpRow{Type: t, Count: int(hNum(m["count"]))}
			if name := vulntax.DisplaySlug(t); name != "" {
				row.Type = name
			} else if isAllDigits(t) {
				// SAST 内部数字编码(如 02000010110081)对读者无意义。退化成可读标签而非
				// 原样展示 —— 条数与排除理由照常给,只是类型名不冒充「一个类型」。
				row.Type = "未分类（SAST 内部编码）"
			}
			if rs, ok := m["reasons"].([]any); ok {
				for _, r := range rs {
					if s := hStr(r); s != "" {
						row.Reasons = append(row.Reasons, s)
					}
				}
			}
			page.FPPatterns = append(page.FPPatterns, row)
		}
		sort.SliceStable(page.FPPatterns, func(i, j int) bool {
			if page.FPPatterns[i].Count != page.FPPatterns[j].Count {
				return page.FPPatterns[i].Count > page.FPPatterns[j].Count
			}
			return page.FPPatterns[i].Type < page.FPPatterns[j].Type
		})
	}

	// 严重度分布：从确认明细自算（不照搬 summary.severity_counts，避免混入 FP/uncertain）
	sevCounts := map[string]int{}
	for _, vm := range details {
		if vm.HasSeverity {
			sevCounts[vm.Severity]++
		}
	}
	total := 0
	for _, c := range sevCounts {
		total += c
	}
	for _, name := range sevOrder {
		if c, ok := sevCounts[name]; ok {
			pct := 0
			if total > 0 {
				pct = c * 100 / total
			}
			page.Severity = append(page.Severity, sevBar{name, c, pct, severityClass(name)})
		}
	}
	// 非标准 severity 排尾
	var extra []string
	for k := range sevCounts {
		found := false
		for _, s := range sevOrder {
			if k == s {
				found = true
				break
			}
		}
		if !found {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		pct := 0
		if total > 0 {
			pct = sevCounts[k] * 100 / total
		}
		page.Severity = append(page.Severity, sevBar{k, sevCounts[k], pct, severityClass(k)})
	}
	page.HasSeverity = len(page.Severity) > 0

	// needs-hardening 提示（口子：本期不进主报告，仅提示人工去单条报告复核）
	nhSet := map[string]struct{}{}
	for _, d := range rawDetails {
		if hStr(d["verdict"]) == "needs-hardening" {
			if bh := hStr(d["bughash"]); bh != "" {
				nhSet[bh] = struct{}{}
			}
		}
	}
	page.NHCount = len(nhSet)
	page.NeedsHardening = page.NHCount > 0

	var tKeys []string
	for k := range typeCounts {
		tKeys = append(tKeys, k)
	}
	sort.Slice(tKeys, func(i, j int) bool {
		if typeCounts[tKeys[i]] != typeCounts[tKeys[j]] {
			return typeCounts[tKeys[i]] > typeCounts[tKeys[j]]
		}
		return tKeys[i] < tKeys[j]
	})
	for _, k := range tKeys {
		page.Types = append(page.Types, typeRow{k, typeCounts[k]})
	}

	var buf bytes.Buffer
	if err := htmlTpl.Execute(&buf, page); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var htmlTpl = template.Must(template.New("audit").Parse(htmlTplSrc))

// RenderAlertHTML — 单条告警的可编辑 HTML 报告（供 needs-hardening 人工复核路径）。
// 复用明细卡模板；修复区块渲染为可编辑 <textarea>，预填 suggested_fix，打印前人工填/改。
// 纯函数无 IO；不落盘、不 POST。
// trace 由 alertReportHandler 经 runsread.Trace 读取后传入，nil/无 hops → 代码切片区跳过。
// 只读变体见 RenderAlertPrintHTML（2026-09-05 落地，供 headless PDF 链路）。
func RenderAlertHTML(detail, meta, trace map[string]any) (string, error) {
	return renderAlert(detail, meta, trace, true)
}

// RenderAlertPrintHTML — 单条告警的**打印/PDF 版**报告（2026-09-05）。
// 与 RenderAlertHTML 唯一差异：修复建议渲染为只读 diff/pre，不用 <textarea> ——
// headless 打印（chromedp PrintToPDF）对 textarea 按指定 rows 截断，PDF 里修复
// 建议会丢失下半段。纯函数无 IO；不落盘。
func RenderAlertPrintHTML(detail, meta, trace map[string]any) (string, error) {
	return renderAlert(detail, meta, trace, false)
}

func renderAlert(detail, meta, trace map[string]any, editable bool) (string, error) {
	vm := buildDetailVM(detail)
	vm.Editable = editable
	vm.DataFlow = matchHopsToSteps(vm.DataFlow, detail, trace)
	vm.recomputeEntryLine()
	page := htmlPage{
		Meta: htmlMeta{
			RunID: hStr(meta["run_id"]), RepoKey: hStr(meta["repo_key"]),
			Adapter: hStr(meta["adapter"]), Model: hStr(meta["model"]),
			Timestamp: hStr(meta["timestamp"]),
		},
		Details:     []detailVM{vm},
		DetailCount: 1,
		EditableFix: editable,
	}
	var buf bytes.Buffer
	if err := htmlTpl.Execute(&buf, page); err != nil {
		return "", err
	}
	return buf.String(), nil
}

const htmlTplSrc = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>漏洞审计报告 - {{.Meta.RunID}}</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#10141a;color:#dfe2eb;font-family:"Inter","Segoe UI",system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6}
.mono{font-family:"JetBrains Mono",ui-monospace,Consolas,"Courier New",monospace}
.wrap{max-width:960px;margin:0 auto;padding:40px 24px 80px}
header.rp{border-bottom:1px solid #2a2f38;padding-bottom:20px;margin-bottom:28px}
header.rp h1{font-size:26px;font-weight:700;letter-spacing:.5px}
header.rp .sub{color:#8b90a0;font-size:12px;margin-top:4px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-top:16px}
.meta .mi{background:#181c22;border:1px solid #2a2f38;border-radius:6px;padding:8px 12px}
.meta .k{color:#8b90a0;font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.meta .v{font-size:13px;margin-top:2px;word-break:break-all}
h2.sec{font-size:16px;font-weight:600;margin:32px 0 14px;padding-left:10px;border-left:3px solid #4b8eff}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:#181c22;border:1px solid #2a2f38;border-radius:8px;padding:14px 16px}
.card .n{font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:26px;font-weight:700}
.card .l{color:#8b90a0;font-size:12px;margin-top:2px}
.t-danger{color:#ff544b}.t-success{color:#13ff43}.t-warn{color:#ffd700}.t-info{color:#adc6ff}.t-muted{color:#c1c6d7}
table.tb{width:100%;border-collapse:collapse;background:#181c22;border:1px solid #2a2f38;border-radius:8px;overflow:hidden}
table.tb th,table.tb td{padding:8px 14px;text-align:left;border-bottom:1px solid #2a2f38;font-size:13px}
table.tb th{background:#1c2026;color:#c1c6d7;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
table.tb tr:last-child td{border-bottom:none}
table.tb td.n{font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;text-align:right}
table.tb th.n{text-align:right}
.bar-row{display:flex;align-items:center;gap:12px;margin:8px 0}
.bar-row .name{width:90px;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:12px}
.bar-row .track{flex:1;background:#0a0e14;border-radius:4px;height:14px;overflow:hidden}
.bar-row .fill{height:100%;border-radius:4px}
.bar-row .cnt{width:48px;text-align:right;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:12px;color:#c1c6d7}
.fill.sev-critical,.badge.sev-critical{background:rgba(255,49,49,.85)}
.fill.sev-high{background:rgba(255,84,75,.85)}
.fill.sev-medium{background:rgba(255,215,0,.75)}
.fill.sev-low{background:rgba(19,255,67,.7)}
.fill.sev-none{background:#414755}
.badge{display:inline-block;padding:1px 10px;border-radius:999px;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:11px;font-weight:600;letter-spacing:.4px}
.badge.sev-critical{background:rgba(255,49,49,.15);color:#ff3131}
.badge.sev-high{background:rgba(255,84,75,.15);color:#ff544b}
.badge.sev-medium{background:rgba(255,215,0,.13);color:#ffd700}
.badge.sev-low{background:rgba(19,255,67,.13);color:#13ff43}
.badge.sev-none{background:rgba(139,144,160,.15);color:#8b90a0}
.badge.v-tp{background:rgba(255,49,49,.15);color:#ff3131}
.badge.v-fp{background:rgba(19,255,67,.13);color:#13ff43}
.badge.v-unc{background:rgba(255,215,0,.13);color:#ffd700}
.badge.v-nh{background:rgba(75,142,255,.18);color:#adc6ff}
.detail{background:#181c22;border:1px solid #2a2f38;border-radius:8px;padding:18px 20px;margin-bottom:16px;break-inside:auto}
.detail .head{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:8px}
.detail .type{font-size:15px;font-weight:600}
.detail .conf{margin-left:auto;color:#8b90a0;font-size:12px;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace}
.detail .entry{color:#adc6ff;font-size:12px;word-break:break-all;margin:4px 0 10px}
.detail h3{font-size:12px;color:#8b90a0;text-transform:uppercase;letter-spacing:.6px;margin:14px 0 6px}
.detail ol.flow{margin-left:20px;color:#c1c6d7;font-size:13px}
.detail ol.flow li{margin:3px 0}
.detail p.reason{color:#c1c6d7;font-size:13px;white-space:pre-wrap}
.detail p.harm-summary{color:#e6e9f2;font-size:14px;margin-bottom:6px}
ul.scope{margin:8px 0 0 18px;color:#c1c6d7;font-size:13px;line-height:1.8}
.detail p.dev-note{color:#e6e9f2;font-size:14px;line-height:1.7;margin:4px 0}
.detail p.design-note{color:#b9c2d6;font-size:13px;border-left:3px solid #3d7a4e;padding-left:10px;margin-top:6px}
.detail .hop-ref{color:#8b93a7;font-size:12px;margin:2px 0 6px}
.detail .flow-summary{color:#9fb4d8;font-size:12px;background:#141821;border-left:3px solid #2f6fd0;padding:6px 10px;margin:8px 0 4px;border-radius:3px;word-break:break-all}
table.funnel td:first-child{color:#c1c6d7}
.tb .reason{color:#c1c6d7;font-size:12px;margin:2px 0}
pre.code{background:#0a0e14;border:1px solid #232830;border-radius:6px;padding:12px 14px;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:12px;line-height:1.55;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#dfe2eb}
.fix{margin-top:6px}.fix-loc{margin-bottom:4px}.fix-diff{background:#0a0e14;border:1px solid #232830;border-radius:6px;overflow-x:auto}
.diff-del,.diff-add{display:flex;gap:6px;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:12px;padding:1px 10px;border-left:2px solid transparent}
.diff-del{border-left-color:#ff544b;background:rgba(255,84,75,.08)}.diff-add{border-left-color:#13ff43;background:rgba(19,255,67,.07)}
.diff-del .sign{color:#ff544b}.diff-add .sign{color:#13ff43}
.diff-ctx{display:flex;gap:6px;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:12px;padding:1px 10px;border-left:2px solid #55606e;color:#c9d1d9}
.fix-ctx-label{font-size:11px;color:#8b949e;padding:2px 10px 4px}
@media print{.fix-diff{background:#f6f8fa;border-color:#ddd}.diff-del{background:rgba(255,84,75,.06)}.diff-add{background:rgba(19,255,67,.05)}}
.step-code{margin:6px 0 10px}.hop-head{font-size:12px;color:#adc6ff;margin-bottom:4px}.hop-head .muted{color:#8b90a0}.hop-head .probe-tag{display:inline-block;margin-left:6px;padding:0 6px;border:1px solid #6b4eff;border-radius:4px;background:rgba(107,78,255,.15);color:#b9a7ff;font-size:11px}
.ln{display:block}
.lnno{user-select:none;-webkit-user-select:none;display:inline-block;min-width:3.5ch;color:#8b90a0}
.ln.note{color:#ff8a80;font-size:12px;line-height:1.55}
.block-note{color:#ff8a80;background:rgba(255,84,75,.06);border-left:3px solid #ff544b;padding:6px 10px;margin:4px 0;font-size:12px;overflow-wrap:break-word;word-break:break-word}
.no-anchor{border:1px dashed #f87171;background:rgba(255,0,0,.03);padding:8px 12px;border-radius:4px;margin:4px 0;font-size:12px;color:#f8a9a4;overflow-wrap:break-word;word-break:break-word}
@media print{
  @page{size:A4;margin:15mm 18mm}
  .detail{break-inside:auto}
  .detail .head{break-after:avoid}
  .ln,tr,.detail .head,.bar-row,.card,.fix-loc{break-inside:avoid}
  h2.sec,.detail h3{break-after:avoid}
  .ln.note{color:#b91c1c;break-inside:avoid}
  .block-note{color:#b91c1c;border-left-color:#b91c1c}
  .no-anchor{border-color:#b91c1c;background:rgba(255,0,0,.04);color:#7f1d1d}
}
.empty{color:#8b90a0;font-size:13px}
footer.ft{margin-top:48px;padding-top:16px;border-top:1px solid #2a2f38;color:#8b90a0;font-size:11px}
@media print{
  :root{color-scheme:light}
  body{background:#fff;color:#111}
  .card,.meta .mi,table.tb,.detail{background:#fff;border-color:#ddd}
  table.tb th{background:#f3f4f6;color:#333}
  .card .l,.meta .k,.detail .conf,.empty,footer.ft,header.rp .sub{color:#666}
  .detail p.reason,.detail ol.flow{color:#222}
  .detail .entry{color:#005bc1}
  .detail p.dev-note{color:#101418}
  .detail p.design-note{color:#31456b;border-left-color:#4e9c66}
  .detail .flow-summary{background:#f2f5fb;color:#31456b;border-left-color:#7aa2e3}
  pre.code{background:#f6f8fa;border-color:#ddd;color:#111}
  h2.sec{border-left-color:#005bc1}
  .bar-row .track{background:#eee}
  .badge{border:1px solid currentColor}
}
</style>
</head>
<body>
<div class="wrap">
<header class="rp">
  <h1>漏洞审计报告</h1>
  <div class="sub">WhiteBox Audit · 白盒代码审计平台</div>
  <div class="meta">
    <div class="mi"><div class="k">项目</div><div class="v">{{.Meta.RepoKey}}</div></div>
    <div class="mi"><div class="k">Run ID</div><div class="v mono">{{.Meta.RunID}}</div></div>
    <div class="mi"><div class="k">模式</div><div class="v">{{.Meta.Mode}}</div></div>
    <div class="mi"><div class="k">适配器</div><div class="v mono">{{.Meta.Adapter}}</div></div>
    <div class="mi"><div class="k">模型</div><div class="v mono">{{.Meta.Model}}</div></div>
    <div class="mi"><div class="k">时间</div><div class="v mono">{{.Meta.Timestamp}}</div></div>
    {{if .Meta.DurationSeconds}}<div class="mi"><div class="k">耗时</div><div class="v mono">{{.Meta.DurationSeconds}}</div></div>{{end}}
  </div>
</header>

{{if .Cards}}
<h2 class="sec">执行摘要</h2>
<div class="cards">
  {{range .Cards}}<div class="card"><div class="n t-{{.Tone}}">{{.Value}}</div><div class="l">{{.Label}}</div></div>{{end}}
</div>
{{end}}

{{if .FixPlan}}
<h2 class="sec">修复优先级建议</h2>
<table class="tb"><thead><tr><th>排期</th><th class="n">条数</th><th>说明</th></tr></thead><tbody>
{{range .FixPlan}}<tr><td>{{.Tier}}</td><td class="n">{{.Count}}</td><td>{{.Note}}</td></tr>{{end}}
</tbody></table>
{{end}}

{{if .Types}}
<h2 class="sec">漏洞分布</h2>
<table class="tb"><thead><tr><th>类型</th><th class="n">数量</th></tr></thead><tbody>
{{range .Types}}<tr><td class="mono">{{.Name}}</td><td class="n">{{.Count}}</td></tr>{{end}}
</tbody></table>
{{end}}

<h2 class="sec">漏洞详情（{{.DetailCount}}）</h2>
{{if .Details}}
{{range .Details}}{{template "detailCard" .}}{{end}}
{{else}}
<p class="empty">本次扫描未发现确认漏洞。</p>
{{end}}

<footer class="ft">本报告由 WhiteBox Audit 自动生成 · AI 判定结果需结合人工复核使用</footer>
</div>
{{define "detailCard"}}
<div class="detail">
  <div class="head">
    {{if .HasSeverity}}<span class="badge {{.SevClass}}">{{.Severity}}</span>{{end}}
    <span class="type mono">{{.VulnType}}</span>
    <span class="badge {{.VerdictClass}}">{{.Verdict}}</span>
    {{if .Label}}<span class="badge {{.LabelClass}}">{{.Label}}</span>{{end}}
    {{if .EvidenceBadge}}<span class="badge sev-none">{{.EvidenceBadge}}</span>{{end}}
    <span class="conf">置信 {{.Confidence}}/10</span>
  </div>
  {{if .DevSummary}}<h3>问题描述</h3><p class="dev-note">{{.DevSummary}}</p>{{end}}
  {{if .DesignNote}}<p class="dev-note design-note">{{.DesignNote}}</p>{{end}}
  {{if .HasImpactLocs}}<h3>影响位置</h3>
  <table class="tb"><thead><tr><th>角色</th><th>文件</th><th>行号</th></tr></thead><tbody>
  {{range .ImpactLocs}}<tr><td>{{.Role}}</td><td class="mono">{{.File}}</td><td class="mono">{{.Line}}</td></tr>{{end}}
  </tbody></table>
  {{end}}
  {{if .DataFlow}}<h3>数据流追踪</h3><ol class="flow">{{range .DataFlow}}<li>{{.Text}}{{if .NoAnchor}}<div class="no-anchor mono">⚠ 本步无独立代码锚点（叙述性步骤，多见于缺鉴权/缺失型漏洞）</div>{{end}}{{if .Hop}}<div class="step-code">{{template "hopCode" .Hop}}</div>{{end}}{{if .HopRef}}<div class="hop-ref mono">↑ 同上：{{.HopRef}}</div>{{end}}</li>{{end}}</ol>{{end}}
  {{if .Editable}}
  <h3>修复方案</h3><textarea class="code" name="suggested_fix" rows="8" style="width:100%">{{.SuggestedFix}}</textarea>
  {{else}}
  {{if .Fix.HasAnchor}}<h3>修复方案</h3>
<div class="fix">
  <div class="fix-loc"><span class="badge sev-none">{{.Fix.Loc}}</span></div>
  <div class="fix-diff">
  {{if .Fix.Paired}}
  {{range .Fix.BeforeLines}}<div class="diff-del"><span class="sign">-</span><code>{{.}}</code></div>{{end}}
  {{range .Fix.AfterLines}}<div class="diff-add"><span class="sign">+</span><code>{{.}}</code></div>{{end}}
  {{else}}{{if .Fix.CodeLines}}<div class="fix-ctx-label">相关代码（模型未给出完整的前后对照，请按下方说明修改）</div>{{range .Fix.CodeLines}}<div class="diff-ctx"><code>{{.}}</code></div>{{end}}{{end}}{{end}}
  </div>
  {{if .Fix.Desc}}<p class="reason">{{.Fix.Desc}}</p>{{end}}
</div>
{{else}}{{if .SuggestedFix}}<h3>修复方案</h3><pre class="code">{{.SuggestedFix}}</pre>{{end}}{{end}}
  {{end}}
</div>
{{end}}
{{define "hopCode"}}<div class="hop-head"><span class="fn">{{if .FunctionName}}{{.FunctionName}}{{else}}&lt;匿名&gt;{{end}}</span>{{if .FromProbe}} <span class="probe-tag">探针读取·非切片内</span>{{else if .FromEngineSink}} <span class="probe-tag">引擎真值·SQL</span>{{else if .FromSinkEvidence}} <span class="probe-tag">LLM 直填·sink 证据</span>{{end}} <span class="muted">@</span> <span class="mono">{{.FilePath}}{{if .LineRange}}:{{.LineRange}}{{end}}</span></div>{{if .BlockNote}}<div class="block-note">{{.BlockNote}}</div>{{end}}<pre class="code">{{range .WinLines}}{{if .Note}}<span class="ln note">{{.Note}}</span>{{else}}<span class="ln">{{if .No}}<span class="lnno">{{.No}}</span>{{end}}{{.Text}}</span>{{end}}{{end}}</pre>{{end}}
</body>
</html>
`

// shortHash 取 bughash 前 8 位（报告里对照条目的可核实标识）。
func shortHash(bh string) string {
	if len(bh) > 8 {
		return bh[:8]
	}
	return bh
}

// stepHasValidCite 判步文的 cite 是否指向真实存在的东西(hop 号在范围内 / 工具探针存在)。
// 越界 cite / 不存在的探针 = 编造的锚点,不算(GR-8)。
func stepHasValidCite(text string, hopCount int, probes []probeRec, sinks []sinkSqlRec) bool {
	hopCite, toolCite := contract.ParseStepCite(text)
	if hopCite != nil && *hopCite >= 0 && *hopCite < hopCount {
		return true
	}
	if toolCite != nil {
		want := strings.ToLower(fileBase(toolCite.File))
		for _, p := range probes {
			if p.base == want || p.stem == stemBeforeDot(want) || p.fn == strings.ToLower(toolCite.File) {
				return true
			}
		}
		// engine sink 真值(reachable_sinks)不在 probes 里,单独比 —— cite `@方法名` 形态。
		// 该 cite 指向 engine 真读到的 SQL,只是多个候选同 tier 无法唯一渲染代码块
		// (GR-8 宁缺毋错),那不等于它是幻觉。
		for _, sk := range sinks {
			if sk.method != "" && sk.method == want {
				return true
			}
		}
	}
	return false
}

// probeRefLabel —— 探针回指标签(函数名/文件 @ 文件:行范围),与 hopRefLabel 同形。
func probeRefLabel(p probeRec) string {
	loc := fileBase(p.fileOrig)
	if p.hasLR && p.start > 0 {
		loc += ":" + strconv.Itoa(p.start) + "-" + strconv.Itoa(p.end)
	}
	switch {
	case p.fnOrig != "" && loc != "":
		return p.fnOrig + " @ " + loc
	case loc != "":
		return loc
	}
	return p.fnOrig
}
