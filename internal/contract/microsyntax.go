package contract

import (
	"regexp"
	"strconv"
	"strings"
)

// microsyntax.go — LLM 自由文本里的「微语法契约」单一解析器(2026-08-22)。
//
// # 类的定义(GR-7 ①升维归类)
//
// 「LLM 微语法」= prompt 要求 LLM 在自由文本字段里嵌的结构化标记(cite `[跳N]`、
// suggested_fix 锚点 `[file:line] a → b`、`location` = `file:line`、空值 null)。
// 这类契约反复漂移的根因**不是** LLM 不听话,而是三条结构性成因:
//
//	① prompt 只「示范」不「禁止」——给正例不给 forbid 边界,LLM 自然产出变体;
//	② 解析器散落、各写各的正则——同一契约多处消费(甚至跨语言重复);
//	③ 无契约一致性测试——没有测试断言「prompt 声明的形式 == 解析器接受的形式」。
//
// 2026-08-22 三 run(33 alerts/137 data_flow 步/30 suggested_fix)实测四个实例:
//
//	I1 cite `[跳N:M]`(M=切片相对行)         26/137 步 (19%)
//	I2 suggested_fix 缺 `[]` 方括号          9/19 真实 fix (47%)
//	I3 字符串 "null" 而非 JSON null          sanitization_found 14 / exploit_payload 13 / suggested_fix 11
//	I4 location 带括号注释或非位置散文        dc.location 14/79
//
// 四者同一根因,故**一处收口**(GR-7 ③架构级封堵,铁律 D「一个守卫防住整类」)。
//
// # 本文件的不变量
//
// 一个微语法契约必须有:① 本文件里唯一的解析器;② 容忍已知变体的宽松匹配;
// ③ table test 断言全部变体同解;④ prompt 侧显式 forbid 坏变体。四缺一即漂移待发。
//
// # 设计红线
//
//   - **只加宽容忍,不改语义**:放宽的是「什么形式能被认出」,不是「认出后算什么」。
//     判决语义仍归 judge 层(硬约束 VerdictOf/TypeMismatchTypes/自动抑制等一律不碰)。
//   - **GR-8 不编真值**:解析器只做「剥离不可核实的部分并如实标注」,绝不补造行号/锚点。
//     `[跳0:41]` 里的 41 是 LLM 抄的切片**相对**行(prompts.linedCode 从 1 重编号),
//     不是文件行 → 一律丢弃,真实行号由渲染层从 hop.line_range 真值回填。

var (
	// hopCiteRe: `[跳N]` —— N=hop 序号(唯一语义载荷)。
	//
	// 容忍 `[跳N:M]` / `[跳 N：M]` / `[跳0:46 → 跳2]` 等后缀变体:后缀整段**丢弃**。
	// 后缀里的 M 是 LLM 从 prompt `linedCode`(messages.go:68,`i+1` 从 1 起编)抄来的
	// **切片相对行**,当文件绝对行展示会误导用户(实证:跳0:41 + hop0 line_range=[905,970]
	// → 905+41-1=945 才是真行)。故不解析、不回填、不采信(GR-8)。
	// 后缀形态实测有两族(2026-08-22 三 run):
	//   ① 冒号系 `[跳0:41]` / `[跳0：41]` / `[跳0:4-5]` / `[跳0:46 → 跳2]`
	//   ② 箭头系 `[跳0→跳3]` / `[跳3 → 跳1]`(无冒号,表"从这跳流到那跳")
	// 两族一律只取**首个**跳号(该步的证据锚点),其余整段丢弃。
	// 分隔符三态:契约形 `[跳N]`、全角 `（跳N）`、半角 `(跳N)`。分隔符是排版糖,跳号才是
	// 语义载荷(与 I2「方括号可选」同一判断)。全角变体实测于 relation-trade 429eb112:
	// LLM 写「（跳0:9-12:63-116）」,只认方括号时该步渲染成一句无锚点描述。
	hopCiteRe = regexp.MustCompile(`[\[（(]跳\s*(\d+)(?:\s*[:：→,，、-][^\]）)]*)?[\]）)]`)

	// hopNumInSuffixRe — 抓 cite 后缀里嵌的第二个跳号(`[跳0:46 → 跳2]` 的「跳2」)。
	hopNumInSuffixRe = regexp.MustCompile(`跳\s*(\d+)`)

	// toolCiteRe: `[工具:code_at_line@Foo.java:90]` —— tool + @file[:line]。
	toolCiteRe = regexp.MustCompile(`\[工具:([a-zA-Z_]+)@([^\]@:]+)(?::(\d+))?\]`)

	// stripCiteRe: 任意 cite 标记(hop 或工具),用于从展示文本移除内部锚点语法。
	// 必须与 hopCiteRe 同步容忍后缀,否则 `[跳0:41]` 剥不掉 → 内部语法泄漏进报告
	// (2026-08-22 实证:用户在 ceshi 报告里看到的 `[跳0:41]` 正是此漏)。
	// **只放宽解析,不放宽剥离**:全角 `（跳N: file:line）` 在本仓有第二种用途 —— 散文式 cite,
	// 由 RewriteHopProseCites 回填**真实行范围后展示给读者**(既有 TestRenderHTMLDataFlow
	// BackfillsRealHopLine 锁住)。把它一并剥掉会删掉读者要看的锚点,故 strip 仍只认方括号。
	// 组合形态 `[跳0, 工具:read_function@X.java]` / `[跳1、工具:…]` 实测存在(2026-08-23 rt),
	// 旧式只认两者各自独立 → 整段留在正文里。改为:方括号内**以 跳N 或 工具: 开头**即视为
	// cite,整段剥掉。按契约,以这两个记号开头的方括号段就是 cite,不会是读者要看的散文。
	stripCiteRe = regexp.MustCompile(`\[(?:跳\s*\d+|工具:)[^\]]*\]`)

	// hopProseCiteRe — 散文式 cite `跳N: file:line` / `跳N: file`(非方括号契约形式)。
	// file 段之后的 `:line` 可选(旧正则强制要求 → `跳6: X.xml` 这类漏匹配)。
	// 供渲染层把 LLM 自填的假行号回填成 hop 真值 range 或剥掉。
	//
	// file 段排除中英文括号/逗号/顿号:LLM 常把 cite 包在「（…）」里,若 file 段吞掉
	// 收尾括号,回填的 range 会落到括号**外**(`（跳0: F.java）:905-970`)。
	hopProseCiteRe = regexp.MustCompile(`跳(\d+)([：:] ?)([^：:\s\]）)，,、]+)(?:[：:][0-9,\-]+)?`)

	// fixAnchorRe — suggested_fix 锚点补丁:`[file:line] 修改前 → 修改后` + `\n说明：…`。
	// **方括号可选**(实测 9/19 真实 fix 裸写 `file:line 修改前…`,占 47%)——方括号是
	// 排版糖,`file:line` + `说明:` 才是语义载荷。
	fixAnchorRe = regexp.MustCompile(`^\s*(?:\[([^\]\n]+)\]|([\w./\\-]+\.\w+:[0-9,\-]+))\s*([\s\S]*?)\n?\s*说明[：:]([\s\S]*)$`)

	// locationRe — `file:line` / `file:line-line` 主体(可嵌在散文里,取首个)。
	locationRe = regexp.MustCompile(`([\w./\\-]+\.\w+):(\d+(?:[,\-]\d+)*)`)
)

// nullishValues — LLM 在「该填 JSON null」处产出的字符串等价物。
//
// 归一是**安全必需**而非洁癖:`judge/guard.go` 的 hollow-TP 门判 `*ExploitPayload == ""`,
// 字符串 `"null"` 非空 → 无证据的高置信 TP 可绕过该门(2026-08-22 三 run 无活体逃逸,
// 仅因未撞上高置信 TP —— 属潜伏洞,GR-8「无证据的高置信比低置信更危险」)。
//
// 只认**整个值**就是这些词的情形(TrimSpace + 小写后全等),绝不做子串匹配 ——
// 「无任何过滤」这类真实叙述必须原样保留。
var nullishValues = map[string]bool{
	"":        true,
	"null":    true,
	"none":    true,
	"nil":     true,
	"n/a":     true,
	"na":      true,
	"unknown": true,
	"无":       true,
	"无。":      true,
}

// ToolCite 是步文里 `[工具:tool@file[:line]]` 标记解析出的工具引用。
type ToolCite struct {
	Tool string // code_at_line / read_function / read_file
	File string // 原样 file(LLM 写的,可能是 basename 或路径)
	Line int    // 行号;0=未给
}

// ParseStepCiteHops 返回步文里 cite 到的**全部** hop 序号,按出现序。
//
// 为什么需要"全部":箭头系 cite `[跳0:46 → 跳2]` / `[跳0→跳3]` 表"从这跳流到那跳",
// 两个跳号都是该步的合法证据锚点。渲染器按「哪个 hop 还没被别的步占用」择一绑定
// (过渡步的**目标** hop 通常更有信息量 —— 源 hop 一般已被上一步占了),
// 门只需知道"有没有任一有效 hop"。故解析层如实返回全部,取舍留给各消费方(铁律 A)。
func ParseStepCiteHops(text string) []int {
	ms := hopCiteRe.FindAllStringSubmatch(text, -1)
	if len(ms) == 0 {
		return nil
	}
	out := make([]int, 0, len(ms)+1)
	seen := map[int]bool{}
	add := func(s string) {
		if n, err := strconv.Atoi(s); err == nil && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, m := range ms {
		add(m[1])
		// 后缀里可能还嵌了跳号(`[跳0:46 → 跳2]` 的「跳2」在后缀内,不是独立 cite)。
		for _, inner := range hopNumInSuffixRe.FindAllStringSubmatch(m[0][len("[")+len("跳"):], -1) {
			add(inner[1])
		}
	}
	return out
}

// ParseStepCite 解析步文里的 cite 标记。hopIdx / tool 任一可能为 nil(无该类 cite)。
// hopIdx 取**首个** hop 号(向后兼容既有调用方);需全部时用 ParseStepCiteHops。
func ParseStepCite(text string) (hopIdx *int, tool *ToolCite) {
	if hs := ParseStepCiteHops(text); len(hs) > 0 {
		n := hs[0]
		hopIdx = &n
	}
	if m := toolCiteRe.FindStringSubmatch(text); m != nil {
		tc := &ToolCite{Tool: m[1], File: m[2]}
		if m[3] != "" {
			if l, err := strconv.Atoi(m[3]); err == nil {
				tc.Line = l
			}
		}
		tool = tc
	}
	return
}

// StripCites 从步文移除所有 cite 标记,供报告展示(cite 是内部锚点语法,不示开发)。
func StripCites(text string) string {
	return strings.TrimSpace(stripCiteRe.ReplaceAllString(text, ""))
}

// HasCite 返回步文是否含任意 cite 标记(门/渲染器用于快速判该步是否走 cite 路径)。
func HasCite(text string) bool {
	return hopCiteRe.MatchString(text) || toolCiteRe.MatchString(text)
}

// RewriteHopProseCites — 把散文式 cite 里 LLM 自填的行号回填成 hop 真值 range,或剥掉。
//
//	lineMap[N] 有真实 range → `跳N: file:真实range`(与代码块 line_range 一致)
//	lineMap[N] 无(hop 缺/无真行号)→ `跳N: file`(留 hop 引用+文件名,删不可核实行号)
//	lineMap == nil(无 trace)→ 全部剥
//
// 纯渲染层,不动 verdict/grounding。不动方括号契约 cite(hopCiteRe 那套,正则不认)。
func RewriteHopProseCites(text string, lineMap map[int]string) string {
	if text == "" {
		return text
	}
	return hopProseCiteRe.ReplaceAllStringFunc(text, func(match string) string {
		sub := hopProseCiteRe.FindStringSubmatch(match)
		// sub[1]=N sub[2]=sep sub[3]=file
		if n, err := strconv.Atoi(sub[1]); err == nil {
			if r, ok := lineMap[n]; ok && r != "" {
				return "跳" + sub[1] + sub[2] + sub[3] + ":" + r
			}
		}
		return "跳" + sub[1] + sub[2] + sub[3] // strip 不可核实行号
	})
}

// NormalizeNullish 把 LLM 产出的「字符串化 null」归一成真 nil。
// 非 nullish 值原样返回(指向原字符串的新指针)。见 nullishValues 注释:安全门依赖此归一。
func NormalizeNullish(s string) *string {
	if nullishValues[strings.ToLower(strings.TrimSpace(s))] {
		return nil
	}
	v := s
	return &v
}

// IsNullish 报告一个字符串值是否等价于 JSON null(供无需指针的调用点)。
func IsNullish(s string) bool {
	return nullishValues[strings.ToLower(strings.TrimSpace(s))]
}

// FixAnchor 是 suggested_fix 解析结果。HasAnchor=false → 调用方回退展示原文。
type FixAnchor struct {
	HasAnchor bool
	Loc       string // file:line(方括号已剥)
	Before    string // 修改前片段(→ 左侧);无 → 时为整段
	After     string // 修改后片段(→ 右侧);可空
	Desc      string // 说明: 之后的一句话
}

// ParseFixAnchor 解析锚点式补丁 `[file:line] 修改前 → 修改后\n说明：…`。
// 方括号可选(实测 47% 真实 fix 裸写);nullish 值直接判无锚点。
func ParseFixAnchor(s string) FixAnchor {
	if IsNullish(s) {
		return FixAnchor{}
	}
	// I5:先还原二次转义,再解析 —— 否则字面转义当普通字符,diff 挤成一行且残留反斜杠。
	s = UnescapeLiteralEscapes(s)
	m := fixAnchorRe.FindStringSubmatch(s)
	if m == nil {
		return FixAnchor{}
	}
	loc := m[1] // 方括号形式
	if loc == "" {
		loc = m[2] // 裸 file:line 形式
	}
	code, desc := m[3], strings.TrimSpace(m[4])
	before, after := strings.TrimSpace(code), ""
	// 优先按独占一行的「修改后」标签切:模型常在两侧各写一个标签且各带箭头,此时首个箭头
	// 属于「修改前」那一侧,按箭头切会把整个后半段连标签一起塞进 after。找不到该标签行
	// 再退回按首个箭头切(两侧标签写在同一行的常见形态)。
	if loc := fixAfterLabelRe.FindStringIndex(code); loc != nil {
		before = strings.TrimSpace(code[:loc[0]])
		after = strings.TrimSpace(code[loc[1]:])
	} else if i := strings.Index(code, "→"); i >= 0 {
		before = strings.TrimSpace(code[:i])
		after = strings.TrimSpace(code[i+len("→"):])
	}
	// I2 变体:模型把 prompt 里的占位符字面(「修改前片段」「修改后代码」…)当内容抄了进来。
	// 不剥的话报告 diff 区会印出「- 修改前片段 / + 修改后片段」—— 占位符当补丁展示,
	// 比没有修复建议更糟(开发会以为这就是要贴的代码)。
	// 相邻空标签对(中间无内容)先整体剥掉,再剥各侧开头的单个标签行 —— 顺序有意义:
	// 活体形态是「首行纯标签对 + 其下用带冒号的标签分段」,不先剥标签对,单标签规则
	// 因为该行后面还跟着东西而不匹配,占位词会进 diff 的 `-` 行。
	before = emptyFixLabelPairRe.ReplaceAllString(before, "")
	after = emptyFixLabelPairRe.ReplaceAllString(after, "")
	before = stripFixLabel(before)
	after = stripFixLabel(after)
	// 说明正文里常再嵌一个补丁,且标签对紧挨着(中间无任何内容)——零信息量的回抄,剔掉。
	desc = strings.TrimSpace(emptyFixLabelPairRe.ReplaceAllString(desc, ""))
	return FixAnchor{HasAnchor: true, Loc: strings.TrimSpace(loc), Before: before, After: after, Desc: desc}
}

// Location 是 `file:line` 锚点解析结果。Anchored=false = 该「位置」不可回挂源码
// (如 `authz_coverage(预计算)`、`仓库全局 *.java`)——GR-8:如实标未锚定,不编造锚点。
type Location struct {
	Anchored bool
	File     string
	Line     string // 原样保留 `12` / `12-19` / `29,41`(不解析成 int,range 形式无损)
	Note     string // 位置之外的散文(括号注释等),原样保留供展示
}

// ParseLocation 从 decisive_check.location / entry_point 等字段提取 file:line 锚点。
// 取首个 file:line;其余散文进 Note。无 file:line → Anchored=false + 全文进 Note。
func ParseLocation(s string) Location {
	s = strings.TrimSpace(s)
	if IsNullish(s) {
		return Location{}
	}
	m := locationRe.FindStringSubmatchIndex(s)
	if m == nil {
		return Location{Note: s}
	}
	sub := locationRe.FindStringSubmatch(s)
	note := strings.TrimSpace(s[:m[0]] + " " + s[m[1]:])
	note = strings.Trim(note, " ()（）,，;；")
	return Location{Anchored: true, File: sub[1], Line: sub[2], Note: note}
}

// literalEscapeReplacer — 字面转义序列 → 真字符。
//
// 顺序有意义:Replacer 在每个位置按参数顺序试最先匹配者、不重叠。反斜杠对放最后仍正确 ——
// 输入「反斜杠 反斜杠 n」在位置 0 只有反斜杠对能匹配(单反斜杠+n 的模式吃不到),故还原成
// 一个反斜杠 + n = **字面转义保留**,正是 Java 源码里 "a\n b" 该有的结果。
var literalEscapeReplacer = strings.NewReplacer(
	`\n`, "\n",
	`\r`, "\r",
	`\t`, "\t",
	`\"`, `"`,
	`\\`, `\`,
)

// UnescapeLiteralEscapes 还原被**二次转义**的自由文本(微语法契约 I5)。
//
// LLM 在该输出真换行处写「反斜杠+n」、该输出双引号处写「反斜杠+引号」,即把值又转义了
// 一遍。三 run 15 条 TP 的 suggested_fix:13 条含前者、11 条含后者 → 报告的修复 diff 挤成
// 一行且显反斜杠,开发照抄会把反斜杠也抄进代码。
//
// **判别器 = 整个值不含真换行**(实测干净可分,非启发式):15 条里 13 条「含字面转义 &&
// 零真换行」、2 条「含真换行 && 零字面转义」、混杂 0 条。已正常分行的值一律不动 ——
// 那种值里的转义是 Java 字符串真值而非转义残留(GR-8 不篡改真值),宁可漏修不可改坏。
func UnescapeLiteralEscapes(s string) string {
	if strings.ContainsAny(s, "\n\r") {
		return s
	}
	// 92 = 反斜杠码点。此处刻意不用转义字面量:这类字面量在编辑/复制链路上极易被
	// 吃掉一层,写错了是静默失效(本 arc 已被咬过一次)。
	if !strings.ContainsRune(s, 92) {
		return s
	}
	return literalEscapeReplacer.Replace(s)
}

// —— I6:provider tool-arg 框架标记漏进自由文本 ————————————————————————

var (
	// arg 框架标记 —— hy3 把工具调用的参数框架
	// `<arg_key:HASH>键名</arg_key:HASH><arg_value:HASH>值` 当普通文本吐进了 JSON
	// **字符串值内部**。JSON 本身合法(json_repaired=false),故三层解析全都察觉不到:
	// 后半段本该是 `", "key": value` 的结构分隔符被转义成了 `\", \"key</arg_key:H>`,
	// 于是 key 之后的所有字段整体被吞进前一个字段的值里 —— 报告既丢字段又印乱码。
	//
	// HASH 是每次调用随机的十六进制串;也实测到无 HASH 的裸标签,故 `(:[^>]*)?` 可选。
	// 2026-08-22 三仓 32 run / 344 alerts 实测 22 个污染实例,吞掉 7 类键
	// (sanitization_found 14 / severity 7 / suggested_fix 5 / dev_summary 5 /
	// design_note 5 / severity_rationale 4 / remaining_gap 1)。
	argFramePairRe = regexp.MustCompile(`</arg_key(?::[^>]*)?>\s*<arg_value(?::[^>]*)?>`)
	argKeyCloseRe  = regexp.MustCompile(`</arg_key(?::[^>]*)?>`)
	argKeyOpenRe   = regexp.MustCompile(`<arg_key(?::[^>]*)?>`)
	argValueAnyRe  = regexp.MustCompile(`</?arg_value(?::[^>]*)?>`)

	// argFrameAnyRe —— 入场券:任一框架标记(开/闭 × key/value)。
	// 刻意不用 strings.Contains("<arg_key") 做守卫 —— 形态②的活体样本里**只有闭标签**
	// `</arg_key:H>`,而 `<` 后面是 `/`,子串匹配认不出来,整条恢复会被守卫挡在门外
	// (TestRecoverArgFraming_UnpairedCloseThenPlainJSON 就是钉这个的)。
	argFrameAnyRe = regexp.MustCompile(`</?arg_(?:key|value)(?::[^>]*)?>`)

	// argFieldBoundaryRe —— 归一后的字段边界 `", "key": `。
	// 三种形态归一到同一形状后,用它一次切开(不为每种形态各写一条正则 —— 那正是
	// 本文件开头列的成因②「解析器散落、各写各的正则」)。
	argFieldBoundaryRe = regexp.MustCompile(`"\s*,\s*"(\w+)"\s*:\s*`)
)

// recoverableArgFields —— 允许从污染文本里拆回的键(**类守卫**)。
//
// 只收 JudgeResult 侧的**字符串**字段:恢复出来的值是文本,写回数值/布尔字段会制造类型
// 事故。白名单同时挡住散文误切 —— 真实 reasoning 里出现 `", "某某": ` 形状时,键名不在
// 表里就不切,正文不会被切碎(TestRecoverArgFraming_NonWhitelistedKeyNotSplit)。
var recoverableArgFields = map[string]bool{
	"sanitization_found": true,
	"severity":           true,
	"severity_rationale": true,
	"suggested_fix":      true,
	"dev_summary":        true,
	"design_note":        true,
	"exploit_payload":    true,
	"attack_request":     true,
	"missing_info":       true,
	"fail_reason":        true,
	"remaining_gap":      true,
	"reasoning":          true,
}

// RecoverArgFraming 从被 provider 框架标记污染的自由文本里拆回被吞掉的字段(微语法契约 I6)。
//
// 返回 (宿主字段的干净值, 拆出的 键→值)。未污染 → 原样返回 (s, nil),绝不改动。
//
// **GR-8 不编真值**:只做「按标记切开 + 剥掉模型自补的假闭合」,不推断、不补造任何内容。
// 拆出的值原样返回(含字面 "null"),是否当空值由调用方按 I3 判(IsNullish)—— 本函数
// 不替调用方做语义决定(见本文件「设计红线」)。
func RecoverArgFraming(s string) (string, map[string]string) {
	// 类守卫:标记是唯一入场券。没有标记的文本一律零改动。
	if !argFrameAnyRe.MatchString(s) {
		return s, nil
	}
	// ① 三形态归一到 `", "key": `。顺序有意义:先吃成对的,剩下的落单标签再各自兜底。
	t := argFramePairRe.ReplaceAllString(s, `": `) // 形态①`</arg_key><arg_value>`
	t = argKeyCloseRe.ReplaceAllString(t, `": `)   // 形态②落单闭标签(其后是裸引号)
	t = argKeyOpenRe.ReplaceAllString(t, `", "`)   // 形态③开标签(前面无 `", "` 引导)
	t = argValueAnyRe.ReplaceAllString(t, "")      // 落单 value 标签直接丢

	// ② 只在白名单键处切分。
	var bounds [][]int
	for _, m := range argFieldBoundaryRe.FindAllStringSubmatchIndex(t, -1) {
		if recoverableArgFields[t[m[2]:m[3]]] {
			bounds = append(bounds, m)
		}
	}
	if len(bounds) == 0 {
		// 标记有、可拆的字段没有 —— 至少把标记剥干净,别让它印进报告。
		return strings.TrimSpace(t), nil
	}
	clean := strings.TrimSpace(t[:bounds[0][0]])
	rec := make(map[string]string, len(bounds))
	for i, m := range bounds {
		end := len(t)
		if i+1 < len(bounds) {
			end = bounds[i+1][0] // 下一段边界的起始 `"` 即本段值的收尾引号
		}
		rec[t[m[2]:m[3]]] = cleanArgValue(t[m[1]:end])
	}
	return clean, rec
}

// cleanArgValue 剥掉拆出值两端的 JSON 残渣:模型自补的假闭合 `"}`、包裹引号、逗号。
// 只剥**成对或明确残缺**的引号,不动值内部的任何字符(GR-8)。
func cleanArgValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, `"}`) // 模型收尾时补的假 JSON 尾巴,不是真值的一部分
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, ",")
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = v[1 : len(v)-1]
	} else {
		v = strings.TrimPrefix(v, `"`)
		v = strings.TrimSuffix(v, `"`)
	}
	return strings.TrimSpace(v)
}

// fixLabelRe — 开头的「修改前/修改后」标签(可与代码同行,活体如 `修改前片段 String p = ...`)。
//
// 四个分支,每个都自带消歧:带「片段」/带「代码」/带冒号/独占一行。
// 各分支均容忍标签前的一个括号注释(活体 `...xml:0 (getBillItemByParam) 修改前片段`)——
// 括号后必须紧跟标签形态才匹配,故 `foo(bar) → …` 这类真代码不会被误剥。**裸的「修改前」后面
// 直接跟中文时一律不算标签** —— 否则 `修改前缀 = ...`、`修改后置条件校验()` 这类真代码会被
// 拦腰剥掉(GR-8 宁可漏剥不可剥错;DoesNotStripRealCode + BareLabelWordNotStripped 钉住)。
var fixLabelRe = regexp.MustCompile(`^[ \t]*(?:\([^)\n]*\)[ \t]*)?(?:→[ \t]*)?修改[前后](?:(?:代码)?片段|代码|[ \t]*[：:])[ \t]*[：:]?[ \t]*(?:→[ \t]*)?|^[ \t]*(?:\([^)\n]*\)[ \t]*)?(?:→[ \t]*)?修改[前后][ \t]*(?:→[ \t]*)?(?:\n|$)`)

// fixAfterLabelRe —— 独占一行的「修改后」标签(可带前导/尾随箭头)。要求整行只有这个标签 ——
// 否则 `修改前代码 → 修改后代码` 这种写在同一行的形态会在错误位置被切开。
var fixAfterLabelRe = regexp.MustCompile(`(?m)^[ 	]*(?:→[ 	]*)?修改后(?:代码)?(?:片段)?[ 	]*[：:]?[ 	]*(?:→[ 	]*)?$`)

// stripFixLabel 剥掉开头独占一行(或独占整段)的「修改前/修改后」标签。
func stripFixLabel(s string) string {
	return strings.TrimSpace(fixLabelRe.ReplaceAllString(strings.TrimSpace(s), ""))
}

// emptyFixLabelPairRe —— 紧挨的「修改前… → 修改后…」标签对(中间无内容)。
// 两标签之间有真代码的不匹配 —— 那是第二个补丁的正文,剔掉就把修复内容删了(GR-8)。
var emptyFixLabelPairRe = regexp.MustCompile(`修改前(?:代码)?(?:片段)?[ 	]*[：:]?[ 	]*→[ 	]*修改后(?:代码)?(?:片段)?[ 	]*[：:]?[ 	]*`)
