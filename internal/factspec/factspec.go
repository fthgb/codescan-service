// Package factspec —— 确定性事实的**取证方式**边界（2026-08-23 P2）。
//
// # 这个包解决什么
//
// 到 2026-08-23 为止，事实层已手写三处：`ComputeAuthzCoverage`（全仓 grep + AST）、
// `ComputeUploadDisposition` b1/b3（全仓 grep + 切片扫）、b2（两个 grep 求差集）。
// 主干（取证 → 三态 → 软注记）三处重复，分歧只在**取证方式**。再加第四类就是第四个包。
//
// 但本包的重点**不是**省代码，而是把这一整轮反复踩的那个坑变成类型系统强制的东西：
//
//	一个取证器能给出「否」这个结论，和它能给出「是」，是**两种完全不同的能力**。
//
// 血泪清单（全部实测，非假设）：
//
//   - `authz_coverage` 的 pattern 集不含 servlet Filter → 对 ceshi 写出确定性的假 "none"，
//     模型据此判出错误的 missing-auth TP，面账分组事实一并被污染。
//   - upload 的 `file_write_sink` 抄 authz 的三态口径险些写出假否定 —— 切片可能截断，
//     「切片里没看到落盘」不等于「不落盘」。
//   - 引擎 `HasSanitizer` 答 false **只代表这个方法体里没有**（它不走调用路径），
//     当成「整条路径没净化」就是假否定。
//
// 三次都是同一件事：**把「我没看到」当成了「它没有」**。
//
// # 不变量
//
// 每个取证器**声明**它能产出的结论集；框架校验它没有越界。
// 能产出 `No` 的取证器必须有语料契约（internal/factguard）—— 因为只有否定会让守卫静默失效。
package factspec

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict 是三态，**故意不用 bool**。
//
// `Unknown` 是「不确定」，**不是**「否」。这个区分是本包存在的理由：
// 用 bool 表达时，零值天然读作「否」，于是「没看到」被静默当成「没有」。
type Verdict int

const (
	// Unknown —— 取证器无法就此下结论。渲染成人话必须是「未确定」，绝不能是「无」「未发现」。
	Unknown Verdict = iota
	// Yes —— 确定性肯定：该事实成立。
	Yes
	// No —— 确定性否定：该事实**不**成立。只有穷举过实现族的取证器才配产出它。
	No
)

func (v Verdict) String() string {
	switch v {
	case Yes:
		return "yes"
	case No:
		return "no"
	}
	return "unknown"
}

// CN 返回给人看的措辞。Unknown 刻意是「未确定」而非「无」。
func (v Verdict) CN() string {
	switch v {
	case Yes:
		return "已确认"
	case No:
		return "已确认不存在"
	}
	return "未确定"
}

// Grain 是一个取证器的**归因粒度** —— 它能把结论落到多细的东西上。
//
// 这不是给取证器排名，是回答一个具体问题：**这条结论有没有资格被当成确定性事实**。
// 三仓量化给出的答案是「按现状不行」：今天判「已中和」的两条告警都由切片级文本扫定调，
// 而文本扫看见「切片里出现过 UUID.randomUUID」这几个字，不知道它作用在谁身上 ——
// 上传方法里生成个链路 id 就足以让它误判。
//
// 首版方案是把粒度做成**准入门槛**（开脱性结论只能由变量级取证器产出）。
// 三仓实测否决了它：那样会让 rt 一条**本来正确**的判断退成 unknown，
// 而它要防的假开脱在三仓 0 例。故改为**分级**：结论保留，强度如实标注，
// 让下游自己权衡 —— 信息不丢，「确定性」这个标签不乱发。
type Grain int

const (
	// GrainRepo —— 仓级：知道整个仓库有没有这个东西，不知道它对本条告警是否生效。
	GrainRepo Grain = iota
	// GrainSlice —— 切片级：知道这条切片的文本里有没有，不知道它作用在哪个变量上。
	GrainSlice
	// GrainVariable —— 变量级：知道它作用在**这条污点变量**上，且能给出锚点。
	GrainVariable
)

func (g Grain) CN() string {
	switch g {
	case GrainVariable:
		return "变量级"
	case GrainSlice:
		return "切片级"
	}
	return "仓级"
}

// Ctx 是取证器的输入（只读）。
type Ctx struct {
	// Sliced 是本条告警的切片上下文（hops / 各字段）。
	Sliced map[string]any
	// RepoRoot 供全仓取证使用；空 = 不可做全仓取证。
	RepoRoot string
	// Grep 做全仓检索；nil = 该能力不可用（取证器须据此返回 Unknown 而非 No）。
	Grep func(pattern, fileGlob string) (matches []string, truncated bool, err error)
	// Engine 是污点引擎查询器；nil = 不可用。
	Engine EngineQuery
}

// EngineQuery —— 本包只依赖它用到的那几个能力，不绑整个 taintbridge 接口（铁律 D）。
type EngineQuery interface {
	ResolveMethodKey(fn, filePath, mk string) (methodKey string, found bool, err error)
	HasSanitizer(methodKey, taintVar string) (found bool, at string, err error)
}

// Prober 是一种取证方式。
//
// **Can 声明它能产出哪些结论**；Probe 越界即被 Validate/测试挡下。
// 这不是形式主义：三次真实的假否定，根因都是「一个只能说 Yes/Unknown 的手段
// 被当成也能说 No」。
type Prober interface {
	Name() string
	// Grain 是该取证器的归因粒度 —— 决定它的结论能否被当成确定性事实（见 Grain）。
	Grain() Grain
	// Can 返回该取证器**可能**产出的结论集合。必须含 Unknown（任何取证都可能答不上来）。
	Can() []Verdict
	Probe(c Ctx) (Verdict, string)
}

// Spec 是一条确定性事实的规格。
type Spec struct {
	// Fact 与 factguard 语料、与源码 `// EXCULPATORY-FACT:` 标记同名（当它能产出 No 时）。
	Fact string
	// Why 说明结论错了会造成什么 —— 写给下一个改这里的人。
	Why string
	// Probers 按序尝试；**第一个给出非 Unknown 的取证器定调**。
	// 排序即优先级：把更可信的取证方式排前面（如引擎 > 切片文本扫）。
	Probers []Prober
	// Applicable 决定该事实是否适用于这条告警（如「非上传流不写 upload 事实」）。
	// nil = 恒适用。
	Applicable func(c Ctx) bool
	// Exculpatory 声明**哪个结论是开脱性的** —— 错了会让一处发现被静默删掉。
	// Unknown = 本事实无开脱方向（两个方向错了都只会让判定更保守）。
	//
	// 为什么必须由作者显式声明、不能从 Can() 推：首版判据就是从 Can() 推的
	// （「能产出 No 就危险」），而 `filename_neutralized` 是个**肯定**事实
	// （yes = 已中和），下游产出的却是开脱结论（「经文件名的 b3 不成立」）。
	// 那条判据不但漏了它，还主动放行（两个取证器都只能说 Yes/Unknown →
	// NegativeCapable 为假 → 不要求语料）。危险方向只有写这条事实的人知道。
	Exculpatory Verdict
}

// Result 是一次取证的产物。
type Result struct {
	Fact     string
	Verdict  Verdict
	By       string // 定调的取证器名 —— 结论可溯源（GR-8）
	Evidence string
	// Grain 是定调取证器的归因粒度。
	Grain Grain
	// Exculpatory 标记本结论正是该 Spec 的开脱方向 —— 错了会让一处发现被静默删掉。
	// 与 Grain 一起决定渲染时 on_this_taint_var 属性写什么。
	Exculpatory bool
	// Implication 是「这条事实对判决意味着什么」—— 由**事实作者**写，渲染器不替它编。
	//
	// 单独成字段而不是拌进 Evidence：证据是「查了什么、查到什么」，含义是「所以该怎么判」。
	// 两者混在一句话里正是散文版的毛病 —— 模型可以只读前半句。
	Implication string
}

// Evaluate 按序跑取证器，第一个非 Unknown 即定调；全 Unknown 则结果为 Unknown。
func Evaluate(s Spec, c Ctx) Result {
	if s.Applicable != nil && !s.Applicable(c) {
		return Result{Fact: s.Fact, Verdict: Unknown, By: "n/a", Evidence: "该事实不适用于本条告警"}
	}
	for _, p := range s.Probers {
		v, ev := p.Probe(c)
		if v == Unknown {
			continue
		}
		if !canEmit(p, v) {
			// 越界即视为不可信 —— 宁可 Unknown，不可采信一个取证器给不出的结论。
			continue
		}
		return Result{
			Fact: s.Fact, Verdict: v, By: p.Name(), Evidence: ev,
			Grain:       p.Grain(),
			Exculpatory: s.Exculpatory != Unknown && v == s.Exculpatory,
		}
	}
	return Result{Fact: s.Fact, Verdict: Unknown, By: "", Evidence: ""}
}

func canEmit(p Prober, v Verdict) bool {
	for _, allowed := range p.Can() {
		if allowed == v {
			return true
		}
	}
	return false
}

// Validate 校验一条 Spec 自洽；返回全部问题（供测试一次性报出）。
func Validate(s Spec) []string {
	var probs []string
	if s.Fact == "" {
		probs = append(probs, "Fact 为空 —— 事实必须有名字才能与语料对齐")
	}
	if s.Why == "" {
		probs = append(probs, "Why 为空 —— 结论错了会造成什么，要能被下一个人读懂")
	}
	if len(s.Probers) == 0 {
		probs = append(probs, "无取证器")
	}
	// 能产出确定性否定却没声明开脱方向 —— 兜底网:否定几乎总是开脱的,
	// 作者漏填时在这里被逼一次,而不是等到某条真漏洞被静默删掉。
	if s.Exculpatory == Unknown {
		for _, p := range s.Probers {
			if contains(p.Can(), No) {
				probs = append(probs, fmt.Sprintf(
					"[%s] 能产出确定性否定却未声明 Exculpatory —— 否定结论几乎总是开脱性的（错了会让发现消失）；"+
						"若确认无开脱方向，请在此写明理由后再留 Unknown", p.Name()))
				break
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range s.Probers {
		if p.Name() == "" {
			probs = append(probs, "取证器无名 —— 结论将无法溯源")
			continue
		}
		if seen[p.Name()] {
			probs = append(probs, "取证器重名: "+p.Name())
		}
		seen[p.Name()] = true
		can := p.Can()
		if !contains(can, Unknown) {
			probs = append(probs,
				fmt.Sprintf("[%s] Can() 不含 Unknown —— 任何取证都可能答不上来，声称永不 Unknown 就是在逼自己编结论", p.Name()))
		}
		if len(can) == 1 {
			probs = append(probs, fmt.Sprintf("[%s] 只能产出 Unknown，等于没有取证能力", p.Name()))
		}
	}
	return probs
}

// NeedsCorpus 报告该 Spec 是否**必须**有 factguard 语料：它声明了开脱方向，
// 且确实有取证器能产出那个结论。
//
// 判据是「结论错了会不会让发现减少」，不是「是不是否定结论」——
// 「确定性否定」只是开脱的最常见形态，不是它的定义（见 internal/factguard 包头）。
func NeedsCorpus(s Spec) bool {
	if s.Exculpatory == Unknown {
		return false
	}
	for _, p := range s.Probers {
		if contains(p.Can(), s.Exculpatory) {
			return true
		}
	}
	return false
}

// Render 把一组结果渲染成给模型看的软注记（**唯一**渲染点）。
//
// # 为什么是 XML —— 实证修正过一次，别照抄原来的理由
//
// **原始理由（假设，2026-08-23 实测未能证实）**：一条确定性事实本质是六元组
// （名称/结论/粒度/是否开脱/证据/含义），散文把它压平成一句话，且压平方式最危险
// ——「结论在前、限制在后」，模型扫读可能只吃到「确认存在中和」而略过 `⚠` 后的从句。
//
// **实测结果（三仓 33 条告警 × 三轮 × 两侧 = 198 次判决）**：
//
//	同侧噪声基线（变量为零，两轮之间的差异）  平均 11.5/33（9-14）
//	跨侧差异（散文 vs XML，含同样的噪声）      平均 10.8/33（8-13）
//
// 跨侧差异 **≤** 同侧噪声 —— 格式效应完全淹没在模型抖动里，**测不出来**。
// 判决分布也几乎不动（TP 46→44、FP 25→28、uncertain 28→27，n=99）。
// 故「XML 让模型读得更准」这条**没有证据**，不要引用它来论证下一次改动。
//
// **保留 XML 的真实理由**（不依赖 LLM 行为，因而不受上述实证影响）：
//
//	① 单一渲染点：改之前 RenderUploadNote / authzNote 各自手写字符串，三处格式会各自漂移。
//	② 结构化字段：粒度、开脱方向是属性而非句子，措辞微调不会把它们悄悄丢掉
//	   （测试也因此从"散文子串断言"升级为"属性断言"）。
//	③ 实测**无害**：见上，没有引入退化。
//
// 顺带钉住那次实验暴露的更大问题：**per-alert 三轮判决只有 48% 稳定**（16/33，
// 折叠后的三值口径，即报告用的那个），两侧完全相同。这印证了「wobble 主因是模型
// 不是 prompt」—— 在这个抖动水平下，33 条样本分辨不出任何 prompt 级改动的效应。
// 下次想用活体实验证明 prompt 改动有效时，**先看这个数**：没有噪声基线的对照没有意义。
//
// # 措辞红线（不随格式改变）
//
// Unknown 一律不进注记，且末尾必须声明「未列出的表示未确定，不是已排除」——
// 把 Unknown 写成「无」，模型就会据此排除掉真实存在的分支。
func Render(title string, rs []Result) string {
	var facts []string
	for _, r := range rs {
		if r.Verdict == Unknown {
			continue // 不确定的不进注记，下面那句声明会兜住它
		}
		facts = append(facts, renderFact(r))
	}
	if len(facts) == 0 {
		return ""
	}
	sort.Strings(facts)
	return "<verified_facts scope=\"" + esc(title) + "\">\n" +
		"  <note>已核实，勿重复推断；**未列出的表示未确定，不是已排除**。</note>\n" +
		strings.Join(facts, "\n") + "\n</verified_facts>"
}

func renderFact(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  <fact name=%q verdict=%q grain=%q", r.Fact, r.Verdict.CN(), r.Grain.CN())
	if r.Exculpatory {
		// 开脱性结论才写这个属性 —— 挂满了等于没挂，读的人会开始无视它。
		v := "已核实"
		if r.Grain < GrainVariable {
			v = "未验证"
		}
		fmt.Fprintf(&b, " on_this_taint_var=%q", v)
	}
	if r.By != "" {
		fmt.Fprintf(&b, " by=%q", r.By)
	}
	b.WriteString(">\n")
	if r.Evidence != "" {
		fmt.Fprintf(&b, "    <evidence>%s</evidence>\n", esc(r.Evidence))
	}
	if imp := implicationOf(r); imp != "" {
		fmt.Fprintf(&b, "    <implication>%s</implication>\n", esc(imp))
	}
	b.WriteString("  </fact>")
	return b.String()
}

// implicationOf 取事实作者写的含义；开脱性 + 粗粒度时补上那句边界说明。
func implicationOf(r Result) string {
	imp := r.Implication
	if note := weakEvidenceNote(r); note != "" {
		if imp != "" {
			imp += " "
		}
		imp += note
	}
	return imp
}

// esc 只转义会破坏标签结构的三个字符。内容是中文散文，过度转义反而难读。
func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return strings.ReplaceAll(s, ">", "&gt;")
}

// weakEvidenceNote —— 开脱性结论 + 粗粒度取证 = 必须如实说明它证明不了什么。
//
// 「开脱」指这条结论错了会让一处发现被静默删掉；粗粒度指取证器没法把结论落到
// 本条污点变量上。两者同时成立时，把结论当确定性事实用就会静默删掉真漏洞 ——
// 活体形态是「上传方法里生成个链路 id」让文本扫误判成文件名已中和。
//
// **不删这条结论**（三仓实测:删了会误伤一条本来正确的判断,而它要防的假开脱 0 例），
// 只是不许它冒充确定性事实。措辞是给模型看的，要说清「证明了什么」和「没证明什么」。
func weakEvidenceNote(r Result) string {
	if !r.Exculpatory || r.Grain >= GrainVariable {
		return ""
	}
	// 只陈述边界,不重复调用方已写的行动指引(否则一条 implication 里两句"请据此复核")。
	return "**边界**：只确认该形态存在于" + r.Grain.CN() + "范围内，" +
		"未验证它作用于本条污点变量，也未验证顺序、分支、是否被重新污染 —— **不得当作已排除**。"
}

func contains(vs []Verdict, v Verdict) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}
