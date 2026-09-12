// Package factguard —— 确定性事实的**语料契约**（2026-08-23）。
//
// # 这个包为什么存在
//
// 2026-08-23 逐条人工核实标注清单时，核出的每一个错误根因完全相同：
//
//	一个**未经证明**的事实被打上「确定性」标签，然后下游全链条当真值采信。
//
// 四个活体实例：
//
//	① authz_coverage 的 globalInterceptorPattern 自称「LLM pattern 集的确定性超集」，
//	   实际不含 servlet Filter → 对 ceshi(有全局 LogCostFilter) 写出确定性的 "none"，
//	   模型据此判出错误的 missing-auth TP，面账的分组事实一并被污染。
//	② authzAnnotationRe 只认 Spring 四注解，漏 Shiro/Sa-Token/JSR-250 →
//	   Shiro 项目会拿到确定性的假 method_guard=false（同一连锁，尚未撞上活体仓）。
//	③ 报告称「路径穿越不可达」——只查了文件名净化，没查目录参数（ceshi ca15851d
//	   的 biz 参数可穿越建目录，真漏洞被说成另一回事）。
//	④ 我自己照搬面账结论说某条是真 missing-auth，没去读那个 Filter。
//
// # 类的定义
//
// **假的确定性事实比 LLM 幻觉危险得多**：幻觉会被守卫拦，而确定性事实**就是守卫本身**，
// 且「确定性」这个标签让下游不再质疑它。GR-8「真相即判据」一直被当成防幻觉的规则，
// 但真正的薄弱点在确定性层。
//
// # 缺的不变量（2026-08-23 修正一次，见下）
//
//	任何**结论错了会让一处发现被静默删掉**的事实计算，必须有一份反例语料
//	证明它认得该类事实的已知实现族。「超集」这类自我声称只能由测试兑现，不能由注释兑现。
//
// # 判据修正：从「是否否定」改成「是否开脱」
//
// 首版把判据写成「产出确定性**否定**结论才需要语料」，理由是「肯定结论出错只会让
// 判定更保守」。这条**不成立**，`filename_neutralized` 就是活体反例：它是个**肯定**
// 事实（"yes，文件名已中和"），但下游拿它产出的是**开脱性**结论 ——
// RenderUploadNote 原话「经文件名的 b3 不成立」。它错了，一条真的路径穿越就此消失。
//
// 更糟的是首版判据下的守卫会**主动放行**它：该 Spec 的两个取证器都只能说 Yes/Unknown，
// `NegativeCapable` 为假 → 不要求语料。判据本身漏了这一整类。
//
// 故判据改为：**这条事实的结论，错了是否会让发现减少**（开脱）。
// 「确定性否定」只是开脱的**最常见形态**，不是它的定义。
//
// # 怎么用
//
// 事实生产者在其 pattern/规则定义处写一行标记：
//
//	// EXCULPATORY-FACT: <fact-name>
//
// 并在本包 corpus.go 里登记同名语料。`TestEveryExculpatoryFactHasCorpus` 扫源码强制
// 两者对齐 —— 新增一个开脱性事实却忘了语料 → 红。这就是让「不能忘」成为结构性质而非纪律。
package factguard

import (
	"regexp"
	"strings"
	"testing"
)

// Sample —— 一份语料样本。Src 取自**真实世界的实现形态**，不虚构。
type Sample struct {
	Name string // 这是什么（"Shiro @RequiresPermissions"）
	Src  string // 待判定的源码片段
	Note string // 为什么它属于/不属于该事实（可空）
}

// Corpus —— 一个开脱性事实的语料契约。
type Corpus struct {
	// Fact 与源码里 `// EXCULPATORY-FACT:` 标记的名字一致。
	Fact string
	// Why 说明「结论错了会让什么发现消失」——语料的存在理由要能被下一个人读懂。
	Why string
	// Exculpatory 说明该事实的**哪个**结论是开脱性的（"no" / "yes"）。
	// 写出来是为了逼作者想清楚危险方向在哪一侧，而不是笼统地"这条要小心"。
	Exculpatory string
	// MustRecognize —— 已知实现族。漏认任一条 = 该事实会对那类仓库产假否定。
	MustRecognize []Sample
	// MustNotRecognize —— 不该被认作该事实的样本。防过度匹配把否定结论变成永不出现
	//（那会让事实退化为无信息量，等于悄悄关掉这条判据）。
	//
	// 只放**判据本身错了**的形态。取证粒度够不着的形态放 GrainLimited —— 两者混在一起，
	// 语料就永远红，而"永远红的测试"等于没有测试。
	MustNotRecognize []Sample

	// GrainLimited —— 本取证**粒度固有区分不了**的形态。
	//
	// 与 MustNotRecognize 的区别是根因不同：那边是 pattern 写错了（改 pattern 能修），
	// 这边是这个粒度看不见（改 pattern 修不了）。活体例子：切片级文本扫看见
	// 「切片里出现过 UUID.randomUUID」这几个字，但上传方法里生成个链路 id 也长这样 ——
	// 要分辨必须知道它作用在哪个变量上，那是变量级才有的信息。
	//
	// 两个用途：
	//  ① 守卫「必须如实标注证据强度」这条要求（VerifyGrainLimited）——
	//     结论不删（三仓实测删了会误伤本来正确的判断），但不许它冒充确定性事实。
	//  ② 作为**提升粒度的验收集**：哪天引擎能答了，这些就该从这里毕业成 MustNotRecognize。
	GrainLimited []Sample
}

// Verify 对一个匹配器跑完整语料。match 返回「该源码片段是否构成此事实」。
func Verify(t *testing.T, c Corpus, match func(string) bool) {
	t.Helper()
	for _, s := range c.MustRecognize {
		if !match(s.Src) {
			t.Errorf("[%s] 漏认已知实现族：%s\n  → 该类仓库会拿到**确定性的假否定**，而 %s\n  %s",
				c.Fact, s.Name, c.Why, s.Note)
		}
	}
	for _, s := range c.MustNotRecognize {
		if match(s.Src) {
			t.Errorf("[%s] 过度匹配：%s 不该被认作该事实\n  → 否定结论将永不出现，这条判据等于被悄悄关掉\n  %s",
				c.Fact, s.Name, s.Note)
		}
	}
}

// VerifyGrainLimited 断言这些形态**确实**被当前粒度误认（限制是真的，不是我担心出来的），
// 且调用方据此挂了弱证据标注。match 同 Verify；weakNoted 回答「这个结论有没有被标成弱证据」。
//
// 为什么要断言"确实被误认"：如果某条其实认不出来，它就不属于粒度限制，
// 放在这里会让人以为标注机制在保护一个不存在的风险 —— 语料必须描述现实。
func VerifyGrainLimited(t *testing.T, c Corpus, match func(string) bool, weakNoted func(string) bool) {
	t.Helper()
	for _, s := range c.GrainLimited {
		if !match(s.Src) {
			t.Errorf("[%s] 粒度限制样本 %q 其实没被误认 —— 它不属于粒度限制，别放这儿（语料要描述现实）\n  %s",
				c.Fact, s.Name, s.Note)
			continue
		}
		if !weakNoted(s.Src) {
			t.Errorf("[%s] 粒度限制样本 %q 被认作该事实,却**没有**挂弱证据标注\n"+
				"  → 下游会把它当确定性事实,而它错了会静默删掉一处真漏洞。\n  %s",
				c.Fact, s.Name, s.Note)
		}
	}
}

// All 返回全部已登记语料（供 corpus_test.go 的覆盖守卫枚举）。
func All() []Corpus { return corpora }

// Names 返回已登记的事实名集合。
func Names() map[string]bool {
	out := map[string]bool{}
	for _, c := range corpora {
		out[c.Fact] = true
	}
	return out
}

// MarkerPrefix —— 源码里标注开脱性事实的记号。
//
// 曾叫 NEGATIVE-FACT（判据是「产出否定结论」），2026-08-23 随判据一起改名：
// 开脱不等于否定，`filename_neutralized=yes` 就是个开脱性的**肯定**事实。
// 旧名**不保留别名** —— 留着就会有人按旧判据登记，而旧判据漏掉一整类。
const MarkerPrefix = "EXCULPATORY-FACT:"

// factNameRe —— 事实名是 **slug**（小写+下划线），不是散文。
//
// 记号在文档里被**提及**（讲用法、举例）和在事实生产者头上被**声明**，长得一样但意思相反。
// 首版只切冒号后的整行 → factspec 包文档里那句「`// EXCULPATORY-FACT: <name>` 标记同名（当它…）」
// 被当成了一个叫「` 标记同名（当它能产出 No 时）。」的事实，守卫当场自锁。
// 收敛成 slug 即可分开两者：声明必是 slug，提及几乎不可能恰好是。
var factNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ParseMarkers 从一段源码里抽出所有 `// NEGATIVE-FACT: name` 的 name。（仅取合法 slug）。
func ParseMarkers(src string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		i := strings.Index(line, MarkerPrefix)
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[i+len(MarkerPrefix):])
		// 声明后允许跟标点/说明（如 `name。`），故只取首个 token。
		if j := strings.IndexAny(name, " \t,;，。（("); j > 0 {
			name = name[:j]
		}
		if factNameRe.MatchString(name) {
			out = append(out, name)
		}
	}
	return out
}

// ByName 取指定事实的语料;不存在则 t.Fatal(避免测试悄悄跳过)。
func ByName(t *testing.T, name string) Corpus {
	t.Helper()
	for _, c := range corpora {
		if c.Fact == name {
			return c
		}
	}
	t.Fatalf("未登记语料的否定事实: %s —— 见 internal/factguard/corpus.go", name)
	return Corpus{}
}
