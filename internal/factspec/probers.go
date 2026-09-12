package factspec

import (
	"regexp"
	"strings"
)

// probers.go —— 三种取证方式。**每个只声明它真正能给出的结论**。
//
// 这三种不是拍脑袋分的，是 2026-08-23 事实层三处手写实现里真实存在的三种：
//
//	RepoGrep    全仓检索  —— authz 的 global_interceptor / upload 的 file_write_sink / nosniff
//	SliceScan   切片文本扫 —— upload 的 filename_neutralized / tainted_path_segment
//	EngineSanitizer 引擎查询 —— 迁 filename_neutralized 的试点
//
// 关键差别在**结论方向**，这正是反复踩坑的地方：

// —— RepoGrep：全仓检索 ——————————————————————————————————————
//
// 只有它能说 No：全仓扫完零命中，才谈得上「这个东西不存在」。
// 但这份「能说 No」的资格是**有条件的**：pattern 必须穷举过该事实的已知实现族 ——
// authz 的 pattern 不含 servlet Filter，于是对 ceshi 写出了确定性的假 "none"。
// 故凡 RepoGrep 参与的 Spec，factguard 语料是硬要求（NegativeCapable 会标出它）。
//
// 截断 = 没扫完 = Unknown，绝不能当 No。
type RepoGrep struct {
	ProberName string
	Pattern    string
	FileGlob   string // 空 = "*.java"
	// YesOnHit：命中时是否算 Yes。默认 false —— 命中往往只说明「存在这个东西」，
	// 不说明「它对本条告警生效」（authz 的 global_interceptor 命中就只写 ""，把覆盖判断交 LLM）。
	YesOnHit bool
}

func (g RepoGrep) Name() string {
	if g.ProberName != "" {
		return g.ProberName
	}
	return "repo_grep"
}

// 仓级：全仓扫得到「有没有」，扫不出「对本条告警是否生效」。
func (RepoGrep) Grain() Grain { return GrainRepo }

func (g RepoGrep) Can() []Verdict {
	if g.YesOnHit {
		return []Verdict{Unknown, Yes, No}
	}
	return []Verdict{Unknown, No}
}

func (g RepoGrep) Probe(c Ctx) (Verdict, string) {
	if c.Grep == nil || c.RepoRoot == "" {
		return Unknown, ""
	}
	glob := g.FileGlob
	if glob == "" {
		glob = "*.java"
	}
	matches, truncated, err := c.Grep(g.Pattern, glob)
	if err != nil || truncated {
		// 没扫完就下「不存在」= 假否定。宁可不知道。
		return Unknown, ""
	}
	if len(matches) == 0 {
		return No, "全仓扫 " + glob + " 零命中"
	}
	if g.YesOnHit {
		return Yes, "全仓命中 " + strings.Join(head(matches, 3), "、")
	}
	// 命中但覆盖不明 —— 存在 ≠ 对本条生效。
	return Unknown, ""
}

// —— SliceScan：切片文本扫 ——————————————————————————————————
//
// **永远说不了 No**：切片可能被截断，「切片里没看到」不等于「不存在」。
// 这是 upload 的 file_write_sink 差点抄错 authz 三态口径的那个坑。
type SliceScan struct {
	ProberName string
	Re         *regexp.Regexp
	// PerHop=true：逐 hop 匹配（要求命中落在同一个方法体内）；
	// false：对拼接后的整段切片匹配（跨 hop 的形态，如「控制器取参 → 服务层拼路径」）。
	PerHop bool
	YesMsg string
}

func (s SliceScan) Name() string {
	if s.ProberName != "" {
		return s.ProberName
	}
	return "slice_scan"
}

// 切片级：认得出切片文本里有没有，认不出它作用在哪个变量上。
func (SliceScan) Grain() Grain { return GrainSlice }

// 只有 Yes 与 Unknown —— 切片扫**没有资格**说「不存在」。
func (s SliceScan) Can() []Verdict { return []Verdict{Unknown, Yes} }

func (s SliceScan) Probe(c Ctx) (Verdict, string) {
	if s.Re == nil {
		return Unknown, ""
	}
	bodies := HopBodies(c.Sliced)
	if len(bodies) == 0 {
		return Unknown, ""
	}
	if s.PerHop {
		for _, b := range bodies {
			if s.Re.MatchString(b) {
				return Yes, s.YesMsg
			}
		}
		return Unknown, ""
	}
	if s.Re.MatchString(strings.Join(bodies, "\n")) {
		return Yes, s.YesMsg
	}
	return Unknown, ""
}

// —— EngineSanitizer：污点引擎查询 ————————————————————————————
//
// 同样**说不了 No**，但理由和 SliceScan 不同：引擎的 `HasSanitizer` 只扫**单个方法体**
// （名字里的 "OnPath" 名不副实，2026-08-23 实测），它的 false 只代表「这个方法里没有」，
// 当成「整条路径没净化」就是假否定。
//
// 相比 SliceScan 的优势是**精确到变量**：文本扫只知道「切片里有净化」，
// 不知道净化的是不是这条污点；引擎知道。故在 Spec 里应排在 SliceScan **之前**。
type EngineSanitizer struct {
	ProberName string
	// AcceptAt 收窄**族**：引擎的净化器目录是一张**漏洞族无关的平表**
	// （`URLEncoder.encode` 对路径穿越根本不是净化，却同样在表里 —— 已记 ROADMAP）。
	// 于是「引擎说有净化」不等于「有本事实要的那种净化」。
	//
	// 设置后，引擎返回的锚点（`Class.method:line`）须匹配它，否则算 Unknown ——
	// **不是 No**：问错了族只说明我这次没问出答案，不说明那种净化不存在。
	// 族知识留在调用方（它知道自己在问文件名还是问编码），不下沉进引擎。
	AcceptAt *regexp.Regexp
}

func (e EngineSanitizer) Name() string {
	if e.ProberName != "" {
		return e.ProberName
	}
	return "engine_sanitizer"
}

// 变量级：精确到污点变量，且带可核实锚点 —— 这正是它排在 SliceScan 之前的理由。
func (EngineSanitizer) Grain() Grain { return GrainVariable }

func (e EngineSanitizer) Can() []Verdict { return []Verdict{Unknown, Yes} }

func (e EngineSanitizer) Probe(c Ctx) (Verdict, string) {
	if c.Engine == nil {
		return Unknown, ""
	}
	for _, h := range Hops(c.Sliced) {
		fn, _ := h["function_name"].(string)
		tv, _ := h["taint_variable"].(string)
		fp, _ := h["file_path"].(string)
		if fn == "" || tv == "" {
			continue // 切片只在入口 hop 记 taint_variable —— 其余问不了（已知限制）
		}
		mk, found, err := c.Engine.ResolveMethodKey(fn, fp, "")
		if err != nil || !found {
			continue
		}
		ok, at, err := c.Engine.HasSanitizer(mk, tv)
		if err != nil || !ok {
			continue
		}
		if e.AcceptAt != nil && !e.AcceptAt.MatchString(at) {
			continue // 有净化，但不是本事实要的那一族 → 没问出答案，不是否定
		}
		return Yes, "引擎确认净化作用于污点变量 " + tv + "，锚点 " + at
	}
	return Unknown, "" // 引擎的 false 只是方法体内没有，不构成 No
}

// —— 共用小工具 ——

// Hops 取切片 hop 列表，容忍 []any 与 []map[string]any 两种形状。
func Hops(sliced map[string]any) []map[string]any {
	raw, ok := sliced["hops"]
	if !ok || raw == nil {
		return nil
	}
	switch hs := raw.(type) {
	case []map[string]any:
		return hs
	case []any:
		out := make([]map[string]any, 0, len(hs))
		for _, h := range hs {
			if m, ok := h.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// HopBodies 取各 hop 的函数体文本。
func HopBodies(sliced map[string]any) []string {
	var out []string
	for _, h := range Hops(sliced) {
		if b, _ := h["function_body"].(string); b != "" {
			out = append(out, b)
		}
	}
	return out
}

func head(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}
