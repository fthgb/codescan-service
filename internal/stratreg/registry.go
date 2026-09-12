package stratreg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"appsecgo/internal/contract"
)

// registry.go — ③-e strategy 注册表（镜像 internal/cwereg 的 loader 形态，但与 cwe
// 正交：strategy 是认识论视角，不绑 filed CWE）。从目录加载 *.json，一文件一视角；
// Select 按切片 token 评分竞争上桌（raptor picker.py:143-160 _score_strategy 精神）。
//
// parity gate（plan §4.3/§7）：nil Registry → Select 返 nil → 生产路径传真 registry
// （general 等上桌），parity 路径传 nil（无 strategy → BuildMessages strategyLayer 空 →
// 字节不变）。nil 指针调 Select 靠方法首行 nil 检查，不解引用 r。

// maxStrategies 是单次 Select 返回的 strategy 上限（含 general 占 1）。噪音控制，
// 镜像 roadmap §8.3 的 per-CWE specificity cap 精神的 strategy 版。
const maxStrategies = 3

// Registry 是 strategy 注册表的内存形态。
type Registry struct {
	strategies []contract.Strategy // 加载序（与 compiled 索引对齐）
	compiled   []compiledStrategy  // 预编译的 trigger regex（fail-open 跳坏 pattern）
}

type compiledStrategy struct {
	name      string
	alwaysOn  bool
	signals   []compiledSignal
	keyQ      []string
	addendum  string
	exemplars []contract.Exemplar
}

type compiledSignal struct {
	kind    string // paths / includes / function_keywords / cwes / authz_none
	pattern string // 原文（paths/includes 子串/精确，function_keywords 用 re，authz_none 无 pattern）
	re      *regexp.Regexp
}

// NewRegistry 从 dir 加载所有 *.json strategy。fail-open：坏 JSON / 坏 regex 跳过不崩
// （镜像 cwereg fail-open 精神）；目录不存在则返错（调用方决定降级）。
func NewRegistry(dir string) (*Registry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	r := &Registry{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // fail-open
		}
		var s contract.Strategy
		if err := json.Unmarshal(raw, &s); err != nil {
			continue // fail-open：坏 strategy 跳过，不致整体加载失败
		}
		if s.Name == "" {
			continue // 无名 strategy 无意义
		}
		r.strategies = append(r.strategies, s)
		r.compiled = append(r.compiled, compileStrategy(s))
	}
	return r, nil
}

func compileStrategy(s contract.Strategy) compiledStrategy {
	cs := compiledStrategy{
		name:      s.Name,
		alwaysOn:  s.AlwaysOn,
		keyQ:      s.KeyQuestions,
		addendum:  s.PromptAddendum,
		exemplars: s.Exemplars,
	}
	for _, sig := range s.TriggerSignals {
		c := compiledSignal{kind: sig.Kind, pattern: sig.Pattern}
		if sig.Kind == "function_keywords" && sig.Pattern != "" {
			if re, err := regexp.Compile(sig.Pattern); err == nil {
				c.re = re
			} else {
				continue // fail-open：跳坏 regex
			}
		}
		cs.signals = append(cs.signals, c)
	}
	return cs
}

// AllStrategies 返回所有已加载 strategy（按加载序；测试/诊断用）。
func (r *Registry) AllStrategies() []contract.Strategy { return r.strategies }

// Select 按切片 token 评分选 strategy：always-on（general）前置 + 得分>0 的 top-N
// （N=maxStrategies，含 general 占 1），按 specificity 降序。nil Registry → 返 nil
// （parity gate）。sliced 取 judge 路径的 map 形（json roundtrip），镜像 cwereg
// ImplicatedSinkTypes(sliced, declared) 的入参形态——JudgeOne 直接传 sliced，
// 无须手搓 []contract.HopSlice 转换。
func (r *Registry) Select(sliced map[string]any, vulnType string) []contract.Strategy {
	if r == nil {
		return nil // parity gate（plan §4.3/§7）
	}
	bodyText, pathText := extractCorpus(sliced)
	authzCoverage, _ := sliced["authz_coverage"].(map[string]any) // Task 1 ComputeAuthzCoverage 写；nil/缺 → authz_none 不 fire

	type scored struct {
		idx   int
		score int
	}
	var hits []scored
	for i, cs := range r.compiled {
		if cs.alwaysOn {
			continue // general 前置单独处理
		}
		if sc := scoreStrategy(cs, bodyText, pathText, vulnType, authzCoverage); sc > 0 {
			hits = append(hits, scored{i, sc})
		}
	}
	// specificity 降序、稳定（镜像 raptor picker.py 评分序）
	sort.SliceStable(hits, func(a, b int) bool { return hits[a].score > hits[b].score })

	out := []contract.Strategy{}
	// general 前置（always-on，不参与评分上限竞争——它占 maxStrategies 的 1 席）
	for i, cs := range r.compiled {
		if cs.alwaysOn {
			out = append(out, r.strategies[i])
		}
	}
	for _, h := range hits {
		if len(out) >= maxStrategies {
			break
		}
		out = append(out, r.strategies[h.idx])
	}
	return out
}

// extractCorpus 拼 signal 匹配语料：所有 hop 的 function_body（去 \r）+ file_path。
// 无 function_calls 字段（roadmap §8.5 territory），故 function_keywords 退化为对
// bodyText 做 regex search——比 raptor 粗（plan §2.1 诚实边界）。sliced 取 map 形，
// hops 容忍 []any（json roundtrip，judge 路径）与 []map[string]any（Go 手搓，单测），
// 镜像 cwereg.hopsOf 的形状容忍。
func extractCorpus(sliced map[string]any) (bodyText, pathText string) {
	raw, ok := sliced["hops"]
	if !ok || raw == nil {
		return "", ""
	}
	var hops []map[string]any
	switch hs := raw.(type) {
	case []map[string]any:
		hops = hs
	case []any:
		hops = make([]map[string]any, 0, len(hs))
		for _, h := range hs {
			if m, ok := h.(map[string]any); ok {
				hops = append(hops, m)
			}
		}
	default:
		return "", ""
	}
	var bodies, paths []string
	for _, h := range hops {
		if b, ok := h["function_body"].(string); ok {
			bodies = append(bodies, strings.ReplaceAll(b, "\r", ""))
		}
		if p, ok := h["file_path"].(string); ok {
			paths = append(paths, p)
		}
	}
	return strings.Join(bodies, "\n"), strings.Join(paths, "\n")
}

// scoreStrategy 镜像 raptor picker.py:_score_strategy 的 specificity 评分：
//   - paths             ：file_path 子串命中 → +len(pattern)（长 pattern 更 specific）
//   - includes          ：file basename 精确等值 → +len(pattern)
//   - function_keywords ：body regex 命中 → +1（等权小分；无结构化 call 列表，无 specificity）
//   - cwes             ：精确 CWE-id 等值 vulnType → +10（大分但不绑死评估——认识论组织根因）
//   - authz_none      ：authz_coverage full-none（全无鉴权）→ +5（事实驱动，A1 spec §1.3）
func scoreStrategy(cs compiledStrategy, bodyText, pathText, vulnType string, authzCoverage map[string]any) int {
	score := 0
	for _, sig := range cs.signals {
		switch sig.kind {
		case "paths":
			if sig.pattern != "" && strings.Contains(pathText, sig.pattern) {
				score += len(sig.pattern)
			}
		case "includes":
			if sig.pattern == "" {
				continue
			}
			for _, p := range strings.Split(pathText, "\n") {
				if filepath.Base(p) == sig.pattern {
					score += len(sig.pattern)
					break
				}
			}
		case "function_keywords":
			if sig.re != nil && sig.re.MatchString(bodyText) {
				score += 1
			}
		case "cwes":
			if sig.pattern != "" && strings.EqualFold(sig.pattern, vulnType) {
				score += 10
			}
		case "authz_none":
			// Steer(F4a-Steer §4.3):gate 退役——missing_auth 经 trigger 上桌(带 override,§1.3),不再 suppress rpc。
			if authzFullNone(authzCoverage) {
				score += 5
			}
		}
	}
	return score
}

// authzFullNone 报 authz_coverage 是否为 full-none（全无鉴权）：global_interceptor=="none"
// 且无方法级/类级守卫。nil/缺字段/类型畸形 → false（fail-open 不 fire）。A1 spec §1.3。
func authzFullNone(ac map[string]any) bool {
	if ac == nil {
		return false
	}
	gi, _ := ac["global_interceptor"].(string)
	if gi != "none" {
		return false
	}
	mg, _ := ac["method_guard"].(bool)
	cg, _ := ac["class_guard"].(bool)
	return !mg && !cg
}
