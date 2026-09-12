// Package funcdistill 移植 appsec/func_distill.py（集群5 per-function 蒸馏缓存）。
//
// 审计时 agentic read_function 读过的函数蒸成 CWE 无关结构化摘要（功能+安全注意点），
// 按函数内容 hash 缓存于 run 内。后续命中 → 注入摘要+短摘录（不重读重蒸，省 token）。
//
// CWE 无关是复用前提：一个函数的行为不随哪个 alert 读它而变（sanitizer 就是 sanitizer）。
package funcdistill

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"appsecgo/internal/llm"
)

// SchemaVersion 移植 SCHEMA_VERSION (func_distill.py:22)。升版强制全部重蒸。
const SchemaVersion = 1

// ExcerptLines 移植 EXCERPT_LINES (func_distill.py:42)：命中缓存时返回的源码摘录行数。
const ExcerptLines = 60

// distillPrompt 移植 _DISTILL_PROMPT (func_distill.py:24-38)。逐字中文。
// sha 锚定版本键（换 prompt 强制重蒸，raptor 范式）。
const distillPrompt = `你是一名代码安全分析专家。蒸馏下面这个函数的**通用**行为与安全注意点（CWE 无关——
不针对某条具体漏洞，描述这个函数本身做什么、对数据安全意味着什么）。输出严格 JSON，字段：
{"function_name":"...","role":"source|sanitizer|sink|guard|propagator|other",
 "behavior":"1-2 句：这个函数做什么（按函数体结构判断，不按函数名/注释/docstring）",
 "security_notes":"安全注意点：若是净化器写它净化的什么+是否完整；若是危险 sink 写危险点；"
                  "部分防御（只挡部分输入/可绕过）必须标 incomplete 或 bypassable；无则 none",
 "confidence":0.0到1.0的float}

质量守卫（铁律 C 第一性原理 > 模式匹配）：
- 注释/docstring 不可信，必须按函数体**实际结构**判断它做什么。
- 空操作/no-op/regex-only/仅命名像净化但无实质逻辑的，confidence 必须 < 0.7。
- 部分防御（如只 replace 一个固定串、只校验部分分支）必须在 security_notes 标 incomplete 或 bypassable。
- role 按实际行为，不按名字（名字含 sanitize 不一定真净化；名字像 sink 不一定危险）。
- 只输出 JSON，不要解释、不要 markdown 围栏。
`

// promptSHA16 是 distillPrompt 的 sha256 前 16（换 prompt 强制重蒸）。
var promptSHA16 = sha256Hex16(distillPrompt)

// FunctionSummary 移植 FunctionSummary (func_distill.py:45-53)。
// CWE 无关的 per-function 蒸馏结果，run 内按 content_hash 复用。
type FunctionSummary struct {
	FunctionName  string  `json:"function_name"`
	Role          string  `json:"role"` // source|sanitizer|sink|guard|propagator|other（闭集）
	Behavior      string  `json:"behavior"`
	SecurityNotes string  `json:"security_notes"`
	Confidence    float64 `json:"confidence"`
	ContentHash   string  `json:"content_hash"`
	Provenance    string  `json:"provenance"`
}

// ModelFamily 移植 _model_family (func_distill.py:56-59)：model.split("-")[0]，换族强制重蒸。
func ModelFamily(model string) string {
	m := strings.TrimSpace(model)
	if m == "" {
		return "unknown"
	}
	return strings.Split(m, "-")[0]
}

// ContentHash 移植 content_hash (func_distill.py:62-63)：sha256 前 16。
func ContentHash(body string) string {
	return sha256Hex16(body)
}

// BuildCacheKey 移植 build_cache_key (func_distill.py:66-69)：
// 多维度版本键 = schema 版本 + prompt sha + 模型族 + 函数内容 sha。
// 任一变化（蒸馏 schema 升级 / prompt 改 / 换模型族 / 函数体改）强制 miss 重蒸。
func BuildCacheKey(body, model string) string {
	return "func_distill:v" + itoa(SchemaVersion) + ":p" + promptSHA16 +
		":m" + ModelFamily(model) + ":" + ContentHash(body)
}

// DistillFunction 移植 distill_function (func_distill.py:72-106)。
// 聚焦短 LLM 调用（text 路径，无 Harness 重试），把函数体蒸成 CWE 无关摘要。
// fail-open：任何失败/解析失败返 nil（不阻塞）。复用 judge.ParseJudgeOutput 三层解析。
func DistillFunction(body, name string, provider llm.Provider, model string) *FunctionSummary {
	if body == "" || name == "" {
		return nil
	}
	messages := []map[string]any{
		{"role": "system", "content": distillPrompt},
		{"role": "user", "content": "函数名：" + name + "\n\n函数体：\n" + body},
	}
	resp, err := provider.Complete(context.Background(), llm.Request{
		Messages:  messages,
		MaxTokens: 600, // 对齐 Python max_tokens=600
		Tools:     nil, // text 路径
	})
	if err != nil {
		return nil // fail-open
	}
	// 内联 3 层 JSON 解析（对齐 judge.ParseJudgeOutput 的 direct/fence/brace），
	// 不 import judge 包以断 funcdistill→judge→agentic→funcdistill 循环。
	// 蒸馏 JSON 无 raw_arguments 异形，不需 NormalizeVerdictData。
	data, ok := parseJSON(resp.Text)
	if !ok {
		return nil
	}
	role := strings.ToLower(strings.TrimSpace(strVal(data, "role")))
	if role != "source" && role != "sanitizer" && role != "sink" &&
		role != "guard" && role != "propagator" && role != "other" {
		role = "other" // 闭集校验：未知值兜底
	}
	conf := toFloat(data["confidence"])
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1 // clamp
	}
	return &FunctionSummary{
		FunctionName:  firstNonEmpty(strVal(data, "function_name"), name),
		Role:          role,
		Behavior:      strings.TrimSpace(strVal(data, "behavior")),
		SecurityNotes: strings.TrimSpace(strVal(data, "security_notes")),
		Confidence:    conf,
		ContentHash:   ContentHash(body),
		Provenance:    "llm_distill",
	}
}

// FunctionSummaryStore 移植 FunctionSummaryStore (func_distill.py:109-131)。
// run 内内存缓存，线程安全（并行 enrich/judge 共享同 store）。键 = BuildCacheKey。
// 跨 run 不持久化（留集群5.5 raptor/annotate 磁盘版）。
type FunctionSummaryStore struct {
	mu   sync.RWMutex
	data map[string]*FunctionSummary
}

// NewFunctionSummaryStore 建空 store。
func NewFunctionSummaryStore() *FunctionSummaryStore {
	return &FunctionSummaryStore{data: make(map[string]*FunctionSummary)}
}

// Get 返回 key 对应的 summary，未命中返 nil。
func (s *FunctionSummaryStore) Get(key string) *FunctionSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key]
}

// Set 存入 summary（覆盖同 key）。
func (s *FunctionSummaryStore) Set(key string, summary *FunctionSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = summary
}

// Len 返回缓存条目数。
func (s *FunctionSummaryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

// Stats 可观测性：命中/未命中计数（喂 trace/日志，证复用生效）。
func (s *FunctionSummaryStore) Stats() map[string]any {
	return map[string]any{"size": s.Len()}
}

// --- helpers ---

// sha256Hex16 返回 sha256 hex 前 16 字符。
func sha256Hex16(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

// itoa 简单整数转字符串。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// strVal 从 map[string]any 取 string，缺省返 ""。
func strVal(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// toFloat 从 any 取 float64（JSON number），支持 int/float64。
func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}

// firstNonEmpty 返回首个非空字符串。
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// fenceReJSON 匹配 markdown 围栏里的 JSON 对象（对齐 judge.parse.go:16 fenceRe）。
var fenceReJSON = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// parseJSON 3 层解析 LLM 文本为 JSON 对象（对齐 judge.ParseJudgeOutput direct/fence/brace）。
// 内联在 funcdistill 包以断 funcdistill→judge 循环依赖（judge→agentic→funcdistill 会闭环）。
// 蒸馏 JSON 无 raw_arguments 异形，不需 NormalizeVerdictData/RepairJSON。
func parseJSON(text string) (map[string]any, bool) {
	// Layer 1: direct
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err == nil {
		return obj, true
	}
	// Layer 2: markdown fenced
	if m := fenceReJSON.FindStringSubmatch(text); m != nil {
		if err := json.Unmarshal([]byte(m[1]), &obj); err == nil {
			return obj, true
		}
	}
	// Layer 3: brace scan (balanced first top-level object)
	depth, start := 0, -1
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 && start >= 0 {
				if err := json.Unmarshal([]byte(text[start:i+1]), &obj); err == nil {
					return obj, true
				}
				start = -1
			}
		}
	}
	return nil, false
}
