package contract

// strategy_contract.go — ③-e strategy-driven evaluation 的认识论视角 schema。
//
// Strategy 是"用什么视角找证据"（认识论），非 CweConfig 的"是什么漏洞"（分类学）。
// 两者正交：Strategy 不塞进 CweConfig，独立注册表（internal/stratreg），独立注入点
// （prompts/messages.go systemText:476-477 的 strategyLayer，非 cweLayer）。镜像
// raptor cwe_strategies/strategies/*.yml + picker.py 的 specificity 评分精神。
//
// 认识论组织的根因（design spec §1）：filed CWE 可贴错，但评估视角不该被它绑死——
// 切片 token 命中的 strategy 竞争上桌，与 filed CWE 正交叠加。

// Strategy 是一个评估视角单元。
type Strategy struct {
	Name              string            `json:"name"`               // auth_privilege / taint_flow / general / ...
	TriggerSignals    []TriggerSignal   `json:"trigger_signals"`    // 命中即得分，specificity-weighted（general 无，靠 always_on）
	KeyQuestions      []string          `json:"key_questions"`      // 给 LLM 的结构化评估步骤（非 taint-flow 槽位；taint_flow 留空）
	PromptAddendum    string            `json:"prompt_addendum"`    // 领域知识片段（攻击者视角/pattern/CVE）
	AddendumOverrides map[string]string `json:"addendum_overrides"` // Steer(F4a-Steer §1.2):entry_nature 值→替换 addendum(rpc_internal_facade→RPC 可达性框定);空 map/缺键→用 PromptAddendum 默认(fail-open,§1.3)
	Exemplars         []Exemplar        `json:"exemplars"`          // 正反例代码
	AlwaysOn          bool              `json:"always_on"`          // general 置 true（始终上桌，不经评分）
}

// TriggerSignal 是 strategy 的命中条件。Kind 决定 Pattern 在何处匹配：
//   - paths            ：file_path 子串（specificity = len(pattern)，`fs/splice.c` 盖过 `fs/`）
//   - includes          ：file 精确名（filepath.Base 等值，预留，Step 1 种子未用）
//   - function_keywords ：function_body 的 token regex（无 function_calls 字段，比 raptor 粗，诚实边界 plan §2.1）
//   - cwes             ：精确 CWE-id 等值 vulnType（大分但不绑死评估——filed CWE 贴错时 strategy 仍能上桌）
type TriggerSignal struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

// Exemplar 是 strategy 的正/反例代码片段，锚定 LLM 的判定边界（设计 spec §7：偏薄，先种子）。
type Exemplar struct {
	Label string `json:"label"` // 正例/反例 + 一句理由
	Code  string `json:"code"`
}
