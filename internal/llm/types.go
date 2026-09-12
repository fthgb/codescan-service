package llm

import "context"

// ToolCall mirrors appsec/llm/base.py:ToolCall (OpenAI-compatible shape).
type ToolCall struct {
	ID        string
	Name      string
	Arguments map[string]any
}

// ToolTurn mirrors appsec/llm/base.py:ToolTurn.
type ToolTurn struct {
	Text      string
	ToolCalls []ToolCall
}

type Usage struct {
	InputTokens  int
	OutputTokens int
}

// Response is the pre-harness raw SDK response view (Anthropic Messages API shape).
// Recording captures exactly this at the SDK boundary, BEFORE Layer A. Go's
// ReplayProvider parses recorded raw content_blocks into this via extract*.
type Response struct {
	Text        string
	ToolCalls   []ToolCall
	StopReason  string
	Usage       Usage
	HasThinking bool
}

// Request carries the OpenAI-shape chat request. ReplayProvider ignores Messages
// (recorded already); live AnthropicProvider (P5) converts OpenAI->Anthropic shape.
// Tools nil = text path; non-nil = tool-first. Temperature nil on tool path
// (thinking forces temp=1, anthropic_native.py:635-638); set on text path.
//
// **无 Model 字段**(2026-08-22 删):model 由 Provider 自持(见下方 Provider.Model)。
// 曾有过一个 Model 字段,13 个调用点都在设它、却无任何消费者 —— 与本次修的 hy3 bug
// 同一失效类(设了却静默不生效)。铁律 D:边界只留一处,删字段让编译器指出全部调用点。
type Request struct {
	Messages    []map[string]any
	MaxTokens   int
	Temperature *float64
	Tools       []map[string]any
	ToolChoice  string
}

// Provider does ONE call (no retry — retry lives in Harness so replay can consume
// recorded attempts). Live AnthropicProvider is P5; P2 parity uses ReplayProvider.
//
// Model() 让 Provider 自持 model 名(铁律 D 真·单边界):factory 构造时从对应 cfg
// 字段塞入,Complete 发请求体用 p.model,调用方用 provider.Model() 取(给 cache key /
// WriteRun meta)。切 provider 自动切 model,无需调用方同步,根除"切 provider 漏切 model"
// (2026-08-21 hy3 bug:仍发 qwen3.7-plus → copilot 返 429 code:14012 fail-open)。
type Provider interface {
	Complete(ctx context.Context, req Request) (Response, error)
	SupportsTools() bool
	Model() string
}
