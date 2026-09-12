package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAIProvider is a net/http client for any OpenAI-compatible /chat/completions
// endpoint (e.g. Tencent Hunyuan hy3 via copilot.tencent.com). Mirrors the standalone
// aiscan-refactored/internal/llm/client.go ChatCompletion + forceStream aggregation,
// adapted to our Provider interface + Response shape (铁律 D: 新 provider = 单边界,
// Provider interface 已抽象;Request.Messages/Tools 本就是 OpenAI shape → 无 shape 转换,
// 比 AnthropicProvider 更简)。
//
// copilot.tencent.com rejects non-streaming ("Non-stream chat request is currently not
// supported");forceStream=true drives a streaming request and aggregates SSE chunks
// into one Response(同参考 chatForceStream)。
type OpenAIProvider struct {
	baseURL string
	apiKey  string // Bearer
	model   string // 自持 model;Complete 发 body["model"]=p.model(铁律 D,见 types.go Provider.Model)
	// temperature — provider 自持的采样温度兜底(nil=不发该键)。
	//
	// 起因:走 hy3 时判决主路径与 agentic 探索**全程在服务端默认温度上采样** ——
	// judge.go:84 工具路径不传温度(Anthropic thinking 强制 temp=1),agentic 两个循环零处
	// 引用 Temperature,而本 provider 只在非 nil 时才发。实测 relation-trade 三跑
	// 11/12(92%)跨相同输入翻判(qwen 历史三跑同仓 42%)。
	// 采样参数属于 provider 边界(与 Model() 同构,铁律 D);opt-in,未配置则一个键都不发。
	temperature *float64
	forceStream bool
	httpClient  *http.Client
}

// NewOpenAIProvider builds an OpenAI-compatible provider. Use WithOpenAIHTTPClient
// to inject a custom *http.Client(tests use httptest + controlled transport). 不能复用
// anthropic.go 的 WithHTTPClient——其 Option 签名钉 *AnthropicProvider,类型不符,故本 provider
// 自带 WithOpenAIHTTPClient(同包不同类型,各自独立)。
func NewOpenAIProvider(baseURL, apiKey, model string, forceStream bool, opts ...func(*OpenAIProvider)) *OpenAIProvider {
	p := &OpenAIProvider{
		baseURL:     strings.TrimRight(baseURL, "/"),
		apiKey:      apiKey,
		model:       model,
		forceStream: forceStream,
		httpClient: &http.Client{
			Transport: &http.Transport{
				IdleConnTimeout:       60 * time.Second,
				ResponseHeaderTimeout: 300 * time.Second,
			},
		},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// WithOpenAIHTTPClient 注入 http.Client(测试用 httptest+controlled transport)。
// WithOpenAITemperature 给 provider 配采样温度兜底。仅在调用方未显式给 Temperature 时生效。
func WithOpenAITemperature(t float64) func(*OpenAIProvider) {
	return func(p *OpenAIProvider) { p.temperature = &t }
}

func WithOpenAIHTTPClient(c *http.Client) func(*OpenAIProvider) {
	return func(p *OpenAIProvider) { p.httpClient = c }
}

func (p *OpenAIProvider) SupportsTools() bool { return true }
func (p *OpenAIProvider) Model() string       { return p.model }

// normalizeToolChoice 把 Anthropic 语义的 ToolChoice 串归一到 OpenAI 合法取值:
// OpenAI 只认 "auto"|"none"|"required"(或 {"type":"function",...} 命名)。Anthropic
// 的 "any"→"required","tool"(命名工具,串里无 name)→"auto",其余透传。
// 不归一则 hy3 网关 400。返回 nil = 不带 tool_choice(让端点默认)。
func normalizeToolChoice(tc string) any {
	switch tc {
	case "any":
		return "required"
	case "tool":
		return "auto" // 无 tool 名可拼,退 auto(同 Anthropic thinking 降级口径)
	case "auto", "none", "required":
		return tc
	case "":
		return nil
	default:
		return tc // 透传,网关不认则 400(不静默吞)
	}
}

// Complete does ONE POST to {baseURL}/chat/completions. forceStream → SSE 聚合;
// 否则非流式。无重试——Harness(Layer A)分类 empty 并重试(同 AnthropicProvider)。
//
// SSE 聚合 5 条不变量(用户 2026-08-21 点出的真坑 + 协议坑):
//  1. 扫前先检 StatusCode:非 2xx→读 body 错误文→直接返 error,不进 SSE 扫描
//     (否则 4xx/5xx JSON 错误体无 data: 行→空响应→Harness 误重试 3 次吞掉真因)。
//  2. arguments 按 delta.tool_calls[index] 累加原始字符串,绝不在单 delta 内 Unmarshal
//     (OpenAI/腾讯网关必把 JSON 串切碎)。
//  3. [DONE]/流结束后,对每个 index 的完整累加串做一次 json.Unmarshal 成 map[string]any
//     → ToolCall.Arguments(落 types.go:6-10 的 map 类型,镜像 anthropic.go:93-98)。
//     Unmarshal 失败→Arguments=nil(容错,不崩)。
//  4. finish_reason 只在末块非空,跨块累加→最终 StopReason。
//  5. ": keep-alive" 注释行(非 data: 前缀)天然跳过;扫完查 scanner.Err() 捕获底层读错。
func (p *OpenAIProvider) Complete(ctx context.Context, req Request) (Response, error) {
	body := map[string]any{
		"model":    p.model,      // 铁律 D:provider 自持 model,不再用 req.Model(切 provider 即切 model)
		"messages": req.Messages, // OpenAI 接受内联 system,不拆(splitSystem 是 Anthropic 专属)
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}
	switch {
	case req.Temperature != nil:
		body["temperature"] = *req.Temperature // 调用方显式值优先
	case p.temperature != nil:
		body["temperature"] = *p.temperature // provider 兜底(未配置则不发该键=零回归)
	}
	if req.Tools != nil {
		body["tools"] = req.Tools // OpenAI shape,透传
		if tc := normalizeToolChoice(req.ToolChoice); tc != nil {
			body["tool_choice"] = tc
		}
	}
	if p.forceStream {
		body["stream"] = true
		return p.completeStream(ctx, body)
	}
	body["stream"] = false
	return p.completeNonStream(ctx, body)
}

func (p *OpenAIProvider) completeNonStream(ctx context.Context, body map[string]any) (Response, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("openai http %d: %s", resp.StatusCode, string(raw))
	}
	return parseOpenAIResponse(raw)
}

// completeStream 驱动流式请求,聚合 SSE chunk 成一个 Response(不变量 1-5)。
func (p *OpenAIProvider) completeStream(ctx context.Context, body map[string]any) (Response, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Accept", "text/event-stream")
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	// 不变量 1:扫前先检 status。非 2xx 的 body 是 JSON 错误不是 SSE,直接返 error,
	// 不进扫描(否则被当空响应→Harness 误重试吞真因)。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return Response{}, fmt.Errorf("openai http %d: %s", resp.StatusCode, string(raw))
	}
	var (
		content strings.Builder
		finish  string
	)
	// 不变量 2:按 index 累加 arguments 原始字符串(不在 delta 内 Unmarshal)。
	type acc struct {
		id   string
		name string
		args strings.Builder
	}
	toolAccs := map[int]*acc{}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB/行,同参考
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") { // 跳过 keep-alive 注释行/空行
			continue
		}
		payload := strings.TrimSpace(line[len("data:"):])
		if payload == "[DONE]" {
			break
		}
		var ev struct {
			Choices []struct {
				Delta struct {
					Role      string `json:"role"`
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		for _, ch := range ev.Choices {
			if ch.Delta.Content != "" {
				content.WriteString(ch.Delta.Content)
			}
			for _, tc := range ch.Delta.ToolCalls {
				a, ok := toolAccs[tc.Index]
				if !ok {
					a = &acc{}
					toolAccs[tc.Index] = a
				}
				if tc.ID != "" {
					a.id = tc.ID
				}
				if tc.Function.Name != "" {
					a.name = tc.Function.Name
				}
				// 不变量 2:累加原始串
				a.args.WriteString(tc.Function.Arguments)
			}
			if ch.FinishReason != "" {
				finish = ch.FinishReason // 不变量 4:末块累加
			}
		}
	}
	// 不变量 5:捕获底层读错(否则静默截断)。
	if err := scanner.Err(); err != nil {
		return Response{}, fmt.Errorf("sse scan: %w", err)
	}
	// 不变量 3:流结束后对每个 index 的完整累加串做一次 Unmarshal 成 map。
	toolCalls := make([]ToolCall, 0, len(toolAccs))
	for _, a := range toolAccs {
		tc := ToolCall{ID: a.id, Name: a.name}
		if raw := a.args.String(); raw != "" {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
				tc.Arguments = parsed
			} // 失败→Arguments=nil(容错,不崩)
		}
		toolCalls = append(toolCalls, tc)
	}
	return Response{
		Text:        content.String(),
		ToolCalls:   toolCalls,
		StopReason:  finish,
		HasThinking: false, // OpenAI 无 thinking 块;harness.go:45 的 thinking-exhausted 门恒不触发
	}, nil
}

// parseOpenAIResponse 解析非流式 /chat/completions 响应 → Response。
func parseOpenAIResponse(raw []byte) (Response, error) {
	var out struct {
		Choices []struct {
			Message struct {
				Role      string `json:"role"`
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     float64 `json:"prompt_tokens"`
			CompletionTokens float64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("unmarshal: %w", err)
	}
	resp := Response{HasThinking: false}
	if len(out.Choices) > 0 {
		ch := out.Choices[0]
		resp.Text = ch.Message.Content
		resp.StopReason = ch.FinishReason
		for _, tc := range ch.Message.ToolCalls {
			c := ToolCall{ID: tc.ID, Name: tc.Function.Name}
			if tc.Function.Arguments != "" {
				var parsed map[string]any
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &parsed); err == nil {
					c.Arguments = parsed
				}
			}
			resp.ToolCalls = append(resp.ToolCalls, c)
		}
	}
	if out.Usage != nil {
		resp.Usage = Usage{
			InputTokens:  int(out.Usage.PromptTokens),
			OutputTokens: int(out.Usage.CompletionTokens),
		}
	}
	return resp, nil
}
