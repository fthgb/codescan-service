package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnthropicProvider is a hand-rolled net/http client for the Anthropic Messages
// API (api.anthropic.com OR a corp Anthropic-shape gateway). No SDK dependency
// (铁律: 墙内 go get 零风险; 复用 P2 extract.go 吃 raw content blocks). One POST
// per Complete — retry/thinking-exhaustion detection lives in Harness (Layer A),
// mirroring anthropic_native.complete/complete_with_tools where Layer A wraps the
// single SDK call.
type AnthropicProvider struct {
	baseURL        string
	authToken      string // Bearer (gateway ANTHROPIC_AUTH_TOKEN)
	model          string // 自持 model;Complete 发 body["model"]=p.model(铁律 D,见 types.go Provider.Model)
	thinkingBudget int    // 0=off (non-thinking gateway); >0 caps thinking
	httpClient     *http.Client
}

// Option configures AnthropicProvider (functional options for test injection).
type Option func(*AnthropicProvider)

// WithHTTPClient injects a custom *http.Client (tests use httptest + controlled
// transport to cover 5xx/timeout/connection-refused). Production default client
// carries per-phase timeouts (connect 10s, read/header 300s, mirrors _TIMEOUT).
func WithHTTPClient(c *http.Client) Option {
	return func(p *AnthropicProvider) { p.httpClient = c }
}

func NewAnthropicProvider(baseURL, authToken, model string, thinkingBudget int, opts ...Option) *AnthropicProvider {
	p := &AnthropicProvider{
		baseURL:        baseURL,
		authToken:      authToken,
		model:          model,
		thinkingBudget: thinkingBudget,
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

func (p *AnthropicProvider) SupportsTools() bool { return true }
func (p *AnthropicProvider) Model() string      { return p.model }

// splitSystem mirrors anthropic_native.py:_split_system (:60-69): pull
// role:"system" messages out, concatenate with "\n\n", preserve rest order.
func splitSystem(messages []map[string]any) (string, []map[string]any) {
	var parts []string
	var rest []map[string]any
	for _, m := range messages {
		if r, _ := m["role"].(string); r == "system" {
			if c, ok := m["content"].(string); ok {
				parts = append(parts, c)
			}
		} else {
			rest = append(rest, m)
		}
	}
	return strings.Join(parts, "\n\n"), rest
}

// toAnthropicMessages mirrors anthropic_native.py:_to_anthropic_messages (:72-108).
// user text passes through; assistant tool_calls -> tool_use blocks; role:"tool"
// -> user-role tool_result block; unknown role -> user turn (str(content)).
func toAnthropicMessages(messages []map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, m := range messages {
		role, _ := m["role"].(string)
		switch role {
		case "user":
			out = append(out, map[string]any{"role": "user", "content": m["content"]})
		case "assistant":
			blocks := []map[string]any{}
			if text, ok := m["content"].(string); ok && text != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": text})
			}
			if tcs, ok := m["tool_calls"].([]any); ok {
				for _, tc := range tcs {
					tcmap, _ := tc.(map[string]any)
					fn, _ := tcmap["function"].(map[string]any)
					var args any = map[string]any{}
					if a, ok := fn["arguments"].(string); ok {
						var parsed map[string]any
						if json.Unmarshal([]byte(a), &parsed) == nil {
							args = parsed
						}
					}
					blocks = append(blocks, map[string]any{
						"type": "tool_use", "id": tcmap["id"], "name": fn["name"], "input": args,
					})
				}
			}
			if len(blocks) == 0 {
				blocks = []map[string]any{{"type": "text", "text": ""}}
			}
			out = append(out, map[string]any{"role": "assistant", "content": blocks})
		case "tool":
			out = append(out, map[string]any{"role": "user", "content": []map[string]any{
				{"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]},
			}})
		default:
			out = append(out, map[string]any{"role": "user", "content": fmt.Sprint(m["content"])})
		}
	}
	return out
}

// toAnthropicTools mirrors anthropic_native.py:_to_anthropic_tools (:111-119):
// OpenAI {"type":"function","function":{name,description,parameters}} ->
// Anthropic {name,description,input_schema}. parameters defaults to empty object.
func toAnthropicTools(tools []map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, t := range tools {
		fn, ok := t["function"].(map[string]any)
		if !ok {
			fn = t
		}
		params, _ := fn["parameters"].(map[string]any)
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, map[string]any{
			"name": fn["name"], "description": fn["description"], "input_schema": params,
		})
	}
	return out
}

// thinkingKwargs mirrors anthropic_native.py:_thinking_kwargs (:173-182):
// b>0 -> {thinking:{type:enabled,budget_tokens:b}, max_tokens:max(maxTokens,b+1024)};
// b=0 -> nil. (tool_choice downgrade for thinking mode is applied in Complete,
// mirroring :259-262.)
func (p *AnthropicProvider) thinkingKwargs(maxTokens int) map[string]any {
	b := p.thinkingBudget
	if b == 0 {
		return nil
	}
	return map[string]any{
		"thinking":   map[string]any{"type": "enabled", "budget_tokens": b},
		"max_tokens": max(maxTokens, b+1024),
	}
}

// Complete does ONE POST to {baseURL}/v1/messages and feeds the raw content blocks
// to Extract* (P2). No retry — Harness (Layer A) classifies empty/thinking and
// retries. HTTP non-2xx / network / timeout -> error (Harness treats as retryable,
// mirroring Python `except Exception`). JSON numbers decode to float64 (Usage cast
// via float64, NOT int).
func (p *AnthropicProvider) Complete(ctx context.Context, req Request) (Response, error) {
	system, rest := splitSystem(req.Messages)
	body := map[string]any{
		"model":    p.model, // 铁律 D:provider 自持 model,不再用 req.Model(切 provider 即切 model)
		"messages": toAnthropicMessages(rest),
	}
	if tk := p.thinkingKwargs(req.MaxTokens); tk != nil {
		for k, v := range tk {
			body[k] = v
		}
		// thinking enabled: API forces temperature==1; do not pass caller temp.
		// Gateway rejects forced tool_choice in thinking mode (anthropic_native:259-262):
		// downgrade tool/any/required -> auto.
		if req.Tools != nil {
			body["tools"] = toAnthropicTools(req.Tools)
			tc := req.ToolChoice
			if tc == "tool" || tc == "any" || tc == "required" {
				tc = "auto"
			}
			body["tool_choice"] = map[string]any{"type": tc}
		}
	} else {
		if req.MaxTokens > 0 {
			body["max_tokens"] = req.MaxTokens
		}
		if req.Temperature != nil {
			body["temperature"] = *req.Temperature
		}
		if req.Tools != nil {
			body["tools"] = toAnthropicTools(req.Tools)
			body["tool_choice"] = map[string]any{"type": req.ToolChoice}
		}
	}
	if system != "" {
		body["system"] = system
	}
	buf, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/v1/messages", strings.NewReader(string(buf)))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.authToken)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("content-type", "application/json")
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("anthropic http %d: %s", resp.StatusCode, string(raw))
	}
	var ap map[string]any
	if err := json.Unmarshal(raw, &ap); err != nil {
		return Response{}, err
	}
	blocks, _ := ap["content"].([]any)
	blockMaps := make([]map[string]any, 0, len(blocks))
	for _, b := range blocks {
		if bm, ok := b.(map[string]any); ok {
			blockMaps = append(blockMaps, bm)
		}
	}
	stop, _ := ap["stop_reason"].(string)
	usage := Usage{}
	if u, ok := ap["usage"].(map[string]any); ok {
		// json.Unmarshal decodes JSON numbers to float64, NOT int.
		if v, ok := u["input_tokens"].(float64); ok {
			usage.InputTokens = int(v)
		}
		if v, ok := u["output_tokens"].(float64); ok {
			usage.OutputTokens = int(v)
		}
	}
	return Response{
		Text:        ExtractText(blockMaps),
		ToolCalls:   ExtractToolCalls(blockMaps),
		StopReason:  stop,
		Usage:       usage,
		HasThinking: HasThinking(blockMaps),
	}, nil
}
