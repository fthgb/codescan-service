package llm

import "strings"

// ExtractText mirrors anthropic_native._extract_text: concatenate TextBlock text,
// then .strip() (trim leading/trailing whitespace — matches Python's str.strip()).
// content blocks arrive as recorded maps (Anthropic SDK shape): {"type":"text","text":...}.
func ExtractText(blocks []map[string]any) string {
	out := ""
	for _, b := range blocks {
		if t, _ := b["type"].(string); t == "text" {
			if s, _ := b["text"].(string); s != "" {
				if out != "" {
					out += "\n"
				}
				out += s
			}
		}
	}
	return strings.TrimSpace(out)
}

// ExtractToolCalls mirrors anthropic_native._extract_tool_calls: tool_use blocks ->
// ToolCall{id,name,arguments=input}. qwen3.7-plus tool_use shape: {"type":"tool_use","id","name","input"}.
func ExtractToolCalls(blocks []map[string]any) []ToolCall {
	out := []ToolCall{}
	for _, b := range blocks {
		if t, _ := b["type"].(string); t != "tool_use" {
			continue
		}
		tc := ToolCall{}
		tc.ID, _ = b["id"].(string)
		tc.Name, _ = b["name"].(string)
		if args, ok := b["input"].(map[string]any); ok {
			tc.Arguments = args
		} else {
			tc.Arguments = map[string]any{}
		}
		out = append(out, tc)
	}
	return out
}

// HasThinking mirrors anthropic_native._has_thinking: any block type=="thinking".
func HasThinking(blocks []map[string]any) bool {
	for _, b := range blocks {
		if t, _ := b["type"].(string); t == "thinking" {
			return true
		}
	}
	return false
}
