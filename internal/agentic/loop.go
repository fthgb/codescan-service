package agentic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"appsecgo/internal/llm"
)

// MaxRounds / CharBudget 移植 config.py:144-145 (AGENTIC_EXPLORE_MAX_ROUNDS=10,
// AGENTIC_EXPLORE_CONTEXT_CHAR_BUDGET=80000)。双上限：loop 至多 MaxRounds 轮，
// 且 messagesCharTotal 超 CharBudget 立即 break → return nil。
const (
	MaxRounds  = 10
	CharBudget = 80000
)

// ForcedConvergenceProse 逐字移植 judge.py:608。loop 用尽/异常/双上限触顶 → 上层
// (judgeViaToolOrText, T8) 注入此 prose + tool_choice=auto 再调一次。循环控制逻辑
// （非 P5 system prompt）；live 时是 golden 文本，必须逐字一致防漂移。replay 时
// ReplayProvider 忽略 messages 不影响输出。本常量定义于此供 T8 复用。
var ForcedConvergenceProse = "你已收集了足够上下文。现在必须调用 submit_verdict 给出判定——基于已有证据；证据不足以确信时按 uncertain/likely 处理，不要再调用 read_file/grep_repo 探索。"

// messagesCharTotal 移植 _messages_char_total (agentic_enrich.py:256-257)：
// sum(len(json.dumps(m, ensure_ascii=False)) for m in messages)。
// Python len(str) 计 codepoint（rune），非字节。faithful 算法：
//   - 每条 message 用 jsonMarshalPython 序列化（SetEscapeHTML(false) +
//     injectPythonSpaces 拟合 Python json.dumps 默认 separators ', '/': '）
//   - 计 utf8.RuneCountInString（非字节），求和
//
// Go json.Marshal 排序 map key，Python 保插入序；但对 SUM（同 key/value 集重排）总长不变，
// 故 total 稳健。该值仅喂 `> CharBudget(80000)` break 比较；P4 stub prompt + 小 fixture
// 总量远低于 80000，break bool 与确切值无关，但 byte-faithful 降 T10 边界风险。
func messagesCharTotal(messages []map[string]any) int {
	n := 0
	for _, m := range messages {
		b, err := jsonMarshalPython(m)
		if err != nil {
			// 序列化失败不应发生（messages 均为 JSON 友好 map）；退化为字节长兜底。
			n += len(fmt.Sprint(m))
			continue
		}
		n += utf8.RuneCountInString(string(b))
	}
	return n
}

// jsonMarshalPython 拟合 Python json.dumps(v, ensure_ascii=False) 默认 separators：
// SetEscapeHTML(false) 关 <>& / U+2028 转义；Go compact 无空格 → injectPythonSpaces
// 在串外补 ', '/': '。Encode 末尾 \n 去 TrimRight。
func jsonMarshalPython(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	b = injectPythonSpaces(b)
	return b, nil
}

// injectPythonSpaces 在串外（inStr=false）的 ':' / ',' 后补一空格，拟合 Python
// json.dumps 默认 separators (', ', ': ')。状态机跟踪 in-string + \" 转义。
// 与 internal/vcache 同实现（彼为 unexported 跨包不可复用，故 inline）。
func injectPythonSpaces(b []byte) []byte {
	var out bytes.Buffer
	inStr := false
	backslashes := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		out.WriteByte(c)
		if c == '\\' {
			backslashes++
			continue
		}
		if c == '"' {
			// 偶数连续反斜杠 → " 未转义 → toggle；奇数 → 转义 → 不 toggle。
			// 旧 b[i-1]!='\\' 单字节回看不处理 \\" （\\ 是转义反斜杠，" 应 toggle
			// 但被误判为转义），致状态机失步、串内外空格注入错位。
			if backslashes%2 == 0 {
				inStr = !inStr
			}
			backslashes = 0
			continue
		}
		backslashes = 0
		if inStr {
			continue
		}
		if (c == ':' || c == ',') && i+1 < len(b) {
			out.WriteByte(' ')
		}
	}
	return out.Bytes()
}

// RunPlanSolveReActLoop 移植 _run_plan_solve_react_loop (agentic_enrich.py:260-343)。
// 双上限（max_rounds + char_budget）。返 6 值：(finishArgs|nil, finalMessages, turns,
// findings, budget, toolLog)。nil → 上层 forced-convergence 兜底（judgeViaToolOrText, T8）。
//
// 6-return 偏离 Python（Python 原地 mutate messages，调用方直接读）：Go slice append
// 不向调用方传播，故 RETURN finalMessages。起手 copy（append([]..., messages...)）
// 使调用方 input slice 不被 mutate。所有路径（finish/nil/exception）均返 finalMessages。
//
// vulnType 仅为对齐 Python 签名占位（Python 未在 loop 内消费），保留供 T8 上下文。
func RunPlanSolveReActLoop(messages []map[string]any, harness llm.Provider, model string,
	tools []map[string]any, executor *ToolExecutor, vulnType, finishTool string,
	maxTokens int) (finishArgs map[string]any, finalMessages []map[string]any, turns int,
	findings []map[string]any, budget map[string]any, toolLog []map[string]any) {

	// copy 入参，避免 mutate 调用方 slice
	finalMessages = append([]map[string]any{}, messages...)
	// allTools = list(tools) + [_FINDING_TOOL]
	allTools := append([]map[string]any{}, tools...)
	allTools = append(allTools, FindingTool)

	findings = []map[string]any{}
	toolLog = []map[string]any{}
	budget = map[string]any{"rounds": 0, "chars": 0, "error": nil}
	exploreRounds := 0
	// Layer B: 去重缓存 key=tool+pythonJSON(args) -> 已截断的 msgContent。
	// 命中重复返缓存 + steering 后缀；连续 2 轮全-dup → break → forced convergence。
	seenCache := map[string]string{} // Layer B: key=tool+pythonJSON(args) → 已截断 msgContent
	seenResult := map[string]any{}   // 结构化 result 缓存(新):dedup 调用也须在 toolLog 存 result
	consecutiveDupRounds := 0

	// 外层异常 → budget.error + return nil（对齐 Python :340-342 except Exception）。
	// Python f"{type(e).__name__}: {e}" 不可在 Go 复现；budget 入 trace（P4 parity 不含）
	// 故格式非 parity-critical，用 fmt.Sprintf("%v", r)。
	defer func() {
		if r := recover(); r != nil {
			budget["error"] = fmt.Sprintf("%v", r)
			budget["rounds"] = exploreRounds
			budget["chars"] = messagesCharTotal(finalMessages)
			finishArgs = nil
		}
	}()

	for i := 0; i < MaxRounds; i++ {
		// char_budget 顶：本轮不调 Complete、turns 不递增（对齐 :274-276）
		if messagesCharTotal(finalMessages) > CharBudget {
			break
		}
		resp, err := harness.Complete(context.Background(), llm.Request{
			Messages: finalMessages, MaxTokens: maxTokens,
			Tools: allTools, ToolChoice: "auto",
		})
		if err != nil {
			// provider 耗尽 / 调用异常 → budget.error + return nil
			// （ReplayProvider 耗尽返 ErrReplayExhausted 走此支，非 panic）
			budget["error"] = fmt.Sprintf("%v", err)
			budget["rounds"] = exploreRounds
			budget["chars"] = messagesCharTotal(finalMessages)
			return nil, finalMessages, turns, findings, budget, toolLog
		}
		turns++
		if len(resp.ToolCalls) == 0 {
			break // 空响应 → return nil → forced-convergence
		}
		// 先扫一遍：统计 read_calls + 取 finish_call（保序，对齐 :292-300）
		readCalls := 0
		var finishCall *llm.ToolCall
		for _, c := range resp.ToolCalls {
			if ReadToolNames[c.Name] {
				readCalls++
			}
			if c.Name == finishTool {
				fc := c
				finishCall = &fc
			}
		}
		// assistant turn（带 tool_calls）；content nil if Text==""（Python turn.text or None）
		finalMessages = append(finalMessages, map[string]any{
			"role":       "assistant",
			"content":    strOrNil(resp.Text),
			"tool_calls": toToolCallsJSON(resp.ToolCalls),
		})
		// 逐个执行 + append role:tool（保配对）。三类：
		//   finish tool      → 合成 role:tool + continue（不执行/不进 toolLog/seen）
		//   record_finding   → Layer C 短路：合成 {"ok":true,"recorded":true}（不经 executor，
		//                       避免 "unknown tool" 回灌）；append findings；算 progress（reset dup）
		//   read/grep/其它   → Layer B 去重：命中 seen 返缓存 msgContent + steering 后缀；
		//                       未命中执行 + 截断 + 入 seen
		roundHadNewTool := false // 本轮有任一新（非-dup read/grep）工具 → 非 all-dup 轮
		for _, c := range resp.ToolCalls {
			if c.Name == finishTool {
				finalMessages = append(finalMessages, map[string]any{
					"role":         "tool",
					"tool_call_id": c.ID,
					"content":      `{"ok": true, "finished": true}`,
				})
				roundHadNewTool = true // finish = 终止意图 → 非 all-dup 轮 → 走下方 finishCall return，非 streak-break
				continue
			}
			if c.Name == FindingToolName {
				// Layer C: record_finding 短路（不经 executor）。
				findings = append(findings, c.Arguments)
				finalMessages = append(finalMessages, map[string]any{
					"role":         "tool",
					"tool_call_id": c.ID,
					"content":      `{"ok": true, "recorded": true}`,
				})
				roundHadNewTool = true // record_finding = progress → 打断 dup 连续
				continue
			}
			// Layer B: 去重 key = tool + pythonJSON(args)（canonical，确定性）
			dedupKey := c.Name + pythonJSON(c.Arguments)
			var result any
			var msgContent string
			if cached, ok := seenCache[dedupKey]; ok {
				msgContent = cached + "\n[系统提示] 你已对该查询执行相同调用，结果未变。目标可能不在分析源码范围内，请换思路或调用 submit_verdict。"
				result = seenResult[dedupKey]
			} else {
				result = executor.Execute(c.Name, c.Arguments) // defer-recover 兜底,不抛
				msgContent = mustJSON(result)
				if cap, ok := readTruncCap(c.Name); ok && runeLen(msgContent) > cap {
					hint := ""
					if c.Name == "read_file" {
						hint = "；输出已截断，改用 grep_repo 取该正则/字面量全文"
					}
					msgContent = truncateToRunes(msgContent, cap) +
						fmt.Sprintf("...[truncated, was %d chars%s]", runeLen(msgContent), hint)
				}
				seenCache[dedupKey] = msgContent
				seenResult[dedupKey] = result
				roundHadNewTool = true
			}
			finalMessages = append(finalMessages, map[string]any{
				"role":         "tool",
				"tool_call_id": c.ID,
				"content":      msgContent,
			})
			toolLog = append(toolLog, map[string]any{
				"tool":   c.Name,
				"args":   c.Arguments,
				"result": result, // 结构化全量(替 result_excerpt 500 字符碎片);报告直接读,不反解
			})
		}
		if readCalls > 0 { // record_finding 不在 ReadToolNames → 不计
			exploreRounds++
		}
		// Layer B 早收口：本轮有 tool_calls 但无新工具（全 dup）→ streak++；
		// 连续 2 轮 → break → return nil → 上层 ForcedConvergenceProse 收口（judge.go:179）。
		// 空 tool_calls 轮已在 line 156 break；finish 轮走下方 finishCall return。
		if len(resp.ToolCalls) > 0 && !roundHadNewTool {
			consecutiveDupRounds++
		} else {
			consecutiveDupRounds = 0
		}
		if consecutiveDupRounds >= 2 {
			budget["rounds"] = exploreRounds
			budget["chars"] = messagesCharTotal(finalMessages)
			return nil, finalMessages, turns, findings, budget, toolLog
		}
		if finishCall != nil {
			budget["rounds"] = exploreRounds
			budget["chars"] = messagesCharTotal(finalMessages)
			return finishCall.Arguments, finalMessages, turns, findings, budget, toolLog
		}
	}
	// max_rounds 用尽 / char break / 空 tool_calls break → nil 返回
	budget["rounds"] = exploreRounds
	budget["chars"] = messagesCharTotal(finalMessages)
	return nil, finalMessages, turns, findings, budget, toolLog
}

// readTruncCap 返回 read 工具的截断上限（read_file→RawTruncCharsReadFile 8000，
// 其它 read 工具→RawTruncChars 800）。非 read 工具 → (0,false) 不截断
// （record_finding/submit_verdict 永不截）。对齐 _READ_TRUNC_CAPS + RAW_TRUNC_CHARS。
func readTruncCap(name string) (int, bool) {
	if !ReadToolNames[name] {
		return 0, false
	}
	if name == "read_file" {
		return RawTruncCharsReadFile, true
	}
	return RawTruncChars, true
}

// runeLen 计 codepoint（rune）数，拟合 Python len(str)。
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// truncateToRunes 按 rune 切前 n 个（Python str[:n] 按 codepoint），避免多字节截半。
// n >= rune 数时原样返回。
func truncateToRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// strOrNil 拟合 Python `turn.text or None`：空串→nil，非空→string。
func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// toToolCallsJSON 转 ToolCall 列表为 OpenAI 兼容 tool_calls 结构（对齐 :297-299）：
// [{"id","type":"function","function":{"name,"arguments": json.dumps(args)}}]。
// arguments 用 pythonJSON（对齐 Python json.dumps 默认 separators ", "/": " + 不转义 HTML）。
func toToolCallsJSON(calls []llm.ToolCall) []map[string]any {
	out := []map[string]any{}
	for _, c := range calls {
		out = append(out, map[string]any{
			"id":   c.ID,
			"type": "function",
			"function": map[string]any{
				"name":      c.Name,
				"arguments": pythonJSON(c.Arguments),
			},
		})
	}
	return out
}

// mustJSON 序列化为 JSON 字符串，失败返 "{}" 兜底（不应发生）。对齐 Python json.dumps
// 默认 separators (", ", ": ") + 不转义 HTML（Go json.Marshal 默认 SetEscapeHTML(true)
// 转 \u003c/\u003e/\u0026；用 Encoder.SetEscapeHTML(false) 关闭）。
func mustJSON(v any) string {
	return pythonJSON(v)
}

// pythonJSON 序列化 v 为 Python json.dumps 风格 JSON：separators (", ", ": ") +
// ensure_ascii=True（非 ASCII 字符转 \uXXXX）+ 不转义 HTML（<> & 保留）。
// 用于 tool_calls arguments + tool result content（需与 Python golden trace byte-exact 对齐）。
func pythonJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "{}"
	}
	return pythonJSONFormat(bytes.TrimRight(buf.Bytes(), "\n"))
}

// pythonJSONFormat 把 Go compact JSON 格式化为 Python json.dumps 默认风格：
// 1) 字符串外结构字符 ,/: 后加空格（separators ", "/": "）；
// 2) 字符串内非 ASCII 字符转 \uXXXX（ensure_ascii=True）。
// stateful 遍历跟踪 in-string + escape，避免修改字符串内容。
func pythonJSONFormat(b []byte) string {
	var out bytes.Buffer
	inStr, escaped := false, false
	for _, r := range string(b) {
		if escaped {
			out.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			out.WriteRune(r)
			escaped = true
			continue
		}
		if r == '"' {
			inStr = !inStr
			out.WriteRune(r)
			continue
		}
		if inStr {
			if r > 127 {
				if r > 0xFFFF {
					r1, r2 := utf16.EncodeRune(r)
					fmt.Fprintf(&out, "\\u%04x\\u%04x", r1, r2)
				} else {
					fmt.Fprintf(&out, "\\u%04x", r)
				}
			} else {
				out.WriteRune(r)
			}
			continue
		}
		if r == ',' || r == ':' {
			out.WriteRune(r)
			out.WriteByte(' ')
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}
