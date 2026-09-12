package agentic

import (
	"context"
	"strconv"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/funcdistill"
	"appsecgo/internal/llm"
	"appsecgo/internal/prompts"
	"appsecgo/internal/slice"
)

// enrich.go — 移植自 appsec/nodes/agentic_enrich.py（ADR-0005 premium tier）。
//
// 让 LLM 通过工具循环决定拉取哪些 in-repo callee body 进切片，补 deterministic 漏的
// 守卫/跨文件事实。model-agnostic（只用 provider.Complete tool 路径）。
//
// 与 enrich.py deterministic 层（internal/slice/enrich.go）的关系：
//   - deterministic 先兜底（EnrichSlice+EnrichGuardCallees），agentic 只做增补
//   - agentic 失败 fail-open 保留 deterministic 结果（铁律 D）
//
// 蒸馏缓存（FUNC_DISTILL_MODE / 集群5）不在本期范围，后续 task。

// MaxIterations 移植 MAX_ITERATIONS (agentic_enrich.py:23)：enrich loop 上限。
// 区别于 RunPlanSolveReActLoop 的 MaxRounds=10（plan-solve 双上限版，judge explore 用）。
// Python 注释："不动老 _run_agentic_loop（enrich 那条路仍用它，[PIT] 隔离）"。
const MaxIterations = 6

// enrichSystemPrompt 移植 _SYSTEM (agentic_enrich.py:126-135)。逐字中文 + UntrustedMaterial。
var enrichSystemPrompt = "你为安全判定器收集「刚好够用」的上下文。你拿到一个污点路径上的函数。" +
	"某些被调用的函数（例如共享的守卫/净化器）可能未被展示。用 search_definitions/read_function " +
	"查看那些可能净化或拦截数据流的被调用函数，然后用 in-repo 中值得纳入的函数调用 finish。" +
	"只拉与判定相关的；不要拉无关的辅助函数。\n\n" +
	"如果某 callee 的净化/拦截行为依赖非 .java 文件的事实（如 yml/properties 里的 allowlist），" +
	"可用 read_file 读取该文件核证；grep_repo 可定位某 id/正则出现在哪个文件。注意：MyBatis mapper " +
	"的 ${} 拼接 vs #{} 参数化由判决阶段的 reachable_sinks 工具带出（sink 结果含 sql_text/" +
	"concat_params/safe_params，一眼看出拼接 vs 参数化），enrich 阶段无需 read_file 读 XML；" +
	"taint_path 上的 XML 跳已在切片里展示，不重复读。\n\n" +
	prompts.UntrustedMaterial

// enrichUserPrompt 移植 _user_prompt (agentic_enrich.py:138-145)。
func enrichUserPrompt(sliced *contract.SlicedContext) string {
	var b strings.Builder
	b.WriteString("## 发现：")
	b.WriteString(sliced.VulnerabilityType)
	b.WriteString(" entry=")
	b.WriteString(sliced.EntryPointSignature)
	for _, h := range sliced.Hops {
		fence := prompts.SafeCodeFence(h.FunctionBody)
		b.WriteString("\n\n### ")
		b.WriteString(h.FilePath)
		b.WriteString(":")
		b.WriteString(strconv.Itoa(h.LineRange[0]))
		b.WriteString(" fn=")
		b.WriteString(h.FunctionName)
		b.WriteString(" taint_var=")
		b.WriteString(h.TaintVariable)
		b.WriteString("\n")
		b.WriteString(fence)
		b.WriteString("java\n")
		b.WriteString(h.FunctionBody)
		b.WriteString("\n")
		b.WriteString(fence)
	}
	b.WriteString("\n\n查看可能净化/守卫该数据流的被调用函数，然后调用 finish。")
	return b.String()
}

// runAgenticLoop 移植 _run_agentic_loop (agentic_enrich.py:190-229)。
// 简单 raw 累积循环（maxIters=6），与 RunPlanSolveReActLoop（plan-solve 双上限版）PIT 隔离。
// 无 char_budget / 无 read 截断 / 无 findings / 无 tool_log。
//
// 配对不变量（2026-07-28）：每个 assistant tool_call 必须紧跟 role:tool 结果（含 finish），
// 否则悬空 → Anthropic/OpenAI 400。finish 也 append role:tool（result={"ok":true}）。
// 遍历完该轮所有 tool_calls 后才判断 break（非 finish 立即 break，保同轮多 tool 配对）。
//
// 返 (finishArgs|nil, turns, error, finalMessages)。error != nil → 上层 fail-open。
// 返回 finalMessages（Python 原地 mutate，Go 需显式返）供测试验证配对。
func runAgenticLoop(messages []map[string]any, provider llm.Provider, model string,
	tools []map[string]any, executor *ToolExecutor, finishToolName string,
	maxIters, maxTokens int) (finishArgs map[string]any, turns int, err error,
	finalMessages []map[string]any) {

	finalMessages = append([]map[string]any{}, messages...) // copy，不 mutate 调用方
	for i := 0; i < maxIters; i++ {
		resp, e := provider.Complete(context.Background(), llm.Request{
			Messages: finalMessages, MaxTokens: maxTokens,
			Tools: tools, ToolChoice: "auto",
		})
		if e != nil {
			return nil, turns, e, finalMessages
		}
		turns++
		if len(resp.ToolCalls) == 0 {
			return nil, turns, nil, finalMessages // prose/gave up
		}
		// assistant turn（含全部 tool_calls）
		finalMessages = append(finalMessages, map[string]any{
			"role":       "assistant",
			"content":    strOrNil(resp.Text),
			"tool_calls": toToolCallsJSON(resp.ToolCalls),
		})
		// 遍历全部 tool_calls：finish 捕获 args（合成 role:tool），其余 executor.Execute。
		// 不 finish 立即 break——遍历完才判 break（保同轮多 tool 配对完整）。
		for _, c := range resp.ToolCalls {
			var result any
			if c.Name == finishToolName {
				finishArgs = c.Arguments
				result = map[string]any{"ok": true} // finish 不经 executor
			} else {
				result = executor.Execute(c.Name, c.Arguments) // 内部 defer-recover
			}
			finalMessages = append(finalMessages, map[string]any{
				"role":         "tool",
				"tool_call_id": c.ID,
				"content":      mustJSON(result),
			})
		}
		if finishArgs != nil {
			return finishArgs, turns, nil, finalMessages
		}
	}
	return nil, turns, nil, finalMessages // maxIters 用尽
}

// maxEnrichTokens 对齐 Python config.LLM_MAX_TOKENS（enrich loop 的 max_tokens）。
// Python 传 config.LLM_MAX_TOKENS；Go 暂用常量（config 未暴露 LLM_MAX_TOKENS，后续可接 config）。
const maxEnrichTokens = 2000

// AgenticEnrichSlice 移植 agentic_enrich_slice (agentic_enrich.py:346-368)。
// 跑 bounded tool-use loop，模型用 finish 列出要纳入的 callee → AppendCalleeHops 内联。
// fail-open：defer recover → result = sliced（保留 deterministic 兜底，铁律 D）。
// 命名返回值 result（defer recover 修改返回值所需）。
func AgenticEnrichSlice(sliced *contract.SlicedContext, index *slice.RepositoryIndex,
	provider llm.Provider, model string, store *funcdistill.FunctionSummaryStore) (result *contract.SlicedContext) {
	result = sliced // 默认返回（fail-open 保底）
	defer func() {
		if r := recover(); r != nil {
			result = sliced // panic → 保留 deterministic 兜底
		}
	}()
	if !provider.SupportsTools() {
		return // caller should gate, but never hard-fail
	}
	messages := []map[string]any{
		{"role": "system", "content": enrichSystemPrompt},
		{"role": "user", "content": enrichUserPrompt(sliced)},
	}
	exec := NewToolExecutor(index, provider, model, store)
	finishArgs, _, err, _ := runAgenticLoop(
		messages, provider, model, enrichTools, exec, "finish", MaxIterations, maxEnrichTokens)
	if err != nil || finishArgs == nil {
		return // 不增补
	}
	include, _ := finishArgs["include"].([]any)
	items := []slice.CalleeItem{}
	for i, ref := range include {
		if i >= slice.MaxEnrichHops {
			break
		}
		m, _ := ref.(map[string]any)
		fp, _ := m["file_path"].(string)
		fn, _ := m["function_name"].(string)
		fd := resolveRef(index, fp, fn)
		if fd != nil {
			items = append(items, slice.CalleeItem{ExpandedFrom: "agentic", FunctionDef: *fd})
		}
	}
	slice.AppendCalleeHops(sliced, items)
	return sliced
}

// EnrichForJudge 移植 enrich_for_judge (agentic_enrich.py:148-180)。
// 编排入口：gate 判断 + deterministic 兜底 + agentic 增补 + fail-open。
//
// index==nil → return；agentic && SupportsTools → 先 slice.EnrichSlice+EnrichGuardCallees
// 兜底 + try AgenticEnrichSlice fail-open；else → 纯 deterministic。
//
// 放 agentic 包（非 slice 包）：依赖方向 agentic→slice+agentic→llm 已存在，无环。
// slice.EnrichForJudge 降为 deterministic-only（保留供测试/向后兼容，pipeline 不再调）。
func EnrichForJudge(sliced *contract.SlicedContext, index *slice.RepositoryIndex,
	provider llm.Provider, model, enrichMode, eagerGuardCallees string,
	store *funcdistill.FunctionSummaryStore) *contract.SlicedContext {
	if index == nil {
		return sliced
	}
	if enrichMode == "agentic" && provider.SupportsTools() {
		// 确定性兜底（service 方法等必进切片，不靠 LLM）
		slice.EnrichSlice(sliced, index)
		// deeper-callee arc 接线（2026-08-28）：CWE-915/862 state-mutating transitive walk，
		// 非 matching CWE no-op（gateForCwe 缺省 taint,1）→ golden-safe。arc 见 2026-08-13-deeper-callee-slicing-design.md。
		slice.EnrichStateMutatingCallees(sliced, index)
		slice.EnrichGuardCallees(sliced, index, eagerGuardCallees)
		// agentic 增补（fail-open：内部 recover 保留 deterministic 结果）
		AgenticEnrichSlice(sliced, index, provider, model, store)
		return sliced
	}
	// 纯 deterministic
	slice.EnrichSlice(sliced, index)
	// deeper-callee arc 接线（同上，CWE-915/862 transitive walk，非 matching no-op）
	slice.EnrichStateMutatingCallees(sliced, index)
	slice.EnrichGuardCallees(sliced, index, eagerGuardCallees)
	return sliced
}
