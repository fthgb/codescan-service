package judge

import (
	"context"
	"strings"

	"appsecgo/internal/agentic"
	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
	"appsecgo/internal/funcdistill"
	"appsecgo/internal/llm"
	"appsecgo/internal/slice"
	"appsecgo/internal/taintbridge"
	"appsecgo/internal/verifier"
)

// rejudge.go — 移植 appsec/nodes/judge.py:371-475 的 _rejudge_* 三策略。
// 守卫拒判（decisive_fact_unknown / bare_fp_buries_actual）后 LLM 重判自修复。
// gate 默认 off（DECISIVE_FACT_REJUDGE_MODE），on 时 judge.go 接缝调 RejudgeContractRejection。
//
// fail-open 链路：任何失败（loop error / provider error / fact 仍未知）→ 保留守卫 uncertain，
// 绝不崩 pipeline。rejudge 结果不再触发 rejudge（防无限循环）。

// contractRejected 判守卫是否拒判（Python result.contract_rejected 等价）。
// Go 无 ContractRejected 字段，用 FailReason 前缀判断：decisive_fact_unknown: 或 bare_fp_buries_actual:。
// gate 和 dispatch 都读此函数，不重复前缀逻辑。
// 注：reachable_callee_demoted: 前缀随 Crack D guard 一同 revert（2026-08-12 实证后）。
func contractRejected(result contract.JudgeResult) bool {
	if result.FailReason == nil {
		return false
	}
	fr := *result.FailReason
	return strings.HasPrefix(fr, "decisive_fact_unknown:") ||
		strings.HasPrefix(fr, "bare_fp_buries_actual:")
}

// RejudgeContractRejection 移植 _rejudge_contract_rejection (judge.py:463-475)。
// 按 fail_reason 前缀分发：decisive_fact_unknown→rejudgeDecisiveFact；bare_fp→rejudgeBareFp；其他→原样。
// 所有策略 fail-open（error/未知 → 保留守卫 uncertain）。
//
// 参数：
//   - result: 守卫拒判后的 result（含 FailReason）
//   - origVerdict/origConf/origDisp: 第一次 LLM 判决（用于一致性校验/恢复）
//   - finalMessages: 第一次 explore loop 的完整对话历史（Python messages mutate 后等价物）
//   - sliced: 切片（rejudge 会 mutate：promote/refresh）
//   - model/provider/repoIndex/summaryStore: LLM + repo infra（复用 funcdistill store）
//   - trace: 取证轨迹（rejudge 的 tool_log 追加于此）
//   - reg: CWE 注册表（守卫重跑用）
func RejudgeContractRejection(result contract.JudgeResult, origVerdict string, origConf float64,
	origDisp string, finalMessages []map[string]any, sliced map[string]any, model string,
	provider llm.Provider, repoIndex *slice.RepositoryIndex,
	summaryStore *funcdistill.FunctionSummaryStore, trace map[string]any,
	reg *cwereg.Registry, engine taintbridge.EngineQuerier) contract.JudgeResult {

	if result.FailReason == nil {
		return result
	}
	fr := *result.FailReason
	switch {
	case strings.HasPrefix(fr, "decisive_fact_unknown:"):
		return rejudgeDecisiveFact(result, origVerdict, origConf, origDisp,
			finalMessages, sliced, model, provider, repoIndex, summaryStore, trace, reg, engine)
	case strings.HasPrefix(fr, "bare_fp_buries_actual:"):
		return rejudgeBareFp(result, origVerdict, origConf, origDisp,
			finalMessages, sliced, model, provider, repoIndex, summaryStore, trace, reg)
	default:
		return result
	}
}

// rejudgeDecisiveFact 移植 _rejudge_decisive_fact (judge.py:371-416)，去 SQLi（spec §4(c)）。
// 重跑 RunPlanSolveReActLoop（plan-solve loop，非 enrich 的 agentic loop）用 fact-agnostic nudge
// 引导 LLM 用 get_callees/search_definitions/read_function/reachable_sinks 核证 required 决定性事实；
// promote + 按 fact 分派 refresh（forward_reachable→RefreshForwardReachable，sink_param_style→
// RefreshSinkParamStyle）后，逐 fact 查 resolved（forward_reachable 读 struct 重算 MapForwardReachable
// D5，其余读 token）。全 resolved → BuildJudgeResult 恢复；任一仍未知 → 保留 uncertain。
// fail-open：finishArgs==nil / parse 失败 / 任一 fact 仍 unknown → 原样返回。不重跑守卫
// （judge.go:511 后走 verifier.VerifyVerdict），不无限循环。
func rejudgeDecisiveFact(result contract.JudgeResult, origVerdict string, origConf float64,
	origDisp string, finalMessages []map[string]any, sliced map[string]any, model string,
	provider llm.Provider, repoIndex *slice.RepositoryIndex,
	summaryStore *funcdistill.FunctionSummaryStore, trace map[string]any,
	reg *cwereg.Registry, engine taintbridge.EngineQuerier) contract.JudgeResult {

	vulnType, _ := sliced["vulnerability_type"].(string)
	// required 决定性事实清单（与守卫同源 requiredDecisiveFacts；铁律 B 单一权威：
	// rejudge 须解决的 = 守卫查的，两份复制会漂移 → 闭环失灵）
	required := requiredDecisiveFacts(reg, vulnType, result.ActualVulnerabilityTypes)
	// nudge message（fact-agnostic，spec §4(c) :119：去 ${}/#{}/reachable_sinks/mapper 写死，
	// 改列 required 清单 + 工具箱提示。换 sink 须 0 改 prompt——铁律 D 抗绑定）
	nudge := map[string]any{
		"role": "user",
		"content": "你之前判了 " + origDisp + "，但决定性事实 [" + strings.Join(required, ", ") +
			"] 未锚定（切片未给出可核实证据）。请用工具核证：get_callees（查 callee 链可达性）/" +
			"search_definitions（按名查定义是否在仓内）/ read_function（读函数体）/ reachable_sinks（查 sink 参数化形态）。" +
			"源码内未收集的 callee → 探其定义；仓外不可达 → 按 uncertain 提交。" +
			"然后调用 submit_verdict 给出最终判定。若仍无法核证，按 uncertain 提交。",
	}
	// mutation safety：copy finalMessages 再追加 nudge（Python list+ 天然新建，Go append 可能复用底层数组）
	rejudgeMsgs := append([]map[string]any{}, finalMessages...)
	rejudgeMsgs = append(rejudgeMsgs, nudge)

	repoRoot := ""
	if repoIndex != nil {
		repoRoot = repoIndex.RepoRoot()
	}
	exec := agentic.NewToolExecutor(repoIndex, provider, model, summaryStore)
	exec.SetEngineQuery(engine) // NEW: nil → 引擎工具 off（零回归）
	// 重跑 plan-solve loop（非 enrich 的 agentic loop），finish_tool=submit_verdict
	va2, _, turns2, _, _, toolLog2 := agentic.RunPlanSolveReActLoop(
		rejudgeMsgs, provider, model, exec.JudgeTools(), exec, vulnType, "submit_verdict", llmMaxTokens)

	// finishArgs==nil（budget 用尽/char break/error）→ fail-open 保留守卫 uncertain
	if va2 == nil {
		return result
	}
	// 取证轨迹落 trace（fail-open 也保，对齐 agentic_enrich.py:320-324）
	if tl, ok := trace["tool_log"].([]map[string]any); ok {
		trace["tool_log"] = append(tl, toolLog2...)
	} else {
		trace["tool_log"] = toolLog2
	}
	if tt, ok := trace["tool_turns"].(int); ok {
		trace["tool_turns"] = tt + turns2
	} else {
		trace["tool_turns"] = turns2
	}
	// 重跑 promote（会话里新的 read_file 结果提升进切片）
	agentic.PromoteAgenticXmlToSlice(sliced, toolLog2, repoRoot)
	// fact 分派 refresh（spec §4(c) :121）+ fact 决断（:120）：按 required 事实分派刷新器，
	// 逐个查是否 resolved（!= "unknown" && != ""）。
	//   forward_reachable → RefreshForwardReachable（drain Uncertain→Definitive，**不回写 token** D5）；
	//     fact 决断读 struct 重算 slice.MapForwardReachable（不读 token，不污染 guard.go:54）。
	//   sink_param_style → RefreshSinkParamStyle（保留，re-classify 写 token）；fact 决断读 token。
	//   其它（未来事实）暂无 refresh，只读既有 token。
	df, _ := sliced["decisive_facts"].(map[string]any)
	resolved := true
	for _, f := range required {
		switch f {
		case "forward_reachable":
			agentic.RefreshForwardReachable(sliced, toolLog2)
		case "sink_param_style":
			verifier.RefreshSinkParamStyle(sliced)
		}
		var val string
		if f == "forward_reachable" {
			// D5：rejudge 读 struct 不读 token；RefreshForwardReachable drain 后重算
			if fr, ok := sliced["forward_reachable"].(map[string]any); ok {
				val = slice.MapForwardReachable(fr)
			}
		} else {
			val, _ = df[f].(string)
		}
		if val == "unknown" || val == "" {
			resolved = false
			break
		}
	}
	// 任一仍未知 → 接受守卫的 uncertain（fail-open，不无限循环）
	if !resolved {
		return result
	}
	// 全 resolved → 用新 va2 调 BuildJudgeResult 恢复 LLM 判决（rejudgeDecisiveFact 不重跑守卫：
	// judge.go:511 后只走 verifier.VerifyVerdict，非 EnforceDecisiveFactKnown——故 stale token 无害）
	newResult, err := BuildJudgeResult(va2, sliced, model, maxConfidence, jsonString(va2), reg)
	if err != nil {
		return result // parse 失败 → fail-open
	}
	newResult.MissingInfo = result.MissingInfo
	return newResult
}

// rejudgeBareFp 移植 _rejudge_bare_fp (judge.py:419-460)。
// 单工具 VerdictTool 单轮质问矛盾 → BuildJudgeResult → 重跑守卫。fail-open。
//
// 注：Python judge.py:435 用 tool_choice="auto"（Fix2，2026-07-28 弃用 forced dict 改 auto+prose，
// 因 forced 形状 provider 不兼容；agentic_enrich.py/decisive_facts.py 同步）。ToolChoice 保持
// string——judge/agentic 均不再用 dict。2026-09-07 与 agenticJudge forced-convergence 同口径
// （spec 2026-09-07-prompt-noise-convergence-taintsource-design §三.1）：首选 "required"（OpenAI
// 原生合法值、anthropic 走 {"type":"required"} 且 thinking-on 自动降级——非 Python 当年弃用的
// dict 形状），唯一工具即 submit_verdict → 机制上必回工具调用；required 被网关拒 → 退 "auto" 重试。
func rejudgeBareFp(result contract.JudgeResult, origVerdict string, origConf float64,
	origDisp string, finalMessages []map[string]any, sliced map[string]any, model string,
	provider llm.Provider, repoIndex *slice.RepositoryIndex,
	summaryStore *funcdistill.FunctionSummaryStore, trace map[string]any,
	reg *cwereg.Registry) contract.JudgeResult {

	// nudge message（逐字移植 judge.py:421-425）
	nudge := map[string]any{
		"role": "user",
		"content": "Bare FP 拒判：你判了 " + origDisp + " 但 sink 不在切片无法核证。" +
			"这是真实 FP 还是真有漏洞被 FP 漏报？调用 submit_verdict 给最终判定。",
	}
	// mutation safety：copy finalMessages 再追加 nudge
	rejudgeMsgs := append([]map[string]any{}, finalMessages...)
	rejudgeMsgs = append(rejudgeMsgs, nudge)

	complete := func(choice string) (llm.Response, error) {
		return provider.Complete(context.Background(), llm.Request{
			Messages:   rejudgeMsgs,
			Tools:      []map[string]any{agentic.VerdictTool},
			ToolChoice: choice,
			MaxTokens:  llmMaxTokens,
		})
	}
	resp, err := complete("required")
	if err != nil {
		resp, err = complete("auto")
	}
	if err != nil || len(resp.ToolCalls) == 0 {
		return result // fail-open
	}
	// 取第一个 submit_verdict 调用
	var va map[string]any
	for _, c := range resp.ToolCalls {
		if c.Name == "submit_verdict" {
			va = c.Arguments
			break
		}
	}
	if va == nil {
		return result // fail-open
	}
	// 用新判决调 BuildJudgeResult
	newResult, err := BuildJudgeResult(va, sliced, model, maxConfidence, jsonString(va), reg)
	if err != nil {
		return result // parse 失败 → fail-open
	}
	newResult.MissingInfo = result.MissingInfo
	// 重跑守卫（rejudge 结果可能再被拒，但保持新判决而非无限循环）
	newResult = EnforceDecisiveFactKnown(newResult, sliced, reg)
	newResult = EnforceNoBareFp(newResult, sliced, reg)
	return newResult
}

// rejudgeReachableCallee (Crack D rejudge remedy) reverted on 2026-08-12 实证后
// together with EnforceReachableSinkClaim. See memory crack-d-reachable-callee-empirical.
