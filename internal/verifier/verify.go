package verifier

import (
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/poc"
)

// verify.go — port of nodes/verifier.py verify_verdict + _downgrade.

// VerifyVerdict performs the inc27 deterministic probe on the sliced context.
// It reads from sliced but does NOT modify it. Caller may reuse sliced after
// this call. (result is returned by value; sliced is the shared read-only input.)
// Only holds or downgrades to uncertain; never produces a new confident verdict.
func VerifyVerdict(result contract.JudgeResult, sliced map[string]any) contract.JudgeResult {
	// 铁律 RC-A：守卫仅作用于中间变量、原始污点仍达 sink → 守卫无关。
	bypass := detectGuardVariableBypass(sliced)
	if bypass != nil {
		// 仍聚合 guards 供渲染（RC-A 短路不改判决方向，但分析师要看守卫清单）。
		agg := evaluateGuards(sliced, result.Verdict, result.ExploitPayload,
			llmChecks(result), actualTypesLower(result))
		if result.Verdict == "false_positive" {
			downgrade(&result, bypass, sliced, agg["guards"].([]map[string]any),
				"[inc27 净化器探针：守卫仅作用于中间变量、原始污点仍达 sink，原 FP 不成立] ")
		} else {
			// TP / uncertain: bypass confirms guard irrelevant; keep verdict (anti-miss).
			result.Verification = mergeMap(bypass, map[string]any{
				"method": "probe", "action": "bypass_confirmed_tp_kept",
				"original_verdict": result.Verdict, "guards": toAnySlice(agg["guards"].([]map[string]any)),
			})
		}
		return result
	}

	agg := evaluateGuards(sliced, result.Verdict, result.ExploitPayload,
		llmChecks(result), actualTypesLower(result))
	contradiction := agg["contradiction"]
	if contradiction != nil {
		downgrade(&result, contradiction.(map[string]any), sliced, agg["guards"].([]map[string]any),
			"[inc27 净化器探针推翻原判定] ")
	} else {
		// 无矛盾：guards 仍写入 verification 供渲染（不改判决）。
		// status = 支撑原判的守卫状态（FP-kept->effective / TP-kept->bypassable；无守卫->kept）。
		guards := agg["guards"].([]map[string]any)
		gStatuses := []string{}
		for _, g := range guards {
			gStatuses = append(gStatuses, strVal(g, "status"))
		}
		keptStatus := "kept"
		if len(gStatuses) > 0 {
			keptStatus = gStatuses[0]
		}
		if result.Verdict == "false_positive" && containsString(gStatuses, "guard_effective") {
			keptStatus = "guard_effective"
		} else if result.Verdict == "true_positive" && containsString(gStatuses, "guard_bypassable") {
			keptStatus = "guard_bypassable"
		}
		result.Verification = map[string]any{
			"method": "probe", "guards": toAnySlice(guards), "action": "kept",
			"status": keptStatus, "original_verdict": result.Verdict,
			"reason": keptReason(keptStatus, result.Verdict, guards),
		}
	}
	return result
}

// keptReason 给 verify kept 分支(无矛盾、保留原判)补顶层 reason 摘要。
// 实证(2026-08-19 三仓):kept 分支原不设 reason → not_verifiable 时顶层 reason 恒空,
// 报告呈现"空心 TP"(guards[].reason 已富实但顶层无摘要)。本函数只富化解释层,
// 不动 verdict/conf/判决语义(cache key=messages 不含 verification,不波及 verdict_cache;
// GR-6:不冻结 uncertain——缓存本就排除 uncertain,reason 是稳定判决后的解释)。
//
// T3-supplement(2026-08-19):原 T3 漏了 "kept" 态(guards==[] 时 keptStatus 保留初始
// "kept")。cce1a7fa 实证:TP9 + guards=[] → keptReason 走 default 返空 → 又一个空心 TP。
// 补 kept 态且 verdict-aware(与 bypassable→TP/effective→FP 同形):guards=[] 是可核实
// 事实(切片内确无守卫),非编造 → GR-8 合规。
func keptReason(keptStatus, verdict string, guards []map[string]any) string {
	switch keptStatus {
	case "not_verifiable":
		// 复用 guards.go:161 的措辞谱("决定性守卫不可验证(执行器不在切片/守卫在切片外)")。
		return "决定性守卫不可验证(执行器不在切片 / 守卫在切片外或非本案污点),保留原判"
	case "guard_bypassable":
		return "守卫可绕过,保留原判 TP"
	case "guard_effective":
		return "守卫有效,保留原判 FP"
	case "kept":
		// guards==[] (keptStatus 保留初始 "kept" 当且仅当切片内无守卫)。
		// verdict-aware 后缀:TP=无守卫证据(支持 TP);FP/uncertain 的理由在 reasoning 而非守卫。
		return "切片内无可评估守卫(无守卫证据),保留原判 " + verdictCN(verdict)
	default:
		return "" // 未识别 status:不编(GR-8)
	}
}

// verdictCN 把 verdict 枚举映射成报告 reason 用的短标(与 guard_bypassable→"TP" /
// guard_effective→"FP" 的口径一致)。未识别 verdict 原样返回(不编)。
func verdictCN(v string) string {
	switch v {
	case "true_positive":
		return "TP"
	case "false_positive":
		return "FP"
	default:
		return v // uncertain 或其他原样
	}
}

// downgrade ports nodes/verifier.py:_downgrade. Fail-open downgrade:
// verdict→uncertain, conf≤4, verification annotated with guards. RC-A-ext:
// FP falsified→uncertain has no exploit_payload, fill attack_request from
// the contradiction's concrete bypass witness. Only fills attack_request.
func downgrade(result *contract.JudgeResult, contradiction map[string]any,
	sliced map[string]any, guards []map[string]any, rationalePrefix string) {
	original := result.Verdict
	result.Verification = mergeMap(contradiction, map[string]any{
		"method": "probe", "action": "downgraded_to_uncertain",
		"original_verdict": original, "guards": toAnySlice(guards),
	})
	result.Verdict = "uncertain"
	if result.Confidence > 4 {
		result.Confidence = 4
	}
	// (A) UX：cryptic [inc27...] tag 后补人话降级摘要——点名原判、矛盾原因、
	// 涉及守卫（code @ location + per-guard reason）。修前 reasoning 只 tag + LLM
	// 原文，分析师看不出"降了什么、哪几个守卫、各为什么"。每条降级（合法/假）
	// 都受益，给 Crack C 回归提供可读基线。不动判决语义（只富化文本）。
	result.Reasoning = rationalePrefix + downgradeSummary(original, contradiction, guards) + result.Reasoning
	if result.AttackRequest == nil {
		if witness, ok := contradiction["witness"].(string); ok && witness != "" {
			if req := poc.BuildBypassPayload(sliced, witness); req != nil {
				result.AttackRequest = req
			}
		}
	}
}

// downgradeSummary 构造一句人话"为什么降级"指针。点名原判 verdict + 矛盾原因，
// 并指向下方「否证结果」卡查看涉及守卫与否证代码——守卫逐条详情（code @ location
// + per-guard reason）现归否证卡结构化渲染（合并重设计），reasoning 不再背 dump。
// 不动 verdict/conf/verification 结构字段，只产文本。guards 参数保留以备未来扩展，
// 当前不逐条拼。
func downgradeSummary(originalVerdict string, contradiction map[string]any, guards []map[string]any) string {
	var b strings.Builder
	b.WriteString("【已降级 uncertain】原判 ")
	b.WriteString(originalVerdict)
	b.WriteString("。")
	if reason := strVal(contradiction, "reason"); reason != "" {
		b.WriteString(reason)
		b.WriteString(" ")
	}
	b.WriteString("涉及守卫与否证代码见下方「否证结果」。")
	_ = guards // 守卫详情已结构化进 verification.guards（否证卡渲染），此处不再逐条拼
	return b.String()
}

// llmChecks ports Python `result.decisive_checks or ([result.decisive_check] if result.decisive_check else None)`.
func llmChecks(r contract.JudgeResult) []map[string]any {
	if len(r.DecisiveChecks) > 0 {
		return r.DecisiveChecks
	}
	if r.DecisiveCheck != nil {
		return []map[string]any{r.DecisiveCheck}
	}
	return nil
}

func actualTypesLower(r contract.JudgeResult) []string {
	out := []string{}
	for _, t := range r.ActualVulnerabilityTypes {
		out = append(out, strings.ToLower(t))
	}
	return out
}

func mergeMap(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// toAnySlice converts a []map[string]any to []any. The parity golden is loaded
// via json.Unmarshal into a generic map[string]any, where nested arrays become
// []any (NOT []map[string]any). reflect.DeepEqual is type-strict, so the
// verification.guards slice must be []any to match the golden's shape — both
// marshal to the same JSON, but DeepEqual distinguishes the element types.
// (Python compares dicts by content, so this is purely a Go typing artifact.)
func toAnySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}
