package judge

import (
	"context"

	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
	"appsecgo/internal/llm"
	"appsecgo/internal/prompts"
)

// falsify.go — 移植 appsec/nodes/judge.py:982-1078 的 falsify（VERIFY_MODE=adversarial）。
// VerifyVerdict 后 LLM 扮攻击者证利用，证不出降 uncertain，证得出保持/降级按矩阵。永不升 TP。
//
// fail-open 链路：provider error / exploitable=false → 降 uncertain（conf≤4，method=falsify）。
// parse 失败 → 保持原判（不降级，对齐 Python 竞品坑#3：不可解析不删"仅无法验证"的）。

// isReclassified 移植 _is_reclassified (judge.py:947-955)。
// actualTypes 含非 declared 类型 → true（被守卫发现埋藏类型）。
func isReclassified(result contract.JudgeResult, declared string) bool {
	if len(result.ActualVulnerabilityTypes) == 0 {
		return false
	}
	for _, t := range result.ActualVulnerabilityTypes {
		if t != declared {
			return true
		}
	}
	return false
}

// irOutcome 移植 _ir_outcome：读 result.Verification["dynamic"]["outcome"]。
// nil=未跑 dynamic_verify（DYNAMIC_VERIFY_MODE=off），falsify_tp gate 通过（None 语义=未决）。
func irOutcome(result contract.JudgeResult) *string {
	if result.Verification == nil {
		return nil
	}
	dyn, _ := result.Verification["dynamic"].(map[string]any)
	if dyn == nil {
		return nil
	}
	oc, _ := dyn["outcome"].(string)
	if oc == "" {
		return nil
	}
	return &oc
}

// falsifyDowngrade 移植 _falsify_downgrade (judge.py:1024-1030)。
// 整替换 verification（method=falsify），降 uncertain + conf≤4。
func falsifyDowngrade(result *contract.JudgeResult, rationale string) {
	result.Verification = map[string]any{
		"method":           "falsify",
		"action":           "downgraded_to_uncertain",
		"original_verdict": result.Verdict,
		"rationale":        rationale,
	}
	result.Verdict = "uncertain"
	if result.Confidence > 4 {
		result.Confidence = 4
	}
}

// falsifyTpDowngrade 移植 _falsify_tp_downgrade (judge.py:1033-1045)。
// MERGE 进现有 verification（保 IR dynamic 子键 provenance），降 uncertain + conf≤4。
func falsifyTpDowngrade(result *contract.JudgeResult, rationale string) {
	overlay := map[string]any{
		"method":           "falsify",
		"action":           "downgraded_to_uncertain",
		"original_verdict": result.Verdict,
		"rationale":        rationale,
	}
	if result.Verification == nil {
		result.Verification = overlay
	} else {
		for k, v := range overlay {
			result.Verification[k] = v
		}
	}
	result.Verdict = "uncertain"
	if result.Confidence > 4 {
		result.Confidence = 4
	}
}

// parseFalsifyJSON 解析 LLM 返回的 {exploitable, exploit_path, rationale}。
// 复用 ParseJudgeOutput 三层解析（falsify JSON 是 judge schema 子集）。
// 返 nil 表示解析失败（调用方保持原判，不降级——对齐 Python 竞品坑#3）。
func parseFalsifyJSON(raw string) map[string]any {
	data, err := ParseJudgeOutput(raw)
	if err != nil {
		return nil
	}
	return data
}

// Falsify 移植 _falsify dispatch (judge.py:876-882)。
// gate VERIFY_MODE=adversarial → 按 isReclassified 分发到两路径。
// 非 reclassified + 非 (TP && IR 未决) → 原样返回。
func Falsify(result contract.JudgeResult, sliced map[string]any, model string,
	provider llm.Provider, reg *cwereg.Registry, verifyMode string) contract.JudgeResult {
	if verifyMode != "adversarial" {
		return result
	}
	declared, _ := sliced["vulnerability_type"].(string)
	if isReclassified(result, declared) {
		return falsifyReclassified(result, sliced, model, provider, reg)
	}
	if result.Verdict == "true_positive" {
		oc := irOutcome(result)
		if oc == nil || *oc == "inconclusive" {
			return falsifyTp(result, sliced, model, provider, reg)
		}
	}
	return result
}

// falsifyReclassified 移植 falsify_reclassified (judge.py:982-1021)。
// 被重判（actualTypes 含非 declared）→ LLM 证利用 → 证不出/mismatch 降 uncertain / 证得出保持。
func falsifyReclassified(result contract.JudgeResult, sliced map[string]any, model string,
	provider llm.Provider, reg *cwereg.Registry) contract.JudgeResult {
	declared, _ := sliced["vulnerability_type"].(string)
	actualTypes := result.ActualVulnerabilityTypes
	messages := prompts.BuildFalsifyMessages(sliced, actualTypes, declared, reg)
	resp, err := provider.Complete(context.Background(), llm.Request{
		Messages: messages, MaxTokens: llmMaxTokens, Tools: nil,
	})
	if err != nil {
		falsifyDowngrade(&result, "provider_error")
		return result
	}
	data := parseFalsifyJSON(resp.Text)
	if data == nil {
		return result // parse 失败 → 不降级（对齐 Python 竞品坑#3）
	}
	exploitable, _ := data["exploitable"].(bool)
	if !exploitable {
		falsifyDowngrade(&result, "not_exploitable")
		return result
	}
	// exploit_path 保留（如果有）
	mismatch := len(result.TypeMismatchTypes) > 0 || isReclassified(result, declared)
	if mismatch {
		falsifyDowngrade(&result, "mismatch_exploitable")
		if ep, _ := data["exploit_path"].(string); ep != "" && result.AttackRequest == nil {
			result.AttackRequest = &ep
		}
		return result
	}
	return result // 证得出 + 无 mismatch → 保持原判
}

// falsifyTp 移植 falsify_tp (judge.py:1048-1078)。
// 自信 TP（非重判，actual==[declared]）+ IR 未决 → LLM 造 PoC → 证不出降 uncertain（保 IR 子键 MERGE）/ 证得出保持。
func falsifyTp(result contract.JudgeResult, sliced map[string]any, model string,
	provider llm.Provider, reg *cwereg.Registry) contract.JudgeResult {
	declared, _ := sliced["vulnerability_type"].(string)
	actualTypes := result.ActualVulnerabilityTypes
	if len(actualTypes) == 0 {
		actualTypes = []string{declared}
	}
	messages := prompts.BuildFalsifyMessages(sliced, actualTypes, declared, reg)
	resp, err := provider.Complete(context.Background(), llm.Request{
		Messages: messages, MaxTokens: llmMaxTokens, Tools: nil,
	})
	if err != nil {
		falsifyTpDowngrade(&result, "provider_error")
		return result
	}
	data := parseFalsifyJSON(resp.Text)
	if data == nil {
		return result // parse 失败 → 不降级
	}
	exploitable, _ := data["exploitable"].(bool)
	if !exploitable {
		falsifyTpDowngrade(&result, "not_exploitable")
		return result
	}
	return result // exploitable → 保持 TP（不升 conf）
}
