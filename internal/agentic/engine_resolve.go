package agentic

import "appsecgo/internal/taintbridge"

// resolveMethodKey 消歧闭环（跨 reachable_sinks/trace_to_sources 共用，契约 §6）。
// 入参 args: function_name(必)、file_path(可选,消歧)、method_key(可选,重载回传)。
// 返 (mk, amb, found):
//   - mk 非空 → 直用(系统句柄回传),found=true,amb=nil
//   - fn → engine.ResolveMethodKey(fn,file_path,mk):
//     err → amb={"error":err.Error()},found=true（诚实透传，不伪装 ambiguous）
//     Found=true → 用其 MethodKey,amb=nil
//     Ambiguous=true → amb=ambiguous map(候选必带 file_path+method_key),found=true
//     else → found=false
func (e *ToolExecutor) resolveMethodKey(args map[string]any) (mk string, amb any, found bool) {
	fn, _ := args["function_name"].(string)
	fp, _ := args["file_path"].(string)
	// Phase 1 (root-2 裸名消歧): LLM 不传 file_path → 用 alert sink file 兜底消歧 (不改逻辑,
	// ResolveMethodKey 既有层 2 路径后缀/层 3 类名 stem 自然生效)。LLM 传 file_path 优先 LLM 的 (不覆盖)。
	if fp == "" && e.alertSinkFile != "" {
		fp = e.alertSinkFile
	}
	mk, _ = args["method_key"].(string)
	if mk != "" {
		return mk, nil, true // 系统句柄回传,不解析不猜
	}
	if fn == "" {
		return "", nil, false
	}
	if e.engine == nil {
		return "", nil, false // 引擎 off → 视作无命中(调用方走 unavailable 已在前置,但保险)
	}
	res, err := e.engine.ResolveMethodKey(fn, fp, mk)
	if err != nil {
		// 引擎错误→诚实透传 error（不伪装成 ambiguous 空 candidate 致 AI 误判/loop；
		// 与 reachable_sinks/trace_to_sources 下游 err.Error() 透传一致，GR-8 真相即判据）。
		// 走 amb 通道(found=true)：调用方 `amb != nil → return amb` 原样透出，不跑下游。
		return "", map[string]any{"error": err.Error()}, true
	}
	if res.Ambiguous {
		return "", ambiguousPayload(res.Candidates), true
	}
	if !res.Found {
		return "", nil, false
	}
	return res.MethodKey, nil, true
}

// ambiguousPayload 构造 ambiguous 返回 map(对齐 search_definitions 返回形状 + method_key)。
// 候选必带 file_path(消歧闭环)+ method_key(重载回传)。
func ambiguousPayload(cands []taintbridge.Candidate) any {
	out := make([]map[string]any, 0, len(cands))
	for _, c := range cands {
		out = append(out, map[string]any{
			"method_key":    c.MethodKey,
			"file_path":     c.FilePath,
			"function_name": c.FunctionName,
			"class_name":    c.ClassName,
			"lines":         c.Lines,
		})
	}
	return map[string]any{"ambiguous": true, "candidates": out}
}
