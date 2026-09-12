package agentic

import "strings"

// RefreshForwardReachable 把 rejudge loop 新解析的 callee（toolLog2 里
// search_definitions found=true / get_callees definitive）并入 sliced["forward_reachable"]
// 的 Definitive，从 Uncertain 移除，并按规则清 Truncated（spec §4(d)）。
//
// 数据源是 toolLog2（rejudge loop 已调过 get_callees/search_definitions，结果在里），
// 不重跑 PrejudgeCalleeReachability——它查静态索引，拿不到 LLM 新读的 callee（spec §4(d)）。
//
// D5（不污染 guard token）：本函数只改 forward_reachable struct（Definitive/Uncertain/Truncated），
// 不回写 decisive_facts["forward_reachable"]。rejudge 的 fact 决断（rejudge.go）读 struct 重算
// slice.MapForwardReachable；guard.go:54 的 token 仍由 pre-judge 写入、不被 rejudge 触碰——
// rejudgeDecisiveFact 也不重跑守卫（judge.go:511 后只走 verifier.VerifyVerdict，非
// EnforceDecisiveFactKnown），故 stale "unknown" token 永不被重检，fail-safe。
//
// fail-open（铁律 D）：toolLog2 解析失败 / 无 forward_reachable struct → 不动（保留守卫 uncertain）。
// 幂等：重复跑同一 toolLog2 不产生重复 Definitive 条目（已并入的 name 跳过）。
func RefreshForwardReachable(sliced map[string]any, toolLog2 []map[string]any) {
	defer func() { _ = recover() }() // 铁律 D fail-open（对齐 verifier/refresh.go:55）

	fr, ok := sliced["forward_reachable"].(map[string]any)
	if !ok {
		return // 无 struct（Prejudge 未写——hop 无候选 callee）→ 无可 drain，dormant 安全
	}
	resolved := collectResolvedCallees(toolLog2)
	if len(resolved) == 0 {
		return // rejudge 未解析任何 callee → 不动（保留 uncertain，fail-open）
	}

	definitive, _ := fr["definitive"].([]any)
	uncertain, _ := fr["uncertain"].([]any)
	truncated, _ := fr["truncated"].(bool)

	// 既有 Definitive 名集合（幂等：已并入的不重复加）
	defNames := map[string]bool{}
	for _, d := range definitive {
		if dm, ok := d.(map[string]any); ok {
			if n, ok := dm["name"].(string); ok {
				defNames[n] = true
			}
		}
	}

	keptUncertain := make([]any, 0, len(uncertain))
	for _, u := range uncertain {
		um, ok := u.(map[string]any)
		if !ok {
			keptUncertain = append(keptUncertain, u)
			continue
		}
		name, _ := um["name"].(string)
		if name != "" && resolved[name] && !defNames[name] {
			// ① 加到 Definitive ② 从 Uncertain 移除（spec §4(d)：漏则 Uncertain 永不空→
			// 永远 fire→rejudge 回收失败，闭环核心逻辑非边界 case）
			definitive = append(definitive, um)
			defNames[name] = true
		} else {
			keptUncertain = append(keptUncertain, u)
		}
	}

	// ③ Truncated 规则（spec §4(d)：Truncated 是 bool 非 per-callee；
	//   refresh 后 Uncertain 空 且 无 rejudge 新截断 → 清）。
	//   "新截断" = get_callees result.truncated==true（rejudge loop 又撞 cap）。
	newTruncation := false
	for _, e := range toolLog2 {
		if t, _ := e["tool"].(string); t != "get_callees" {
			continue
		}
		if r, ok := e["result"].(map[string]any); ok {
			if nt, _ := r["truncated"].(bool); nt {
				newTruncation = true
				break
			}
		}
	}
	if len(keptUncertain) == 0 && !newTruncation {
		truncated = false
	}

	fr["definitive"] = definitive
	fr["uncertain"] = keptUncertain
	fr["truncated"] = truncated
}

// collectResolvedCallees 从 toolLog2 提取 rejudge loop 已解析的 callee 名集合。
// 数据源（spec §4(d) :128-129）：
//   - search_definitions found=true → args["name"]（裸方法名，与 Prejudge 查询同形，
//     reachability.go:103 exec.searchDefinitions({"name": callee}））已解析；
//   - get_callees result.definitive → callee.method_key（Class.method 形，engine_tools.go:300）
//     已解析，取末段（"." 后）+ 全形都入集合，与 Uncertain 的裸 name 对齐
//     （ExtractCandidateCallees 提取裸方法名 m[2]，reachability.go:48-54）。
func collectResolvedCallees(toolLog2 []map[string]any) map[string]bool {
	resolved := map[string]bool{}
	for _, e := range toolLog2 {
		tool, _ := e["tool"].(string)
		result, ok := e["result"].(map[string]any)
		if !ok {
			continue
		}
		switch tool {
		case "search_definitions":
			found, _ := result["found"].(bool)
			if !found {
				continue
			}
			args, _ := e["args"].(map[string]any)
			if name, _ := args["name"].(string); name != "" {
				resolved[name] = true
			}
		case "get_callees":
			// found=false（method_key 未解析）时 definitive 也空，自然跳过
			// 注意类型：executor toCalleeMaps 产 []map[string]any（真实 toolLog2 形），
			// 单测手构 fixture 可能是 []any——Go 静态类型不可互通赋值，须双断言
			// （曾因此漂移：[]any 断言遇 []map[string]any 静默失败 → 不 drain → 闭环失灵）。
			for _, dm := range calleeListOfMaps(result["definitive"]) {
				mk, _ := dm["method_key"].(string)
				if mk == "" {
					continue
				}
				resolved[mk] = true
				if seg := methodSegment(mk); seg != "" && seg != mk {
					resolved[seg] = true
				}
			}
		}
	}
	return resolved
}

// methodSegment 取 method_key 末段（"." 后），对齐 Uncertain callee 的裸 name
// （ExtractCandidateCallees 提取的是裸方法名 m[2]，非 Class.method 全形）。
func methodSegment(methodKey string) string {
	if i := strings.LastIndex(methodKey, "."); i >= 0 {
		return methodKey[i+1:]
	}
	return methodKey
}

// calleeListOfMaps 提取 callee 列表，兼容 toolLog2 两种存储形：
//   - 真实 executor 输出（toCalleeMaps）→ []map[string]any
//   - 单测手构 fixture → []any（元素 map[string]any）
//
// Go 静态类型：[]map[string]any 与 []any 不可互通赋值，[]any 断言遇前者静默失败
// （ok=false）→ drain 漏掉所有真实 callee → 闭环失灵。故双断言兜底。
func calleeListOfMaps(v any) []map[string]any {
	if dm, ok := v.([]map[string]any); ok {
		return dm
	}
	if ais, ok := v.([]any); ok {
		out := make([]map[string]any, 0, len(ais))
		for _, x := range ais {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}
