package engine

import "strings"

// ============================================================
//  ReachabilityChecker — 三态可达性判定（raptor CalleeResult）
//  reachable / unreachable / unknown
// ============================================================

type ReachabilityChecker struct {
	store        *AnalysisStore
	typeResolver *TypeResolver
}

func NewReachabilityChecker(store *AnalysisStore, tr *TypeResolver) *ReachabilityChecker {
	return &ReachabilityChecker{store: store, typeResolver: tr}
}

// CheckCalleeReachability 判定单个 callee 的可达性。
func (rc *ReachabilityChecker) CheckCalleeReachability(calleeName string) ReachabilityState {
	// calleeName 格式: "Class.method" 或 "Class.method(params)"
	cls := calleeName
	method := calleeName
	if dotIdx := strings.LastIndex(calleeName, "."); dotIdx > 0 {
		cls = calleeName[:dotIdx]
		method = calleeName[dotIdx+1:]
	}
	if parenIdx := strings.Index(method, "("); parenIdx > 0 {
		method = method[:parenIdx]
	}
	pattern := cls + "." + method
	matched, ok := rc.store.Indices.MethodNameIndex[pattern]
	if ok && len(matched) > 0 {
		if len(matched) == 1 {
			return ReachReachable
		}
		// 多定义 → unknown（可能多态/重载）
		return ReachUnknown
	}
	// 在 edges/reverse_edges 有调用点但无定义 → unreachable
	hasCall := false
	for _, edges := range rc.store.Calls.Edges {
		for _, e := range edges {
			if e.CalleeClass == cls && e.CalleeMethod == method {
				hasCall = true
				break
			}
		}
		if hasCall {
			break
		}
	}
	if hasCall {
		return ReachUnreachable
	}
	// 模糊匹配
	results := rc.store.SearchMethodsByPattern(method, 10)
	if len(results) > 0 {
		return ReachUnknown
	}
	return ReachUnreachable
}

// GetForwardReachable 获取方法的前向可达 callee 列表（结构化结果）。
func (rc *ReachabilityChecker) GetForwardReachable(methodKey string) ReachabilityResult {
	result := ReachabilityResult{}
	edges := rc.store.Calls.Edges[methodKey]
	nodeCount := 0
	for _, edge := range edges {
		if nodeCount >= rc.store.Config.MaxCallNodes {
			result.Truncated = true
			break
		}
		nodeCount++
		pattern := edge.CalleeClass + "." + edge.CalleeMethod
		matched, ok := rc.store.Indices.MethodNameIndex[pattern]
		ref := CalleeRef{Name: pattern, FilePath: edge.FilePath, Line: edge.Line}
		if ok && len(matched) > 0 {
			if len(matched) == 1 {
				result.Definitive = append(result.Definitive, ref)
			} else {
				result.HasMethodDispatch = true
				result.Uncertain = append(result.Uncertain, ref)
			}
		} else {
			// 检查是否是 self.foo() 分派
			if edge.CalleeClass == (MethodKeyHelper{}).ClassName(methodKey) {
				result.HasMethodDispatch = true
				result.Uncertain = append(result.Uncertain, ref)
			} else {
				result.Uncertain = append(result.Uncertain, ref)
			}
		}
	}
	return result
}
