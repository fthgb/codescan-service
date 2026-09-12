package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type QueryService struct {
	store             *AnalysisStore
	fieldResolver     *FieldValueResolver
	methodPrefixIndex map[string][]string // 方法前缀索引：prefix="Class.method(" -> 匹配的方法键列表（Edges+Functions 合并）。
}

func NewQueryService(store *AnalysisStore) *QueryService {
	qs := &QueryService{store: store, fieldResolver: NewFieldValueResolver()}
	qs.buildMethodPrefixIndex()
	return qs
}

// buildMethodPrefixIndex 一次性构建方法前缀索引，将 calleeKeys 的 O(全仓) 线性扫描
// 降到 O(匹配数) 查表。calleeKeys 在 DFS 内部每条边都会调用，原先每次遍历整个
// Methods.Functions（9000+ 键）做 strings.HasPrefix，使 9118 方法的分类 DFS 退化为
// O(N²×E) 而卡死（第二十九轮引入的 prefix+Functions fallback 退化）。索引在仓库
// 加载时构建一次，之后所有查询复用。
func (q *QueryService) buildMethodPrefixIndex() {
	idx := make(map[string][]string)
	add := func(mk string) {
		// 仅索引含 '(' 的键（calleeKeys 的 prefix 总为 "Class.method(" 形态）。
		i := strings.Index(mk, "(")
		if i < 0 {
			return
		}
		prefix := mk[:i+1]
		idx[prefix] = append(idx[prefix], mk)
	}
	if q.store.Calls != nil {
		for mk := range q.store.Calls.Edges {
			add(mk)
		}
	}
	if q.store.Methods != nil {
		for mk := range q.store.Methods.Functions {
			add(mk)
		}
	}
	q.methodPrefixIndex = idx
}

// CallerQueryResult 是 GetCallersRobust 的返回值，区分三种情况（G3-2 三面矩阵）：
//   - Edges 非空、Ambiguous=false：精确匹配或去签名后唯一签名命中，返回真实调用方；
//   - Ambiguous=true：去签名降级命中多个不同签名的方法（Java 重载），不盲目合并，
//     交由 AI 依据 Candidates 中的签名列表决断；
//   - Edges 空、Ambiguous=false：真死代码，确实无调用方（含仅被同名不同签名重载调用的死方法）。
type CallerQueryResult struct {
	Edges      []ReverseEdge `json:"edges,omitempty"`
	Ambiguous  bool          `json:"ambiguous,omitempty"`
	Candidates []string      `json:"candidates,omitempty"` // 重载时的不同签名键
}

// getCallers 兼容旧调用方的薄包装：仅返回调用方边，丢弃 ambiguity 信号。
// 用于 DFS 追溯（TraceToSources/CallTree）等探索性场景——ambiguity 在那里非致命，
// 命中重载时返回空（不向上误合并），不影响主链路。
func (q *QueryService) getCallers(mk string) []ReverseEdge {
	return q.GetCallersRobust(mk).Edges
}

// GetCallersRobust 合并 ReverseEdges + UnresolvedReverseEdges，按 (CallerKey, Line, FilePath)
// 三元组去重，并严格遵循 G3-2 三面矩阵做重载防护：
//
//  1. 全限定名精确查 ReverseEdges[mk]：命中即返回（正常匹配不受影响）。
//  2. 精确查无结果时，用 simpleKey（去签名）降级查：
//     - 命中且 simpleKey 下仅一个签名 → 返回该签名的调用方；
//     - 命中且 simpleKey 下存在多个不同签名（重载）→ 返回 Ambiguous=true + Candidates，
//     绝不盲目合并同名不同签名的调用方（避免 setUnitId(int) 与 setUnitId(String) 串链）；
//     - 完全无命中 → 真死代码，返回空（不干扰、不误报）。
//
// 注：ReverseEdges 的键格式在多处写入时不统一（有的带签名，有的不带），故降级查
// 同时覆盖 ReverseEdges[simpleKey] 与 UnresolvedReverseEdges[simpleKey]。
func (q *QueryService) GetCallersRobust(mk string) CallerQueryResult {
	// 1. 带签名的全限定名精确查：仅当 mk 含签名且确为带签名键时才视为确定匹配，
	//    避免无签名键（ReverseEdges 键格式不统一）误吞同 simpleKey 下的重载判定。
	if strings.Contains(mk, "(") {
		if exact := q.store.Calls.ReverseEdges[mk]; len(exact) > 0 {
			return CallerQueryResult{Edges: dedupeCallers(exact)}
		}
	}
	// 计算 simpleKey（去签名），与 mk 可能相同（mk 本就不含签名）。
	simpleKey := mk
	if idx := strings.Index(mk, "("); idx > 0 {
		simpleKey = mk[:idx]
	}
	// 2. 重载判定（覆盖所有入口，含无签名 simpleKey）：同一 simpleKey 下若存在多个不同签名，
	//    绝不盲目合并调用方（防 setUnitId(int) 与 setUnitId(String) 串链），交由 AI 依据
	//    Candidates 决断。无论是否找到调用方边，重载一律标 ambiguous。
	if sigs := distinctSignatures(q.store.Calls.ReverseEdges, simpleKey); len(sigs) > 1 {
		return CallerQueryResult{Ambiguous: true, Candidates: sigs}
	}
	// 3. simpleKey 降级合并调用方（已解析 ReverseEdges[simpleKey] + 未解析 UnresolvedReverseEdges[simpleKey]）。
	merged := append([]ReverseEdge(nil), q.store.Calls.ReverseEdges[simpleKey]...)
	merged = append(merged, q.store.Calls.UnresolvedReverseEdges[simpleKey]...)
	if len(merged) == 0 {
		return CallerQueryResult{} // 真死代码（无精确命中、无重载、无降级调用方）
	}
	return CallerQueryResult{Edges: dedupeCallers(merged)}
}

// dedupeCallers 按 (CallerKey, Line, FilePath) 三元组去重。
func dedupeCallers(edges []ReverseEdge) []ReverseEdge {
	seen := make(map[string]bool)
	var result []ReverseEdge
	for _, e := range edges {
		key := fmt.Sprintf("%s|%d|%s", e.CallerKey, e.Line, e.FilePath)
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}

// distinctSignatures 返回 ReverseEdges 中所有以 simpleKey 为去签名前缀的键（不同签名）。
func distinctSignatures(reverseEdges map[string][]ReverseEdge, simpleKey string) []string {
	prefix := simpleKey + "("
	seenSig := make(map[string]bool)
	var sigs []string
	for k := range reverseEdges {
		if k == simpleKey || strings.HasPrefix(k, prefix) {
			if !seenSig[k] {
				seenSig[k] = true
				sigs = append(sigs, k)
			}
		}
	}
	return sigs
}

type SourceTrace struct {
	Path    []CallNode `json:"path"`
	Sources []string   `json:"sources"`
	IsEntry bool       `json:"is_entry"`
	// R19-边界：本次 TraceToSources 探索因 MaxCallDepth 封顶而未穷尽下游时置 true，
	// 表示这条 trace 所属调用链本可更长、切片可能不全。供 sim/AI 区分「链已到头」
	// 与「被 depth 钳制截断」，避免把截断的短切片误读为完整数据流。
	Truncated bool `json:"truncated,omitempty"`
	// R-F3（架构级，F35）：当方法结构性命中危险 sink（nodeDirectlyCallsDangerSink=true）
	// 但数据流溯源未能确认具体 source（参数未播种/间接来源未解析）时置 true，
	// 表示此链路 source 端为「未确认」——AI 应知道需自行补全参数来源方向（验收标准2断点锚点）。
	// 与纯空链区分：Unconfirmed trace 仍含 sink 端行号锚点，仅 source 待确认。
	Unconfirmed bool `json:"unconfirmed,omitempty"`
}

// ============================================================
//  G-Out 参数级绑定展示（R09 数据基础 CallParamTaints 落地后的报告层收口）
//  目标：让 AI 不止看到方法级 confirmed，还能直接看到「source 变量 -> 经本方法 -> 绑定到
//  sink 第 N 个参数 (arg#N)」的参数级污点绑定证据，消弭「confirmed 但不知污点落在哪个参数」的盲区。
// ============================================================

// ParamBinding 描述一处 sink 调用边上参数级污点绑定：
// 本方法 mk 调用 (CalleeClass.CalleeMethod) 时，第 ParamIndex 个实参的污点来源 TaintSource。
type ParamBinding struct {
	CallerKey    string `json:"caller_key"`           // 调用方方法键（通常为 SampleResult.MethodFQN）
	CalleeClass  string `json:"callee_class"`         // sink 类（短名或全限定）
	CalleeMethod string `json:"callee_method"`        // sink 方法
	ParamIndex   int    `json:"param_index"`          // 污点绑定的参数位置（0-based）
	ParamName    string `json:"param_name,omitempty"` // 反查的参数名（若有）
	TaintSource  string `json:"taint_source"`         // 污点来源（如 @RequestParam name / userInput）
	VulnType     string `json:"vuln_type,omitempty"`
	CWE          string `json:"cwe,omitempty"`
}

// isAnyDangerSink 统合静态 sinkDict（IsDangerousSink）+ 动态判定（R10 XML mapper / R09 JPA），
// 覆盖所有「本引擎判为危险 sink」的 callee，供 SinkParamBindings 过滤。
func (q *QueryService) isAnyDangerSink(calleeClass, calleeMethod string) (string, bool) {
	if IsDangerousSink(calleeClass, calleeMethod) {
		v, _ := SinkVulnType(calleeClass, calleeMethod)
		return v, true
	}
	if v, _, ok := q.xmlMapperSink(calleeClass, calleeMethod); ok {
		return v, true
	}
	if q.isJPASQLSink(calleeClass, calleeMethod) {
		return "sql_injection", true
	}
	return "", false
}

// SinkParamBindings 返回本方法 mk 直接调用危险 sink 时，各实参的污点来源绑定（参数级）。
// 仅当该调用边在 CallParamTaints 中记录且 TaintSource 非空、且 callee 确为危险 sink 才计入。
// 这是 G-Out 参数级绑定展示的唯一权威来源，覆盖注解/XML mapper/JPA 三种 sink 形态。
func (q *QueryService) SinkParamBindings(mk string) []ParamBinding {
	var out []ParamBinding
	if mk == "" {
		return out
	}
	for _, cpt := range q.store.Calls.CallParamTaints {
		// R6-2：lambda 内 sink 调用的 CallerKey 是 lambda method key（methodKey+"$lambda$..."），
		// 其前缀即外层方法 mk；故匹配 mk 自身及其直接 lambda 内的 sink 调用。
		if cpt.TaintSource == "" {
			continue
		}
		if cpt.CallerKey != mk && !strings.HasPrefix(cpt.CallerKey, mk+"$") {
			continue
		}
		vuln, ok := q.isAnyDangerSink(cpt.CalleeClass, cpt.CalleeMethod)
		if !ok {
			continue
		}
		_, cwe := SinkVulnType(cpt.CalleeClass, cpt.CalleeMethod)
		if vuln == "" {
			vuln = "sql_injection" // 动态 sink（XML/JPA）无 sinkDict 条目，统一标 sql_injection
			cwe = "CWE-89"
		}
		pb := ParamBinding{
			CallerKey:    cpt.CallerKey,
			CalleeClass:  cpt.CalleeClass,
			CalleeMethod: cpt.CalleeMethod,
			ParamIndex:   cpt.ParamIndex,
			TaintSource:  cpt.TaintSource,
			VulnType:     vuln,
			CWE:          cwe,
		}
		// 反查参数名：callee 方法键（去签名）-> ParamOrder
		if calleeKey := q.calleeKeyFor(cpt.CalleeClass, cpt.CalleeMethod, cpt.ParamIndex); calleeKey != "" {
			if po := q.store.Methods.ParamOrder[calleeKey]; po != nil {
				for n, o := range po {
					if o == cpt.ParamIndex {
						pb.ParamName = n
						break
					}
				}
			}
		}
		out = append(out, pb)
	}
	return out
}

// calleeKeyFor 由 CalleeClass.CalleeMethod + ParamIndex 反推方法键（去签名），
// 用于从 ParamOrder 反查参数名。优先匹配 ParamCounts 满足 ParamIndex 的键。
//
// ⚠ 下面两条 fallback 回路曾是**死代码**：它们拿 `fn.Method` 去比裸方法名，只剥了 `(`
// 没剥类前缀 —— 而 `fn.Method` 是 `DisplayName(methodKey)`，即**类限定**名
// (analyzer.go:139)，剥 `(` 在它身上是 no-op，故 `mm == m` 恒不成立。
// 结果：MethodNameIndex 缺失时 `ParamBinding.ParamName` 永远为空。
// 同一个「`.Method` 是 DisplayName 不是裸名」的坑在本仓咬过三次
// (taintbridge.filterByExactName / engine.findMethodNode —— 后者让 HasSanitizerOnPath
// 从来没工作过 / 此处)。三次都在单测全绿下活着，因为 fixture 手写的是裸名。
func (q *QueryService) calleeKeyFor(calleeClass, calleeMethod string, paramIndex int) string {
	pattern := calleeClass + "." + calleeMethod
	// 去签名后缀
	m := calleeMethod
	if idx := strings.Index(m, "("); idx >= 0 {
		m = m[:idx]
	}
	shortPattern := calleeClass + "." + m
	keys := q.store.Indices.MethodNameIndex[pattern]
	if len(keys) == 0 {
		keys = q.store.Indices.MethodNameIndex[shortPattern]
	}
	for _, k := range keys {
		if pc := q.store.Methods.ParamCounts[k]; pc > paramIndex {
			return k
		}
	}
	if len(keys) > 0 {
		return keys[0]
	}
	// G01（第二十六轮真实仓盲测）：MethodNameIndex 在真实扫描中未必填充，
	// 退化遍历 Methods.Functions 做 Class+Method(去签名) 匹配，保证 DFS 推进不断裂。
	// 与 CallerHasDangerousSink 的推进口径对齐（其直接边命中不依赖该索引）。
	for k, fn := range q.store.Methods.Functions {
		if fn.Class != calleeClass {
			continue
		}
		mm := bareMethodDisplayName(fn.Method)
		if mm == m {
			if pc := q.store.Methods.ParamCounts[k]; pc > paramIndex {
				return k
			}
		}
	}
	// 末选：任一 Class+Method 匹配（忽略参数个数）
	for k, fn := range q.store.Methods.Functions {
		if fn.Class != calleeClass {
			continue
		}
		mm := bareMethodDisplayName(fn.Method)
		if mm == m {
			return k
		}
	}
	return ""
}

// SourceTraceResult 是 TraceToSourcesEx 的返回载体。在 SourceTrace 切片之外，额外携带
// ExhaustedDepth 顶层信号，闭合 R19 家族残余暗角（第十五轮 B-R19b-2）：当 source 自身处于
// 超深调用链末端、反向 DFS 在到达 entry 前即因 depth 封顶（MaxCallDepth）未探明下游时，
// 原 TraceToSources 会静默返空、连「未探明」信号都无。ExhaustedDepth=true 明确告知调用方
// 「本次探索深度用尽、可能根本没探到 entry，空结果不可信、需加大 depth 或人工复核」。
type SourceTraceResult struct {
	Traces         []SourceTrace `json:"traces"`
	ExhaustedDepth bool          `json:"exhausted_depth"`
}

// TraceToSources 方法级反向追溯（保留原签名，零回归）。等价于 TraceToSourcesEx(...).Traces。
func (q *QueryService) TraceToSources(mk string, maxDepth int) []SourceTrace {
	traces, _ := q.traceToSourcesCore(mk, maxDepth)
	return traces
}

// TraceToSourcesEx 在 TraceToSources 基础上额外返回 ExhaustedDepth 顶层信号。
// ExhaustedDepth 当且仅当「DFS 曾因 depth 封顶未穷尽、且本次探索未产出任何 trace」为真——
// 即 source 在超深链末端、反向 DFS 在到达 entry 前即被 depth 截断的暗角场景。
func (q *QueryService) TraceToSourcesEx(mk string, maxDepth int) SourceTraceResult {
	traces, truncated := q.traceToSourcesCore(mk, maxDepth)
	return SourceTraceResult{
		Traces:         traces,
		ExhaustedDepth: truncated && len(traces) == 0,
	}
}

// traceToSourcesCore 反向追溯核心：返回切片 + 探索是否因 depth 封顶未穷尽（truncated）。
// 公开 TraceToSources / TraceToSourcesEx 均复用此核心，避免逻辑分叉。
func (q *QueryService) traceToSourcesCore(mk string, maxDepth int) ([]SourceTrace, bool) {
	if maxDepth <= 0 {
		maxDepth = q.store.Config.MaxCallDepth
	}
	visited := make(map[string]bool)
	var results []SourceTrace
	// R19-边界：贯穿整棵反向 DFS 的截断标记——任一路径因 depth 封顶未探明下游即置位，
	// 使本次探索返回的所有 trace 都标记为「切片可能不全」（Truncated）。
	truncated := false
	q.traceSrcDFS(mk, []CallNode{}, visited, &results, 0, maxDepth, &truncated)
	// R16 修复：entry point 自身即污点注入起点（如 servlet handler 的 HttpServletRequest 参数）。
	// 原逻辑遇到 EntryPoint 直接 return，使 entry 的 trace 仅含自身、丢失其调用链上所有流向
	// sink 的关键中间节点（setter/getter 链、数据透传、字段读写）。这里额外从 mk 沿 Edges
	// 正向展开到危险 sink，补全 entry -> ... -> sink 的完整调用链，使 flow 切片含全部中间节点。
	if q.store.Calls.EntryPoints[mk] || func() bool { hit, _, _, _ := q.CallerHasDangerousSink(mk); return hit }() {
		// R-F5（架构级修复，F24）：放宽正向 DFS 入口——除 EntryPoint 外，任何"调用链含危险 sink"
		// 的方法（含多态间接调用 dispatch->ImplBad.process->exec 这类非 EntryPoint 但 INDIRECT_DANGER
		// 的场景）也启动正向 DFS，补全 mk -> ... -> sink 的完整溯源链路。纯架构机制，非 hardcoded。
		if fwd := q.traceForwardToSink(mk, maxDepth, &truncated); len(fwd.Path) > 1 {
			results = append(results, fwd)
		}
	}
	// R-F2（架构级修复，H09）：过程内 source->sink 切片补全。
	// 根因（F17）：当 mk 自身方法体内直接调用危险 sink 时，反向 DFS 从 mk 沿 ReverseEdges
	// 回溯找不到 sink 端（sink 在 mk 内部而非被 mk 调用的方法），正向 traceForwardToSink
	// 又仅对 EntryPoints[mk] 触发，导致"同方法内 source->sink"场景溯源链永远缺 sink 端行号。
	// 这同时解释了 F15(隐式流)/F14(DAG) 的系统性格空链——它们本质都是"source 与 sink 共处一个方法体"。
	// 修复（架构级，基于 Edges + LocalVars + methodSrcs，不 hardcode 任何特定函数名）：
	//   若 mk 直接调 sink，则对每条来源 trace（Path[0].MethodKey==mk，来自反向DFS的source端）
	//   在其 Path 前端补全 sink 端节点（行号取 sink 调用边精确行），使链路含 sink 锚点；
	//   若 results 为空（如纯 sink 入口），仍追加一条以 sink 端为起点的基础 trace。
	if nodeDirectlyCallsDangerSink(q.store, mk) {
		sinkLine := q.methodLine(mk)
		for _, e := range q.store.Calls.Edges[mk] {
			if IsDangerousSink(e.CalleeClass, e.CalleeMethod) && e.Line > 0 {
				sinkLine = e.Line // 取 sink 调用边的精确行号作为 sink 锚点
				break
			}
		}
		sinkNode := CallNode{MethodKey: mk, FilePath: q.methodFP(mk), Line: sinkLine}
		appended := false
		for i := range results {
			if len(results[i].Path) > 0 && results[i].Path[0].MethodKey == mk {
				// 在来源 trace 前端补全 sink 端节点（去重：若已含同 Line sink 节点则跳过）
				dup := false
				for _, n := range results[i].Path {
					if n.Line == sinkLine && n.MethodKey == mk {
						dup = true
						break
					}
				}
				if !dup {
					results[i].Path = append([]CallNode{sinkNode}, results[i].Path...)
				}
				appended = true
			}
		}
		if !appended {
			// 纯 sink 入口场景（无反向来源 trace）：追加基础 trace，source 端取方法内污点变量
			var path []CallNode
			path = append(path, sinkNode)
			for _, lv := range q.store.Methods.LocalVars[mk] {
				if lv.Tainted {
					path = append(path, CallNode{MethodKey: mk, FilePath: q.methodFP(mk), Line: lv.Line})
				}
			}
			srcs := q.methodSrcs(mk)
			// R-F3（架构级，F35）：结构性命中 sink 但数据流 source 缺失——将方法直接参数
			// 标记为「未确认 source」，使溯源链路不再空链，且 AI 可据 Unconfirmed 标志
			// 补全参数来源方向（验收标准2 断点锚点）。复用 ParamOrder 通用数据，非 hardcode。
			unconfirmed := false
			if len(srcs) == 0 && len(q.store.Methods.ParamOrder[mk]) > 0 {
				for pname := range q.store.Methods.ParamOrder[mk] {
					srcs = append(srcs, "<unconfirmed:"+pname+">")
				}
				unconfirmed = true
			}
			results = append(results, SourceTrace{
				Path:        path,
				Sources:     srcs,
				IsEntry:     q.store.Calls.EntryPoints[mk],
				Unconfirmed: unconfirmed,
			})
		}
	}
	// R19-边界：本次探索若曾因 depth 封顶未穷尽下游，给所有返回 trace 统一标记 Truncated，
	// 使 AI 知道「这些 trace 出自未穷尽的探索、切片可能不全」，而非把截断短切片误读为完整链。
	if truncated {
		for i := range results {
			results[i].Truncated = true
		}
	}
	return results, truncated
}

// traceForwardToSink 从 start 沿调用边（Edges）正向 DFS 到直接调用危险 sink 的节点，
// 返回 SourceTrace，其 Path 约定为 Path[0]=sink 端、Path[last]=entry 端（与反向 trace 一致）。
func (q *QueryService) traceForwardToSink(start string, maxDepth int, truncated *bool) SourceTrace {
	visited := make(map[string]bool)
	var best SourceTrace
	q.traceFwdDFS(start, start, []CallNode{}, visited, &best, 0, maxDepth, truncated)
	return best
}

func (q *QueryService) traceFwdDFS(start, mk string, path []CallNode, vis map[string]bool, best *SourceTrace, d, md int, truncated *bool) {
	if d > md {
		// R19-边界：正向 DFS 深度封顶，更深的 sink 下游未探明——标记截断。
		if truncated != nil {
			*truncated = true
		}
		return
	}
	if vis[mk] {
		return
	}
	vis[mk] = true
	defer delete(vis, mk)
	node := CallNode{MethodKey: mk, FilePath: q.methodFP(mk), Line: q.methodLine(mk)}
	np := append(path, node)
	if nodeDirectlyCallsDangerSink(q.store, mk) {
		rev := make([]CallNode, len(np))
		for i, c := range np {
			rev[len(np)-1-i] = c
		}
		if len(rev) > len(best.Path) {
			*best = SourceTrace{Path: rev, Sources: q.methodSrcs(start), IsEntry: true}
		}
		return
	}
	for _, e := range q.store.Calls.Edges[mk] {
		// Edges 的键是全方法键（含参数签名，如 "Pipe.sink(String)"），而 CallEdge 的
		// CalleeMethod 是短名（"sink"）。需用 MethodNameIndex 解析出全键作为下一跳 mk，
		// 否则拼出的 "Pipe.sink" 查不到 Edges，导致 entry->...->sink 链在 store->sink 处断裂。
		callee := e.CalleeClass + "." + e.CalleeMethod
		if keys := q.store.Indices.MethodNameIndex[callee]; len(keys) > 0 {
			callee = keys[0]
		}
		if callee == "" {
			continue
		}
		q.traceFwdDFS(start, callee, np, vis, best, d+1, md, truncated)
	}
	// R16 数据流感知：除调用图后继外，补齐「返回值被 caller 内下游方法消费」的数据流边。
	// 例如 entry 调 fetch() 返回 q，q 作为 entry 调 setBuf(q) 的参数——fetch 在调用图上与
	// setBuf 平行，但数据流上 fetch->setBuf 串联。仅走调用图会丢失 setter/getter 链这类
	// 关键中间节点，使切片两端化、AI 无法还原数据走向。这里用 CallReturnToLocalMap +
	// ParamToCallParam 把数据流后继也并入路径。
	for _, pair := range q.store.Calls.CallReturnToLocalMap[mk] {
		callerKey, localVar := pair[0], pair[1]
		for _, cp := range q.store.Methods.ParamToCallParam[callerKey][localVar] {
			callee := cp.CalleeClass + "." + cp.CalleeMethod
			if keys := q.store.Indices.MethodNameIndex[callee]; len(keys) > 0 {
				callee = keys[0]
			}
			if callee == "" || callee == mk {
				continue
			}
			q.traceFwdDFS(start, callee, np, vis, best, d+1, md, truncated)
		}
	}
}

// traceSrcDFS 反向回溯 mk 的所有 source/entry 路径。truncated 指针贯穿整树：任一路径因
// depth 封顶（d>md）未探明更上层 caller 即置位，使本次探索生成的所有 trace 标记 Truncated。
func (q *QueryService) traceSrcDFS(mk string, path []CallNode, vis map[string]bool, res *[]SourceTrace, d, md int, truncated *bool) {
	if d > md {
		// R19-边界：反向 DFS 深度封顶，更上层 caller 未探明——标记截断。
		if truncated != nil {
			*truncated = true
		}
		return
	}
	if vis[mk] {
		return
	}
	vis[mk] = true
	defer delete(vis, mk)
	node := CallNode{MethodKey: mk, FilePath: q.methodFP(mk), Line: q.methodLine(mk)}
	np := append(path, node)
	if q.store.Calls.EntryPoints[mk] {
		*res = append(*res, SourceTrace{Path: cpNodes(np), Sources: q.methodSrcs(mk), IsEntry: true})
		// R16：EntryPoint 在此不 return，继续向上回溯 callers（兼容非顶层入口反向链）。
	}
	srcs := q.methodSrcs(mk)
	if len(srcs) > 0 {
		*res = append(*res, SourceTrace{Path: cpNodes(np), Sources: srcs, IsEntry: false})
	}
	for _, re := range q.getCallers(mk) {
		q.traceSrcDFS(re.CallerKey, np, vis, res, d+1, md, truncated)
	}
}

type CallTree struct {
	MethodKey string     `json:"method_key"`
	FilePath  string     `json:"file_path"`
	Line      int        `json:"line"`
	IsEntry   bool       `json:"is_entry"`
	IsCycle   bool       `json:"is_cycle"`
	Callers   []CallTree `json:"callers,omitempty"`
	// 以下字段仅 TraceCallersChain(who_calls 工具)富化填;TraceCallersStructured(CLI 用)不填,
	// formatter 只读 IsEntry/IsCycle 忽略它们——CLI 零影响。adapter 映射 CallTree→CallerChainNode。
	EntryType        EntryPointType      `json:"entry_type,omitempty"`
	HttpMethod       string              `json:"http_method,omitempty"`
	HttpPath         string              `json:"http_path,omitempty"`
	ParamTaints      map[string][]string `json:"param_taints,omitempty"`
	ReturnTaints     []string            `json:"return_taints,omitempty"`
	IsTest           bool                `json:"is_test,omitempty"`
	CallersTruncated int                 `json:"callers_truncated,omitempty"`
}

func (q *QueryService) TraceCallersStructured(mk string, maxDepth int) *CallTree {
	if maxDepth <= 0 {
		maxDepth = q.store.Config.MaxCallDepth
	}
	return q.callersDFS(mk, 0, maxDepth, make(map[string]bool))
}

func (q *QueryService) callersDFS(mk string, d, md int, vis map[string]bool) *CallTree {
	t := &CallTree{MethodKey: mk, FilePath: q.methodFP(mk), Line: q.methodLine(mk), IsEntry: q.store.Calls.EntryPoints[mk]}
	if d >= md {
		return t
	}
	if vis[mk] {
		t.IsCycle = true
		return t
	}
	vis[mk] = true
	defer delete(vis, mk)
	for _, re := range q.getCallers(mk) {
		c := q.callersDFS(re.CallerKey, d+1, md, vis)
		c.Line = re.Line
		c.FilePath = re.FilePath
		t.Callers = append(t.Callers, *c)
	}
	return t
}

// who_calls 工具(TraceCallersChain)的默认封顶。maxDepth=4 覆盖 alert11 depth-3 链;
// maxCallersPerNode=5 兜底 utility-sink blowup(一个方法被 50 caller 调用 → 50×4 巨树)。
// alert11 树 ~30 节点,cap 不触发——cap 只挡 blowup,不挡 real-TP-FN case。
const (
	defaultChainMaxDepth          = 4
	defaultChainMaxCallersPerNode = 5
)

// TraceCallersChain 是 who_calls 工具的 engine 侧实现(judge loop 用;非评估 (b) 的 WhoCalls)。
// 与 TraceCallersStructured(CLI 用,无 cap/无富化)并列——不动它。返回 (tree, found, truncated):
//   - found=false = mk 不在 store.Functions(方法未解析,GR-8 不编锚点);
//   - truncated=true = 有路径深度封顶未达 entry(非"无生产 caller",GR-8 诚实)。
//
// 设计见 docs/superpowers/specs/2026-08-26-who-calls-reachability-tool-design.md §4⑦ + §2 反 D1.2。
func (q *QueryService) TraceCallersChain(mk string, maxDepth, maxCallersPerNode int) (tree *CallTree, found bool, truncated bool) {
	if _, ok := q.store.Methods.Functions[mk]; !ok {
		return &CallTree{MethodKey: mk}, false, false // 方法未解析:found=false,不编 caller 不编锚点(GR-8)
	}
	if maxDepth <= 0 {
		maxDepth = defaultChainMaxDepth
	}
	if maxCallersPerNode <= 0 {
		maxCallersPerNode = defaultChainMaxCallersPerNode
	}
	tree = q.callersChainDFS(mk, 0, maxDepth, maxCallersPerNode, make(map[string]bool), &truncated)
	return tree, true, truncated
}

// callersChainDFS 是 callersDFS 的 cap+富化变体(不动 callersDFS,CLI 用旧版)。
// ① per-node 从 store 富化 entry_type/http/taint/is_test(enrichCallTree,FormatEntryPointInfo/QueryFunction 同源,GR-8 不编);
// ② caller 排序 (is_entry desc, is_test asc, method_key asc)——getCallers 返 dedupeCallers 的 scan 序
//
//	(非确定),砍前必排否则 cap 砍不同 caller 跨 run → 新 wobble(正是要修的);排序保 entry payload 不被 cap 砍;
//
// ③ breadth cap(maxCallersPerNode)engine 侧建树时生效(非 adapter post-filter,防巨树先建后砍),砍数记 CallersTruncated;
// ④ 深度封顶 maxDepth:d>=md 且本节点非 entry → truncated=true(该路径未达入口,诚实标);⑤ 环已检 IsCycle(path-scoped vis)。
// is_test 标注 show-both 非过滤(反 D1.2:TestCodeMethods 标 IsTest=true 但仍展示,排序靠后而已,绝不藏)。
func (q *QueryService) callersChainDFS(mk string, d, md, breadth int, vis map[string]bool, trunc *bool) *CallTree {
	t := &CallTree{
		MethodKey: mk,
		FilePath:  q.methodFP(mk),
		Line:      q.methodLine(mk),
		IsEntry:   q.store.Calls.EntryPoints[mk],
	}
	q.enrichCallTree(t, mk)
	if d >= md {
		if trunc != nil && !t.IsEntry {
			*trunc = true // 深度封顶且本节点非 entry——该路径未达入口,顶层 Truncated 诚实标(GR-8)
		}
		return t
	}
	if vis[mk] {
		t.IsCycle = true
		return t
	}
	vis[mk] = true
	defer delete(vis, mk)
	callers := q.getCallers(mk)
	// 排序 (is_entry desc, is_test asc, method_key asc):确定性兜底(map 迭代非确定)+ 保 entry payload。
	sort.SliceStable(callers, func(i, j int) bool {
		ei, ej := q.store.Calls.EntryPoints[callers[i].CallerKey], q.store.Calls.EntryPoints[callers[j].CallerKey]
		if ei != ej {
			return ei // entry 在前(is_entry desc)——cap 砍尾部时 entry 永不丢
		}
		ti, tj := q.IsTestMethod(callers[i].CallerKey), q.IsTestMethod(callers[j].CallerKey)
		if ti != tj {
			return tj // 非 test 在前(is_test asc)——test 排后但仍展示(反 D1.2,非过滤)
		}
		return callers[i].CallerKey < callers[j].CallerKey // method_key asc 兜底确定性
	})
	if len(callers) > breadth {
		t.CallersTruncated = len(callers) - breadth // 砍掉的 caller 数,GR-8 诚实标
		callers = callers[:breadth]
	}
	for _, re := range callers {
		c := q.callersChainDFS(re.CallerKey, d+1, md, breadth, vis, trunc)
		c.Line = re.Line
		c.FilePath = re.FilePath
		t.Callers = append(t.Callers, *c)
	}
	return t
}

// enrichCallTree 从 store 富化节点 entry_type/http/taint/is_test。
// FormatEntryPointInfo(formatter.go:220)/QueryFunction(query.go:584-597)同源真值,GR-8 不编:store 无则空。
func (q *QueryService) enrichCallTree(t *CallTree, mk string) {
	if t.IsEntry {
		t.EntryType = q.store.Calls.EntryTypes[mk]
	}
	t.HttpPath = q.store.Calls.HttpPaths[mk]
	t.HttpMethod = q.store.Calls.HttpMethods[mk]
	t.ReturnTaints = q.store.Methods.ReturnTaints[mk]
	if pts, ok := q.store.Methods.ParamTaints[mk]; ok {
		t.ParamTaints = pts
	}
	t.IsTest = q.IsTestMethod(mk)
}

type FunctionInfo struct {
	MethodKey        string              `json:"method_key"`
	Class            string              `json:"class"`
	Method           string              `json:"method"`
	Line             int                 `json:"line"`
	FilePath         string              `json:"file_path"`
	IsEntry          bool                `json:"is_entry"`
	EntryType        EntryPointType      `json:"entry_type,omitempty"`
	ParamCount       int                 `json:"param_count"`
	ReturnType       string              `json:"return_type"`
	ReturnTaints     []string            `json:"return_taints,omitempty"`
	ParamTaints      map[string][]string `json:"param_taints,omitempty"`
	HttpPath         string              `json:"http_path,omitempty"`
	HttpMethod       string              `json:"http_method,omitempty"`
	CallerCount      int                 `json:"caller_count"`
	CalleeCount      int                 `json:"callee_count"`
	CallerAmbiguous  bool                `json:"caller_ambiguous,omitempty"`  // 重载导致调用方无法唯一判定
	CallerCandidates []string            `json:"caller_candidates,omitempty"` // 重载签名列表
}

func (q *QueryService) QueryFunction(pattern string, max int) []FunctionInfo {
	if max <= 0 {
		max = 20
	}
	var results []FunctionInfo
	for _, mk := range q.store.SearchMethodsByPattern(pattern, max) {
		fi := FunctionInfo{MethodKey: mk}
		if fn, ok := q.store.Methods.Functions[mk]; ok {
			fi.Class, fi.Method, fi.Line, fi.FilePath = fn.Class, fn.Method, fn.Line, fn.FilePath
		}
		fi.IsEntry = q.store.Calls.EntryPoints[mk]
		if fi.IsEntry {
			fi.EntryType = q.store.Calls.EntryTypes[mk]
		}
		fi.ParamCount = q.store.Methods.ParamCounts[mk]
		if sig, ok := q.store.Types.MethodSigs[mk]; ok && len(sig) > 0 {
			fi.ReturnType = sig[0]
		}
		fi.ReturnTaints = q.store.Methods.ReturnTaints[mk]
		if pts, ok := q.store.Methods.ParamTaints[mk]; ok {
			fi.ParamTaints = pts
		}
		fi.HttpPath = q.store.Calls.HttpPaths[mk]
		fi.HttpMethod = q.store.Calls.HttpMethods[mk]
		cqr := q.GetCallersRobust(mk)
		fi.CallerCount = len(cqr.Edges)
		fi.CallerAmbiguous = cqr.Ambiguous
		fi.CallerCandidates = cqr.Candidates
		fi.CalleeCount = len(q.store.Calls.Edges[mk])
		results = append(results, fi)
	}
	return results
}

type FieldInfo struct {
	Key         string            `json:"key"`
	Definition  FieldDefinition   `json:"definition"`
	Type        string            `json:"type"`
	IsStatic    bool              `json:"is_static"`
	IsTransient bool              `json:"is_transient"`
	Taints      []TaintInfo       `json:"taints,omitempty"`
	Assignments []FieldAssignment `json:"assignments,omitempty"`
	Reads       []FieldRead       `json:"reads,omitempty"`
	// ConfigSource 冒泡该字段的赋值来源是否为配置文件（A1 引擎侧扩展）。
	// 优先取 ResolveFieldValue 的配置源语义；否则由 Taints 中的配置值污点源推导。
	// 为空表示非配置来源。additive 字段，不破 EngineQuerier 契约（FieldInfo 为 engine 内部结构）。
	ConfigSource string `json:"config_source,omitempty"`
}

func (q *QueryService) QueryField(cn, fn string) *FieldInfo {
	k := cn + "." + fn
	fd, ok := q.store.Fields.Defs[k]
	if !ok {
		return nil
	}
	fi := &FieldInfo{Key: k, Definition: fd, Type: fd.TypeName, IsStatic: q.store.Fields.IsStatic[k], IsTransient: q.store.Fields.IsTransient[k], Taints: q.store.Fields.Taints[k], Assignments: q.store.Fields.Assignments[k], Reads: q.store.Fields.Reads[k]}
	// A1：冒泡配置源。优先用已解析的配置值贡献（@Value/@ConfigurationProperties），
	// 否则由字段污点源中的配置值标记推导，使 QueryField 返回的 FieldInfo 能体现
	// "赋值来源=配置文件"，满足文档 A1 判据。
	if contrib := q.ResolveFieldValue(cn, fn); contrib != nil && contrib.Source != "" {
		fi.ConfigSource = contrib.Source
	} else {
		for _, t := range fi.Taints {
			if t.SourceType == TaintSrcConfigValue {
				fi.ConfigSource = "config_value"
				break
			}
		}
	}
	return fi
}

func (q *QueryService) ResolveFieldValue(cn, fn string) *FieldValueContribution {
	return NewFieldValueResolver().Resolve(q.store, NewTypeResolver(q.store), cn, fn)
}

func (q *QueryService) Stats() string {
	var b strings.Builder
	b.WriteString("=== 分析统计 ===\n")
	b.WriteString("类: " + itoa(len(q.store.Types.ClassAnnotations)) + "\n")
	b.WriteString("方法: " + itoa(len(q.store.Methods.Functions)) + "\n")
	b.WriteString("字段: " + itoa(len(q.store.Fields.Defs)) + "\n")
	b.WriteString("入口点: " + itoa(len(q.store.Calls.EntryPoints)) + "\n")
	b.WriteString("调用边: " + itoa(countEdges(q.store.Calls.Edges)) + "\n")
	b.WriteString("反向调用边: " + itoa(countReverseEdges(q.store.Calls.ReverseEdges)) + "\n")
	b.WriteString("污点字段: " + itoa(len(q.store.Fields.Taints)) + "\n")
	b.WriteString("污点参数: " + itoa(len(q.store.Methods.ParamTaints)) + "\n")
	b.WriteString("污点返回: " + itoa(len(q.store.Methods.ReturnTaints)) + "\n")
	return b.String()
}

func countEdges(m map[string][]CallEdge) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}
func countReverseEdges(m map[string][]ReverseEdge) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

func (q *QueryService) methodFP(mk string) string {
	if fn, ok := q.store.Methods.Functions[mk]; ok {
		return fn.FilePath
	}
	return ""
}
func (q *QueryService) methodLine(mk string) int {
	if fn, ok := q.store.Methods.Functions[mk]; ok {
		return fn.Line
	}
	return 0
}
func (q *QueryService) methodSrcs(mk string) []string {
	seen := make(map[string]bool)
	var s []string
	add := func(src string) {
		if src == "" || seen[src] {
			return
		}
		seen[src] = true
		s = append(s, src)
	}
	for _, src := range q.store.Methods.ReturnTaints[mk] {
		add(src)
	}
	for _, pts := range q.store.Methods.ParamTaints[mk] {
		for _, src := range pts {
			add(src)
		}
	}
	// D-R16c 修复：纳入方法内局部变量 source（如 `raw = req.getParameter(...)`）。
	// 原逻辑仅看 ParamTaints/ReturnTaints，使"source 为局部变量"的字段污点链
	// 在反向 DFS 走到 entry 时 methodSrcs 空、不 append 任何 trace，导致
	// TraceToSources 反推 Path 为空、切片无中间节点/无污点高亮。安全判定不受影响。
	for _, lv := range q.store.Methods.LocalVars[mk] {
		for _, src := range lv.Sources {
			add(src)
		}
	}
	return s
}
func cpNodes(n []CallNode) []CallNode { out := make([]CallNode, len(n)); copy(out, n); return out }

// ============================================================
//  QueryService 辅助方法（镜像 7.py:4081-4114）
// ============================================================

// GetTaintForCallEdge 获取调用边的污点信息（镜像 7.py:4081-4088）。
// 返回 "参数N <- source" 格式字符串，无污点则返回空串。
func (q *QueryService) GetTaintForCallEdge(callerKey, calleeClass, calleeMethod string) string {
	var taints []string
	for _, cpt := range q.store.Calls.CallParamTaints {
		if cpt.CallerKey == callerKey && cpt.CalleeClass == calleeClass && cpt.CalleeMethod == calleeMethod {
			taints = append(taints, fmt.Sprintf("参数%d <- %s", cpt.ParamIndex, cpt.TaintSource))
		}
	}
	return strings.Join(taints, ", ")
}

// GetFieldModifiers 返回字段的修改器列表（镜像 7.py:4096-4114）。
func (q *QueryService) GetFieldModifiers(fieldKey string) []FieldAssignment {
	return q.store.Fields.Assignments[fieldKey]
}

// GetFieldEffectiveInitialValue 返回字段有效初始值字符串（镜像 7.py:4090-4091）。
// 委托 FieldValueResolver 链解析，取 Value 字段；无则兜底从 Defs 取 InitText。
func (q *QueryService) GetFieldEffectiveInitialValue(fieldKey string) string {
	if i := strings.LastIndex(fieldKey, "."); i > 0 {
		cn, fn := fieldKey[:i], fieldKey[i+1:]
		if contrib := q.fieldResolver.Resolve(q.store, NewTypeResolver(q.store), cn, fn); contrib != nil {
			return contrib.Value
		}
	}
	if def, ok := q.store.Fields.Defs[fieldKey]; ok && def.InitText != "" {
		return def.InitText
	}
	return ""
}

// GetEffectiveValueSummary 返回字段有效值摘要（薄包装，镜像 7.py:4093-4094）。
func (q *QueryService) GetEffectiveValueSummary(fieldKey string) string {
	if i := strings.LastIndex(fieldKey, "."); i > 0 {
		cn, fn := fieldKey[:i], fieldKey[i+1:]
		return q.fieldResolver.GetEffectiveValueSummary(q.store, NewTypeResolver(q.store), cn, fn)
	}
	return ""
}

// ============================================================
//  G2 — 变量级污点查询（方法内局部变量，不追跨方法传播）
// ============================================================

// TraceVarFlow 回答"第 line 行（位于 file 中）的变量 varName 被什么污染、
// 该污点后续经哪些方法传播、最终流入哪个危险 sink"。
//
// 引擎是方法级污点图，局部变量污点由 bodycollector 在变量声明点播种，
// 存于 store.Methods.LocalVars[methodKey][varName]。
// G01（第二十六轮）升级：在 D4 一层传导（DownstreamSinks）之上，
// 新增变量级完整数据流——沿调用图做有界正向 DFS，仅当调用边在 CallParamTaints
// 中携带污点实参（污点真正沿该边传播，见 U05 多层穿透证据）才继续深入，
// 命中危险 sink 时记录完整 FlowPath（变量 -> 多层传播 -> sink），
// 使空白 AI 单调用即可还原深层链路（验收②/③核心）。
//
// 定位策略：file 做后缀匹配（容忍路径前缀差异），在匹配方法中取 line >= 方法
// 声明行且最接近的一条。这是只读查询，O(方法数) 单次可接受。
func (q *QueryService) TraceVarFlow(file string, line int, varName string) VarFlowResult {
	// 1) 定位 methodKey：file 后缀匹配 + line 落在方法体内
	normFile := normalizePath(file)
	var bestKey string
	bestDelta := int(^uint(0) >> 1) // 最大 int
	for mk, fn := range q.store.Methods.Functions {
		if fn.FilePath == "" || !strings.HasSuffix(normFile, normalizePath(fn.FilePath)) {
			continue
		}
		if line < fn.Line {
			continue
		}
		delta := line - fn.Line
		if delta < bestDelta {
			bestDelta = delta
			bestKey = mk
		}
	}
	if bestKey == "" {
		return VarFlowResult{Found: false, Message: "未在该文件/行定位到任何方法，无法查询变量污点"}
	}
	// 2) 查 LocalVars
	vars := q.store.Methods.LocalVars[bestKey]
	lv, ok := vars[varName]
	if !ok {
		return VarFlowResult{
			Found:     false,
			MethodKey: bestKey,
			VarName:   varName,
			Message:   "该方法已解析，但变量未出现在污点局部变量表中（可能非 source、未被追踪，或行号/变量名不匹配）",
		}
	}
	res := VarFlowResult{
		Found:     true,
		MethodKey: bestKey,
		VarName:   varName,
		DeclLine:  lv.Line,
		Type:      lv.Type,
		InitText:  lv.InitText,
		Tainted:   lv.Tainted,
		Sources:   lv.Sources,
	}
	if lv.Tainted {
		if len(lv.Sources) > 0 {
			res.Message = fmt.Sprintf("变量 %s（第 %d 行）被污点污染，source 类型：%s。",
				varName, lv.Line, strings.Join(lv.Sources, ", "))
		} else {
			res.Message = fmt.Sprintf("变量 %s（第 %d 行）被污点污染（无显式 source 类型）。",
				varName, lv.Line)
		}
	} else {
		res.Message = fmt.Sprintf("变量 %s（第 %d 行）未被污点标记。", varName, lv.Line)
	}
	// G4-3/D4：填充变量所属方法直接可达的危险sink（一层传导），使空白AI
	// 直接获得「变量->sink」证据，无需二次推理（验收②核心）。
	if q.store.Calls != nil && q.store.Calls.Edges != nil {
		if edges, ok := q.store.Calls.Edges[bestKey]; ok {
			for _, e := range edges {
				if IsDangerousSink(e.CalleeClass, e.CalleeMethod) {
					vuln, cwe := SinkVulnType(e.CalleeClass, e.CalleeMethod)
					res.DownstreamSinks = append(res.DownstreamSinks, SinkHit{
						CalleeClass:  e.CalleeClass,
						CalleeMethod: e.CalleeMethod,
						VulnType:     vuln,
						CWE:          cwe,
						Line:         e.Line,
						FilePath:     e.FilePath,
					})
				}
			}
			if len(res.DownstreamSinks) > 0 {
				res.Message += fmt.Sprintf(" 变量所属方法直接可达危险sink %d 个（G4-3变量级链路）。",
					len(res.DownstreamSinks))
			}
		}
	}
	// G01（第二十六轮，第二十八轮去重/最短优先优化）：变量级完整数据流——从变量声明点
	// （污点变量所在方法）出发，沿调用图做有界正向 DFS（推进口径与 CallerHasDangerousSink
	// 一致，跟进所有出边），仅当到达危险 sink 才记录完整链路。返回后做「路径签名去重 +
	// hop 数升序（最短路径优先）」处理，过滤真实仓稠密调用图产生的冗余路径。
	res.FlowPath = dedupeAndSortFlowPaths(q.varFlowReachSink(bestKey, lv.Tainted, make(map[string]bool), 0, nil))
	if len(res.FlowPath) > 0 {
		shortest := len(res.FlowPath[0])
		var sinkTypes []string
		for _, p := range res.FlowPath {
			if last := p[len(p)-1]; last.SinkVuln != "" {
				sinkTypes = append(sinkTypes, last.SinkVuln)
			}
		}
		res.Message += fmt.Sprintf(" 变量级完整数据流：污点经 %d 条去重路径传播至危险sink（G01），最短链路 %d 跳，sink 类型：%s。",
			len(res.FlowPath), shortest, strings.Join(sinkTypes, "/"))
	}
	return res
}

// varFlowReachSink 从持有污点的方法 mk 出发，沿调用图做有界正向 DFS，
// 收集污点最终流入危险 sink 的传播路径。
//
// 推进口径与 CallerHasDangerousSink 完全一致：跟进 mk 的所有出边（无条件过滤），
// 仅当到达危险 sink（IsDangerousSink）才将该 hop 记录为路径终点（VarFlowHop.SinkVuln
// 非空）。这与 U05 多层危险判定口径对齐——真实仓中污点沿调用边传播的播种
// （CallParamTaints）并不完整（跨模块/RPC 边常缺失），若用 edgeCarriesTaint 过滤会
// 导致链路在第一跳即断裂、漏报多层变量流；而"仅到达 sink 才记录"已能保证不谎报
// （未到 sink 的普通调用链不进入 FlowPath）。起点守卫 `tainted` 保证 FlowPath 仅从
// 被污点变量声明的方法启动，保留 G01 变量级语义。
// 非 sink 的外部方法（calleeKeys 返回空）停止本支，不编造路径。
// flowPathKey 生成一条完整路径的规范化签名（hop 序列），用于去重。
func flowPathKey(path []VarFlowHop) string {
	var b strings.Builder
	for i, h := range path {
		if i > 0 {
			b.WriteByte('>')
		}
		b.WriteString(h.FromMethod)
		b.WriteByte('#')
		b.WriteString(h.ToClass)
		b.WriteByte('.')
		b.WriteString(h.ToMethod)
	}
	return b.String()
}

// dedupeAndSortFlowPaths 对完整路径去重，并按 hop 数升序（最短路径优先）排序，
// 使空白 AI 优先看到最短、最有价值的「变量 -> ... -> sink」链路，过滤 G01 真实仓
// 稠密调用图产生的 1441 条冗余路径（第二十七轮盲测发现）。
func dedupeAndSortFlowPaths(paths [][]VarFlowHop) [][]VarFlowHop {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(paths))
	uniq := make([][]VarFlowHop, 0, len(paths))
	for _, p := range paths {
		if len(p) == 0 {
			continue
		}
		k := flowPathKey(p)
		if seen[k] {
			continue
		}
		seen[k] = true
		// 复制，避免与 DFS 内部共享底层数组
		cp := make([]VarFlowHop, len(p))
		copy(cp, p)
		uniq = append(uniq, cp)
	}
	// 最短路径优先：hop 数少的排前面；相同长度保持稳定（按插入序）。
	sort.SliceStable(uniq, func(i, j int) bool {
		return len(uniq[i]) < len(uniq[j])
	})
	return uniq
}

func (q *QueryService) varFlowReachSink(mk string, tainted bool, visited map[string]bool, depth int, path []VarFlowHop) [][]VarFlowHop {
	const maxFlowPaths = 500 // 完整路径收集上限，防止稠密调用图组合爆炸（G01 真实仓盲测发现）
	if !tainted {
		return nil
	}
	if depth > maxSinkReachDepth {
		return nil
	}
	if visited[mk] {
		return nil
	}
	visited[mk] = true
	defer func() { visited[mk] = false }() // 允许路径分叉复用同一方法的不同子链

	if q.store.Calls == nil || q.store.Calls.Edges == nil {
		return nil
	}
	edges, ok := q.store.Calls.Edges[mk]
	if !ok {
		return nil
	}
	var paths [][]VarFlowHop
	for _, e := range edges {
		if len(paths) >= maxFlowPaths {
			break
		}
		// 被调方法自身即危险 sink -> 一条完整路径（以 sink hop 结尾）
		if IsDangerousSink(e.CalleeClass, e.CalleeMethod) {
			vuln, cwe := SinkVulnType(e.CalleeClass, e.CalleeMethod)
			hop := VarFlowHop{
				FromMethod: mk,
				CallLine:   e.Line,
				CallFile:   e.FilePath,
				ToClass:    e.CalleeClass,
				ToMethod:   e.CalleeMethod,
				SinkVuln:   vuln,
				SinkCWE:    cwe,
			}
			full := append(append([]VarFlowHop{}, path...), hop)
			paths = append(paths, full)
			continue
		}
		// 递归深入被调方法（污点已进入该方法，故 tainted=true）。
		// 用 calleeKeys(e) 获取被调方法键（与 CallerHasDangerousSink 同口径，
		// 含接口实现映射 + prefix 匹配 + Methods.Functions fallback），
		// 修复真实仓 calleeKeyFor 因 MethodNameIndex 缺失返回空导致 DFS 断裂。
		cks := q.calleeKeys(e)
		if len(cks) == 0 {
			// 被调方法不在本仓（外部/stdlib），若自身即 sink 已在上文处理；
			// 非 sink 的外部方法无内部调用图可深入，停止本支。
			continue
		}
		subPath := append(append([]VarFlowHop{}, path...), VarFlowHop{
			FromMethod: mk,
			CallLine:   e.Line,
			CallFile:   e.FilePath,
			ToClass:    e.CalleeClass,
			ToMethod:   e.CalleeMethod,
		})
		for _, calleeMK := range cks {
			sub := q.varFlowReachSink(calleeMK, true, visited, depth+1, subPath)
			paths = append(paths, sub...)
		}
	}
	return paths
}

// normalizePath 统一路径分隔符便于后缀匹配。
func normalizePath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// ============================================================
//  B2 — 断点补齐（交互式数据流搜索）
// ============================================================

// Breakpoint 描述一个未解析调用（数据流断裂点），结构化供 AI 补齐。
type Breakpoint struct {
	CalleePattern      string           `json:"callee_pattern"`          // 断裂点符号（Class.method）
	CallType           CallType         `json:"call_type"`               // 调用类别
	Callers            []BreakCaller    `json:"callers"`                 // 调用该符号的位点
	ResolvedCandidates []MethodDef      `json:"resolved_candidates"`     // 全局索引命中的候选定义
	Ambiguous          bool             `json:"ambiguous,omitempty"`     // 重载导致调用方无法唯一判定
	Candidates         []string         `json:"candidates,omitempty"`    // 重载签名列表
	RPCInterface       *RPCInterfaceDef `json:"rpc_interface,omitempty"` // G4-1：RPC 断点附加的仓内接口定义
}

// VarFlowResult 是 TraceVarFlow 的返回值：回答"第 N 行这个变量被什么污染、
// 该污点后续经哪些方法传播、最终流入哪个危险 sink"。
// G01（第二十六轮）：在 D4 一层传导（DownstreamSinks）基础上，升级为
// 变量级完整数据流（多层跨方法）——FlowPath 记录「变量声明点 -> 多层传播 -> sink」
// 的完整链路，使空白 AI 单调用即可还原深层链路（验收②/③核心）。
type VarFlowResult struct {
	Found     bool     `json:"found"`                // 是否定位到该方法的该变量
	MethodKey string   `json:"method_key,omitempty"` // 变量所属方法
	VarName   string   `json:"var_name,omitempty"`   // 变量名
	DeclLine  int      `json:"decl_line,omitempty"`  // 变量声明行
	Type      string   `json:"type,omitempty"`       // 变量类型
	InitText  string   `json:"init_text,omitempty"`  // 声明/初始化文本
	Tainted   bool     `json:"tainted"`              // 是否带污点
	Sources   []string `json:"sources,omitempty"`    // 污点 source 类型（如 HttpRequest.getParameter）
	Message   string   `json:"message,omitempty"`    // 人类可读说明（AI 友好）
	// G4-3/D4：变量所属方法直接可达的危险sink（一层传导，基于 Edges + sinkDict）。
	// 向后兼容字段，令空白AI无需二次推理即可获得「变量->sink」直接证据（验收②核心）。
	DownstreamSinks []SinkHit `json:"downstream_sinks,omitempty"`
	// G01（第二十六轮，第二十八轮去重/最短优先优化）：变量级完整数据流的多层传播路径。
	// 每条子切片即一条「变量 -> ... -> sink」完整链路（以标记 SinkVuln 的 hop 结尾）；
	// 多条表示变量污点经不同调用链汇流到不同危险 sink。
	// 已按「路径签名去重 + hop 数升序（最短路径优先）」处理，供空白 AI 优先还原最短链路。
	FlowPath [][]VarFlowHop `json:"flow_path,omitempty"`
}

// SinkHit 是变量所属方法直接调用的危险sink信息（G4-3/D4）。
type SinkHit struct {
	CalleeClass  string `json:"callee_class"`  // sink 方法所在类
	CalleeMethod string `json:"callee_method"` // sink 方法名
	VulnType     string `json:"vuln_type"`     // 漏洞类型（如 command_injection）
	CWE          string `json:"cwe,omitempty"`
	Line         int    `json:"line,omitempty"`      // §8: downstream_sink 行号锚点
	FilePath     string `json:"file_path,omitempty"` // §8: downstream_sink 文件锚点
}

// VarFlowHop 描述变量污点传播路径上的一跳（G01）。
// FromMethod 是当前持有污点的方法；它调用了 ToClass.ToMethod（位于 CallLine / CallFile），
// 污点经该调用边的实参传播到被调方法。若被调方法自身即危险 sink，则 SinkVuln 非空。
type VarFlowHop struct {
	FromMethod string `json:"from_method"`         // 持有污点、发起调用的方法键
	CallLine   int    `json:"call_line,omitempty"` // 调用发生行
	CallFile   string `json:"call_file,omitempty"` // 调用所在文件
	ToClass    string `json:"to_class"`            // 被调类
	ToMethod   string `json:"to_method"`           // 被调方法（含签名）
	SinkVuln   string `json:"sink_vuln,omitempty"` // 非空表示该 hop 即为危险 sink（漏洞类型）
	SinkCWE    string `json:"sink_cwe,omitempty"`  // sink 对应 CWE
}

// RPCInterfaceDef 是 G4-1 断点聚合时附加的仓内 RPC 接口定义信息，
// 让 AI 在单仓范围内基于接口契约推理，无需跨仓索引。
type RPCInterfaceDef struct {
	Class       string   `json:"class"`                 // 接口类（如 com.example.UserClient）
	Method      string   `json:"method"`                // 方法名
	Annotations []string `json:"annotations,omitempty"` // 关键注解（@FeignClient(name=user-service) 等）
	HTTPPath    string   `json:"http_path,omitempty"`   // 拼接出的完整 HTTP 路径（类+方法映射）
	HTTPMethod  string   `json:"http_method,omitempty"` // GET/POST/...
	Params      []string `json:"params,omitempty"`      // 方法参数签名（类型列表）
	SourceFile  string   `json:"source_file,omitempty"` // 接口定义源文件
	Line        int      `json:"line,omitempty"`        // 接口方法定义行
}

// BreakCaller 是调用断裂点的具体位点。
type BreakCaller struct {
	CallerKey string   `json:"caller_key"`
	Line      int      `json:"line"`
	FilePath  string   `json:"file_path"`
	CallType  CallType `json:"call_type"`
}

// MethodDef 是全局索引解析出的方法定义位置。
type MethodDef struct {
	MethodKey string `json:"method_key"`
	Class     string `json:"class"`
	Method    string `json:"method"`
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
	IsEntry   bool   `json:"is_entry"`
}

// ListBreakpoints 返回某方法键的未解析调用断点（数据流断裂点），
// 含结构化 call_type 与全局索引候选定义（前提#2）。
func (q *QueryService) ListBreakpoints(mk string) []Breakpoint {
	simpleKey := mk
	if idx := strings.Index(mk, "("); idx > 0 {
		simpleKey = mk[:idx]
	}
	edges := q.store.Calls.UnresolvedReverseEdges[simpleKey]
	if len(edges) == 0 {
		return nil
	}
	// 按 callee_pattern 归并
	byPattern := make(map[string][]ReverseEdge)
	for _, e := range edges {
		// UnresolvedReverseEdges 的 key 是 pattern，但这里 edge 本身不带 pattern；
		// 用 caller 无法反推 pattern，故改为以 simpleKey 作为 callee_pattern 聚合。
		byPattern[simpleKey] = append(byPattern[simpleKey], e)
	}
	var bps []Breakpoint
	for pattern, es := range byPattern {
		bp := Breakpoint{CalleePattern: pattern}
		ct := CallUnresolved
		for _, e := range es {
			bp.Callers = append(bp.Callers, BreakCaller{CallerKey: e.CallerKey, Line: e.Line, FilePath: e.FilePath, CallType: e.CallType})
			if e.CallType != "" {
				ct = e.CallType
			}
		}
		bp.CallType = ct
		// 全局索引解析候选定义
		for _, cand := range q.resolveSymbolToDefs(pattern) {
			bp.ResolvedCandidates = append(bp.ResolvedCandidates, cand)
		}
		// G4-2b：简名未直接匹配时，尝试以 caller 的 outer class 推导嵌套类全名
		// （如 caller=RpcCallTemplate.execute → outer=RpcCallTemplate，拼 RpcCallTemplate$Remote.invoke）。
		// 通用规则：从 caller FQN 推导 outer 前缀，不硬编码特定符号。
		if len(bp.ResolvedCandidates) == 0 {
			for _, e := range es {
				outer := callerOuterClass(e.CallerKey)
				if outer == "" {
					continue
				}
				nested := outer + "$" + pattern
				for _, cand := range q.resolveSymbolToDefs(nested) {
					bp.ResolvedCandidates = append(bp.ResolvedCandidates, cand)
				}
				if len(bp.ResolvedCandidates) > 0 {
					break
				}
			}
		}
		// G4-2：若断点实际在仓内有可解析定义（ResolvedCandidates 非空），
		// 则非真断裂点——重分类为 interface，消除「既标 unresolved 又给定义」的自相矛盾（F08）。
		// 通用规则：有仓内定义即非 unresolved，不依赖特定符号硬编码。
		if bp.CallType == CallUnresolved && len(bp.ResolvedCandidates) > 0 {
			bp.CallType = CallInterface
		}
		// G4-1：RPC 类断点附加仓内接口定义，让 AI 基于契约推理
		if ct == CallRPCFeign || ct == CallRPCDubbo || ct == CallRPCGrpc {
			if def := q.resolveRPCInterface(pattern); def != nil {
				bp.RPCInterface = def
			}
		}
		bps = append(bps, bp)
	}
	return bps
}

// ListCallBreakpoints 返回某 caller 方法「自身的调用断点」（caller 视角），
// 即该方法内部存在但静态无法闭合的出边（反射/动态代理/未解析/接口多态/RPC/native 黑盒）。
// 与 ListBreakpoints（callee→callers，用于上游补全）互补：本函数供 AI 在审 caller 方法时，
// 直接拿到「这个方法里有哪些断链调用」清单，无需 grep 即可补齐残缺流（R13 核心能力）。
func (q *QueryService) ListCallBreakpoints(callerMk string) []Breakpoint {
	edges := q.store.Calls.Edges[callerMk]
	if len(edges) == 0 {
		return nil
	}
	// 断裂类别：反射/代理/未解析/接口/RPC/native。native 仅当污点流入时标断裂。
	brokenTypes := map[CallType]bool{
		CallReflection: true, CallDynamicProxy: true, CallUnresolved: true,
		CallInterface: true, CallRPCFeign: true, CallRPCDubbo: true, CallRPCGrpc: true,
	}
	taintedNative := q.callerHasTaintedNativeEdge(callerMk)
	var bps []Breakpoint
	for _, e := range edges {
		isBroken := brokenTypes[e.CallType]
		if e.CallType == CallNative && taintedNative {
			isBroken = true
		}
		// 容错：callee 不在仓内 Methods 定义中、且非标准库，也视作断裂未解析
		if !isBroken && !isStdlibClass(e.CalleeClass) {
			if _, inRepo := q.store.Indices.MethodNameIndex[e.CalleeClass+"."+e.CalleeMethod]; !inRepo {
				isBroken = true
			}
		}
		if !isBroken {
			continue
		}
		pattern := e.CalleeClass + "." + e.CalleeMethod
		bp := Breakpoint{
			CalleePattern: pattern,
			CallType:      e.CallType,
			Callers:       []BreakCaller{{CallerKey: callerMk, Line: e.Line, FilePath: e.FilePath, CallType: e.CallType}},
		}
		for _, cand := range q.resolveSymbolToDefs(pattern) {
			bp.ResolvedCandidates = append(bp.ResolvedCandidates, cand)
		}
		// native 黑盒无仓内定义，跳过 RPC 接口附加
		bps = append(bps, bp)
	}
	return bps
}

// CallerHasDangerousSink 报告某方法是否「直接调用了危险 sink」（G4-3/D3 迭代）。
// 验收③核心：仅Sink场景下，方法自身不在 sinkDict，但其调用链含危险sink——
// 空白AI需识别该方法为漏洞入口。通用规则：遍历 Edges[mk] 的 callee 用 IsDangerousSink 判定。
//
// 第三轮(R06补强)增强：第4返回值 reason 给出负结论成因枚举，让空白AI区分
// 「真安全」(VERIFIED_SAFE) 与「动态分发导致静态不可确认」(REFLECTION_UNRESOLVED /
// DYNAMIC_PROXY_UNRESOLVED / LAMBDA_UNTRACED)。架构级字段，覆盖所有 caller，无 per-method 特判。
type SinkReachReason string

const (
	ReasonVerifiedSafe         SinkReachReason = "VERIFIED_SAFE"              // 无危险sink且无私解析动态边
	ReasonReflectionUnresolved SinkReachReason = "REFLECTION_UNRESOLVED"      // 含反射边(如Method.invoke)指向未确认callee
	ReasonProxyUnresolved      SinkReachReason = "DYNAMIC_PROXY_UNRESOLVED"   // 含动态代理/接口未解析边
	ReasonNativeUnresolved     SinkReachReason = "NATIVE_BLACKBOX_UNRESOLVED" // 含 JNI native 边且污点流入黑盒（R12）
	ReasonLambdaUntraced       SinkReachReason = "LAMBDA_UNTRACED"            // 含lambda/匿名类未追踪边
	ReasonDangerHit            SinkReachReason = "DANGER_HIT"                 // 命中危险sink
	ReasonSinkSelf             SinkReachReason = "SINK_SELF"                  // 方法自身即已注册危险sink（纯Sink入口点）
	ReasonIndirectDanger       SinkReachReason = "INDIRECT_DANGER"            // 经中间方法间接可达危险sink（U05:source->中间层->sink）
	// R19 修复：调用图 DFS 因深度封顶（maxSinkReachDepth）未能探明下游时，
	// 结论降级为 DEPTH_TRUNCATED 而非 VERIFIED_SAFE，使「深递归/长链导致引擎
	// depth 钳制截断漏报」可被上层（sim/空白AI）识别为「未探明」而非「真安全」，
	// 避免静默漏报。命中（true）优先级不变，仅影响「未命中」结论的可观测性。
	ReasonDepthTruncated SinkReachReason = "DEPTH_TRUNCATED"
)

// maxSinkReachDepth 是 CallerHasDangerousSink 递归遍历调用图时的深度上限，
// 防环 + 控复杂度（Java 调用图可达性本就是污点前向传播目标，深度封顶即够）。
const maxSinkReachDepth = 24

// CallerHasDangerousSink 判断某方法是否「可达危险 sink」——包含三层（U05 架构修正）：
//  1. 自身即 sink（ReasonSinkSelf，纯Sink入口点）；
//  2. 直接调用边命中 sinkDict（ReasonDangerHit，单层直接边）；
//  3. 经中间方法间接可达 sink（ReasonIndirectDanger，递归下游传播）。
//
// 修复前仅做 1+2（单层），对「source -> 中间方法 -> sink」的间接链路（如
// UserController.upload -> GenericRepo.persist -> RpcCallTemplate.execute）
// 完全漏判为 VERIFIED_SAFE（U05 实体化）。修复后用全局 visited 防环 DFS，
// 将下游可达的危险 sink 沿调用图向上游传播，使中间层与最外层入口均被正确判定。
// 注意：本函数只回答「可达性」，不回答「污点是否真正流入」；后者由
// CallerDangerWithSources 的 taintConfirmed（SourceTrace 必须存在）第二闸把关。
func (q *QueryService) CallerHasDangerousSink(mk string) (bool, string, string, SinkReachReason) {
	truncated := false
	return q.callerHasDangerousSinkDFS(mk, 0, make(map[string]bool), &truncated)
}

// IsTestMethod 返回该方法是否位于测试代码（R12 架构级标记）。供输出层对测试代码的
// 危险命中降权/排除，避免 AI 脚手架被测试代码中的危险调用淹没（不破坏 sink 判定口径）。
func (q *QueryService) IsTestMethod(mk string) bool {
	return q.store.Methods.TestCodeMethods[mk]
}

// callerHasDangerousSinkDFS 递归遍历调用图判定 mk 是否可达危险 sink。
// truncated 指针贯穿整棵 DFS 树：任意路径因深度封顶（maxSinkReachDepth）未能探明
// 下游时置位。命中（true）优先级不变；仅当整树探完且未命中时，若 truncated 为真，
// 最终结论降级为 ReasonDepthTruncated（R19：深链截断不再静默伪装成 VERIFIED_SAFE）。
func (q *QueryService) callerHasDangerousSinkDFS(mk string, depth int, visited map[string]bool, truncated *bool) (bool, string, string, SinkReachReason) {
	if depth > maxSinkReachDepth {
		// R19：深度封顶，本路径下游未探明——标记截断但不影响已命中结论。
		if truncated != nil {
			*truncated = true
		}
		return false, "", "", ReasonVerifiedSafe
	}
	if visited[mk] {
		return false, "", "", ReasonVerifiedSafe
	}
	visited[mk] = true // 全局去重防环：一条路径命中即结论成立，无需回溯复用

	// 1) 自身即 sink（纯Sink入口点）
	if cls, m := methodClassMethod(mk); cls != "" {
		if idx := strings.Index(m, "("); idx >= 0 {
			m = m[:idx]
		}
		fq := cls + "." + m
		if e, ok := sinkDict[fq]; ok && !e.Benign {
			return true, e.VulnType, e.CWE, ReasonSinkSelf
		}
		// R08：Mapper 接口方法自身即 MyBatis 注解 SQL 拼接 sink（如直接查询 Mapper 方法）
		if v, c, ok := q.myBatisAnnoSink(cls, m); ok {
			return true, v, c, ReasonSinkSelf
		}
		// R10：Mapper 接口方法自身即 MyBatis XML mapper ${...} 拼接 sink
		if v, c, ok := q.xmlMapperSink(cls, m); ok {
			return true, v, c, ReasonSinkSelf
		}
	}

	edges, ok := q.store.Calls.Edges[mk]
	if !ok {
		return false, "", "", ReasonVerifiedSafe
	}
	hasUnresolved := false
	var directVulns, directCwes []string     // 直接边命中（DANGER_HIT）
	var indirectVulns, indirectCwes []string // 经中间方法递归命中（INDIRECT_DANGER）
	for _, e := range edges {
		// 修正B：直接边命中危险sink
		if IsDangerousSink(e.CalleeClass, e.CalleeMethod) {
			// R09：JPA/Hibernate SQL sink 需 SQL 字符串实参含污点拼接才危险
			// （区分「字符串拼接注入」与「参数化查询 setParameter 绑定」——后者安全，不过宽）。
			if q.isJPASQLSink(e.CalleeClass, e.CalleeMethod) && !q.callHasTaintedSQLArg(mk, e.CalleeClass, e.CalleeMethod) {
				continue
			}
			vuln, cwe := SinkVulnType(e.CalleeClass, e.CalleeMethod)
			directVulns = append(directVulns, vuln)
			directCwes = append(directCwes, cwe)
			continue
		}
		// R08：直接边命中 MyBatis 注解 SQL 拼接 sink（Mapper 接口方法，SQL 在注解里）。
		// 这是 R08 的核心闭环点：Controller -> mapper.xxx(${...} 拼接) 经此被识别为 sql_injection。
		if v, c, ok := q.myBatisAnnoSink(e.CalleeClass, e.CalleeMethod); ok {
			directVulns = append(directVulns, v)
			directCwes = append(directCwes, c)
			continue
		}
		// R10：直接边命中 MyBatis XML mapper ${...} 拼接 sink（Mapper 接口方法，SQL 在 xml 里）。
		if v, c, ok := q.xmlMapperSink(e.CalleeClass, e.CalleeMethod); ok {
			directVulns = append(directVulns, v)
			directCwes = append(directCwes, c)
			continue
		}
		// 修正B（架构级）：未解析/接口/合成边的 target 可能是"已注册危险sink"
		// （如 RpcCallTemplate$Remote.invoke 经 Method.invoke 提升），需二次sink匹配，
		// 避免纯Sink+跨模块RPC被误判 VERIFIED_SAFE（规则8降级掩盖实体化）。
		switch e.CallType {
		case CallReflection, CallDynamicProxy, CallUnresolved, CallInterface, CallRPCFeign, CallRPCDubbo, CallRPCGrpc:
			hasUnresolved = true
			if v, c := SinkVulnType(e.CalleeClass, e.CalleeMethod); v != "" {
				if IsDangerousSink(e.CalleeClass, e.CalleeMethod) {
					directVulns = append(directVulns, v)
					directCwes = append(directCwes, c)
				}
			}
		// R12：native 方法（JNI 黑盒）边——污点流入黑盒时标为「流入黑盒未确认」，
		// 避免 secret 经 native 逃逸被误判 VERIFIED_SAFE。仅当该 native 调用实参
		// 携带污点（CallParamTaints 命中）才升级未确认，防止无污点场景误报。
		case CallNative:
			if q.callerHasTaintedNativeEdge(mk) {
				hasUnresolved = true
			}
		}
		// U05 架构修正：对未直接命中的 callee 递归查询其下游是否可达危险 sink。
		// 这使「source -> 中间方法 -> sink」的间接链路被正确传播（如
		// UserController.upload -> GenericRepo.persist -> RpcCallTemplate.execute）。
		// 仅当 callee 自身非直接 sink 时下沉递归，避免与直接命中重复计数。
		for _, ck := range q.calleeKeys(e) {
			if dh, dv, dc, _ := q.callerHasDangerousSinkDFS(ck, depth+1, visited, truncated); dh {
				indirectVulns = append(indirectVulns, dv)
				indirectCwes = append(indirectCwes, dc)
			}
		}
	}
	// 修正A：累积所有命中sink，并列输出（多sink标签不再被首个压制，R17/B4）
	if len(directVulns) > 0 {
		seen := map[string]bool{}
		var uniqV, uniqC []string
		for i, v := range directVulns {
			if seen[v] {
				continue
			}
			seen[v] = true
			uniqV = append(uniqV, v)
			uniqC = append(uniqC, directCwes[i])
		}
		return true, strings.Join(uniqV, "+"), strings.Join(uniqC, "+"), ReasonDangerHit
	}
	if len(indirectVulns) > 0 {
		seen := map[string]bool{}
		var uniqV, uniqC []string
		for i, v := range indirectVulns {
			if seen[v] {
				continue
			}
			seen[v] = true
			uniqV = append(uniqV, v)
			uniqC = append(uniqC, indirectCwes[i])
		}
		return true, strings.Join(uniqV, "+"), strings.Join(uniqC, "+"), ReasonIndirectDanger
	}
	if hasUnresolved {
		// 进一步细分：反射边优先标反射，其次代理，其次通用未解析
		if q.callerHasEdgeType(mk, CallReflection) {
			return false, "", "", ReasonReflectionUnresolved
		}
		if q.callerHasEdgeType(mk, CallDynamicProxy) || q.callerHasEdgeType(mk, CallInterface) {
			return false, "", "", ReasonProxyUnresolved
		}
		if q.callerHasTaintedNativeEdge(mk) {
			return false, "", "", ReasonNativeUnresolved
		}
		return false, "", "", ReasonLambdaUntraced
	}
	// R19：整树探完且未命中。若 DFS 过程曾因深度封顶未探明下游，则结论降级为
	// DEPTH_TRUNCATED（未探明），而非 VERIFIED_SAFE（真安全），避免深链截断静默漏报。
	// 命中（true）已在上方提前返回，故此分支仅决定「未命中」结论的可观测语义。
	if truncated != nil && *truncated {
		return false, "", "", ReasonDepthTruncated
	}
	return false, "", "", ReasonVerifiedSafe
}

// calleeKeys 由一条调用边推断其 callee 在 Edges/Functions 中的完整方法键集合。
// CallEdge 仅含 CalleeClass/CalleeMethod（无参数签名），而 Edges 键为
// Class.method(Sig) 全限定形式。处理方式：
//  1. 先试 Class.method 简键直接查（无重载时恰好命中）；
//  2. 否则按 Class.method( 前缀匹配所有签名重载（Java 重载/泛型擦除场景）。
//
// 返回空表示 callee 无定义/无出边（递归自然终止为 safe）。
func (q *QueryService) calleeKeys(e CallEdge) []string {
	exact := e.CalleeClass + "." + e.CalleeMethod
	if _, ok := q.store.Calls.Edges[exact]; ok {
		return []string{exact}
	}
	prefix := exact + "("
	// 直接查前缀索引（O(匹配数)），替代原先遍历整个 Edges/Functions 的 O(全仓) 扫描。
	if keys, ok := q.methodPrefixIndex[prefix]; ok {
		return keys
	}
	return nil
}

// CallerDangerWithSources 在 CallerHasDangerousSink 的危险判定之上，附加上
// 反向追踪到的「污点来源链路」（source/入口点 -> ... -> 本sink方法）。
// 架构级闭环补全（修复C）：纯Sink/多sink场景下，引擎不仅告知"方法是危险sink"，
// 还输出"谁把污点传进来"，使空白AI Agent 无需grep即可确认 source->...->sink 可达性闭环。
// 复用现有 TraceToSources 反向DFS，不改图算法稳定性。
func (q *QueryService) CallerDangerWithSources(mk string, maxDepth int) (bool, string, string, SinkReachReason, []SourceTrace) {
	hit, vuln, cwe, reason := q.CallerHasDangerousSink(mk)
	if !hit {
		return false, "", "", reason, nil
	}
	traces := q.TraceToSources(mk, maxDepth)
	return true, vuln, cwe, reason, traces
}

// ReachableSinks 返回 mk 经调用图可达的所有「危险 sink 方法键」集合（含直接边命中
// 与经中间方法间接可达，U05 消费层补全用）。供 sim 层在 INDIRECT_DANGER 场景下把
// 下游真实 sink（如 RpcSink.execute -> Runtime.exec）填入 SinkTrace，使 source->...->sink
// 闭环对空白AI可见，避免 indirect 链路被反推为 partial（仅 source 侧）而无法闭环。
// 基于与 CallerHasDangerousSink 相同的防环 DFS，保证口径一致。
func (q *QueryService) ReachableSinks(mk string) []string {
	visited := make(map[string]bool)
	var out []string
	truncated := false
	q.reachableSinksDFS(mk, 0, visited, &out, &truncated)
	_ = truncated // R19：截断状态暂仅内部标记，供后续 sim 消费（ReachableSinks 返回已收集到的 sink）
	// 去重且排除自身（自身若即 sink 由调用方自行判定）
	seen := map[string]bool{}
	var uniq []string
	for _, s := range out {
		if s == mk || seen[s] {
			continue
		}
		seen[s] = true
		uniq = append(uniq, s)
	}
	return uniq
}

// reachableSinksDFS 递归收集 mk 前向可达的危险 sink 方法键。truncated 指针贯穿整树：
// 任意路径因深度封顶未探明下游时置位，供调用方（如 sim）区分「已穷尽」与「被 depth 截断」。
func (q *QueryService) reachableSinksDFS(mk string, depth int, visited map[string]bool, out *[]string, truncated *bool) {
	if depth > maxSinkReachDepth {
		if truncated != nil {
			*truncated = true
		}
		return
	}
	if visited[mk] {
		return
	}
	visited[mk] = true
	// 自身即 sink
	if cls, m := methodClassMethod(mk); cls != "" {
		if idx := strings.Index(m, "("); idx >= 0 {
			m = m[:idx]
		}
		if e, ok := sinkDict[cls+"."+m]; ok && !e.Benign {
			*out = append(*out, mk)
		}
	}
	for _, e := range q.store.Calls.Edges[mk] {
		if IsDangerousSink(e.CalleeClass, e.CalleeMethod) {
			*out = append(*out, e.CalleeClass+"."+e.CalleeMethod)
			continue
		}
		// R08：MyBatis 注解 SQL 拼接 sink 也计入可达 sink（供 sim 补全 SinkTrace）
		if v, _, ok := q.myBatisAnnoSink(e.CalleeClass, e.CalleeMethod); ok && v != "" {
			*out = append(*out, e.CalleeClass+"."+e.CalleeMethod)
			continue
		}
		// R10：MyBatis XML mapper ${...} 拼接 sink 也计入可达 sink
		if v, _, ok := q.xmlMapperSink(e.CalleeClass, e.CalleeMethod); ok && v != "" {
			*out = append(*out, e.CalleeClass+"."+e.CalleeMethod)
			continue
		}
		for _, ck := range q.calleeKeys(e) {
			q.reachableSinksDFS(ck, depth+1, visited, out, truncated)
		}
	}
}

// callerHasEdgeType 判断 caller 是否含有指定 call_type 的调用边。
func (q *QueryService) callerHasEdgeType(mk string, ct CallType) bool {
	for _, e := range q.store.Calls.Edges[mk] {
		if e.CallType == ct {
			return true
		}
	}
	return false
}

// callerHasTaintedNativeEdge 报告 caller 方法是否存在「污点流入 native 黑盒」的边。
// 仅当该 native 调用的实参携带污点（CallParamTaints 命中相同 caller+callee）才返回 true，
// 避免无污点场景（如 native 调用纯字面量）被误判为未确认（R12 精准化，不误报）。
func (q *QueryService) callerHasTaintedNativeEdge(mk string) bool {
	tainted := map[string]bool{}
	for _, pt := range q.store.Calls.CallParamTaints {
		if pt.CallerKey == mk && pt.TaintSource != "" {
			tainted[pt.CalleeClass+"."+pt.CalleeMethod] = true
		}
	}
	for _, e := range q.store.Calls.Edges[mk] {
		if e.CallType == CallNative && tainted[e.CalleeClass+"."+e.CalleeMethod] {
			return true
		}
	}
	return false
}

// ============================================================
//  R08 — MyBatis 注解 SQL sink 判定
//  Mapper 接口方法上的 @Select/@Update/@Insert/@Delete 把 SQL 文本写在注解里，
//  其 ${...} 直接拼接即 SQL 注入 sink（CWE-89），而 #{...} 预编译参数非 sink。
//  解析层（extractor.collectAnnotationInfo）已把 SQL 文本存入
//  Methods.Annotations[mk].Params["_value"]，缺口在「sink 判定层未消费该注解」。
// ============================================================

// mybatisAnnoNames 是 MyBatis 直接写 SQL 的注解集合。
var mybatisAnnoNames = map[string]bool{
	"Select":         true,
	"Update":         true,
	"Insert":         true,
	"Delete":         true,
	"SelectProvider": false, // provider 方法体间接生成 SQL，不在此直接判定
	"UpdateProvider": false,
	"InsertProvider": false,
	"DeleteProvider": false,
}

// reSQLConcat 匹配 MyBatis ${...} 直接拼接占位符（SQL 注入风险点）。
// 与 #{...}（预编译参数，安全）严格区分。
var reSQLConcat = regexp.MustCompile(`\$\{[^}]*\}`)

// myBatisAnnoSink 判定 callee（class.method）是否为 MyBatis 注解 SQL 拼接 sink。
// 返回 (vulnType, cwe, ok)。ok=true 表示命中危险 sink（含 ${...} 拼接的 SQL）。
// 仅当注解 SQL 文本中存在 ${...} 直接拼接才判 sink——#{...} 预编译 SQL 不判，避免过宽（F1）。
func (q *QueryService) myBatisAnnoSink(calleeClass, calleeMethod string) (string, string, bool) {
	if calleeClass == "" || calleeMethod == "" {
		return "", "", false
	}
	prefix := calleeClass + "." + calleeMethod + "("
	// 注解以全签名方法键存储（如 UserMapper.findByDynamic(String)），按前缀匹配
	for mk, anns := range q.store.Methods.Annotations {
		if mk != calleeClass+"."+calleeMethod && !strings.HasPrefix(mk, prefix) {
			continue
		}
		for _, ann := range anns {
			if !mybatisAnnoNames[ann.Name] {
				continue
			}
			sql := ann.Params["_value"]
			if sql == "" {
				continue
			}
			// 仅 ${...} 直接拼接判为 sink；纯 #{...} 预编译 SQL 不判
			if reSQLConcat.MatchString(sql) {
				return "sql_injection", "CWE-89", true
			}
		}
	}
	return "", "", false
}

// isJPASQLSink 判断 callee 是否为 JPA/Hibernate 的 SQL 执行 API（R09）。
// 仅收录标准 SQL 执行方法（createQuery/createNativeQuery/createSQLQuery），不收录宽泛 execute，
// 避免 D1 误判。
func (q *QueryService) isJPASQLSink(calleeClass, calleeMethod string) bool {
	switch calleeMethod {
	case "createQuery", "createNativeQuery", "createSQLQuery":
		return strings.Contains(calleeClass, "EntityManager") || strings.Contains(calleeClass, "Session")
	}
	return false
}

// callHasTaintedSQLArg 判断 mk 方法对 (calleeClass.calleeMethod) 的 SQL 字符串实参（第0参）
// 是否含污点（来自 source 拼接）。R09 不过宽护栏：仅当 SQL 字符串含污点拼接才判危险，
// 区分「字符串拼接注入」与「参数化查询(setParameter 绑定)」。数据来自 bodycollector 已持久化的
// store.Calls.CallParamTaints。
func (q *QueryService) callHasTaintedSQLArg(mk, calleeClass, calleeMethod string) bool {
	for _, pt := range q.store.Calls.CallParamTaints {
		if pt.CallerKey == mk && pt.CalleeClass == calleeClass && pt.CalleeMethod == calleeMethod && pt.ParamIndex == 0 && pt.TaintSource != "" {
			return true
		}
	}
	return false
}

// myBatisAnnoSinkByKey 是 myBatisAnnoSink 的 MethodKey 重载版本（自身即 sink 判定用）。
func (q *QueryService) myBatisAnnoSinkByKey(mk string) (string, string, bool) {
	cls, m := methodClassMethod(mk)
	if idx := strings.Index(m, "("); idx >= 0 {
		m = m[:idx]
	}
	return q.myBatisAnnoSink(cls, m)
}

// MyBatisAnnoSink 是 myBatisAnnoSink 的导出版本，供 sim 消费层（deepQuery）补全
// MyBatis 注解 SQL 拼接 sink 证据使用，避免 sim 私有字典与引擎漂移。
func (q *QueryService) MyBatisAnnoSink(calleeClass, calleeMethod string) (string, string, bool) {
	return q.myBatisAnnoSink(calleeClass, calleeMethod)
}

// xmlMapperSink 判定 callee（class.method）是否对应 MyBatis XML mapper 中 ${...} 拼接的
// 危险 statement（R10）。返回 (vulnType, cwe, ok)。
//  1. 直接边命中 Mapper 接口方法时，calleeClass 是短类名（如 UserMapper），calleeMethod 是方法名，
//     用 store.XmlMappers[shortClass.id] 查（解析层已同时写入 namespace.id 与 shortClass.id 双向键）；
//  2. 仅当该 statement SQL 含 ${...} 直接拼接才判 sink——纯 #{...} 预编译 SQL 不判，避免过宽。
func (q *QueryService) xmlMapperSink(calleeClass, calleeMethod string) (string, string, bool) {
	if calleeClass == "" || calleeMethod == "" {
		return "", "", false
	}
	// 去掉可能的签名后缀（calleeMethod 可能形如 findByName(String)）
	method := calleeMethod
	if idx := strings.Index(method, "("); idx >= 0 {
		method = method[:idx]
	}
	// 先按 shortClass.id 查（与调用图 Mapper 接口方法键对齐），再回退全限定 namespace.id
	for _, key := range []string{calleeClass + "." + method, q.xmlNamespaceKey(calleeClass, method)} {
		if stmt, ok := q.store.XmlMappers[key]; ok && stmt.HasConcat {
			return "sql_injection", "CWE-89", true
		}
	}
	return "", "", false
}

// xmlNamespaceKey 由短类名反推全限定 key：遍历 XmlMappers 找 ShortClass 匹配项（R10 兜底）。
// 多数场景 shortClass.id 已直接命中，本函数仅用于 namespace 为全限定但调用边用短类的极端错位。
func (q *QueryService) xmlNamespaceKey(shortClass, method string) string {
	for k, stmt := range q.store.XmlMappers {
		if stmt.ShortClass == shortClass && stmt.Id == method {
			return k
		}
	}
	return shortClass + "." + method
}

// XmlMapperSink 是 xmlMapperSink 的导出版本，供 sim 层 deepQuery 补全 XML mapper sink 证据，
// 与 MyBatisAnnoSink 同口径，避免 sim 私有字典漂移。
func (q *QueryService) XmlMapperSink(calleeClass, calleeMethod string) (string, string, bool) {
	return q.xmlMapperSink(calleeClass, calleeMethod)
}

// MapperSqlInfo 返回 callee(class.method)对应 MyBatis XML mapper 的 SQL 文本 +
// ${}/#{ 参数名列表(供 adapter GetMapperSql 富化 reachable_sinks)。found=false =
// 非 mapper 或 store 无该 mapper 数据(GR-8 不编)。查找口径同 xmlMapperSink 双 key。
// 扩展点:另一个模型增强 MyBatis 能力(如 per-param source binding)后此返回变丰富,
// reachable_sinks 自动受益,LLM 侧零改动(见 tools-standard-and-taint-capability-design §4)。
func (q *QueryService) MapperSqlInfo(calleeClass, calleeMethod string) (sqlText string, concatParams, safeParams []string, found bool) {
	if calleeClass == "" || calleeMethod == "" {
		return
	}
	method := calleeMethod
	if idx := strings.Index(method, "("); idx >= 0 {
		method = method[:idx]
	}
	for _, key := range []string{calleeClass + "." + method, q.xmlNamespaceKey(calleeClass, method)} {
		if stmt, ok := q.store.XmlMappers[key]; ok {
			concatParams, safeParams = extractXmlParams(stmt.SQLText)
			return stmt.SQLText, concatParams, safeParams, true
		}
	}
	return
}

// UnresolvedCallees 返回 caller 的「未解析/动态分发出口边」结构化清单（R06补强）。
// 挂接在 caller 结论对象上，使全局边界统计与具体方法一一对应，空白AI可据此外推
// 将"带动态边的 hit:false"归类为「需补充运行时/动态信息」，而非直接判安全。
func (q *QueryService) UnresolvedCallees(mk string) []UnresolvedCallee {
	edges, ok := q.store.Calls.Edges[mk]
	if !ok {
		return nil
	}
	var out []UnresolvedCallee
	for _, e := range edges {
		switch e.CallType {
		case CallReflection, CallDynamicProxy, CallUnresolved, CallInterface, CallRPCFeign, CallRPCDubbo, CallRPCGrpc:
			out = append(out, UnresolvedCallee{
				Target:   e.CalleeClass + "." + e.CalleeMethod,
				Kind:     string(e.CallType),
				Line:     e.Line,
				FilePath: e.FilePath,
			})
		}
	}
	return out
}

// UnresolvedCallee 是 caller 的一条动态/未解析出口边（结构化，供 prompt 复用）。
type UnresolvedCallee struct {
	Target   string `json:"target"`
	Kind     string `json:"kind"` // reflection / proxy / unresolved / interface / lambda
	Line     int    `json:"line"`
	FilePath string `json:"file_path"`
}

// callerOuterClass 从 CallerKey（如 RpcCallTemplate.execute(String) 或
// RpcCallTemplate$Remote.invoke(String)）解析其 outer class 名，用于推导
// 嵌套类候选全名（G4-2b）。规则：取首个 '(' 前的签名，再取最后一个 '.' 前的
// class 段；若含 '$' 则取 '$' 前 outer（RpcCallTemplate$Remote → RpcCallTemplate）。
func callerOuterClass(callerKey string) string {
	sig := callerKey
	if idx := strings.Index(callerKey, "("); idx > 0 {
		sig = callerKey[:idx]
	}
	dot := strings.LastIndex(sig, ".")
	if dot < 0 {
		return ""
	}
	cls := sig[:dot]
	if idx := strings.Index(cls, "$"); idx > 0 {
		return cls[:idx]
	}
	return cls
}

// resolveSymbolToDefs 用全局索引将符号解析为方法定义列表（前提#1）。
func (q *QueryService) resolveSymbolToDefs(symbol string) []MethodDef {
	var defs []MethodDef
	seen := make(map[string]bool)
	for _, mk := range q.store.SearchMethodsByPattern(symbol, 20) {
		if seen[mk] {
			continue
		}
		seen[mk] = true
		d := MethodDef{MethodKey: mk, IsEntry: q.store.Calls.EntryPoints[mk]}
		if fn, ok := q.store.Methods.Functions[mk]; ok {
			d.Class, d.Method, d.Line, d.FilePath = fn.Class, fn.Method, fn.Line, fn.FilePath
		}
		defs = append(defs, d)
	}
	return defs
}

// resolveRPCInterface 为 G4-1 服务：依据断裂点 pattern（class.method）从仓内已
// 解析数据拼出 RPC 接口定义。仅依赖单仓数据（类/方法注解、HTTP path、参数、源码位置），
// 不跨仓加载对端实现。无对应仓内定义时返回 nil。
func (q *QueryService) resolveRPCInterface(pattern string) *RPCInterfaceDef {
	i := strings.LastIndex(pattern, ".")
	if i <= 0 {
		return nil
	}
	class, method := pattern[:i], pattern[i+1:]
	methodKey := pattern
	def := &RPCInterfaceDef{Class: class, Method: method}

	// 注解
	var anns []string
	for _, ann := range q.store.Types.ClassAnnotations[class] {
		anns = append(anns, ann.Short())
	}
	for _, ann := range q.store.Methods.Annotations[methodKey] {
		anns = append(anns, ann.Short())
	}
	def.Annotations = anns

	// HTTP 路径：优先用已解析的 entry point path；否则按 类@RequestMapping + 方法映射 拼接
	if p, ok := q.store.Calls.HttpPaths[methodKey]; ok && p != "" {
		def.HTTPPath = p
		def.HTTPMethod = q.store.Calls.HttpMethods[methodKey]
	} else {
		classPath, methodPath, httpMethod := "", "", ""
		for _, ann := range q.store.Types.ClassAnnotations[class] {
			if ann.Name == "RequestMapping" {
				classPath = annParamsPath(ann)
			}
		}
		for _, ann := range q.store.Methods.Annotations[methodKey] {
			switch ann.Name {
			case "GetMapping":
				httpMethod, methodPath = "GET", annParamsPath(ann)
			case "PostMapping":
				httpMethod, methodPath = "POST", annParamsPath(ann)
			case "PutMapping":
				httpMethod, methodPath = "PUT", annParamsPath(ann)
			case "DeleteMapping":
				httpMethod, methodPath = "DELETE", annParamsPath(ann)
			case "PatchMapping":
				httpMethod, methodPath = "PATCH", annParamsPath(ann)
			case "RequestMapping":
				if methodPath == "" {
					methodPath = annParamsPath(ann)
				}
				if httpMethod == "" {
					if m := ann.Params["method"]; m != "" {
						httpMethod = strings.ToUpper(strings.Trim(m, "[]\""))
					}
				}
			}
		}
		def.HTTPPath = strings.TrimSuffix(classPath, "/") + "/" + strings.TrimPrefix(methodPath, "/")
		def.HTTPPath = strings.Trim(def.HTTPPath, "/")
		def.HTTPMethod = httpMethod
	}

	// 参数（按声明顺序）
	if po := q.store.Methods.ParamOrder[methodKey]; len(po) > 0 {
		names := make([]string, len(po))
		for name, idx := range po {
			if idx >= 0 && idx < len(names) {
				names[idx] = name
			}
		}
		def.Params = names
	}

	// 源码位置
	if fn, ok := q.store.Methods.Functions[methodKey]; ok {
		def.SourceFile = fn.FilePath
		def.Line = fn.Line
	}
	return def
}

// annParamsPath 从注解参数中取 path/value/_value（RequestMapping 系）。
func annParamsPath(ann Annotation) string {
	for _, k := range []string{"path", "value", "_value"} {
		if v := ann.Params[k]; v != "" {
			return strings.Trim(v, "[]\"")
		}
	}
	return ""
}

// stringLastDotSplit 拆分 class.method（保留兼容）。
func stringLastDotSplit(s string) (string, string) {
	i := strings.LastIndex(s, ".")
	if i <= 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// SymbolTrace 是 TraceFromSymbol 的返回值：符号→候选定义→直接调用方（单层）。
type SymbolTrace struct {
	Symbol     string        `json:"symbol"`
	Defs       []MethodDef   `json:"defs"`
	Callers    []BreakCaller `json:"callers"` // 仅一层，不递归（前提#3）
	MaxDepth   int           `json:"max_depth"`
	Ambiguous  bool          `json:"ambiguous,omitempty"`  // 任一候选定义命中重载，调用方无法唯一判定
	Candidates []string      `json:"candidates,omitempty"` // 重载签名列表
}

// TraceFromSymbol 解析符号到方法定义，并沿调用方做单步（maxDepth 默认 1，
// 绝不自动递归）向上追溯，填补数据流断裂（前提#3）。
//
// 语义：maxDepth 控制"向上追几层调用方"。默认 1 = 仅直接调用方一层，绝不
// 自动递归无限。更高深度做有界链式展开（安全上限 3），同样不递归。
// 若符号在本仓库无法解析为定义（跨模块/反射等），则回退到
// UnresolvedReverseEdges 中记录的断裂点调用方（单层），保证至少给出断点位点。
func (q *QueryService) TraceFromSymbol(symbol string, maxDepth int) SymbolTrace {
	if maxDepth <= 0 {
		maxDepth = 1
	} // 默认单步，绝不自动递归
	callerDepth := maxDepth
	if callerDepth > 3 {
		callerDepth = 3
	} // 安全上限，避免爆炸
	st := SymbolTrace{Symbol: symbol, MaxDepth: callerDepth}
	defs := q.resolveSymbolToDefs(symbol)
	st.Defs = defs

	seenCaller := make(map[string]bool)
	// 有界 BFS：从起始调用方出发，向上追 callerDepth 层，绝不无限递归。
	type item struct {
		re    ReverseEdge
		depth int
	}
	var queue []item
	if len(defs) > 0 {
		for _, d := range defs {
			cqr := q.GetCallersRobust(d.MethodKey)
			if cqr.Ambiguous {
				st.Ambiguous = true
				st.Candidates = append(st.Candidates, cqr.Candidates...)
			}
			for _, re := range cqr.Edges {
				queue = append(queue, item{re, 1})
			}
		}
	} else {
		// 符号未解析：回退到断裂点记录的调用方（单层）
		for _, re := range q.store.Calls.UnresolvedReverseEdges[symbol] {
			queue = append(queue, item{re, 1})
		}
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if it.depth > callerDepth {
			continue
		}
		key := fmt.Sprintf("%s|%d|%s", it.re.CallerKey, it.re.Line, it.re.FilePath)
		if seenCaller[key] {
			continue
		}
		seenCaller[key] = true
		st.Callers = append(st.Callers, BreakCaller{
			CallerKey: it.re.CallerKey, Line: it.re.Line, FilePath: it.re.FilePath, CallType: it.re.CallType,
		})
		if it.depth+1 <= callerDepth {
			for _, up := range q.GetCallersRobust(it.re.CallerKey).Edges {
				queue = append(queue, item{up, it.depth + 1})
			}
		}
	}
	return st
}
