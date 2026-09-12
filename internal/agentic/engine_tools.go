package agentic

import "appsecgo/internal/taintbridge"

// engine 工具的 trace 反向链默认深度（透传 engine TraceToSourcesEx）。可调。
const defaultTraceMaxDepth = 8

// reachableSinksTool / traceToSourcesTool — JudgeTools() 条件追加的两件 schema（中文 description）。
var reachableSinksTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "reachable_sinks",
	"description": "给定一个方法，返回它经调用图能到达的所有危险 sink + 该方法自身的危险判定（是否危险入口/漏洞类型/CWE/reason）。多同名时返候选让你用 file_path 或 method_key 消歧重试。每个 sink 带 file_path/line 锚点（sink 定义位置）。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"function_name": map[string]any{"type": "string", "description": "要查的方法名"},
		"file_path":     map[string]any{"type": "string", "description": "可选,多同名时按文件消歧"},
		"method_key":    map[string]any{"type": "string", "description": "可选,重载歧义时回传系统给的 method_key"},
	}, "required": []string{"function_name"}},
}}

var traceToSourcesTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "trace_to_sources",
	"description": "给定一个 sink 方法，反向追溯它能否被外部输入(source/入口点)到达 + 链路。path[0]=sink 端、path[last]=source/entry 端，每跳带 file_path/line 锚点。多同名返候选消歧。exhausted_depth=true 时结果不可信。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"function_name": map[string]any{"type": "string", "description": "要查的方法名(sink)"},
		"file_path":     map[string]any{"type": "string", "description": "可选,多同名时按文件消歧"},
		"method_key":    map[string]any{"type": "string", "description": "可选,重载歧义时回传系统给的 method_key"},
	}, "required": []string{"function_name"}},
}}

var getCalleesTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "get_callees",
	"description": "给定一个方法,返回它经前向调用图能到达的所有被调方法(callee),分确定/不确定两组,带 file_path/line 调用位点锚点。has_method_dispatch=true 表示存在接口/动态分派(Definitive 不全)。truncated=true 表示深度封顶结果不全。多同名时返候选让你用 file_path 或 method_key 消歧重试。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"function_name": map[string]any{"type": "string", "description": "要查的方法名"},
		"file_path":     map[string]any{"type": "string", "description": "可选,多同名时按文件消歧"},
		"method_key":    map[string]any{"type": "string", "description": "可选,重载歧义时回传系统给的 method_key"},
	}, "required": []string{"function_name"}},
}}

var traceVarFlowTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "trace_var_flow",
	"description": "给定文件路径+行号+变量名,查该变量的污点来源(source 类型)+ 后续跨方法传播链(flow_path,每跳带 from_method/call_line/call_file/to_class/to_method,sink_vuln 非空表该跳即危险 sink)+ 一层传导可达的危险 sink(downstream_sinks 带 callee_class/callee_method/file_path/line/vuln_type/cwe)。用于还原变量→sink 完整数据流。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"file_path": map[string]any{"type": "string", "description": "变量所在文件路径"},
		"line":      map[string]any{"type": "integer", "description": "变量出现的行号"},
		"var_name":  map[string]any{"type": "string", "description": "变量名"},
	}, "required": []string{"file_path", "line", "var_name"}},
}}

var codeAtLineTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "code_at_line",
	"description": "给定文件路径+行号,返回该行所属方法的自包含代码片段(含类上下文)+ 行区间(start_line/end_line)。用于跨层查看任意 file:line 的方法体代码(如 callee 实现细节),与切片器(alert 数据流 curation)不同层不同职责。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"file_path": map[string]any{"type": "string", "description": "要查看的文件路径"},
		"line":      map[string]any{"type": "integer", "description": "行号"},
	}, "required": []string{"file_path", "line"}},
}}

// whoCallsTool — who_calls 工具 schema(反向可达链,judge loop 用)。description 仅输出语义;
// "何时调/教训锚"触发句落 §5 EngineToolsSuffix(用户 review),不混入 description(分离:① 描述 WHAT,§5 说 WHEN/WHY)。
var whoCallsTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "who_calls",
	"description": "给定一个方法(通常是 sink),反向查谁调它,返到生产入口的 caller 链(递归)。每跳带 file_path/line + is_entry(是否生产入口)/entry_type(http_endpoint/scheduled/message_listener/event_listener/container)/http_method/http_path/is_test(是否测试代码,标 true 但仍展示非过滤)/is_cycle;callers_truncated=本节点 breadth 上限砍掉的 caller 数(生产 caller 优先保留);顶层 truncated=深度封顶未穷尽(不代表无生产 caller,可能还有)。多同名返候选消歧。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"function_name": map[string]any{"type": "string", "description": "要查的方法名(通常是 sink)"},
		"file_path":     map[string]any{"type": "string", "description": "可选,多同名时按文件消歧"},
		"method_key":    map[string]any{"type": "string", "description": "可选,重载歧义时回传系统给的 method_key"},
	}, "required": []string{"function_name"}},
}}

// JudgeTools 条件化构造工具集（零回归 + 结构性优先）。
// engine==nil → 返静态 AgenticJudgeTools(5 件),字节同今天(parity/replay 不破,off/enrich 路径)。
// engine!=nil → engine 5 件置前 + escape 5 件置后;其中 search_definitions/read_function
// 带 [约束] 前缀强拦截(其 engine 替代 get_callees/code_at_line 此 on 路径可用,[约束] 才成立;
// off/enrich 路径不进此分支,用原静态 AgenticJudgeTools → get_callees 不可用时不误导)。
// 置前理由:LLM 工具选择对列表顺序敏感,engine 优先取前段(2026-08-19 实证 escape 在前被压用)。
// 顺序/前缀仅 on 路径(off DeepEqual AgenticJudgeTools 不破);cache key=messages 不含 tool schemas,
// 故 EngineToolsSuffix 的优先级锚定句是让本重排可被 cache 观测的必要 prompt delta(见 TOOLS_STANDARD §8-2)。
func (e *ToolExecutor) JudgeTools() []map[string]any {
	if e.engine == nil {
		return AgenticJudgeTools // 零回归基底
	}
	const sdPrefix = "[约束] engine 可用时禁止用本工具逐个追 callee/调用链——改用 get_callees 一步取全调用链。仅作 engine 返回无数据或查非代码产物时的兜底。 "
	const rfPrefix = "[约束] engine 可用时禁止用本工具读代码做污点/调用链研判——改用 code_at_line(看某行方法体)或 trace_var_flow(看变量流)。仅作兜底。 "
	out := make([]map[string]any, 0, len(AgenticJudgeTools)+5)
	out = append(out, reachableSinksTool, traceToSourcesTool, getCalleesTool, traceVarFlowTool, codeAtLineTool, whoCallsTool)
	out = append(out,
		cloneToolWithDesc(searchDefinitionsTool, sdPrefix),
		cloneToolWithDesc(readFunctionTool, rfPrefix),
		ReadTools[0], ReadTools[1], VerdictTool,
	)
	return out
}

// cloneToolWithDesc 返回 tool 的浅副本,其 function.description 替换为 prefix+原描述。
// 不改原静态 var(off/enrich 路径仍用原 description,字节不变 → 判据2 安全 + DRY:base 描述一处)。
// 仅克隆顶层 map + function 内层 map(设 description 所需),parameters 等深层共享(不被改)。
func cloneToolWithDesc(tool map[string]any, descPrefix string) map[string]any {
	fn, _ := tool["function"].(map[string]any)
	cloneFn := make(map[string]any, len(fn))
	for k, v := range fn {
		cloneFn[k] = v
	}
	if orig, ok := fn["description"].(string); ok {
		cloneFn["description"] = descPrefix + orig
	}
	out := make(map[string]any, len(tool))
	for k, v := range tool {
		out[k] = v
	}
	out["function"] = cloneFn
	return out
}

// reachableSinks 实现（组合 resolveMethodKey + engine.ReachableSinks）。
func (e *ToolExecutor) reachableSinks(args map[string]any) any {
	if e.engine == nil {
		return map[string]any{"error": "engine unavailable"}
	}
	mk, amb, found := e.resolveMethodKey(args)
	if !found {
		return map[string]any{"found": false}
	}
	if amb != nil {
		return amb // ambiguous,不跑下游
	}
	res, err := e.engine.ReachableSinks(mk)
	if err != nil {
		return map[string]any{"found": true, "method_key": mk, "error": err.Error()}
	}
	return map[string]any{
		"found":           res.Found,
		"method_key":      res.MethodKey,
		"dangerous":       res.Dangerous,
		"vuln_type":       res.VulnType, // 缺失→"UNKNOWN"(adapter 已填)
		"cwe":             res.CWE,
		"reason":          res.Reason,
		"reachable_sinks": toSinkMaps(res.ReachableSinks),
		"truncated":       res.Truncated,
	}
}

func (e *ToolExecutor) traceToSources(args map[string]any) any {
	if e.engine == nil {
		return map[string]any{"error": "engine unavailable"}
	}
	mk, amb, found := e.resolveMethodKey(args)
	if !found {
		return map[string]any{"found": false}
	}
	if amb != nil {
		return amb
	}
	res, err := e.engine.TraceToSources(mk, defaultTraceMaxDepth)
	if err != nil {
		return map[string]any{"found": true, "method_key": mk, "error": err.Error()}
	}
	return map[string]any{
		"found":           res.Found,
		"method_key":      res.MethodKey,
		"traces":          toTraceMaps(res.Traces),
		"exhausted_depth": res.ExhaustedDepth,
	}
}

func (e *ToolExecutor) getCallees(args map[string]any) any {
	if e.engine == nil {
		return map[string]any{"error": "engine unavailable"}
	}
	mk, amb, found := e.resolveMethodKey(args)
	if !found {
		return map[string]any{"found": false}
	}
	if amb != nil {
		return amb
	}
	res, err := e.engine.GetCallees(mk)
	if err != nil {
		return map[string]any{"found": true, "method_key": mk, "error": err.Error()}
	}
	return map[string]any{
		"found":               res.Found,
		"method_key":          res.MethodKey,
		"definitive":          toCalleeMaps(res.Definitive),
		"uncertain":           toCalleeMaps(res.Uncertain),
		"has_method_dispatch": res.HasMethodDispatch,
		"truncated":           res.Truncated,
	}
}

func (e *ToolExecutor) traceVarFlow(args map[string]any) any {
	if e.engine == nil {
		return map[string]any{"error": "engine unavailable"}
	}
	fp, _ := args["file_path"].(string)
	line := intArg(args, "line")
	vn, _ := args["var_name"].(string)
	if fp == "" || line == 0 || vn == "" {
		return map[string]any{"error": "file_path/line/var_name required"}
	}
	res, err := e.engine.TraceVarFlow(fp, line, vn)
	if err != nil {
		return map[string]any{"found": true, "error": err.Error()}
	}
	paths := make([][]map[string]any, 0, len(res.FlowPath))
	for _, p := range res.FlowPath {
		hops := make([]map[string]any, 0, len(p))
		for _, h := range p {
			hop := map[string]any{
				"from_method": h.FromMethod, "to_class": h.ToClass, "to_method": h.ToMethod,
			}
			if h.CallLine != 0 {
				hop["call_line"] = h.CallLine
			}
			if h.CallFile != "" {
				hop["call_file"] = h.CallFile
			}
			if h.SinkVuln != "" {
				hop["sink_vuln"] = h.SinkVuln
			}
			if h.SinkCWE != "" {
				hop["sink_cwe"] = h.SinkCWE
			}
			hops = append(hops, hop)
		}
		paths = append(paths, hops)
	}
	return map[string]any{
		"found":            res.Found,
		"method_key":       res.MethodKey,
		"var_name":         res.VarName,
		"decl_line":        res.DeclLine,
		"tainted":          res.Tainted,
		"sources":          res.Sources,
		"downstream_sinks": toDownstreamSinkMaps(res.DownstreamSinks),
		"flow_path":        paths,
		"message":          res.Message,
	}
}

func (e *ToolExecutor) codeAtLine(args map[string]any) any {
	if e.engine == nil {
		return map[string]any{"error": "engine unavailable"}
	}
	fp, _ := args["file_path"].(string)
	line := intArg(args, "line")
	if fp == "" || line == 0 {
		return map[string]any{"error": "file_path/line required"}
	}
	res, err := e.engine.CodeAtLine(fp, line)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{
		"method_body": res.MethodBody,
		"file_path":   res.FilePath,
		"start_line":  res.StartLine,
		"end_line":    res.EndLine,
		// class_context 留空时省略(决策4,不返空串占位)
	}
}

// whoCalls 实现(组合 resolveMethodKey + engine.WhoCallsChain)。maxDepth/maxCallersPerNode 透 0
// → engine 默认 4/5(LLM 不调深度/breadth,降误用;spec §10 默认值待 L5 实测调)。
func (e *ToolExecutor) whoCalls(args map[string]any) any {
	if e.engine == nil {
		return map[string]any{"error": "engine unavailable"}
	}
	mk, amb, found := e.resolveMethodKey(args)
	if !found {
		return map[string]any{"found": false}
	}
	if amb != nil {
		return amb // ambiguous,不跑下游
	}
	res, err := e.engine.WhoCallsChain(mk, 0, 0)
	if err != nil {
		return map[string]any{"found": true, "method_key": mk, "error": err.Error()}
	}
	return map[string]any{
		"found":      res.Found,
		"method_key": res.MethodKey,
		"root":       toCallerChainNodeMap(res.Root),
		"truncated":  res.Truncated,
	}
}

// toCallerChainNodeMap:CallerChainNode→map(条件渲染:空字段不出键,降噪;is_entry/is_test
// 恒出——anti-D1.2 信号 LLM 必须每节点可见)。callers 递归。GR-8 真值不编。
func toCallerChainNodeMap(n taintbridge.CallerChainNode) map[string]any {
	m := map[string]any{
		"method_key": n.MethodKey,
		"is_entry":   n.IsEntry,
		"is_test":    n.IsTest,
	}
	if n.FilePath != "" {
		m["file_path"] = n.FilePath
	}
	if n.Line != 0 {
		m["line"] = n.Line
	}
	if n.EntryType != "" {
		m["entry_type"] = n.EntryType
	}
	if n.HttpMethod != "" {
		m["http_method"] = n.HttpMethod
	}
	if n.HttpPath != "" {
		m["http_path"] = n.HttpPath
	}
	if len(n.ParamTaints) > 0 {
		m["param_taints"] = n.ParamTaints
	}
	if len(n.ReturnTaints) > 0 {
		m["return_taints"] = n.ReturnTaints
	}
	if n.IsCycle {
		m["is_cycle"] = n.IsCycle
	}
	if len(n.Callers) > 0 {
		cms := make([]map[string]any, 0, len(n.Callers))
		for _, c := range n.Callers {
			cms = append(cms, toCallerChainNodeMap(c))
		}
		m["callers"] = cms
	}
	if n.CallersTruncated > 0 {
		m["callers_truncated"] = n.CallersTruncated
	}
	return m
}

// toSinkMaps / toTraceMaps / toCalleeMaps：把 taintbridge 结构转 map[string]any(loop 存 toolLog result + marshal 喂 LLM)。
func toSinkMaps(sinks []taintbridge.ReachableSink) []map[string]any {
	out := make([]map[string]any, 0, len(sinks))
	for _, s := range sinks {
		m := map[string]any{
			"method_key": s.MethodKey, "file_path": s.FilePath, "line": s.Line,
			"vuln_type": s.VulnType, "cwe": s.CWE,
		}
		// MyBatis 专属(非 MyBatis sink 全空,不返键,LLM 不见)。融入 reachable_sinks(spec §3)。
		if s.SqlText != "" {
			m["sql_text"] = s.SqlText
		}
		if s.ParamStyle != "" {
			m["param_style"] = s.ParamStyle
		}
		if len(s.ConcatParams) > 0 {
			m["concat_params"] = s.ConcatParams
		}
		if len(s.SafeParams) > 0 {
			m["safe_params"] = s.SafeParams
		}
		out = append(out, m)
	}
	return out
}
func toTraceMaps(traces []taintbridge.Trace) []map[string]any {
	out := make([]map[string]any, 0, len(traces))
	for _, tr := range traces {
		hops := make([]map[string]any, 0, len(tr.Path))
		for _, h := range tr.Path {
			hop := map[string]any{
				"method_key": h.MethodKey, "file_path": h.FilePath, "line": h.Line,
			}
			if h.Role != "" {
				hop["role"] = h.Role
			}
			hops = append(hops, hop)
		}
		out = append(out, map[string]any{
			"sources":   tr.Sources,
			"path":      hops,
			"is_entry":  tr.IsEntry,
			"truncated": tr.Truncated,
		})
	}
	return out
}
func toCalleeMaps(callees []taintbridge.Callee) []map[string]any {
	out := make([]map[string]any, 0, len(callees))
	for _, c := range callees {
		out = append(out, map[string]any{
			"method_key": c.MethodKey, "file_path": c.FilePath, "line": c.Line,
		})
	}
	return out
}

func toDownstreamSinkMaps(sinks []taintbridge.DownstreamSink) []map[string]any {
	out := make([]map[string]any, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, map[string]any{
			"callee_class": s.CalleeClass, "callee_method": s.CalleeMethod,
			"file_path": s.FilePath, "line": s.Line,
			"vuln_type": s.VulnType, "cwe": s.CWE,
		})
	}
	return out
}

// intArg 从 args 取整数(LLM 可能传 float64 via JSON)。
func intArg(args map[string]any, key string) int {
	switch v := args[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}
