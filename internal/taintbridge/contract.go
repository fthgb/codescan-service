package taintbridge

// EngineQuerier 是 appsecgo 调用 taint 引擎的稳定契约面。
// appsecgo 全代码只依赖此 interface；唯一实现是 adapter.go（import appsecgo/taint/engine）。
// 铁律 D：换掉 taint-repo 只改 adapter.go，appsecgo 不动。
// nil 实现 = 引擎 off（JudgeTools 返原 5 件，Execute 返 engine unavailable）。
type EngineQuerier interface {
	// ResolveMethodKey 消歧闭环（跨所有 engine 工具共用）。
	// mk 非空 → 直用（系统句柄回传，不解析不猜）。
	// 否则 fn → 候选查询；0→Found=false；1→Found=true+MethodKey；多→file_path 消歧，
	// 仍多→Ambiguous=true + Candidates（不猜不跑下游，GR-8）。
	ResolveMethodKey(fn, filePath, mk string) (MethodKeyResolution, error)

	// ReachableSinks：输入方法 mk 经调用图能到达的所有危险 sink + 该方法自身危险判定。
	// per-sink file_path/line = sink **定义**位置（非 call-site）；vuln_type/cwe 缺失标 UNKNOWN。
	// Truncated = (Reason=="DEPTH_TRUNCATED")。
	ReachableSinks(mk string) (ReachableSinksResult, error)

	// TraceToSources：sink mk 反向追溯能否被外部输入(source/entry)到达 + 链路。
	// path[0]=sink 端、path[last]=source/entry 端。ExhaustedDepth=true 时结果不可信，显式标。
	TraceToSources(mk string, maxDepth int) (TraceResult, error)

	// GetCallees：输入方法 mk 经前向调用图能到达的所有 callee(确定 + 不确定)。
	// per-callee file_path/line = callee 调用位点锚点(§8 缺口1 CalleeRef.Line)。
	// has_method_dispatch=true 表示存在接口/动态分派,Definitive 不全;truncated=true 表示深度封顶。
	GetCallees(mk string) (GetCalleesResult, error)

	// TraceVarFlow：给定文件/行/变量,查该变量的污点来源 + 后续传播链 + 流入的危险 sink。
	// downstream_sinks 用 callee_class/callee_method(engine SinkHit 真值,不编 method_key,决策2)。
	// flow_path hop 保留 engine 全字段(不降维,决策3)。VulnType/CWE 缺失标 UNKNOWN。
	TraceVarFlow(filePath string, line int, varName string) (TraceVarFlowResult, error)

	// CodeAtLine：给定文件/行,返该行所属方法的自包含代码片段 + 行区间。
	// class_context 留空(engine BuildSelfContainedSliceRanged 把类上下文烘进 method_body,
	// 不单独暴露——决策4,不编)。start_line/end_line = §8 缺口3 真值。
	CodeAtLine(filePath string, line int) (CodeAtLineResult, error)

	// WhoCalls:输入方法 mk 反向查所有 caller(谁调它)。per-caller file_path/line = 调用位点。
	// Ambiguous/Candidates 走 engine CallerQueryResult 真值(不猜)。仅评估 harness (b) 用,不接 LLM。
	WhoCalls(mk string) (WhoCallsResult, error)
	// WhoCallsChain:输入方法 mk 反向查 caller 链(到生产入口),judge loop who_calls 工具用(非评估 (b))。
	// per-node 带 is_entry/entry_type/http_method/http_path/param_taints/return_taints/is_test/is_cycle
	// 标注(从 store 富化,FormatEntryPointInfo 同源,GR-8 真值不编;EntryPointType 是 string 别名无损)。
	// breadth cap(maxCallersPerNode,<=0→默认5)+ 深度封顶(maxDepth,<=0→默认4)**engine 侧建树时生效**
	// (非 adapter post-filter——防巨树先建后砍);caller 排序 (is_entry desc, is_test asc, method_key asc)
	// 保 entry payload 不被 cap 砍 + 确定性防 wobble(map 迭代非确定,砍前必排)。
	// is_test 标注 show-both 非过滤(反 D1.2:test caller 仍展示标 is_test=true;engine EntryPoint 集
	// 本排除 test 是 engine 事实非判断)。Truncated(深度未穷尽)/CallersTruncated(breadth 砍数)诚实标。
	WhoCallsChain(mk string, maxDepth, maxCallersPerNode int) (CallerChainResult, error)
	// ListBreakpoints:输入 mk,返该方法的调用断点(callee pattern + callers + resolved candidates)。
	// 仅评估 harness (b) 用,不接 LLM。
	ListBreakpoints(mk string) (BreakpointResult, error)
	// HasSanitizer:输入 mk + taintVar,查该变量路径上有无净化器 + 位置(Class.method:line)。
	// 仅评估 harness (b) 用,不接 LLM。
	HasSanitizer(mk, taintVar string) (SanitizerResult, error)
	// QueryField:输入 class + field,返字段定义/类型/taints/赋值点/读点/effective_value(二调组合)。
	// 仅评估 harness (b) 用,不接 LLM。
	QueryField(class, field string) (FieldQueryResult, error)

	// GetMapperSql:输入 Java Mapper 方法(cls.mth),返该 mapper 的 SQL 文本 + ${}/#{}
	// 参数绑定(参数名列表)。found=false = 非 mapper 或 engine 无该 mapper 数据(不编,GR-8)。
	// 仅 reachable_sinks 富化用(不接 LLM 独立工具——MyBatis 细节融入 sink 结果,LLM 侧零
	// tool 增加,见 spec §3/§4)。engine 扩展点:增强 MyBatis 能力后返回变丰富,LLM 零改动。
	GetMapperSql(cls, mth string) (MapperSqlResult, error)
}

// MethodKeyResolution — ResolveMethodKey 结果。Ambiguous=true 时 Candidates 非空、MethodKey 空。
type MethodKeyResolution struct {
	Found      bool        `json:"found"`
	MethodKey  string      `json:"method_key"`
	Ambiguous  bool        `json:"ambiguous"`
	Candidates []Candidate `json:"candidates,omitempty"`
}

// Candidate — 消歧候选。必带 file_path（消歧闭环）+ method_key（重载回传）。
// lines 为 [start,end]；引擎 FunctionInfo 仅知定义起始行，故为 [Line,Line] 退化区间（诚实，GR-8）。
type Candidate struct {
	MethodKey    string `json:"method_key"`
	FilePath     string `json:"file_path"`
	FunctionName string `json:"function_name"`
	ClassName    string `json:"class_name"`
	Lines        []int  `json:"lines"`
}

// ReachableSinksResult — reachable_sinks 工具返回。reason 顶层，per-sink 仅 vuln_type/cwe。
type ReachableSinksResult struct {
	Found          bool            `json:"found"`
	MethodKey      string          `json:"method_key"`
	Dangerous      bool            `json:"dangerous"`
	VulnType       string          `json:"vuln_type"` // 缺失→"UNKNOWN"
	CWE            string          `json:"cwe"`       // 缺失→"UNKNOWN"
	Reason         string          `json:"reason"`    // DANGER_HIT/INDIRECT_DANGER/.../DEPTH_TRUNCATED
	ReachableSinks []ReachableSink `json:"reachable_sinks"`
	Truncated      bool            `json:"truncated"` // = (Reason=="DEPTH_TRUNCATED")
}

// ReachableSink — 单个可达 sink。file_path/line = sink 定义位置。
// MyBatis 专属字段(GetMapperSql found 才填,非 MyBatis sink 全空):融入 reachable_sinks,
// LLM 一次调用得 sink + SQL 文本 + 参数绑定,不需独立 inspect_mapper_sql tool(见 spec §3)。
type ReachableSink struct {
	MethodKey string `json:"method_key"`
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
	VulnType  string `json:"vuln_type"` // 缺失→"UNKNOWN"
	CWE       string `json:"cwe"`
	// MyBatis 专属(omitempty,非 MyBatis sink 不返)。adapter ReachableSinks 富化时:
	// GetMapperSql found→填;并覆 VulnType/CWE=sql_injection/CWE-89(修 SinkVulnType 不含
	// MyBatis 致原 lossy UNKNOWN,GR-8:engine 已判 sql_injection,DTO 应如实)。
	SqlText      string   `json:"sql_text,omitempty"`      // "SELECT ... WHERE id=${id} AND name=#{name}"
	ParamStyle   string   `json:"param_style,omitempty"`   // "concat"=有${} / "mixed"=${}+#{} 混用
	ConcatParams []string `json:"concat_params,omitempty"` // ${} 参数名(危险)— ["id"]
	SafeParams   []string `json:"safe_params,omitempty"`   // #{} 参数名(参数化)— ["name"]
}

// TraceResult — trace_to_sources 工具返回。
type TraceResult struct {
	Found          bool    `json:"found"`
	MethodKey      string  `json:"method_key"`
	Traces         []Trace `json:"traces"`
	ExhaustedDepth bool    `json:"exhausted_depth"` // true→结果不可信，显式标
}

// Trace — 单条反向链。path[0]=sink 端，path[last]=source/entry 端。
type Trace struct {
	Sources   []string   `json:"sources"`
	Path      []TraceHop `json:"path"`
	IsEntry   bool       `json:"is_entry"`
	Truncated bool       `json:"truncated"`
}

// TraceHop — 链上一跳。必带 method_key/file_path/line 锚点（从 CallNode 取真值）。
// Role 仅当引擎 CallNode 暴露 role 时映射；引擎 CallNode 无 role（types.go:174），故恒 ""。
type TraceHop struct {
	MethodKey string `json:"method_key"`
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
	Role      string `json:"role,omitempty"`
}

// GetCalleesResult — get_callees 工具返回。
// CalleeRef.Name 是 reachability 构造的 callee 标识(来自 call edge pattern,reachability.go:75);
// 若非 canonical method_key(带 sig),AI 下游消歧可能需二次 resolve——engine 现状真值,不编(GR-8 决策1)。
type GetCalleesResult struct {
	Found             bool     `json:"found"`
	MethodKey         string   `json:"method_key"`
	Definitive        []Callee `json:"definitive"`
	Uncertain         []Callee `json:"uncertain"`
	HasMethodDispatch bool     `json:"has_method_dispatch"`
	Truncated         bool     `json:"truncated"`
}

// Callee — 单个可达 callee。method_key = CalleeRef.Name;line/file_path = §8 缺口1 真值。
type Callee struct {
	MethodKey string `json:"method_key"`
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
}

// TraceVarFlowResult — trace_var_flow 工具返回。
// downstream_sinks:engine SinkHit 给 callee_class/callee_method(无 method_key),DTO 不编(决策2)。
// flow_path:engine VarFlowHop 全字段保留(决策3,不降维到稀疏 {method_key,file,line})。
type TraceVarFlowResult struct {
	Found           bool             `json:"found"`
	MethodKey       string           `json:"method_key,omitempty"`
	VarName         string           `json:"var_name,omitempty"`
	DeclLine        int              `json:"decl_line,omitempty"`
	Tainted         bool             `json:"tainted"`
	Sources         []string         `json:"sources,omitempty"`
	DownstreamSinks []DownstreamSink `json:"downstream_sinks,omitempty"`
	FlowPath        [][]VarFlowHop   `json:"flow_path,omitempty"`
	Message         string           `json:"message,omitempty"`
}

// DownstreamSink — 不编 method_key(决策2:engine SinkHit 无该字段,拼出可能非 canonical key)。
type DownstreamSink struct {
	CalleeClass  string `json:"callee_class"`
	CalleeMethod string `json:"callee_method"`
	FilePath     string `json:"file_path"`
	Line         int    `json:"line"`
	VulnType     string `json:"vuln_type"` // 缺失→"UNKNOWN"
	CWE          string `json:"cwe"`
}

// VarFlowHop — engine 全字段保留(决策3:SinkVuln 非空表该 hop 即危险 sink,降维会丢此标记)。
type VarFlowHop struct {
	FromMethod string `json:"from_method"`
	CallLine   int    `json:"call_line,omitempty"`
	CallFile   string `json:"call_file,omitempty"`
	ToClass    string `json:"to_class"`
	ToMethod   string `json:"to_method"`
	SinkVuln   string `json:"sink_vuln,omitempty"`
	SinkCWE    string `json:"sink_cwe,omitempty"`
}

// CodeAtLineResult — code_at_line 工具返回。
// class_context 留空(决策4:engine BuildSelfContainedSliceRanged 类上下文已烘进 method_body,
// 不单独返字符串;留空即真相,不编造)。
type CodeAtLineResult struct {
	MethodBody   string `json:"method_body"`
	ClassContext string `json:"class_context,omitempty"` // 留空,engine 不单独暴露
	FilePath     string `json:"file_path"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
}

// WhoCallsResult — who_calls 查询返回(评估 (b) 用,不接 LLM 工具)。
// Candidates 仅放 engine 真给的签名键(置 MethodKey,不编 file/line,GR-8)。
type WhoCallsResult struct {
	Found      bool           `json:"found"`
	MethodKey  string         `json:"method_key"`
	Callers    []CallerAnchor `json:"callers"`
	Ambiguous  bool           `json:"ambiguous"`
	Candidates []Candidate    `json:"candidates,omitempty"` // 仅 MethodKey(签名键),无 file/line
}

// CallerAnchor — 单个 caller。file_path/line = 调用位点(ReverseEdge 真值)。
type CallerAnchor struct {
	MethodKey string `json:"method_key"`
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
	CallType  string `json:"call_type"`
}

// CallerChainNode — who_calls 反向可达链节点(judge loop 工具用;不动 CallerAnchor/既有 WhoCalls,
// 评估 harness (b) 不受影响)。per-node entry/http/taint/is_test 从 engine store 富化
// (FormatEntryPointInfo 同源,GR-8 真值不编)。is_test 标注 show-both(反 D1.2:绝不过滤 test caller,
// 只标注);CallersTruncated = breadth cap 砍掉的 caller 数(诚实标,GR-8)。
type CallerChainNode struct {
	MethodKey        string              `json:"method_key"`
	FilePath         string              `json:"file_path,omitempty"`
	Line             int                 `json:"line,omitempty"`
	IsEntry          bool                `json:"is_entry"`
	EntryType        string              `json:"entry_type,omitempty"`   // http_endpoint/scheduled/...(EntryPointType string 别名,无损)
	HttpMethod       string              `json:"http_method,omitempty"`  // POST/GET/...(EntryHTTP 才填)
	HttpPath         string              `json:"http_path,omitempty"`    // /submit(EntryHTTP 才填)
	ParamTaints      map[string][]string `json:"param_taints,omitempty"` // 参数名→污点源(req <- @RequestBody)
	ReturnTaints     []string            `json:"return_taints,omitempty"`
	IsTest           bool                `json:"is_test"`                     // show-both 标注,非过滤(反 D1.2)
	IsCycle          bool                `json:"is_cycle,omitempty"`          // engine 已检环(path-scoped vis)
	Callers          []CallerChainNode   `json:"callers,omitempty"`           // 递归链
	CallersTruncated int                 `json:"callers_truncated,omitempty"` // breadth cap 砍掉的 caller 数(GR-8 诚实)
}

// CallerChainResult — who_calls 工具返回。Truncated=true = 深度封顶未穷尽(非"无生产 caller",GR-8)。
type CallerChainResult struct {
	Found     bool            `json:"found"`
	MethodKey string          `json:"method_key"`
	Root      CallerChainNode `json:"root"`
	Truncated bool            `json:"truncated"` // 深度封顶(到达 maxDepth 未穷尽)
}

// BreakpointResult — list_breakpoints 查询返回(评估 (b) 用)。
type BreakpointResult struct {
	Found       bool             `json:"found"`
	MethodKey   string           `json:"method_key"`
	Breakpoints []EvalBreakpoint `json:"breakpoints"`
}

// EvalBreakpoint — 单个断点(engine Breakpoint 真值映射)。
// RPCInterface = engine *RPCInterfaceDef 的 Class.Method(单字符串,空=无,GR-8 不编全字段)。
type EvalBreakpoint struct {
	CalleePattern      string         `json:"callee_pattern"`
	CallType           string         `json:"call_type"`
	Callers            []CallerAnchor `json:"callers"`
	ResolvedCandidates []Candidate    `json:"resolved_candidates,omitempty"`
	Ambiguous          bool           `json:"ambiguous"`
	RPCInterface       string         `json:"rpc_interface,omitempty"`
}

// SanitizerResult — has_sanitizer 查询返回(评估 (b) 用)。
type SanitizerResult struct {
	Found       bool   `json:"found"`
	MethodKey   string `json:"method_key"`
	TaintVar    string `json:"taint_var"`
	SanitizerAt string `json:"sanitizer_at,omitempty"` // Class.method:line(engine 真值,空=无)
}

// FieldQueryResult — field_query 查询返回(评估 (b) 用,二调组合 QueryField + ResolveFieldValue)。
// Definition = FieldDefinition.InitText(声明/初始化文本,空=引擎无,不编);Taints = TaintInfo 源标识串。
// EffectiveValue = FieldValueContribution.Value(解析值,空=引擎无)。
type FieldQueryResult struct {
	Found          bool           `json:"found"`
	Class          string         `json:"class"`
	Field          string         `json:"field"`
	Definition     string         `json:"definition,omitempty"`
	Type           string         `json:"type,omitempty"`
	Taints         []string       `json:"taints,omitempty"`
	Assignments    []CallerAnchor `json:"assignments,omitempty"` // FieldAssignment 有 MethodKey/Line/FilePath,复用 CallerAnchor
	Reads          []CallerAnchor `json:"reads,omitempty"`
	EffectiveValue string         `json:"effective_value,omitempty"` // ResolveFieldValue 二调取,空=引擎无
}

// MapperSqlResult — GetMapperSql 查询返回(reachable_sinks 富化用,不接 LLM 独立 tool)。
// engine MapperSqlInfo 真值映射(found=false=非 mapper/无数据,不编,GR-8)。
// ParamStyle:"concat"=仅 ${} / "mixed"=${}+#{} 混用(纯 #{} 非 sink 不进 reachable_sinks,此分支不返)。
type MapperSqlResult struct {
	Found        bool     `json:"found"`
	SqlText      string   `json:"sql_text,omitempty"`
	ParamStyle   string   `json:"param_style,omitempty"`   // concat/mixed
	ConcatParams []string `json:"concat_params,omitempty"` // ${} 参数名(危险)
	SafeParams   []string `json:"safe_params,omitempty"`   // #{} 参数名(参数化)
}
