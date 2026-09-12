package taintbridge

import (
	"os"
	"strings"

	"appsecgo/taint/engine"
)

// ScanAndBuild 建引擎 analyzer + Scan + 取 store + 包成 Adapter。
// pipeline 調此函数（唯一入口）；appsecgo 其他代码不 import engine。
// Scan 失败 → 返 (nil, err)，调用方 fail-open → engine=nil → 引擎工具 off（铁律 D）。
// 注：引擎 Scan（analyzer.go:35）本身恒返 nil err（bad path 走 0 文件建空 store），
// 故此处前置 os.Stat：repo 根不存在/不可达 → (nil, err) 让 pipeline gate 的 fail-open
// 真正生效（GR-8：缺 repo = 切不到的第三义「路径不存在」，诚实降级为 off，不静默喂空 adapter
// 让 judge 误判"无 sink"）。真实但空 repo（0 .java）Stat 通过 → Scan 返空 adapter（真值"无可达 sink"）。
func ScanAndBuild(repoRoot string) (EngineQuerier, error) {
	if _, err := os.Stat(repoRoot); err != nil {
		return nil, err
	}
	a := engine.NewJavaRepoAnalyzer(engine.DefaultConfig())
	if err := a.Scan(repoRoot); err != nil {
		return nil, err
	}
	return NewAdapter(a.Store()), nil
}

// Adapter — EngineQuerier 的引擎实现。唯一 import engine 的类型。
type Adapter struct {
	store *engine.AnalysisStore       // 导出路径取 method_key→定义位置(Multi.Funcs[mk].{FilePath,Line,Class,Method})
	q     *engine.QueryService        // ReachableSinks/CallerHasDangerousSink/TraceToSourcesEx/QueryFunction
	rc    *engine.ReachabilityChecker // get_callees:GetForwardReachable
	bc    *engine.BlockClimber        // code_at_line(T3 加构造,此处字段一并加避免二次改 struct)
	cf    *engine.ControlFlowAnalyzer // Task 1 加:has_sanitizer(controlflow.go:99)
}

func NewAdapter(store *engine.AnalysisStore) *Adapter {
	return &Adapter{
		store: store,
		q:     engine.NewQueryService(store),
		rc:    engine.NewReachabilityChecker(store, engine.NewTypeResolver(store)),
		bc:    engine.NewBlockClimber(),
		cf:    engine.NewControlFlowAnalyzer(store), // controlflow.go:12 单参 store(Step 1 已核实)
	}
}

var _ EngineQuerier = (*Adapter)(nil)

// ResolveMethodKey 消歧闭环。mk 非空→直用；否则 QueryFunction(fn,max) 取候选。
func (a *Adapter) ResolveMethodKey(fn, filePath, mk string) (MethodKeyResolution, error) {
	if mk != "" {
		return MethodKeyResolution{Found: true, MethodKey: mk}, nil
	}
	if fn == "" {
		return MethodKeyResolution{}, nil
	}
	// cap 放宽:引擎侧是**子串**搜索,20 可能在精确名之前就截断。反正下面会精确过滤。
	fis := a.q.QueryFunction(fn, 200)
	if len(fis) == 0 {
		return MethodKeyResolution{}, nil // Found=false
	}
	// —— 分层消歧（2026-08-23）。每层只**收窄**候选，收窄到 1 即定；仍多则进下一层。
	//
	// 本函数是方法身份的**单一权威**（文档:「消歧闭环,跨所有 engine 工具共用」）。
	// 它一失效,依赖方法句柄的四件工具全部用不了 —— 实测 18 个上传流 hop 有 16 个卡在这里。
	//
	// 层 1 精确名:引擎的 SearchMethodsByPattern 是子串匹配,查 getListWithStock 会带回
	//   getListWithStockCount,人为放大歧义。模糊搜索本身是合法原语,故不动引擎,在身份边界精确化。
	if exact := filterByExactName(fis, fn); len(exact) > 0 {
		fis = exact
	}
	if len(fis) == 1 {
		return MethodKeyResolution{Found: true, MethodKey: fis[0].MethodKey}, nil
	}
	// 层 2 路径:切片给**仓库相对路径**,引擎存**绝对路径 + 平台分隔符**,
	//   `==` 永不成立(此前"能解析"的案例全是名字唯一直接返回,不是路径匹配起了作用)。
	//   改为归一后互为后缀 —— 对 abs/rel 与 `/`、`\` 差异都稳。
	matched := fis
	if filePath != "" {
		if byPath := filterByPathSuffix(fis, filePath); len(byPath) > 0 {
			matched = byPath
		}
	}
	if len(matched) == 1 {
		return MethodKeyResolution{Found: true, MethodKey: matched[0].MethodKey}, nil
	}
	// 层 3 类名兜底:MyBatis mapper 的 hop 其 file_path 是 **.xml**,而引擎里对应的是同名
	//   .java 接口,路径后缀永远对不上。按「切片文件名 stem == 引擎类名」兜底。
	if filePath != "" {
		if byClass := filterByClassStem(matched, filePath); len(byClass) == 1 {
			return MethodKeyResolution{Found: true, MethodKey: byClass[0].MethodKey}, nil
		}
	}
	// 仍多 → ambiguous（候选必带 file_path + method_key，不猜不跑下游）
	cands := make([]Candidate, 0, len(matched))
	src := matched
	if len(src) == 0 {
		src = fis // file_path 不匹配任何 → 返全部候选让 AI 看真实情况
	}
	for _, fi := range src {
		cands = append(cands, Candidate{
			MethodKey:    fi.MethodKey,
			FilePath:     fi.FilePath,
			FunctionName: fi.Method,
			ClassName:    fi.Class,
			Lines:        []int{fi.Line, fi.Line}, // 引擎仅知起始行，退化区间（诚实，GR-8）
		})
	}
	return MethodKeyResolution{Ambiguous: true, Candidates: cands}, nil
}

// ReachableSinks 组合（契约 §5.2）：
// 顶层 dangerous/vuln_type/cwe/reason ← CallerHasDangerousSink(mk)
// per-sink ← ReachableSinks(mk)[]string：逐个 store.Methods.Functions[sk] 取定义 FilePath/Line/Class/Method + SinkVulnType(Class,Method) 取 vuln_type/cwe
// Truncated ← (reason==DEPTH_TRUNCATED)
func (a *Adapter) ReachableSinks(mk string) (ReachableSinksResult, error) {
	dangerous, topVT, topCWE, reason := a.q.CallerHasDangerousSink(mk)
	sinkKeys := a.q.ReachableSinks(mk)
	sinks := make([]ReachableSink, 0, len(sinkKeys))
	for _, sk := range sinkKeys {
		mf, ok := a.store.Methods.Functions[sk] // 导出路径（store.go:447→257→235）
		var fp string
		var ln int
		var cls, mth string
		if ok {
			// repo 定义 sink：store 取真值（FilePath/Line/Class/Method）
			fp, ln, cls, mth = mf.FilePath, mf.Line, mf.Class, mf.Method
		} else {
			// 外部 sink（JDK/库方法,如 Statement.executeUpdate）store 无 repo 定义。
			// sink key 本身编码 Class.Method（引擎自身 id），据此取 vuln_type/cwe（真值,非编,GR-8）。
			// file_path/line 留空：外部 sink 无 repo 定义位置,空即真相（不编造锚点,GR-8）。
			cls, mth = parseClassMethod(sk)
		}
		vt, cwe := engine.SinkVulnType(cls, mth) // sinks.go:225 包级函数
		if vt == "" {
			vt = "UNKNOWN" // GR-8：缺失即真相，不省略
		}
		if cwe == "" {
			cwe = "UNKNOWN"
		}
		sink := ReachableSink{MethodKey: sk, FilePath: fp, Line: ln, VulnType: vt, CWE: cwe}
		// MyBatis 富化:每 sink 调 GetMapperSql,found 才填(engine 自知是否 mapper,
		// 不靠 vuln_type 猜——Java 字符串拼接 SQLi 也是 sql_injection)。found 必 HasConcat
		// 路径,覆 VulnType/CWE=sql_injection/CWE-89(修 SinkVulnType 不含 MyBatis 致原 lossy
		// UNKNOWN,GR-8:engine 已判 sql_injection,DTO 应如实)。见 spec §3。
		if ms, e := a.GetMapperSql(cls, mth); e == nil && ms.Found {
			sink.SqlText, sink.ParamStyle = ms.SqlText, ms.ParamStyle
			sink.ConcatParams, sink.SafeParams = ms.ConcatParams, ms.SafeParams
			sink.VulnType, sink.CWE = "sql_injection", "CWE-89"
		}
		sinks = append(sinks, sink)
	}
	topV := topVT
	topC := topCWE
	if topV == "" {
		topV = "UNKNOWN"
	}
	if topC == "" {
		topC = "UNKNOWN"
	}
	return ReachableSinksResult{
		Found:          len(sinkKeys) > 0 || dangerous,
		MethodKey:      mk,
		Dangerous:      dangerous,
		VulnType:       topV,
		CWE:            topC,
		Reason:         string(reason),
		ReachableSinks: sinks,
		Truncated:      string(reason) == "DEPTH_TRUNCATED",
	}, nil
}

// GetMapperSql:委托 engine QueryService.MapperSqlInfo,返 MyBatis mapper SQL 文本 +
// ${}/#{ 参数名绑定。found=false=非 mapper/无数据(GR-8 不编)。reachable_sinks 富化用
// (见 contract.go GetMapperSql 注 + spec §3/§4)。engine 扩展点:增强后返回变丰富。
func (a *Adapter) GetMapperSql(cls, mth string) (MapperSqlResult, error) {
	sqlText, concatParams, safeParams, found := a.q.MapperSqlInfo(cls, mth)
	if !found {
		return MapperSqlResult{}, nil
	}
	style := ""
	switch {
	case len(concatParams) > 0 && len(safeParams) > 0:
		style = "mixed"
	case len(concatParams) > 0:
		style = "concat"
	case len(safeParams) > 0:
		style = "parameterized"
	}
	return MapperSqlResult{
		Found:        true,
		SqlText:      sqlText,
		ParamStyle:   style,
		ConcatParams: concatParams,
		SafeParams:   safeParams,
	}, nil
}

// TraceToSources：TraceToSourcesEx(mk,maxDepth) → 映射 path/sources/is_entry/truncated + exhausted_depth。
// hop file_path/line ← CallNode.FilePath/CallNode.Line（types.go:174，引擎自带锚点）。
func (a *Adapter) TraceToSources(mk string, maxDepth int) (TraceResult, error) {
	r := a.q.TraceToSourcesEx(mk, maxDepth)
	traces := make([]Trace, 0, len(r.Traces))
	for _, st := range r.Traces {
		hops := make([]TraceHop, 0, len(st.Path))
		for _, cn := range st.Path {
			hops = append(hops, TraceHop{
				MethodKey: cn.MethodKey,
				FilePath:  cn.FilePath,
				Line:      cn.Line,
				// Role 不设：CallNode 无 role（types.go:174），omitempty→省略，不编
			})
		}
		traces = append(traces, Trace{
			Sources:   st.Sources,
			Path:      hops,
			IsEntry:   st.IsEntry,
			Truncated: st.Truncated,
		})
	}
	return TraceResult{
		Found:          len(traces) > 0,
		MethodKey:      mk,
		Traces:         traces,
		ExhaustedDepth: r.ExhaustedDepth,
	}, nil
}

// GetCallees:GetForwardReachable(mk) → CalleeRef→Callee 映射。
// CalleeRef.Name → Callee.MethodKey(决策1:Name 是引擎 callee 标识,非编)。
// Line/FilePath ← CalleeRef 真值(§8 缺口1,reachability.go:75 填 edge.Line)。
func (a *Adapter) GetCallees(mk string) (GetCalleesResult, error) {
	r := a.rc.GetForwardReachable(mk)
	return GetCalleesResult{
		Found:             len(r.Definitive) > 0 || len(r.Uncertain) > 0,
		MethodKey:         mk,
		Definitive:        toCallees(r.Definitive),
		Uncertain:         toCallees(r.Uncertain),
		HasMethodDispatch: r.HasMethodDispatch,
		Truncated:         r.Truncated,
	}, nil
}

func toCallees(refs []engine.CalleeRef) []Callee {
	out := make([]Callee, 0, len(refs))
	for _, ref := range refs {
		out = append(out, Callee{
			MethodKey: ref.Name, // 决策1:CalleeRef.Name 即引擎 callee 标识
			FilePath:  ref.FilePath,
			Line:      ref.Line,
		})
	}
	return out
}

// TraceVarFlow:q.TraceVarFlow(filePath,line,var) → VarFlowResult→DTO 映射。
// SinkHit→DownstreamSink(callee_class/callee_method 真值,不编 method_key,决策2)。
// VarFlowHop 全字段保留(决策3)。VulnType/CWE 缺失→UNKNOWN(§7 不变量2)。
func (a *Adapter) TraceVarFlow(filePath string, line int, varName string) (TraceVarFlowResult, error) {
	r := a.q.TraceVarFlow(filePath, line, varName)
	sinks := make([]DownstreamSink, 0, len(r.DownstreamSinks))
	for _, s := range r.DownstreamSinks {
		vt, cwe := s.VulnType, s.CWE
		if vt == "" {
			vt = "UNKNOWN"
		}
		if cwe == "" {
			cwe = "UNKNOWN"
		}
		sinks = append(sinks, DownstreamSink{
			CalleeClass:  s.CalleeClass,
			CalleeMethod: s.CalleeMethod,
			FilePath:     s.FilePath,
			Line:         s.Line,
			VulnType:     vt,
			CWE:          cwe,
		})
	}
	paths := make([][]VarFlowHop, 0, len(r.FlowPath))
	for _, p := range r.FlowPath {
		hops := make([]VarFlowHop, 0, len(p))
		for _, h := range p {
			hops = append(hops, VarFlowHop{
				FromMethod: h.FromMethod, CallLine: h.CallLine, CallFile: h.CallFile,
				ToClass: h.ToClass, ToMethod: h.ToMethod,
				SinkVuln: h.SinkVuln, SinkCWE: h.SinkCWE,
			})
		}
		paths = append(paths, hops)
	}
	return TraceVarFlowResult{
		Found:           r.Found,
		MethodKey:       r.MethodKey,
		VarName:         r.VarName,
		DeclLine:        r.DeclLine,
		Tainted:         r.Tainted,
		Sources:         r.Sources,
		DownstreamSinks: sinks,
		FlowPath:        paths,
		Message:         r.Message,
	}, nil
}

// CodeAtLine:bc.BuildSelfContainedSliceRanged(filePath, {line:true}) → (code,start,end)。
// class_context 留空(决策4:类上下文已烘进 code,engine 不单独返)。
func (a *Adapter) CodeAtLine(filePath string, line int) (CodeAtLineResult, error) {
	code, start, end := a.bc.BuildSelfContainedSliceRanged(filePath, map[int]bool{line: true})
	return CodeAtLineResult{
		MethodBody: code,
		FilePath:   filePath,
		StartLine:  start,
		EndLine:    end,
		// ClassContext 留空(决策4)
	}, nil
}

// WhoCalls:GetCallersRobust(mk) → ReverseEdge→CallerAnchor 映射(评估 (b) 用,不接 LLM)。
// engine CallerQueryResult.Candidates 是 []string(重载签名键,非 FunctionInfo),仅置 MethodKey,
// 不编 file/line(GR-8:engine 只给签名键,锚点无真相不下判断)。
func (a *Adapter) WhoCalls(mk string) (WhoCallsResult, error) {
	r := a.q.GetCallersRobust(mk) // query.go:81
	callers := make([]CallerAnchor, 0, len(r.Edges))
	for _, e := range r.Edges {
		callers = append(callers, CallerAnchor{
			MethodKey: e.CallerKey, FilePath: e.FilePath, Line: e.Line, CallType: string(e.CallType),
		})
	}
	return WhoCallsResult{
		Found:      len(callers) > 0 || r.Ambiguous,
		MethodKey:  mk,
		Callers:    callers,
		Ambiguous:  r.Ambiguous,
		Candidates: toCandidatesFromSigs(r.Candidates),
	}, nil
}

// toCandidatesFromSigs:engine Candidates 仅 []string(重载签名键),无 file/line。
// 置 MethodKey=sig,其余留空(诚实:engine 不给锚点,不编,Gром-8)。
func toCandidatesFromSigs(sigs []string) []Candidate {
	if len(sigs) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(sigs))
	for _, sig := range sigs {
		out = append(out, Candidate{MethodKey: sig})
	}
	return out
}

// WhoCallsChain:TraceCallersChain(mk,maxDepth,maxCallersPerNode) → CallTree→CallerChainNode 递归映射
// (judge loop who_calls 工具用,非评估 (b))。cap/sort/enrich 全在 engine 侧建树时生效
// (query.go callersChainDFS),adapter 只做 1:1 字段映射(GR-8 真值不编;EntryPointType→string 无损)。
// found=false=方法未解析(不编 caller 不编锚点,GR-8)。
func (a *Adapter) WhoCallsChain(mk string, maxDepth, maxCallersPerNode int) (CallerChainResult, error) {
	tree, found, truncated := a.q.TraceCallersChain(mk, maxDepth, maxCallersPerNode) // query.go:TraceCallersChain
	res := CallerChainResult{
		Found:     found,
		MethodKey: mk,
		Truncated: truncated,
	}
	if tree != nil {
		res.Root = a.mapCallTree(tree)
	}
	return res, nil
}

// mapCallTree:engine CallTree→contract CallerChainNode 递归映射。
// 字段全 1:1(engine enrichCallTree 已填 entry_type/http/taint/is_test/callers_truncated);
// adapter 不富化不编(GR-8)。Callers 是 []CallTree 值切片,按索引取址递归(避开 loop-var 别名)。
func (a *Adapter) mapCallTree(t *engine.CallTree) CallerChainNode {
	if t == nil {
		return CallerChainNode{}
	}
	node := CallerChainNode{
		MethodKey:        t.MethodKey,
		FilePath:         t.FilePath,
		Line:             t.Line,
		IsEntry:          t.IsEntry,
		EntryType:        string(t.EntryType),
		HttpMethod:       t.HttpMethod,
		HttpPath:         t.HttpPath,
		ParamTaints:      t.ParamTaints,
		ReturnTaints:     t.ReturnTaints,
		IsTest:           t.IsTest,
		IsCycle:          t.IsCycle,
		CallersTruncated: t.CallersTruncated,
	}
	for i := range t.Callers {
		node.Callers = append(node.Callers, a.mapCallTree(&t.Callers[i]))
	}
	return node
}

// ListBreakpoints:ListBreakpoints(mk) → Breakpoint→EvalBreakpoint 映射(评估 (b) 用)。
// bp.Callers 是 []BreakCaller(CallerKey/Line/FilePath/CallType);ResolvedCandidates 是 []MethodDef。
// RPCInterface 是 *RPCInterfaceDef,DTO 单字符串→取 Class.Method(空=nil,不编全字段,GR-8)。
func (a *Adapter) ListBreakpoints(mk string) (BreakpointResult, error) {
	bps := a.q.ListBreakpoints(mk) // query.go:1027
	out := make([]EvalBreakpoint, 0, len(bps))
	for _, bp := range bps {
		callers := make([]CallerAnchor, 0, len(bp.Callers))
		for _, c := range bp.Callers {
			callers = append(callers, CallerAnchor{
				MethodKey: c.CallerKey, FilePath: c.FilePath, Line: c.Line, CallType: string(c.CallType),
			})
		}
		out = append(out, EvalBreakpoint{
			CalleePattern:      bp.CalleePattern,
			CallType:           string(bp.CallType),
			Callers:            callers,
			ResolvedCandidates: toCandidatesFromMethodDefs(bp.ResolvedCandidates),
			Ambiguous:          bp.Ambiguous,
			RPCInterface:       rpcInterfaceString(bp.RPCInterface),
		})
	}
	return BreakpointResult{Found: len(out) > 0, MethodKey: mk, Breakpoints: out}, nil
}

// toCandidatesFromMethodDefs:MethodDef(全局索引定义)→Candidate,带 file/line 真锚点。
func toCandidatesFromMethodDefs(mds []engine.MethodDef) []Candidate {
	if len(mds) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(mds))
	for _, md := range mds {
		out = append(out, Candidate{
			MethodKey: md.MethodKey, FilePath: md.FilePath,
			FunctionName: md.Method, ClassName: md.Class,
			Lines: []int{md.Line, md.Line},
		})
	}
	return out
}

// rpcInterfaceString:*RPCInterfaceDef → "Class.Method"(单字符串,空指针="" )。
// DTO 字段为 string,不编全字段;Class.Method 是接口身份的最简诚实编码(GR-8)。
func rpcInterfaceString(rpc *engine.RPCInterfaceDef) string {
	if rpc == nil {
		return ""
	}
	return rpc.Class + "." + rpc.Method
}

// HasSanitizer:HasSanitizerOnPath(mk,taintVar) → SanitizerResult(评估 (b) 用)。
// engine 返 (bool,string) 无 error;adapter 层统一 (SanitizerResult,error),err 恒 nil。
func (a *Adapter) HasSanitizer(mk, taintVar string) (SanitizerResult, error) {
	found, at := a.cf.HasSanitizerOnPath(mk, taintVar) // controlflow.go:99
	return SanitizerResult{
		Found: found, MethodKey: mk, TaintVar: taintVar, SanitizerAt: at,
	}, nil
}

// QueryField:QueryField(cn,fn)+ResolveFieldValue 二调组合(评估 (b) 用)。
// fi.Definition 是 FieldDefinition 结构(非 string)→取 InitText(声明/初始化文本,空=无)。
// fi.Taints 是 []TaintInfo(非 []string)→每项编 "SourceType:SourceMethod" 源标识串。
// fv 无 String() 方法;EffectiveValue = fv.Value(解析值,空=引擎无)。
func (a *Adapter) QueryField(class, field string) (FieldQueryResult, error) {
	fi := a.q.QueryField(class, field)        // query.go:589
	fv := a.q.ResolveFieldValue(class, field) // query.go:596(二调取 effective_value)
	if fi == nil {
		return FieldQueryResult{Class: class, Field: field}, nil
	}
	assigns := make([]CallerAnchor, 0, len(fi.Assignments))
	for _, a2 := range fi.Assignments {
		assigns = append(assigns, CallerAnchor{MethodKey: a2.MethodKey, FilePath: a2.FilePath, Line: a2.Line})
	}
	reads := make([]CallerAnchor, 0, len(fi.Reads))
	for _, r2 := range fi.Reads {
		reads = append(reads, CallerAnchor{MethodKey: r2.MethodKey, FilePath: r2.FilePath, Line: r2.Line})
	}
	ev := ""
	if fv != nil {
		ev = fv.Value // FieldValueContribution 无 String(),真值取 Value(fieldresolver.go:19)
	}
	return FieldQueryResult{
		Found: true, Class: class, Field: field,
		Definition:     fi.Definition.InitText,
		Type:           fi.Type,
		Taints:         taintInfoToStrings(fi.Taints),
		Assignments:    assigns,
		Reads:          reads,
		EffectiveValue: ev,
	}, nil
}

// taintInfoToStrings:TaintInfo → 源标识串(诚实:SourceType+SourceMethod,engine 真字段)。
func taintInfoToStrings(ts []engine.TaintInfo) []string {
	if len(ts) == 0 {
		return nil
	}
	out := make([]string, 0, len(ts))
	for _, ti := range ts {
		s := string(ti.SourceType)
		if ti.SourceMethod != "" {
			s += ":" + ti.SourceMethod
		}
		out = append(out, s)
	}
	return out
}

// parseClassMethod 从 sink key（形如 Class.method 或 Class.method(sig)）取 (class, method)。
// 外部 sink（JDK/库方法）store 无定义，但其 sink key 编码 Class.Method；
// 据此调 SinkVulnType 取 vuln_type/cwe（引擎自身 id 派生,GR-8 真值,非编造）。
// 去签名：方法名可能带 (sig)，SinkVulnType 只认方法名。
func parseClassMethod(sk string) (class, method string) {
	sigStart := strings.Index(sk, "(")
	base := sk
	if sigStart >= 0 {
		base = sk[:sigStart]
	}
	if i := strings.LastIndex(base, "."); i >= 0 {
		return base[:i], base[i+1:]
	}
	return "", base
}

// —— 方法身份消歧的三个过滤器（2026-08-23）。每个只收窄，绝不新增候选。——

// filterByExactName 保留方法名**逐字相等**的候选（引擎侧是子串搜索）。
//
// ⚠ `fi.Method` 是**类限定**的（`MaterialService.getListWithStock`），不是裸方法名。
// 首版写成 `fi.Method == fn` → 永不命中 → 过滤静默失效，而当时那条测试因为也拿
// 类限定串去比裸名而**空过**。同一个「自我声称未被测试兑现」的类（见 internal/factguard）。
func filterByExactName(fis []engine.FunctionInfo, fn string) []engine.FunctionInfo {
	var out []engine.FunctionInfo
	for _, fi := range fis {
		if bareMethodName(fi.Method) == fn {
			out = append(out, fi)
		}
	}
	return out
}

// bareMethodName 去掉类限定前缀：`Cls.m` → `m`；已是裸名则原样。
func bareMethodName(m string) string {
	if i := strings.LastIndex(m, "."); i >= 0 {
		return m[i+1:]
	}
	return m
}

// filterByPathSuffix 保留路径**归一后互为后缀**的候选。
// 切片给相对路径、引擎给绝对路径,故双向判后缀;分隔符与大小写都归一(Windows)。
func filterByPathSuffix(fis []engine.FunctionInfo, filePath string) []engine.FunctionInfo {
	want := normPath(filePath)
	if want == "" {
		return nil
	}
	var out []engine.FunctionInfo
	for _, fi := range fis {
		got := normPath(fi.FilePath)
		if got == "" {
			continue
		}
		if strings.HasSuffix(got, want) || strings.HasSuffix(want, got) {
			out = append(out, fi)
		}
	}
	return out
}

// filterByClassStem 保留「引擎类名 == 切片文件名去扩展名」的候选（MyBatis .xml → .java 接口）。
func filterByClassStem(fis []engine.FunctionInfo, filePath string) []engine.FunctionInfo {
	stem := pathStem(filePath)
	if stem == "" {
		return nil
	}
	var out []engine.FunctionInfo
	for _, fi := range fis {
		if strings.EqualFold(fi.Class, stem) {
			out = append(out, fi)
		}
	}
	return out
}

func normPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	return strings.ToLower(strings.TrimPrefix(p, "./"))
}

func pathStem(p string) string {
	p = normPath(p)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.LastIndex(p, "."); i > 0 {
		p = p[:i]
	}
	return p
}
