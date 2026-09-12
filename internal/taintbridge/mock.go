package taintbridge

// MockQuerier — EngineQuerier 的假实现，供 agentic/judge 单测，不依赖 taint-repo。
// 三个字段分别预置三个方法的返回；方法被调时把入参记进 Calls（断言调用次数/入参）。
type MockQuerier struct {
	ResolveMethodKeyFn func(fn, filePath, mk string) (MethodKeyResolution, error)
	ReachableSinksFn   func(mk string) (ReachableSinksResult, error)
	TraceToSourcesFn   func(mk string, maxDepth int) (TraceResult, error)
	GetCalleesFn       func(mk string) (GetCalleesResult, error)
	TraceVarFlowFn     func(filePath string, line int, varName string) (TraceVarFlowResult, error)
	CodeAtLineFn       func(filePath string, line int) (CodeAtLineResult, error)
	WhoCallsChainFn    func(mk string, maxDepth, maxCallersPerNode int) (CallerChainResult, error)

	ResolveCalls []struct{ Fn, FilePath, Mk string }
	ReachCalls   []string
	TraceCalls   []struct {
		Mk       string
		MaxDepth int
	}
	CalleesCalls      []string
	TraceVarFlowCalls []struct {
		FilePath string
		Line     int
		VarName  string
	}
	CodeAtLineCalls []struct {
		FilePath string
		Line     int
	}
	WhoCallsChainCalls []struct {
		Mk                string
		MaxDepth          int
		MaxCallersPerNode int
	}
}

func (m *MockQuerier) ResolveMethodKey(fn, filePath, mk string) (MethodKeyResolution, error) {
	m.ResolveCalls = append(m.ResolveCalls, struct{ Fn, FilePath, Mk string }{fn, filePath, mk})
	if m.ResolveMethodKeyFn != nil {
		return m.ResolveMethodKeyFn(fn, filePath, mk)
	}
	return MethodKeyResolution{}, nil
}

func (m *MockQuerier) ReachableSinks(mk string) (ReachableSinksResult, error) {
	m.ReachCalls = append(m.ReachCalls, mk)
	if m.ReachableSinksFn != nil {
		return m.ReachableSinksFn(mk)
	}
	return ReachableSinksResult{}, nil
}

func (m *MockQuerier) TraceToSources(mk string, maxDepth int) (TraceResult, error) {
	m.TraceCalls = append(m.TraceCalls, struct {
		Mk       string
		MaxDepth int
	}{mk, maxDepth})
	if m.TraceToSourcesFn != nil {
		return m.TraceToSourcesFn(mk, maxDepth)
	}
	return TraceResult{}, nil
}

func (m *MockQuerier) GetCallees(mk string) (GetCalleesResult, error) {
	m.CalleesCalls = append(m.CalleesCalls, mk)
	if m.GetCalleesFn != nil {
		return m.GetCalleesFn(mk)
	}
	return GetCalleesResult{}, nil
}

func (m *MockQuerier) TraceVarFlow(filePath string, line int, varName string) (TraceVarFlowResult, error) {
	m.TraceVarFlowCalls = append(m.TraceVarFlowCalls, struct {
		FilePath string
		Line     int
		VarName  string
	}{filePath, line, varName})
	if m.TraceVarFlowFn != nil {
		return m.TraceVarFlowFn(filePath, line, varName)
	}
	return TraceVarFlowResult{}, nil
}

func (m *MockQuerier) CodeAtLine(filePath string, line int) (CodeAtLineResult, error) {
	m.CodeAtLineCalls = append(m.CodeAtLineCalls, struct {
		FilePath string
		Line     int
	}{filePath, line})
	if m.CodeAtLineFn != nil {
		return m.CodeAtLineFn(filePath, line)
	}
	return CodeAtLineResult{}, nil
}

// WhoCallsChain:judge loop who_calls 工具 mock。记入参(断言 LLM 调用 mk/maxDepth/maxCallersPerNode);
// WhoCallsChainFn 非空则委托(供 agentic/judge 单测注入期望链),否则返零值(found=false,GR-8 诚实)。
func (m *MockQuerier) WhoCallsChain(mk string, maxDepth, maxCallersPerNode int) (CallerChainResult, error) {
	m.WhoCallsChainCalls = append(m.WhoCallsChainCalls, struct {
		Mk                string
		MaxDepth          int
		MaxCallersPerNode int
	}{mk, maxDepth, maxCallersPerNode})
	if m.WhoCallsChainFn != nil {
		return m.WhoCallsChainFn(mk, maxDepth, maxCallersPerNode)
	}
	return CallerChainResult{MethodKey: mk}, nil
}

// Task 1: 4 件未接工具查询方法(评估 (b) 用,不接 LLM)。返零值保持 interface 满足。
func (m *MockQuerier) WhoCalls(mk string) (WhoCallsResult, error) {
	return WhoCallsResult{MethodKey: mk}, nil
}
func (m *MockQuerier) ListBreakpoints(mk string) (BreakpointResult, error) {
	return BreakpointResult{MethodKey: mk}, nil
}
func (m *MockQuerier) HasSanitizer(mk, tv string) (SanitizerResult, error) {
	return SanitizerResult{MethodKey: mk, TaintVar: tv}, nil
}
func (m *MockQuerier) QueryField(c, f string) (FieldQueryResult, error) {
	return FieldQueryResult{Class: c, Field: f}, nil
}

// GetMapperSql:返零值(found=false)。Mock 无真实 mapper 数据,reachable_sinks 富化
// 走此路径时 found=false → 不填 MyBatis 字段(诚实,GR-8)。真值由 Adapter.GetMapperSql 委托 engine 提供。
func (m *MockQuerier) GetMapperSql(cls, mth string) (MapperSqlResult, error) {
	return MapperSqlResult{}, nil
}

// 编译期断言：MockQuerier 实现 EngineQuerier。
var _ EngineQuerier = (*MockQuerier)(nil)
