package engine

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/odvcencio/gotreesitter"
)

const (
	defaultOverlapLines = 2  // 每个切片区间向外扩的行数（形成相邻 hop 重叠）
	maxClimbDepth       = 64 // parent 链爬升上限，防异常深树死循环
)

// ============================================================
//  BlockClimber — 块爬升自包含切片（llmxcpg enhancer.py）
//  从路径行逐层向上爬嵌套块边界，产出自包含代码片段
// ============================================================

type BlockClimber struct{}

func NewBlockClimber() *BlockClimber { return &BlockClimber{} }

// locateNodeAtLine 返回 line 行所属的最小 AST 节点（1-based 行号）。
// 优先用 gotreesitter 的位置定位 API；不可用时 fallback 递归找最小覆盖节点。
func (bc *BlockClimber) locateNodeAtLine(pf *ParsedFile, line int) *gotreesitter.Node {
	if pf == nil || pf.Root == nil || line < 1 {
		return nil
	}
	pt := gotreesitter.Point{Row: uint32(line - 1), Column: 0}
	if n := pf.Root.NamedDescendantForPointRange(pt, pt); n != nil && nodeType(n) != "" {
		return n
	}
	return bc.minCoveringNode(pf.Root, line)
}

// minCoveringNode 递归找覆盖 line 且嵌套最深的节点（fallback 用）。
func (bc *BlockClimber) minCoveringNode(node *gotreesitter.Node, line int) *gotreesitter.Node {
	if node == nil {
		return nil
	}
	s, e := startLine1(node), endLine1(node)
	if line < s || line > e {
		return nil
	}
	var deepest *gotreesitter.Node
	for _, c := range nodeChildren(node) {
		if found := bc.minCoveringNode(c, line); found != nil {
			deepest = found
		}
	}
	if deepest != nil {
		return deepest
	}
	return node
}

// buildSliceWithLines 是 BuildSelfContainedSlice 的内部实现，额外返 trim 后的 sortedLines
// 供 BuildSelfContainedSliceRanged 取首末行(range)。逻辑与原 BuildSelfContainedSlice 字节等价。
func (bc *BlockClimber) buildSliceWithLines(filePath string, lines map[int]bool) (string, []int) {
	if len(lines) == 0 || filePath == "" {
		return "", nil
	}
	pf, err := parseJavaFile(filePath)
	if err != nil {
		return "", nil
	}
	srcLines := strings.Split(string(pf.Src), "\n")
	maxLine := len(srcLines)

	allLines := make(map[int]bool)
	var classSpans [][2]int
	for l := range lines {
		if l < 1 || l > maxLine {
			continue
		}
		allLines[l] = true
		n := bc.locateNodeAtLine(pf, l)
		if n != nil {
			bc.climbToClassBarrier(n, allLines, &classSpans)
		}
	}

	// overlap：区间先聚合再向外扩 defaultOverlapLines 行，且不越出所属 class 顶界
	applyOverlap(allLines, maxLine, defaultOverlapLines, classSpans)

	// 排序
	sortedLines := make([]int, 0, len(allLines))
	for l := range allLines {
		sortedLines = append(sortedLines, l)
	}
	sort.Ints(sortedLines)

	// trim：裁剪整体首尾纯空白行
	for len(sortedLines) > 0 {
		if strings.TrimSpace(srcLines[sortedLines[0]-1]) == "" {
			sortedLines = sortedLines[1:]
		} else {
			break
		}
	}
	for len(sortedLines) > 0 {
		last := sortedLines[len(sortedLines)-1]
		if strings.TrimSpace(srcLines[last-1]) == "" {
			sortedLines = sortedLines[:len(sortedLines)-1]
		} else {
			break
		}
	}

	// 输出，非连续处插入 "// ..."
	var b strings.Builder
	prevLine := 0
	for _, lineNum := range sortedLines {
		if lineNum < 1 || lineNum > maxLine {
			continue
		}
		if prevLine > 0 && lineNum > prevLine+1 {
			b.WriteString("    // ...\n")
		}
		b.WriteString(srcLines[lineNum-1])
		b.WriteString("\n")
		prevLine = lineNum
	}
	return b.String(), sortedLines
}

// BuildSelfContainedSlice 从路径行号构建自包含代码片段（class context 已烘进文本）。
// §8 缺口3: 委托 buildSliceWithLines 取 code；签名不变，7 调用方零波及。
func (bc *BlockClimber) BuildSelfContainedSlice(filePath string, lines map[int]bool) string {
	code, _ := bc.buildSliceWithLines(filePath, lines)
	return code
}

// BuildSelfContainedSliceRanged 同 BuildSelfContainedSlice 但额外返首末行 range。
// §8 缺口3: code_at_line 工具需 {start_line,end_line}；sortedLines trim 后真值。
// sortedLines 空（全空白被裁/空输入）→ 返 ("",0,0)。
func (bc *BlockClimber) BuildSelfContainedSliceRanged(filePath string, lines map[int]bool) (string, int, int) {
	code, sortedLines := bc.buildSliceWithLines(filePath, lines)
	if len(sortedLines) == 0 {
		return "", 0, 0
	}
	return code, sortedLines[0], sortedLines[len(sortedLines)-1]
}

// climbToClassBarrier 沿 parent 链自底向上爬，收集路径节点所属的方法/块/类起止行。
// 爬到 class/interface/enum/record 声明作为顶界并纳入后停止，并记录该 class 的 [start,end] 跨度。
func (bc *BlockClimber) climbToClassBarrier(node *gotreesitter.Node, lines map[int]bool, classSpans *[][2]int) {
	cur := node
	depth := 0
	for cur != nil && depth < maxClimbDepth {
		nt := nodeType(cur)
		start, end := startLine1(cur), endLine1(cur)
		switch nt {
		case "block", "if_statement", "for_statement", "while_statement",
			"do_statement", "enhanced_for_statement", "try_statement",
			"catch_clause", "synchronized_statement":
			lines[start] = true
			if end > start {
				lines[end] = true
			}
		case "method_declaration", "constructor_declaration":
			lines[start] = true
			lines[end] = true
		case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
			// 类级顶界：纳入整段后停止
			lines[start] = true
			lines[end] = true
			*classSpans = append(*classSpans, [2]int{start, end})
			return
		}
		cur = nodeParent(cur)
		depth++
	}
}

// inAnySpan 判断行 x 是否落在任一 class 跨度内。
func inAnySpan(x int, spans [][2]int) bool {
	for _, s := range spans {
		if x >= s[0] && x <= s[1] {
			return true
		}
	}
	return false
}

// applyOverlap 把行集合先聚合成连续区间，每个区间上下各扩 k 行（夹在 [1,maxLine]），
// 且扩边结果不越出所属 class 顶界（避免溢出到无关类）。
func applyOverlap(lines map[int]bool, maxLine, k int, classSpans [][2]int) {
	if len(lines) == 0 {
		return
	}
	sorted := make([]int, 0, len(lines))
	for l := range lines {
		sorted = append(sorted, l)
	}
	sort.Ints(sorted)
	// 聚合成区间
	type interval struct{ a, b int }
	var intervals []interval
	s, prev := sorted[0], sorted[0]
	for _, l := range sorted[1:] {
		if l == prev+1 {
			prev = l
			continue
		}
		intervals = append(intervals, interval{s, prev})
		s, prev = l, l
	}
	intervals = append(intervals, interval{s, prev})
	// 扩边写回（过滤掉越出 class 顶界的行）
	for key := range lines {
		delete(lines, key)
	}
	for _, iv := range intervals {
		lo := overlapMax(1, iv.a-k)
		hi := overlapMin(maxLine, iv.b+k)
		for x := lo; x <= hi; x++ {
			if len(classSpans) == 0 || inAnySpan(x, classSpans) {
				lines[x] = true
			}
		}
	}
}

// overlapMax/overlapMin 包级函数（不依赖 Go 1.21+ 内置 min/max，墙内版本不确定）。
func overlapMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func overlapMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// methodClassMethod 按最后一个 "." 拆分 MethodKey 为 (class, method)。
// 容错：无 "." 时整体作为 method，class 为空。
func methodClassMethod(mk string) (string, string) {
	idx := strings.LastIndex(mk, ".")
	if idx < 0 {
		return "", mk
	}
	return mk[:idx], mk[idx+1:]
}

// isEntryPoint 该方法是否为 HTTP/入口点（传入来自用户输入的权威来源）。
func isEntryPoint(store *AnalysisStore, mk string) bool {
	return store.Calls.EntryPoints[mk]
}

// isExternalRef 该方法是否被其它方法调用（出现在某条调用边的 callee 中）。
func isExternalRef(store *AnalysisStore, mk string) bool {
	cls, mtd := methodClassMethod(mk)
	for caller, edges := range store.Calls.Edges {
		if caller == mk {
			continue
		}
		for _, e := range edges {
			if e.CalleeMethod == mtd && (e.CalleeClass == "" || e.CalleeClass == cls) {
				return true
			}
		}
	}
	return false
}

// isCycleInPath 路径中该方法出现 >=2 次（循环/递归）。
func isCycleInPath(path []CallNode, mk string) bool {
	n := 0
	for _, c := range path {
		if c.MethodKey == mk {
			n++
		}
	}
	return n >= 2
}

// edgeConfidenceRule 返回 caller→callee 这条调用边的置信度与规则依据。
// 注：污点回溯路径上的 hop 多为数据流推导（而非直接调用边表里登记的边），
// 此前一律返回 unknown 导致 complete 样本看起来"未确认"（D2）。这里对回溯
// 推断出的边给出 heuristic 置信度（数据可达），仅当命中直接调用边登记时才给 exact。
func edgeConfidenceRule(store *AnalysisStore, caller, callee CallNode, inferred bool) (CallConfidence, string) {
	_, calleeMtd := methodClassMethod(callee.MethodKey)
	calleeCls, _ := methodClassMethod(callee.MethodKey)
	for _, e := range store.Calls.Edges[caller.MethodKey] {
		if e.CalleeMethod == calleeMtd && (e.CalleeClass == "" || e.CalleeClass == calleeCls) {
			return e.Confidence, e.Rule
		}
	}
	if inferred {
		return ConfHeuristic, "dataflow-inferred (taint propagation edge, not in direct call graph)"
	}
	return CallConfidence("unknown"), ""
}

// sanitizerOf 探测该方法的任一污点参数是否在方法体内被净化。
// 遍历 ParamTaints 的每个参数名作为污点变量，调用 HasSanitizerOnPath。
// 任一命中返回 (true, "Class.method:行号")；无 ParamTaints 则保守返回 (false, "")（不误报净化）。
func sanitizerOf(cfa *ControlFlowAnalyzer, store *AnalysisStore, mk string) (bool, string) {
	for param := range store.Methods.ParamTaints[mk] {
		if found, at := cfa.HasSanitizerOnPath(mk, param); found {
			return true, at
		}
	}
	return false, ""
}

// taintSourcesOf 展平该方法的污点来源（返回值污点 + 各参数污点 + 方法内局部变量污点）。
// D-R16c 修复：新增局部变量污点，使切片中"source 为局部变量"的节点也能显示 @taint 高亮。
func taintSourcesOf(store *AnalysisStore, mk string) []string {
	var s []string
	s = append(s, store.Methods.ReturnTaints[mk]...)
	for _, pts := range store.Methods.ParamTaints[mk] {
		s = append(s, pts...)
	}
	for _, lv := range store.Methods.LocalVars[mk] {
		s = append(s, lv.Sources...)
	}
	return s
}

// httpInfoOf 返回该入口点的 HTTP 路径与方法（无则空）。
func httpInfoOf(store *AnalysisStore, mk string) (string, string) {
	return store.Calls.HttpPaths[mk], store.Calls.HttpMethods[mk]
}

// collectMethodBodyCallLines 返回 mk 方法体内所有 method_invocation 调用语句的
// 1-based 行号（含 if/else、循环内联调用）。用于切片：除方法声明行外，把方法体内
// 全部调用语句行也纳入，避免 BuildSelfContainedSlice 因离散点把分支内污点传播代码
// 折叠为 "// ..."（D5 边界：审计员看不到分支内污点传播路径）。
func (bc *BlockClimber) collectMethodBodyCallLines(pf *ParsedFile, store *AnalysisStore, mk string) []int {
	fn, ok := store.Methods.Functions[mk]
	if !ok || fn.Line <= 0 || pf == nil {
		return nil
	}
	// 定位声明行节点并沿父链找到 method_declaration 子树
	cur := bc.locateNodeAtLine(pf, fn.Line)
	for cur != nil && nodeType(cur) != "method_declaration" {
		cur = nodeParent(cur)
	}
	if cur == nil {
		return nil
	}
	var lines []int
	var walk func(n *gotreesitter.Node)
	walk = func(n *gotreesitter.Node) {
		if n == nil {
			return
		}
		if nodeType(n) == "method_invocation" {
			ln := startLine1(n)
			lines = append(lines, ln)
			// D5 增强：把调用节点所属的最近控制结构块（if/else/for/while/try 等）
			// 整段 [start,end] 纳入 lines，使同分支内联逻辑连贯呈现，
			// 避免离散调用行被 applyOverlap 扩边后由 '// ...' 隔离成碎片段
			// （原 D5 仅收集调用行，分支内 mid/tail 调用点隔空被折叠）。
			lines = append(lines, bc.includeEnclosingBlock(pf, ln)...)
		}
		for _, c := range nodeChildren(n) {
			walk(c)
		}
	}
	walk(cur)
	return lines
}

// includeEnclosingBlock 从某行的 method_invocation 节点沿父链上溯，找到最近的
// 控制结构块（if/else/for/while/try/catch/synchronized/do），把整段 [start,end]
// 行作为切片纳入。仅用于切片可读性增强（D5），不影响安全判定。
func (bc *BlockClimber) includeEnclosingBlock(pf *ParsedFile, line int) []int {
	var out []int
	cur := bc.locateNodeAtLine(pf, line)
	// 上溯到 method_invocation 节点
	for cur != nil && nodeType(cur) != "method_invocation" {
		cur = nodeParent(cur)
	}
	if cur == nil {
		return out
	}
	for p := nodeParent(cur); p != nil; p = nodeParent(p) {
		nt := nodeType(p)
		switch nt {
		case "if_statement", "for_statement", "while_statement", "do_statement",
			"enhanced_for_statement", "try_statement", "catch_clause", "synchronized_statement":
			st, en := startLine1(p), endLine1(p)
			for x := st; x <= en; x++ {
				out = append(out, x)
			}
			return out
		case "method_declaration", "constructor_declaration":
			return out // 到达方法边界，不再上溯
		}
	}
	return out
}

// BuildSliceFromTraceAnnotated 从追溯路径构建带 AI 标注的自包含切片。
// 形态：保留可读代码片段（人/AI 可读），并在每 file 块前附加结构化标注
// （@entry/@taint/@edge/@source/@flag），使 AI 无需自行猜测"是否真调用/
// 传入是否用户输入"。代码切片逻辑复用 BuildSelfContainedSlice，不退化。
func (bc *BlockClimber) BuildSliceFromTraceAnnotated(store *AnalysisStore, cfa *ControlFlowAnalyzer, trace SourceTrace) string {
	if len(trace.Path) == 0 {
		return ""
	}
	// 按 file 分组节点
	nodesByFile := make(map[string][]CallNode)
	var fileOrder []string
	for _, node := range trace.Path {
		if node.FilePath == "" {
			continue
		}
		if _, ok := nodesByFile[node.FilePath]; !ok {
			fileOrder = append(fileOrder, node.FilePath)
		}
		nodesByFile[node.FilePath] = append(nodesByFile[node.FilePath], node)
	}

	var parts []string
	for _, filePath := range fileOrder {
		nodes := nodesByFile[filePath]
		var b strings.Builder
		// —— 标注块 ——
		b.WriteString("// [trace] flow: source -> sink  共 " + itoa(len(trace.Path)) + " 跳\n")
		if len(trace.Sources) > 0 {
			b.WriteString("// @source " + strings.Join(trace.Sources, ", ") + "\n")
		}
		for _, node := range nodes {
			mk := node.MethodKey
			// role: Path[0]=sink（SAST 回溯起点），entry=source 侧
			if node == trace.Path[0] {
				b.WriteString("// @role sink " + mk + "\n")
			} else if isEntryPoint(store, mk) {
				b.WriteString("// @role entry " + mk + "\n")
			}
			if isEntryPoint(store, mk) {
				hp, hm := httpInfoOf(store, mk)
				if hp != "" || hm != "" {
					b.WriteString("// @entry " + mk + " (HTTP: " + hm + " " + hp + ")\n")
				} else {
					b.WriteString("// @entry " + mk + "\n")
				}
			}
			if srcs := taintSourcesOf(store, mk); len(srcs) > 0 {
				// 去重计数，避免 @RequestParam 重复刷屏
				b.WriteString("// @taint " + mk + ": " + joinDeduped(srcs) + "\n")
			}
			if isExternalRef(store, mk) {
				b.WriteString("// @flag external " + mk + "\n")
			}
			if isCycleInPath(trace.Path, mk) {
				b.WriteString("// @flag cycle " + mk + "\n")
			}
			// 净化状态：仅对 entry/taint 节点有意义
			if isEntryPoint(store, mk) || len(taintSourcesOf(store, mk)) > 0 {
				if ok, at := sanitizerOf(cfa, store, mk); ok {
					b.WriteString("// @sanitized " + mk + " @ " + at + "\n")
				} else {
					b.WriteString("// @unsanitized " + mk + " @ note: no sanitizer call found on taint var(s)\n")
				}
			}
		}
		// 相邻调用边标注：真实污点流向 source->sink（Path 为 sink->source 回溯序）
		for i := 0; i+1 < len(trace.Path); i++ {
			from, to := trace.Path[i+1], trace.Path[i]
			conf, rule := edgeConfidenceRule(store, from, to, true)
			impl := confidenceImplication(conf)
			edgeLine := "// @edge " + from.MethodKey + " -> " + to.MethodKey +
				" [taint_flow," + string(conf) + "] rule=" + rule
			if impl != "" {
				edgeLine += " // " + impl
			}
			b.WriteString(edgeLine + "\n")
		}
		// —— 代码块 ——
		lines := make(map[int]bool)
		for _, node := range nodes {
			if fn, ok := store.Methods.Functions[node.MethodKey]; ok && fn.Line > 0 {
				lines[fn.Line] = true
			}
			if node.Line > 0 {
				lines[node.Line] = true
			}
		}
		// D5 修复：除方法声明行/调用行外，纳入各 Path 节点方法体内全部调用语句行
		// （含 if/else、循环内的内联调用），避免 BuildSelfContainedSlice 因离散点
		// 把分支内污点传播代码折叠为 "// ..."，导致切片可读性受损（审计员看不到
		// 分支内污点传播路径）。安全判定不受影响（sink 仍命中）。
		if pf, perr := parseJavaFile(filePath); perr == nil && pf != nil {
			for _, node := range nodes {
				for _, cl := range bc.collectMethodBodyCallLines(pf, store, node.MethodKey) {
					lines[cl] = true
				}
			}
		}
		slice := bc.BuildSelfContainedSlice(filePath, lines)
		if slice != "" {
			parts = append(parts, "// === "+filePath+" ===\n"+b.String()+slice)
		}
	}
	return strings.Join(parts, "\n\n")
}

// —— JSON 模式（结构化证据清单，供 AI 直接解析）——
type sliceHTTPJSON struct {
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}
type sliceSanitizedJSON struct {
	Sanitized bool   `json:"sanitized"`
	At        string `json:"at,omitempty"`         // 净化发生位置 Class.method:行号
	CheckedBy string `json:"checked_by,omitempty"` // 命中的 sanitizer 方法（若有）
	Note      string `json:"note,omitempty"`       // 未净化时的说明
}
type sliceTaintJSON struct {
	Param   string            `json:"param"`
	Sources []sliceSourceJSON `json:"sources"`
}
type sliceSourceJSON struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}
type sliceVarJSON struct {
	Name     string   `json:"name"`
	Line     int      `json:"line"`
	Tainted  bool     `json:"tainted"`
	Sources  []string `json:"sources,omitempty"`
	InitText string   `json:"init_text,omitempty"` // 变量声明/赋值所在行代码片段（R16 行级变量锚点）
}
type sliceNodeJSON struct {
	MethodKey  string             `json:"methodKey"`
	File       string             `json:"file"`
	Line       int                `json:"line"`
	Role       string             `json:"role,omitempty"` // "sink" | "entry" | ""（中间节点）
	IsEntry    bool               `json:"isEntry"`
	IsAnalyzed bool               `json:"is_analyzed"` // 是否为本切片被分析方法（verdict 主体）；其余节点为上下文
	HTTP       *sliceHTTPJSON     `json:"http,omitempty"`
	Taint      []sliceTaintJSON   `json:"taint,omitempty"`
	Variables  []sliceVarJSON     `json:"variables,omitempty"`    // R16：行级变量粒度锚点（仅污点相关变量，精简噪声）
	IsTestCode bool               `json:"is_test_code,omitempty"` // R12/R18：测试代码命中标记，供 AI 降权/排除误报
	External   bool               `json:"external"`
	Cycle      bool               `json:"cycle"`
	Sanitized  sliceSanitizedJSON `json:"sanitized"`
}
type sliceEdgeJSON struct {
	From        string `json:"from"`      // 污点来源侧（source 方向）
	To          string `json:"to"`        // 污点流向侧（sink 方向）
	Direction   string `json:"direction"` // 固定 "taint_flow"
	Confidence  string `json:"confidence"`
	Rule        string `json:"rule,omitempty"`
	Implication string `json:"implication,omitempty"` // confidence=unknown/heuristic 时的盲区说明
}
type sliceTraceJSON struct {
	Hops              int      `json:"hops"`
	Flow              string   `json:"flow"`                          // R6：可达时为 "source -> ... -> sink"，不可达为 "source -> (path unresolvable)"
	HasHeuristicEdges bool     `json:"has_heuristic_edges,omitempty"` // R7：路径含启发式/多态分派边（confidence 非 definitive/inferred）
	Sources           []string `json:"sources"`
}
type sliceJSON struct {
	AnalyzedMethod string          `json:"analyzed_method"` // 被分析方法 FQN：本切片 verdict 仅针对此方法；其余节点为其上下游上下文
	Trace          sliceTraceJSON  `json:"trace"`
	Nodes          []sliceNodeJSON `json:"nodes"`
	Edges          []sliceEdgeJSON `json:"edges"`
}

// confidenceImplication 返回该置信度对 AI 的盲区说明。
func confidenceImplication(c CallConfidence) string {
	switch c {
	case ConfExact:
		return ""
	case ConfHeuristic:
		return "call resolved heuristically; may not execute at runtime"
	case ConfPolymorphic:
		return "call resolved via polymorphic dispatch; actual target may differ at runtime"
	default:
		return "call resolution uncertain; may not execute at runtime"
	}
}

// dedupeSources 将来源标签按 type 计数去重，降低 token 浪费。
func dedupeSources(srcs []string) []sliceSourceJSON {
	counts := make(map[string]int)
	for _, s := range srcs {
		counts[s]++
	}
	out := make([]sliceSourceJSON, 0, len(counts))
	for t, c := range counts {
		out = append(out, sliceSourceJSON{Type: t, Count: c})
	}
	return out
}

// joinDeduped 将来源标签去重计数为 "type(×N)" 形式，供代码标注行使用。
func joinDeduped(srcs []string) string {
	counts := make(map[string]int)
	for _, s := range srcs {
		counts[s]++
	}
	var parts []string
	for t, c := range counts {
		if c > 1 {
			parts = append(parts, t+" (×"+itoa(c)+")")
		} else {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, ", ")
}

// BuildSliceJSON 从追溯路径构建结构化 JSON 证据清单。
// 形态与 BuildSliceFromTraceAnnotated 同口径，但输出 JSON 供 AI 直接解析：
// trace(flow/sources) + nodes[](role/entry/taint/external/cycle/sanitized) + edges[](污点流向 from->to + 置信度+implication)。
// 约定：nodes 保持 Path 原序（Path[0]=sink，Path[last]=source），edges 的 from/to 表示真实污点流向（source->sink）。
func (bc *BlockClimber) BuildSliceJSON(store *AnalysisStore, cfa *ControlFlowAnalyzer, analyzedMethod string, trace SourceTrace) (string, error) {
	// R10（架构修复）：Flow 字段必须反映此 trace 终点的真实性质，而非一律 "-> sink"。
	// Path[0] 是 sink 端（被调方）。仅当终点确实直接调用字典危险 sink 时才是真正的 sink；
	// 否则终点只是某个普通/良性方法，flow 文本须如实标注 (terminal: not a danger sink)，
	// 避免与权威 taint_status（针对被分析方法）脱钩导致 AI 误读。
	flowStr := "source -> (path unresolvable)"
	if len(trace.Path) >= 2 {
		terminal := trace.Path[0] // sink 端节点
		if nodeDirectlyCallsDangerSink(store, terminal.MethodKey) {
			flowStr = "source -> ... -> sink"
		} else {
			flowStr = "source -> ... -> " + terminal.MethodKey + " (terminal: not a danger sink)"
		}
	}
	out := sliceJSON{
		AnalyzedMethod: analyzedMethod,
		Trace:          sliceTraceJSON{Hops: len(trace.Path), Flow: flowStr, Sources: trace.Sources},
	}
	for _, node := range trace.Path {
		mk := node.MethodKey
		n := sliceNodeJSON{
			MethodKey:  mk,
			File:       node.FilePath,
			Line:       node.Line,
			IsEntry:    isEntryPoint(store, mk),
			IsAnalyzed: mk == analyzedMethod,
			External:   isExternalRef(store, mk),
			Cycle:      isCycleInPath(trace.Path, mk),
		}
		// role 硬约束（R6）：仅当该节点"直接调用字典命中的危险 sink API"时才标 "sink"。
		// 其余节点一律不标 sink——良性 sink 标 "benign"，入口标 "entry"，
		// 其余传递性中间节点 role 留空（等价于 intermediate），绝不臆造 sink 标签。
		switch {
		case nodeDirectlyCallsDangerSink(store, mk):
			n.Role = "sink"
		case nodeDirectlyCallsBenignSink(store, mk):
			n.Role = "benign"
		case isEntryPoint(store, mk):
			n.Role = "entry"
		}
		// R12/R18（架构级）：测试代码命中标记。供 AI 脚手架区分生产漏洞与测试代码疑似，
		// 对测试代码命中降级提示（不静默排除，避免漏报真漏洞）。
		if store.Methods.TestCodeMethods[mk] {
			n.IsTestCode = true
		}
		if hm, hp := httpInfoOf(store, mk); hm != "" || hp != "" {
			// httpInfoOf 返回 (HttpPaths, HttpMethods)，故 Method=HttpMethods(hp), Path=HttpPaths(hm)
			n.HTTP = &sliceHTTPJSON{Method: hp, Path: hm}
		}
		// taint: 去重计数，结构化为 {param, sources:[{type,count}]}
		if pts, ok := store.Methods.ParamTaints[mk]; ok {
			for param, srcs := range pts {
				n.Taint = append(n.Taint, sliceTaintJSON{Param: param, Sources: dedupeSources(srcs)})
			}
		}
		if rts := store.Methods.ReturnTaints[mk]; len(rts) > 0 {
			n.Taint = append(n.Taint, sliceTaintJSON{Param: "return", Sources: dedupeSources(rts)})
		}
		// R16（架构级，非 hardcode）：行级变量粒度锚点。遍历该方法的 LocalVars，
		// 仅纳入「被污点影响」的变量（Tainted 或携带 source），输出变量名+行号+代码片段，
		// 使 AI 可逐变量无歧义解析数据流，无需自主 grep。复用现有 LocalVars 数据。
		if lvs, ok := store.Methods.LocalVars[mk]; ok {
			for vname, lv := range lvs {
				if lv.Tainted || len(lv.Sources) > 0 {
					n.Variables = append(n.Variables, sliceVarJSON{
						Name:     vname,
						Line:     lv.Line,
						Tainted:  lv.Tainted,
						Sources:  lv.Sources,
						InitText: lv.InitText,
					})
				}
			}
		}
		// sanitizer 说明：命中则给位置+方法；未命中则说明"未找到净化调用"
		if ok, at := sanitizerOf(cfa, store, mk); ok {
			n.Sanitized = sliceSanitizedJSON{Sanitized: true, At: at, CheckedBy: at}
		} else {
			n.Sanitized = sliceSanitizedJSON{Sanitized: false, Note: "no sanitizer call found on taint var(s)"}
		}
		out.Nodes = append(out.Nodes, n)
	}
	// edges: 真实污点流向 source->sink。Path 是 sink->source 回溯序，
	// 故 Path[i+1] 是调用方（source 侧），Path[i] 是被调方（sink 侧）。
	for i := 0; i+1 < len(trace.Path); i++ {
		from, to := trace.Path[i+1], trace.Path[i]
		// from 是调用者（source 侧），调用边存于 Edges[from.MethodKey]
		conf, rule := edgeConfidenceRule(store, from, to, true)
		// R7：收集路径是否含启发式/多态分派边（非 exact）。
		if conf == ConfHeuristic || conf == ConfPolymorphic || conf == CallConfidence("unknown") {
			out.Trace.HasHeuristicEdges = true
		}
		out.Edges = append(out.Edges, sliceEdgeJSON{
			From:        from.MethodKey,
			To:          to.MethodKey,
			Direction:   "taint_flow",
			Confidence:  string(conf),
			Rule:        rule,
			Implication: confidenceImplication(conf),
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // 保留 "->" 等符号，避免转义为 \u003e，对 AI 更友好
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// BuildSliceFromTrace 从追溯路径构建自包含切片。
// trace 中的每个节点贡献其方法体涉及的行。
func (bc *BlockClimber) BuildSliceFromTrace(store *AnalysisStore, trace []CallNode) string {
	linesByFile := make(map[string]map[int]bool)
	for _, node := range trace {
		fn, ok := store.Methods.Functions[node.MethodKey]
		if !ok {
			continue
		}
		if linesByFile[fn.FilePath] == nil {
			linesByFile[fn.FilePath] = make(map[int]bool)
		}
		linesByFile[fn.FilePath][fn.Line] = true
		// 也加入调用行
		if node.Line > 0 {
			linesByFile[fn.FilePath][node.Line] = true
		}
	}
	var parts []string
	for filePath, lines := range linesByFile {
		slice := bc.BuildSelfContainedSlice(filePath, lines)
		if slice != "" {
			parts = append(parts, "// === "+filePath+" ===\n"+slice)
		}
	}
	return strings.Join(parts, "\n\n")
}
