package agentic

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"appsecgo/internal/funcdistill"
	"appsecgo/internal/llm"
	"appsecgo/internal/slice"
	"appsecgo/internal/taintbridge"
)

// ToolExecutor 移植 _ToolExecutor (agentic_enrich.py:371-482)。
// 集群5 per-function 蒸馏缓存：store==nil → off 路径（read_function 返 full body）；
// store!=nil → on 路径（命中返 summary+excerpt，未命中返 full body + side-effect 蒸馏存入）。
type ToolExecutor struct {
	idx      *slice.RepositoryIndex // 复用 P1b RepositoryIndex（search_definitions/read_function）
	repoRoot string
	// 集群5 蒸馏缓存字段（store==nil 时全走 off 路径，零开销）。
	provider llm.Provider                      // 蒸馏 LLM 调用（text 路径，无 Harness）
	model    string                            // 模型族键（换族强制重蒸）
	store    *funcdistill.FunctionSummaryStore // run 内 per-function 摘要缓存
	engine   taintbridge.EngineQuerier         // NEW: nil → 引擎工具 off（零回归）
	// Phase 1 (root-2 裸名消歧, disambiguation spec §4): alert 的 sink 文件 (codesafe bugFile)。
	// LLM 调 who_calls/reachable_sinks 等不带 file_path 时,resolveMethodKey 用它兜底消歧
	// (component.submit 而非 controller.submit)。off 路径 (engine==nil) resolveMethodKey 早返不读 → 零变。
	alertSinkFile string
}

// SetEngineQuery 注入引擎查询器（nil = off）。judge/rejudge 路径调用；
// enrich/authz_coverage 不调用（用各自工具集，不需 engine）。
func (e *ToolExecutor) SetEngineQuery(eq taintbridge.EngineQuerier) {
	e.engine = eq
}

// SetAlertSinkFile 注入 alert 的 sink 文件 (codesafe bugFile, authoritative sink location)。
// Phase 1 (root-2 裸名消歧): LLM 调 who_calls/reachable_sinks/trace_to_sources/get_callees
// 不带 file_path 时,resolveMethodKey 用它兜底消歧 (既有层 2 路径后缀/层 3 类名 stem 自然生效,
// 不改 ResolveMethodKey 逻辑)。LLM 传 file_path 时优先 LLM 的 (不覆盖)。off 路径 (engine==nil)
// resolveMethodKey 早返 false 不读 → off 行为零变。
func (e *ToolExecutor) SetAlertSinkFile(f string) { e.alertSinkFile = f }

// NewToolExecutor 构造执行器。store==nil → 蒸馏 off（read_function 返 full body，现状行为）。
// judge explore 路径传 (nil, "", nil) 走 off；agentic enrich 传真实值走 on。
func NewToolExecutor(idx *slice.RepositoryIndex, provider llm.Provider,
	model string, store *funcdistill.FunctionSummaryStore) *ToolExecutor {
	root := ""
	if idx != nil {
		root = idx.RepoRoot()
	}
	return &ToolExecutor{idx: idx, repoRoot: root, provider: provider, model: model, store: store}
}

// Execute 移植 _ToolExecutor.execute (agentic_enrich.py:384-404)。异常/panic → {"error":...}
// 不抛出（保 loop 配对；铁律 D）。未知 name（含 record_finding）→ {"error":"unknown tool: <name>"}。
// defer recover 拟合 Python try/except Exception catch-all：任何 readFile/grepRepo/
// searchDefinitions/readFunction panic 不得杀死 agentic loop。
func (e *ToolExecutor) Execute(name string, args map[string]any) (ret any) {
	defer func() {
		if r := recover(); r != nil {
			ret = map[string]any{"error": fmt.Sprintf("%v", r)}
		}
	}()
	switch name {
	case "read_file":
		return e.readFile(args)
	case "grep_repo":
		return e.grepRepo(args) // T3
	case "search_definitions":
		return e.searchDefinitions(args) // T4
	case "read_function":
		return e.readFunction(args) // T4
	case "reachable_sinks":
		return e.reachableSinks(args)
	case "trace_to_sources":
		return e.traceToSources(args)
	case "get_callees":
		return e.getCallees(args)
	case "trace_var_flow":
		return e.traceVarFlow(args)
	case "code_at_line":
		return e.codeAtLine(args)
	case "who_calls":
		return e.whoCalls(args)
	}
	return map[string]any{"error": "unknown tool: " + name}
}

// safeResolve 移植 _safe_resolve (agentic_enrich.py:82-97)：rel 须留在 repoRoot 内，
// 拒 .. 逃逸 / 绝对路径 / Windows 盘符。返 (realpath, true) 或 ("", false)。
// 用 filepath.EvalSymlinks 拟合 os.path.realpath（解析符号链接）；
// EvalSymlinks 失败（路径尚不存在等）退回 filepath.Abs。
// 注：prefix 检查用 root+sep（非裸 root）以防 string-prefix 误判（如 root=C:\foo 被
// C:\foobar 冒充）。filepath.Join 先 clean，../etc/passwd 逃逸到 root 兄弟目录，
// 不满足 root+sep 前缀 → 拒绝。
func (e *ToolExecutor) safeResolve(rel string) (string, bool) {
	if rel == "" {
		return "", false
	}
	rel = strings.ReplaceAll(rel, "\\", "/")
	if strings.HasPrefix(rel, "/") || driveLetterRe.MatchString(rel) {
		return "", false
	}
	root, err := filepath.EvalSymlinks(e.repoRoot)
	if err != nil || root == "" {
		root, _ = filepath.Abs(e.repoRoot)
	}
	target, err := filepath.EvalSymlinks(filepath.Join(root, rel))
	if err != nil || target == "" {
		target, _ = filepath.Abs(filepath.Join(root, rel))
	}
	if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return "", false
	}
	return target, true
}

var driveLetterRe = regexp.MustCompile(`^[A-Za-z]:`)

// readFile 移植 _read_file (agentic_enrich.py:431-449)。忠实 1:1：
//   - repo_root 空 → {"error":"repo_root unavailable"}
//   - safeResolve 失败或 isfile 失败（含目录）→ {"error":"file not found or path outside repo_root: "+rel}
//   - start = max(1, int(start_line or 1))：缺省/0/负 → 1
//   - endDefault = start + MaxReadLines - 1；end = min(endDefault, int(end_line or endDefault))
//     Python `args.get("end_line", endDefault) or endDefault` 真值：缺省/0(falsy) → endDefault，
//     非零(含负) → 保留原值；再上夹 endDefault（min(start+399, ...)）。负 end 保留为负。
//   - readlines parity：归一化 \r\n/\r → \n，按 \n 切且保留行尾分隔符（SplitAfter），
//     去掉单一尾部空元素（拟合 Python text-mode readlines：末行无 \n 不补 \n）
//   - OOB-safe slice：lo=start-1 clamp[0,total]，hi=end clamp[0,total]，lo>hi → 空 sel
//   - content = strings.Join(sel, "")（拟合 "".join，空 sel → ""，无尾随 \n）
//   - end_line 报 = start+len(sel)-1（Python）；空 sel → start-1
//   - truncated = end < total（用上夹后的 end，非 len(sel)）
func (e *ToolExecutor) readFile(args map[string]any) any {
	rel, _ := args["file_path"].(string)
	if e.repoRoot == "" {
		return map[string]any{"error": "repo_root unavailable"}
	}
	target, ok := e.safeResolve(rel)
	if !ok {
		return map[string]any{"error": "file not found or path outside repo_root: " + rel}
	}
	// isfile parity：os.Stat + IsDir → 拒目录/不存在
	st, err := os.Stat(target)
	if err != nil || st.IsDir() {
		return map[string]any{"error": "file not found or path outside repo_root: " + rel}
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return map[string]any{"error": "read failed: " + err.Error()}
	}
	// universal-newline 归一化（\r\n/\r → \n），拟合 Python text-mode open + readlines
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	// readlines parity：保留每行 \n 终止符。SplitAfter("a\nb\n","\n") → ["a\n","b\n",""]，
	// 去掉单一尾部 "" 即得 ["a\n","b\n"]（拟合 readlines）；末行无 \n 不补 \n。
	lines := strings.SplitAfter(normalized, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	total := len(lines)
	// start_line：缺省/0/负 → 1（拟合 Python max(1, int(... or 1))）
	start := toInt(args["start_line"])
	if start < 1 {
		start = 1
	}
	// end_line：缺省/0(falsy) → endDefault；非零(含负) 保留原值；再上夹 endDefault
	// （Python `args.get("end_line", endDefault) or endDefault`；负值保留以拟合 Python 负 stop 索引）
	endDefault := start + MaxReadLines - 1
	end := toInt(args["end_line"])
	if end == 0 {
		end = endDefault
	}
	if end > endDefault {
		end = endDefault
	}
	// OOB-safe slice（拟合 Python list[lo:hi] 越界不报错，永不 panic）
	lo := start - 1
	if lo < 0 {
		lo = 0
	}
	if lo > total {
		lo = total
	}
	hi := end
	if hi < 0 {
		hi = 0
	}
	if hi > total {
		hi = total
	}
	var sel []string
	if lo < hi {
		sel = lines[lo:hi]
	} else {
		sel = lines[:0]
	}
	return readFileResult{
		FilePath:   rel,
		StartLine:  start,
		EndLine:    start + len(sel) - 1,
		LinesTotal: total,
		Truncated:  end < total,
		Content:    strings.Join(sel, ""),
	}
}

// readFileResult — read_file 工具返回结构。json tags 顺序对齐 Python dict 插入序
// （file_path, start_line, end_line, lines_total, truncated, content），保证 Go
// json.Marshal 输出的 key 顺序 byte-exact 匹配 Python json.dumps（Go map 无序）。
type readFileResult struct {
	FilePath   string `json:"file_path"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	LinesTotal int    `json:"lines_total"`
	Truncated  bool   `json:"truncated"`
	Content    string `json:"content"`
}

// toInt 拟合 Python int(args.get(...) or default) 的 int() 转换 + 真值判断：
// 缺省/nil → 0；int/float → 数值；其余 → 0。调用方据 <1 判定是否走 default。
func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

// grepRepo 移植 _grep_repo (agentic_enrich.py:451-482)。faithful 1:1：
//   - file_glob 缺省/nil/"" → "*.java"（拟合 Python `args.get(...,"*.java") or "*.java"` 真值）
//   - file cap：scanned++ 后若 > MaxGrepFiles 立即停走（SkipAll）+ truncated=true,
//     reason="file cap reached"（Python immediate return，带 reason 字段）
//   - match cap：append 后若 len(matches) >= MaxGrepMatches 立即停走 + truncated=true（无 reason）
//   - text：匹配行去尾随 \n（Split 已切掉）+ 截断 200 字符（Python line.rstrip("\n")[:200]）
//   - file：filepath.Rel + filepath.ToSlash（Python os.path.relpath + sep→"/"）
//   - fnmatch：filepath.Match(base(glob), fn) || filepath.Match(glob, fn)
//   - regex：Compile 失败 → {"error":"bad regex: " + err}（RE2 无 lookahead；P4 fixture 用简单正则）
//   - 排序：(file, line) 升序兜底——单文件 P4 fixture 下与 Python 同序；多文件 walk 序 parity defer 到 P5+
//
// Execute 已有 defer-recover 兜底，grepRepo 不再另加 recover（拟合 Python execute try/except 包 _grep_repo）。
func (e *ToolExecutor) grepRepo(args map[string]any) any {
	pat, _ := args["pattern"].(string)
	if e.repoRoot == "" || pat == "" {
		return map[string]any{"error": "pattern and repo_root required"}
	}
	rx, err := regexp.Compile(pat)
	if err != nil {
		return map[string]any{"error": "bad regex: " + err.Error()}
	}
	// file_glob：缺省/nil(type assert 失败→"")/"" → "*.java"
	glob, _ := args["file_glob"].(string)
	if glob == "" {
		glob = "*.java"
	}
	base := filepath.Base(glob)
	matches := []map[string]any{}
	scanned := 0
	truncated := false
	reason := ""
	filepath.Walk(e.repoRoot, func(fpath string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() {
			return nil
		}
		fn := filepath.Base(fpath)
		// 对齐 Python fnmatch.fnmatch(fn, basename(glob)) OR fnmatch(fn, glob)
		if !matchFn(fn, base) && !matchFn(fn, glob) {
			return nil
		}
		scanned++
		if scanned > MaxGrepFiles {
			// Python IMMEDIATE return（不读本文件），带 reason="file cap reached"
			truncated = true
			reason = "file cap reached"
			return filepath.SkipAll
		}
		data, rerr := os.ReadFile(fpath)
		if rerr != nil {
			return nil // 拟合 Python except OSError: continue
		}
		// universal-newline 归一化（\r\n/\r → \n），拟合 Python text-mode open
		normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
		normalized = strings.ReplaceAll(normalized, "\r", "\n")
		lines := strings.Split(normalized, "\n")
		// 去单一尾部空元素：拟合 Python 文件行迭代（末行无 \n 不补 \n，无尾随空行）
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = lines[:n-1]
		}
		for i, line := range lines {
			if rx.MatchString(line) {
				rel, _ := filepath.Rel(e.repoRoot, fpath)
				rel = filepath.ToSlash(rel)
				matches = append(matches, map[string]any{
					"file": rel,
					"line": i + 1,
					"text": truncateLine(line),
				})
				if len(matches) >= MaxGrepMatches {
					// Python IMMEDIATE return（无 reason）
					truncated = true
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	// 排序兜底（spec §5）：单文件时 line 升序 == Python 同序；多文件 defer 到 P5+。
	sortMatches(matches)
	out := grepRepoResult{
		Matches:   matches,
		Count:     len(matches),
		Truncated: truncated,
	}
	if reason != "" {
		out.Reason = reason
	}
	return out
}

// grepRepoResult — grep_repo 工具返回结构。json tags 顺序对齐 Python dict 插入序
// （matches, count, truncated, reason?），保证 Go json.Marshal key 顺序 byte-exact
// 匹配 Python json.dumps（Go map 无序）。reason 可选（omitempty）。
type grepRepoResult struct {
	Matches   []map[string]any `json:"matches"`
	Count     int              `json:"count"`
	Truncated bool             `json:"truncated"`
	Reason    string           `json:"reason,omitempty"`
}

// truncateLine 拟合 Python line.rstrip("\n")[:200]：Split 已去 \n，仅截断 200 字符。
// 注：按字节切片（Python 按字符），对 ASCII fixture 等价；非 ASCII 多字节字符可能截半（defer 增强）。
func truncateLine(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// matchFn 对齐 Python fnmatch.fnmatch（单 basename / glob），用 filepath.Match。
// filepath.Match 大小写敏感、支持 * ? [seq]；对 *.java/*.xml fixture 与 fnmatch 等价。
func matchFn(name, pattern string) bool {
	matched, _ := filepath.Match(pattern, name)
	return matched
}

// sortMatches 按 (file, line) 升序——单文件 P4 fixture 下与 Python line-order 同序。
// 插入排序，matches ≤ MaxGrepMatches(30)，规模小。
func sortMatches(m []map[string]any) {
	for i := 1; i < len(m); i++ {
		for j := i; j > 0; j-- {
			fj, _ := m[j]["file"].(string)
			fk, _ := m[j-1]["file"].(string)
			lj, _ := m[j]["line"].(int)
			lk, _ := m[j-1]["line"].(int)
			if fj < fk || (fj == fk && lj < lk) {
				m[j], m[j-1] = m[j-1], m[j]
			} else {
				break
			}
		}
	}
}

// searchDefinitions 移植 _ToolExecutor.execute search_definitions 分支
// (agentic_enrich.py:386-391)。复用 slice.RepositoryIndex.Resolve（P1b parity）。
// 返 {"found": bool, "results": [...]}：max 10 defs，resolve-order；
// class_name nil→JSON null（Go nil any），非 nil→解引用 string；lines=[start,end]。
// results 初始化为非 nil 空 slice（Python `[]` parity；对齐 T3 修复模式）。
func (e *ToolExecutor) searchDefinitions(args map[string]any) map[string]any {
	if e.idx == nil {
		return map[string]any{"error": "repo_index unavailable"}
	}
	name, _ := args["name"].(string) // 缺省→""，拟合 Python args.get("name","")
	defs := e.idx.Resolve(name)
	results := []map[string]any{}
	n := len(defs)
	if n > 10 {
		n = 10
	}
	for _, d := range defs[:n] {
		results = append(results, map[string]any{
			"file_path":     d.FilePath,
			"function_name": d.Name,
			"class_name":    ptrDeref(d.ClassName), // nil→nil any (JSON null)；非 nil→string
			"lines":         []int{d.LineRange[0], d.LineRange[1]},
		})
	}
	return map[string]any{"found": len(defs) > 0, "results": results}
}

// readFunction 移植 read_function 分支 (agentic_enrich.py:392-397) + _read_function_cached
// distill-off fresh path (:412-414)。FUNC_DISTILL 默认 off → 返 full body，无
// summary/excerpt/cached 键（蒸馏推增强期）。nil idx → unavailable；miss → {"found":false}。
func (e *ToolExecutor) readFunction(args map[string]any) map[string]any {
	if e.idx == nil {
		return map[string]any{"error": "repo_index unavailable"}
	}
	fp, _ := args["file_path"].(string)
	fn, _ := args["function_name"].(string)
	fd := resolveRef(e.idx, fp, fn)
	if fd == nil {
		return map[string]any{"found": false}
	}
	// off 路径（store==nil）：现状行为，零开销。
	if e.store == nil {
		return map[string]any{
			"found":         true,
			"file_path":     fd.FilePath,
			"function_name": fd.Name,
			"code":          fd.Body,
		}
	}
	// on 路径：命中 → 摘要+摘录（不重读重蒸，省 token）；未命中 → full body + side-effect 蒸馏。
	key := funcdistill.BuildCacheKey(fd.Body, e.model)
	if cached := e.store.Get(key); cached != nil {
		return map[string]any{
			"found":         true,
			"cached":        true,
			"file_path":     fd.FilePath,
			"function_name": fd.Name,
			"summary":       cached,
			"excerpt":       firstNLines(fd.Body, funcdistill.ExcerptLines),
		}
	}
	// 未命中：返 full body 让本轮 LLM 推理 + side-effect 蒸馏存入（失败 fail-open 不阻塞）。
	if e.provider != nil {
		if summary := funcdistill.DistillFunction(fd.Body, fd.Name, e.provider, e.model); summary != nil {
			e.store.Set(key, summary)
		}
	}
	return map[string]any{
		"found":         true,
		"file_path":     fd.FilePath,
		"function_name": fd.Name,
		"code":          fd.Body,
	}
}

// firstNLines 返回 body 前 n 行（\n join），对齐 Python "\n".join(body.splitlines()[:n])。
func firstNLines(body string, n int) string {
	lines := strings.Split(body, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// ptrDeref: *string nil → nil any (JSON null，对齐 Python None)；非 nil → 解引用 string。
func ptrDeref(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// resolveRef 移植 _resolve_ref (agentic_enrich.py:183-188)：按 file_path+function_name
// 定位首个匹配 FunctionDef。file_path 空时取首个（`fd.file_path == file_path or not file_path`）。
// 返回指针到副本（避免取循环变量地址的移植可移植性陷阱；Go 1.22+ 虽已 per-iteration 但 copy 更稳妥）。
func resolveRef(idx *slice.RepositoryIndex, file, name string) *slice.FunctionDef {
	for _, d := range idx.Resolve(name) {
		if file == "" || d.FilePath == file {
			dc := d
			return &dc
		}
	}
	return nil
}

// reachableSinks / traceToSources 真实实现 + JudgeTools() schema 见 engine_tools.go（Task 5）。
