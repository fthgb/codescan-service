package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"appsecgo/internal/faces"
)

// exploratoryTools = 探索性工具(贡献路径分叉信号)。
// record_finding/submit_verdict 是终结动作(Layer C 短路/收尾),固定出现、不贡献分叉,纳入只拉高 LCS 噪声,故排除。
var exploratoryTools = map[string]bool{
	"read_file": true, "grep_repo": true, "search_definitions": true, "read_function": true,
	"reachable_sinks": true, "trace_to_sources": true, "get_callees": true, "trace_var_flow": true, "code_at_line": true,
}

// ExtractToolTypeSeq 从 trace["tool_log"] 提取探索性工具名序列(不含参数,去终结符)。
// tool_log entry 形如 {tool, args, result_excerpt}(judge.go:195 写入,loop.go seenResult 缓存)。
func ExtractToolTypeSeq(toolLog []map[string]any) []string {
	out := make([]string, 0, len(toolLog))
	for _, e := range toolLog {
		name, _ := e["tool"].(string)
		if name == "" {
			continue
		}
		if exploratoryTools[name] {
			out = append(out, name)
		}
	}
	return out
}

// LCSRatio = 最长公共子序列长度 / 较长序列长度。
// 容忍插入(一次额外工具不重创),保序,对开头分叉敏感(前缀不同 LCS 自然短)。
// 两空序列 = 无分叉 → 1.0(诚实:都为空即一致)。
func LCSRatio(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	lcs := lcsLen(a, b)
	return float64(lcs) / float64(maxLen)
}

// lcsLen 经典 DP 最长公共子序列长度。
func lcsLen(a, b []string) int {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	return dp[n][m]
}

// CommonPrefixLen = 两序列从首元素起连续相同元素数。
// 前缀=0/1 ⇒ turn0 fork(3de4b5c0 模式直接信号),补 LCS ratio 不区分"开头分叉 vs 中间多一步"的缺陷。
func CommonPrefixLen(a, b []string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// Task 4: 两层信号归类器(未接工具需求 + 已接工具绕路)。

// CoverageGapSignal — 第一层:未接工具需求(tool-coverage-gap 取证)。
type CoverageGapSignal struct {
	HasWhoCalls        bool
	HasListBreakpoints bool
	HasHasSanitizer    bool
	HasFieldQuery      bool
	Reasons            []string // 命中依据(reasoning 片段/grep pattern),报告 dump 用
}

// BypassSignal — 第二层:已接工具未被 LLM 选用(绕路 vs 不需要)。
type BypassSignal struct {
	HasGetCalleesBypass   bool // search_definitions 连续 callee 追踪 = get_callees/trace_var_flow 绕路
	HasTraceVarFlowBypass bool
	ChainTruncatedHint    bool // result_excerpt 截断影响链式判定置信度
	ConsecutiveSearchDef  int  // seq 中最长连续 search_definitions 段(2026-08-18 校准加:主信号)
	MaxResultChain        int  // search_definitions 结果链式最长连续(跨断段保留)
	Reasons               []string
}

// SearchDefCall — search_definitions 调用记录(tool_log entry 简化)。
type SearchDefCall struct {
	Name          string // args.name
	ResultExcerpt string // result_excerpt(500 字符截断)
}

// classify patterns — 基于真实 grep 语料迭代(spec §5.3:不拍脑袋,先 dump 再定)。
// 2026-08-18 校准:probe-core live 5-run §3 零命中(旧 regex 太窄)→ 扩同义词 +
// §3/§4 改 dump 全量 raw evidence(reasoning-head/grep patterns/search-def names)
// 供离线校准(GR-8:不猜阈值,先 dump 真语料)。regex 仍保守,命中即候选,非定论。
// 2026-08-18 §3 再校准(离线 cells JSON):扩同义词后 12/12 relation-trade 全过火,
// 根因=否定句"无净化""无校验"被当 has_sanitizer want。改 uncertainty-gated:只在
// uncertainty marker 之后窗口内出现 category 词才发信号,且 category 前紧邻否定=抑制。
var (
	// reUncertainty — LLM 表达未确定(无法验证/不能排除/不清楚...)。§3 只在 uncertainty
	// 之后的窗口内找 category 词,无 uncertainty = 无未确定点 → §3 不发信号(杀否定句过火)。
	reUncertainty = regexp.MustCompile(`(?:无法|不能|未能|难以|没法)(?:确定|验证|排除|判断|确认|得出|断定)|不清楚|不确定|未知|存疑`)
	// reNegation — category 词前紧邻否定(无/未/没有...)= 已断言不存在 → 抑制(不报 want)。
	reNegation        = regexp.MustCompile(`无|未|没有|不|缺乏|缺少|未经|未做|无任何`)
	reFieldAssignment = regexp.MustCompile(`(?i)set[A-Z]\w+|\.\s*set\s*\(|字段|field\s+assignment|赋值|\w+\s*\.\s*\w+\s*=\s*`)
	// reSanitizer 去掉 验证/检查(避免与 reUncertainty 的 验证 自激);补 白名单/安全措施/
	// magic/content-type(a8r0 真语料:无法验证...安全措施)。
	reSanitizer  = regexp.MustCompile(`(?i)sanitize|sanitise|escape|encode|过滤|净化|转义|消毒|白名单|安全措施|magic|content-type`)
	reWhoCalls   = regexp.MustCompile(`(?i)调用方|谁调|谁在调|谁调用|caller|who calls|call site|invoked by`)
	reBreakpoint = regexp.MustCompile(`(?i)分支|分叉|不同路径|if\s*\{|switch|breakpoint|条件分支`)
)

// ClassifyCoverageGapSignals — 第一层:未接工具需求。
// reasoning:前 500 字(不足由 grep 兜底,三路互补)。grepPatterns:tool_log 所有 grep_repo 的 args.pattern。
// 2026-08-18:每个命中信号都记 Reason(校准 dump 用:看命中了哪条同义词)。
// 2026-08-18 §3 再校准(离线 cells JSON):改 uncertainty-gated——只在 uncertainty marker
// 之后 80 字符窗口内出现该工具 category 词才发信号,且 category 前紧邻否定=抑制。
// 根因:扩同义词后 12/12 relation-trade 全过火,否定句"无净化""无校验"(已断言不存在)
// 被误报为 has_sanitizer want。live 实证:仅 a8r0"无法验证...安全措施"真火,余 50+ 否定句
// 无 uncertainty marker → 不发。grep-only / 无 uncertainty = 无未确定点 → §3 不发信号。
func ClassifyCoverageGapSignals(reasoning string, grepPatterns []string) CoverageGapSignal {
	sig := CoverageGapSignal{}
	combined := reasoning
	for _, p := range grepPatterns {
		combined += "\n" + p
	}
	if m := firstUncertainCategoryMatch(combined, reWhoCalls); m != "" {
		sig.HasWhoCalls = true
		sig.Reasons = append(sig.Reasons, "who_calls:"+m)
	}
	if m := firstUncertainCategoryMatch(combined, reBreakpoint); m != "" {
		sig.HasListBreakpoints = true
		sig.Reasons = append(sig.Reasons, "list_breakpoints:"+m)
	}
	if m := firstUncertainCategoryMatch(combined, reSanitizer); m != "" {
		sig.HasHasSanitizer = true
		sig.Reasons = append(sig.Reasons, "has_sanitizer:"+m)
	}
	if m := firstUncertainCategoryMatch(combined, reFieldAssignment); m != "" {
		sig.HasFieldQuery = true
		sig.Reasons = append(sig.Reasons, "field_query:"+m)
	}
	return sig
}

// firstUncertainCategoryMatch — uncertainty-gated category 命中:返回首个"落在某
// uncertainty marker 之后 80 字符窗口内、且其前 10 字符无否定词"的 category 词;无则 ""。
// 三步:(1) 无 uncertainty marker → 直接 ""(无未确定点);(2) category 须在 unc 之后窗口内
// (区分"无法验证...净化"=want vs"已净化"无 unc=不发);(3) category 前 10 字符有否定词
// (无/未/没有...)= 已断言不存在 → 抑制(杀"无法确定...无净化"这类 unc+否定同现)。
func firstUncertainCategoryMatch(combined string, re *regexp.Regexp) string {
	uncIdxs := reUncertainty.FindAllStringIndex(combined, -1)
	if len(uncIdxs) == 0 {
		return ""
	}
	matches := re.FindAllStringIndex(combined, -1)
	for _, u := range uncIdxs {
		windowEnd := u[1] + 80
		if windowEnd > len(combined) {
			windowEnd = len(combined)
		}
		for _, m := range matches {
			if m[0] < u[1] || m[1] > windowEnd {
				continue // category 不在该 uncertainty 之后 80 字符窗口内
			}
			negStart := m[0] - 10
			if negStart < 0 {
				negStart = 0
			}
			if m[0] > 0 && reNegation.MatchString(combined[negStart:m[0]]) {
				continue // 否定前缀 → 已断言不存在,抑制
			}
			return combined[m[0]:m[1]]
		}
	}
	return ""
}

// ClassifyBypassSignals — 第二层:已接工具绕路。
// 两路信号,任一命中即 HasGetCalleesBypass:
//  1. ConsecutiveSearchDef(seq) ≥3:LLM 连续 ≥3 次 search_definitions = 手动 callee 遍历,
//     本可一次 get_callees 得(2026-08-18 校准:旧 result-chain 规则 live 零命中,太严;
//     §2 真语料显示连续 search_definitions 是主模式)。≥3 区分"重 callee 遍历(绕路)"
//     vs "2 次无关查找" vs "欠探索(alert3 run2 仅 1 次 search)"。
//  2. MaxResultChain ≥2(旧规则,保留作确认):call N+1.Name 出现在 call N result_excerpt。
//
// 截断置信度:result_excerpt 500 字截断,链路深处 target 可能看不到 → 标 ChainTruncatedHint。
// 跨断段取 MaxResultChain:序列 A→B→C(链3)后断再 D→E(链2),取最长链=3,不丢前段。
//
// 2026-08-18:签名加 seq []string(连续 search_definitions 需全序列,filtered calls 看不出
// 中间是否夹其他工具)。旧调用方传 nil seq → ConsecutiveSearchDef=0,仅走 result-chain(向后兼容)。
func ClassifyBypassSignals(seq []string, calls []SearchDefCall) BypassSignal {
	sig := BypassSignal{}
	sig.ConsecutiveSearchDef = maxConsecutiveSearchDef(seq)
	if sig.ConsecutiveSearchDef >= 3 {
		sig.HasGetCalleesBypass = true
		sig.HasTraceVarFlowBypass = true
		sig.Reasons = append(sig.Reasons, fmt.Sprintf("seq 连续 search_definitions×%d(≥3=手动 callee 遍历,get_callees/trace_var_flow 绕路)", sig.ConsecutiveSearchDef))
	}
	if len(calls) >= 2 {
		chainLen := 1
		for i := 1; i < len(calls); i++ {
			prev := calls[i-1].ResultExcerpt
			target := calls[i].Name
			if strings.Contains(prev, target) {
				chainLen++
				if len(prev) >= 490 {
					sig.ChainTruncatedHint = true
				}
				if chainLen > sig.MaxResultChain {
					sig.MaxResultChain = chainLen
				}
			} else {
				chainLen = 1
			}
		}
		if sig.MaxResultChain >= 2 {
			sig.HasGetCalleesBypass = true
			sig.HasTraceVarFlowBypass = true
			sig.Reasons = append(sig.Reasons, fmt.Sprintf("search_definitions 结果链式最长连续 %d 次(沿 callee 链,绕路)", sig.MaxResultChain))
		}
	}
	return sig
}

// maxConsecutiveSearchDef — seq 中最长连续 search_definitions 段长度(其他工具夹断即重置)。
func maxConsecutiveSearchDef(seq []string) int {
	max, cur := 0, 0
	for _, t := range seq {
		if t == "search_definitions" {
			cur++
			if cur > max {
				max = cur
			}
		} else {
			cur = 0
		}
	}
	return max
}

// Task 5: 报告 dump DumpReport(5 段 markdown 落盘)。

// EvalCell — harness grid 单元(alert × run)。Task 6 填。
type EvalCell struct {
	Verdict        string
	Cwe            string
	Confidence     int
	Bughash        string
	ActualTypes    []string // jr.ActualVulnerabilityTypes;§6 族级 wobble 用,faces.FamilyOf 收敛(导出注释明文授权 harness 复用同表)
	AttackerControl string // jr.ExploitPath.AttackerControlAtSink;2026-08-30 NEW observed 前提取证:conclusive-negative(none)→uncertain 计数(离线 cells JSON 读;§5 avt 不读此字段 → 零 avt-wobble/verdict 风险)
	ToolTurns      int
	Action         string
	Guards         string
	ReasoningHead  string
	ToolTypeSeq    []string
	GrepPatterns   []string        // tool_log 所有 grep_repo 的 args.pattern(信号归类第一层用)
	SearchDefCalls []SearchDefCall // tool_log 所有 search_definitions(第二层绕路用)
	Err            error
}

// DumpReport 写 5 段 markdown 到 path(os.MkdirAll 父目录)。
// grid 可能 nil(空跑不崩)。报告含 live LLM 数据 → 调用方(Task 6)不 git add。
func DumpReport(path string, grid [][]EvalCell) error {
	// filepath.Dir 跨平台:正确处理 `/`(POSIX)与 `\`(Windows,filepath.Join 产出)。
	// 旧 strings.LastIndex(path,"/") 在 Windows 反斜杠路径返 -1 → 跳过 MkdirAll → WriteFile 失败。
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	var b strings.Builder
	b.WriteString("# Tool-Usage & Judgment-Stability Diagnostic Report\n\n")
	b.WriteString("## 1. Verdict Wobble Grid (alert × run)\n\n")
	writeWobbleGrid(&b, grid)
	b.WriteString("\n## 2. Tool Sequence Consistency (LCS ratio + longest common prefix)\n\n")
	writeSeqConsistency(&b, grid)
	b.WriteString("\n## 3. Tool-Coverage Gap Signals (未接工具需求)\n\n")
	writeCoverageGap(&b, grid)
	b.WriteString("\n## 4. Bypassed-Tool Signals (已接工具绕路)\n\n")
	writeBypass(&b, grid)
	b.WriteString("\n## 5. AVT-Family Wobble (族级收敛后跨 run 比)\n\n")
	writeAVTFamily(&b, grid)
	b.WriteString("\n## 6. Conclusions & Recommendations\n\n")
	b.WriteString("- 因果耦合假说验证:见 §2 verdict wobble 的 alert 其 LCS ratio 是否也低。\n")
	b.WriteString("- avt-family wobble:见 §5 族集跨 run 一致=prose 噪声被族级去噪;族集不同=真多面 wobble(#1 真异面率信号)。\n")
	b.WriteString("- 后续 arc 建议:基于 §3/§4/§5 命中点设计事实固化 / 接工具 / prompt 引导(非盲打,GR-8)。\n")
	return os.WriteFile(path, []byte(b.String()), 0644)
}

// DumpCellsJSON — 落盘全量 EvalCell grid(raw:reasoning-head/grep patterns/search-def
// calls/seq/verdict...)为 JSON,供离线校准 §3/§4 启发式无需重跑 live(GR-8:dump 真语料再定阈值)。
// 含 live LLM 数据 → 调用方不 git add。grid nil → 写 "[]"(空跑不崩)。
func DumpCellsJSON(path string, grid [][]EvalCell) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	if grid == nil {
		grid = [][]EvalCell{}
	}
	data, err := json.MarshalIndent(grid, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func writeWobbleGrid(b *strings.Builder, grid [][]EvalCell) {
	if len(grid) == 0 {
		b.WriteString("(no data)\n")
		return
	}
	for i, row := range grid {
		set := map[string]bool{}
		for _, c := range row {
			if c.Err != nil {
				continue
			}
			set[c.Verdict] = true
		}
		wobble := ""
		if len(set) > 1 {
			wobble = " ⚠️WOBBLE"
		}
		fmt.Fprintf(b, "- alert%d %s: verdicts=%v%s\n", i, shortHash(row), keys(set), wobble)
	}
}

// writeSeqConsistency — Bug2 修复版:per alert 5 run 两两比 C(5,2)=10 取最低 LCS ratio
// + 对应 worst run 对(非只比 run1↔run2;wobble 可能在 run3-5 才出现)。公共前缀仍取 run1↔run2
// (turn0 fork 直接信号,首 run 即代表)。
func writeSeqConsistency(b *strings.Builder, grid [][]EvalCell) {
	if len(grid) == 0 {
		b.WriteString("(no data)\n")
		return
	}
	for i, row := range grid {
		if len(row) < 2 {
			continue
		}
		minRatio := 1.0
		worstPair := ""
		for j := 0; j < len(row); j++ {
			for k := j + 1; k < len(row); k++ {
				r := LCSRatio(row[j].ToolTypeSeq, row[k].ToolTypeSeq)
				if r < minRatio {
					minRatio = r
					worstPair = fmt.Sprintf("run%d↔run%d", j+1, k+1)
				}
			}
		}
		p01 := CommonPrefixLen(row[0].ToolTypeSeq, row[1].ToolTypeSeq)
		fmt.Fprintf(b, "- alert%d: min_LCS=%.3f (%s) prefix(run1↔run2)=%d fork_at_start=%v\n",
			i, minRatio, worstPair, p01, p01 <= 1)
		for j, c := range row {
			fmt.Fprintf(b, "  run%d seq=%v\n", j+1, c.ToolTypeSeq)
		}
	}
}

// writeCoverageGap — 2026-08-18 校准:per alert 聚合(跨 run 去重 grep patterns)+ dump
// run1 reasoning-head + 命中信号。always-dump(非 only-on-signal)→ 报告即校准语料
// (GR-8:代码注释承诺"dump 全量 patterns 后校准"但旧版未做,§3 live 零命中即此故)。
func writeCoverageGap(b *strings.Builder, grid [][]EvalCell) {
	if len(grid) == 0 {
		b.WriteString("(no data)\n")
		return
	}
	for i, row := range grid {
		seen := map[string]bool{}
		var greps []string
		var reasons []string
		for _, c := range row {
			sig := ClassifyCoverageGapSignals(c.ReasoningHead, c.GrepPatterns)
			if sig.HasWhoCalls || sig.HasHasSanitizer || sig.HasFieldQuery || sig.HasListBreakpoints {
				reasons = append(reasons, sig.Reasons...)
			}
			for _, p := range c.GrepPatterns {
				if !seen[p] {
					seen[p] = true
					greps = append(greps, p)
				}
			}
		}
		head := ""
		if len(row) > 0 {
			head = row[0].ReasoningHead
		}
		flag := "no-signal"
		if len(reasons) > 0 {
			flag = "SIGNAL"
		}
		fmt.Fprintf(b, "- alert%d [%s]: grep_patterns(dedup)=%v\n", i, flag, greps)
		fmt.Fprintf(b, "    reasoning_head(run1)=%q\n", head)
		if len(reasons) > 0 {
			fmt.Fprintf(b, "    signals=%v\n", reasons)
		}
	}
}

// writeBypass — 2026-08-18 校准:per alert 聚合(跨 run)max_consec_search_def /
// max_result_chain / search_def_names(去重)+ 命中 reasons。always-dump → 报告即校准语料。
func writeBypass(b *strings.Builder, grid [][]EvalCell) {
	if len(grid) == 0 {
		b.WriteString("(no data)\n")
		return
	}
	for i, row := range grid {
		seen := map[string]bool{}
		var names []string
		maxConsec, maxChain := 0, 0
		var reasons []string
		for _, c := range row {
			sig := ClassifyBypassSignals(c.ToolTypeSeq, c.SearchDefCalls)
			if sig.ConsecutiveSearchDef > maxConsec {
				maxConsec = sig.ConsecutiveSearchDef
			}
			if sig.MaxResultChain > maxChain {
				maxChain = sig.MaxResultChain
			}
			if sig.HasGetCalleesBypass {
				reasons = append(reasons, sig.Reasons...)
			}
			for _, sd := range c.SearchDefCalls {
				if !seen[sd.Name] {
					seen[sd.Name] = true
					names = append(names, sd.Name)
				}
			}
		}
		flag := "no-bypass"
		if len(reasons) > 0 {
			flag = "BYPASS"
		}
		fmt.Fprintf(b, "- alert%d [%s]: max_consec_search_def=%d max_result_chain=%d search_def_names(dedup)=%v\n",
			i, flag, maxConsec, maxChain, names)
		if len(reasons) > 0 {
			fmt.Fprintf(b, "    reasons=%v\n", reasons)
		}
	}
}

// writeAVTFamily — §5: avt 族级 wobble(alert × run)。用 faces.FamilyOf 把每 run 的 avt
// 收敛成面族集跨 run 比:族集一致=AVT-FAMILY-STABLE(散文重命名被族级去噪,即 68% 非canonical
// prose 噪声的治理);族集不同=AVT-FAMILY-WOBBLE(真多面 wobble,#1 真异面率信号)。raw_avt 跨 run
// 还变异则标 raw_varies(族级去噪的价值可视化:prose 变但族不变)。空 avt([])=TP-empty 子集(见
// #2),族集空不当 wobble。FamilyOf 导出注释明文授权 harness 复用同表(非外泄,见 faces.go:302-304)。
func writeAVTFamily(b *strings.Builder, grid [][]EvalCell) {
	if len(grid) == 0 {
		b.WriteString("(no data)\n")
		return
	}
	for i, row := range grid {
		// 每 run 的族集(去重,first-seen 序)+ 原始 avt(看散文变异)。
		var famSets [][]string
		var rawAvts [][]string
		for _, c := range row {
			if c.Err != nil {
				continue
			}
			rawAvts = append(rawAvts, c.ActualTypes)
			famSets = append(famSets, famSetOf(c.ActualTypes))
		}
		if len(famSets) == 0 {
			fmt.Fprintf(b, "- alert%d (no valid cells)\n", i)
			continue
		}
		// 族集跨 run 一致?
		stable := true
		for j := 1; j < len(famSets); j++ {
			if !setEq(famSets[0], famSets[j]) {
				stable = false
				break
			}
		}
		// 原始 avt 跨 run 一致?(散文变异检测:族级去噪的价值所在)
		rawStable := true
		for j := 1; j < len(rawAvts); j++ {
			if !setEq(rawAvts[0], rawAvts[j]) {
				rawStable = false
				break
			}
		}
		flag := "AVT-FAMILY-STABLE"
		if !stable {
			flag = "⚠️AVT-FAMILY-WOBBLE"
		}
		fmt.Fprintf(b, "- alert%d [%s]: family_sets=%v\n", i, flag, famSets)
		fmt.Fprintf(b, "    raw_avt(run1)=%v raw_varies_across_runs=%v\n", rawAvts[0], !rawStable)
	}
}

// famSetOf — avt []string -> 去重面族集(first-seen 序),用 faces.FamilyOf(族级收敛)。
// 表外 slug 原样自成一族(faces.norm:绝不猜归属,GR-8)。
func famSetOf(avt []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(avt))
	for _, t := range avt {
		f := faces.FamilyOf(t)
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// setEq — 两 []string 作集合比(序无关、容忍重复元素、空集相等)。
// 用于跨 run 族集 / raw avt 一致性判断。
func setEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ma := map[string]bool{}
	mb := map[string]bool{}
	for _, x := range a {
		ma[x] = true
	}
	for _, x := range b {
		mb[x] = true
	}
	if len(ma) != len(mb) {
		return false
	}
	for x := range ma {
		if !mb[x] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func shortHash(row []EvalCell) string {
	for _, c := range row {
		if len(c.Bughash) >= 12 {
			return c.Bughash[:12]
		}
		return c.Bughash
	}
	return ""
}
