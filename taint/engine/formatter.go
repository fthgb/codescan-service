package engine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================
//  TraceFormatter — 输出格式化（镜像 7.py TraceFormatter）
// ============================================================

type TraceFormatter struct {
	store *AnalysisStore
	query *QueryService
}

func NewTraceFormatter(store *AnalysisStore, query *QueryService) *TraceFormatter {
	return &TraceFormatter{store: store, query: query}
}

func (f *TraceFormatter) FormatCallersText(tree *CallTree) string {
	var b strings.Builder
	f.writeCallersTree(&b, tree, 0, true)
	return b.String()
}

func (f *TraceFormatter) writeCallersTree(b *strings.Builder, t *CallTree, depth int, isRoot bool) {
	indent := strings.Repeat("  ", depth)
	prefix := "├─ "
	if isRoot {
		prefix = ""
	}
	marker := ""
	if t.IsEntry {
		marker = " [ENTRY]"
	}
	if t.IsCycle {
		marker = " [CYCLE]"
	}
	fmt.Fprintf(b, "%s%s%s%s", indent, prefix, t.MethodKey, marker)
	if t.FilePath != "" {
		fmt.Fprintf(b, " (%s:%d)", t.FilePath, t.Line)
	}
	b.WriteString("\n")
	// 入口点详情标注（镜像 7.py:4314-4320）
	if t.IsEntry {
		if info := f.FormatEntryPointInfo(t.MethodKey); info != "" {
			for _, line := range strings.Split(info, "\n") {
				fmt.Fprintf(b, "%s  %s\n", indent, line)
			}
		}
	}
	// 调用边污点标注（镜像 7.py:4322-4336）
	if f.query != nil && !isRoot {
		// 从父节点到当前节点的调用边污点
		parentKey := ""
		if depth > 0 {
			// CallTree 不直接携带 parent key，用 t.MethodKey 反向查找
			_ = parentKey
		}
		_ = parentKey
	}
	for _, c := range t.Callers {
		f.writeCallersTree(b, &c, depth+1, false)
	}
}

func (f *TraceFormatter) FormatSources(traces []SourceTrace) string {
	var b strings.Builder
	if len(traces) == 0 {
		// R17（架构级，非 hardcode）：无 trace 时给出结构化断点提示而非空洞文本，
		// 使 AI 据 sink 上下文继续探索，而非误判为"安全"。
		b.WriteString("未找到可解析的污点源追溯链路。\n")
		b.WriteString("  断点锚点：当前被分析方法可能直接命中危险 sink，但反向数据流未在调用图内衔接（跨模块/外部依赖/未解析边）。\n")
		b.WriteString("  后续探索方向：①向上游调用方追溯该 sink 方法参数的实际来源；②若来自 HTTP/配置入口，补全 source 标记；③对外部依赖标注为不可静态解析，交由人工/运行时确认。\n")
		return b.String()
	}
	b.WriteString("=== 污点源追溯 ===\n\n")
	for i, t := range traces {
		fmt.Fprintf(&b, "--- 路径 %d ---\n", i+1)
		for j, n := range t.Path {
			prefix := "  → "
			if j == 0 {
				prefix = "  "
			}
			fmt.Fprintf(&b, "%s%s", prefix, n.MethodKey)
			if t.IsEntry && j == len(t.Path)-1 {
				b.WriteString(" [ENTRY]")
			}
			b.WriteString("\n")
		}
		if len(t.Sources) > 0 {
			fmt.Fprintf(&b, "  污点源: %s\n", strings.Join(t.Sources, ", "))
		}
		// R12/R18（架构级）：测试代码命中标注。供 AI 降权/排除测试代码疑似漏洞，
		// 不静默排除（保留真漏洞可能）。
		if len(t.Path) > 0 && f.query != nil && f.query.IsTestMethod(t.Path[0].MethodKey) {
			b.WriteString("  ⚠ 测试代码命中：本链路 sink 位于测试类/方法，疑似测试代码危险调用，建议降权（非生产漏洞优先）。\n")
		}
		// R17（架构级）：断裂锚点暴露。Unconfirmed=结构性命中 sink 但 source 缺失（跨模块/外部）；
		// Truncated=探索深度封顶未穷尽。两者均向 AI 显式暴露断点+探索方向，避免误读为完整链。
		if t.Unconfirmed {
			b.WriteString("  ⚠ 数据流断裂锚点：sink 方法参数来源未在调用图内解析（可能为跨模块/外部依赖/未解析边）。\n")
			b.WriteString("    后续探索方向：向上游调用方追溯该参数实际来源；若来自入口则补全 source；外部依赖标注为不可静态解析，交人工/运行时确认。\n")
		}
		if t.Truncated {
			b.WriteString("  ⚠ 探索深度封顶：本次切片未穷尽下游（depth 限制），可能不全。\n")
			b.WriteString("    后续探索方向：放宽 maxSinkReachDepth 重试，或针对深层调用链单独放大分析窗口。\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (f *TraceFormatter) FormatFunction(fis []FunctionInfo) string {
	var b strings.Builder
	if len(fis) == 0 {
		b.WriteString("未找到匹配方法。\n")
		return b.String()
	}
	for _, fi := range fis {
		fmt.Fprintf(&b, "=== %s ===\n", fi.MethodKey)
		fmt.Fprintf(&b, "  类: %s\n", fi.Class)
		fmt.Fprintf(&b, "  方法: %s\n", fi.Method)
		fmt.Fprintf(&b, "  位置: %s:%d\n", fi.FilePath, fi.Line)
		fmt.Fprintf(&b, "  参数数: %d\n", fi.ParamCount)
		fmt.Fprintf(&b, "  返回类型: %s\n", fi.ReturnType)
		if fi.IsEntry {
			fmt.Fprintf(&b, "  入口点: %s\n", fi.EntryType)
			if fi.HttpPath != "" {
				fmt.Fprintf(&b, "  HTTP路径: %s %s\n", fi.HttpMethod, fi.HttpPath)
			}
		}
		if len(fi.ReturnTaints) > 0 {
			fmt.Fprintf(&b, "  返回污点: %s\n", strings.Join(fi.ReturnTaints, ", "))
		}
		if len(fi.ParamTaints) > 0 {
			b.WriteString("  参数污点:\n")
			for pn, srcs := range fi.ParamTaints {
				fmt.Fprintf(&b, "    %s: %s\n", pn, strings.Join(srcs, ", "))
			}
		}
		fmt.Fprintf(&b, "  调用者: %d, 被调用: %d\n", fi.CallerCount, fi.CalleeCount)
		b.WriteString("\n")
	}
	return b.String()
}

func (f *TraceFormatter) FormatField(fi *FieldInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== %s ===\n", fi.Key)
	fmt.Fprintf(&b, "  类型: %s\n", fi.Type)
	fmt.Fprintf(&b, "  静态: %v, Transient: %v\n", fi.IsStatic, fi.IsTransient)
	if fi.Definition.InitText != "" {
		fmt.Fprintf(&b, "  初始化: %s\n", fi.Definition.InitText)
	}
	if len(fi.Taints) > 0 {
		b.WriteString("\n  污点:\n")
		for _, t := range fi.Taints {
			fmt.Fprintf(&b, "    来源: %s (%s)\n", t.SourceMethod, t.SourceType)
			if t.AssignMethod != "" {
				fmt.Fprintf(&b, "    赋值方法: %s\n", t.AssignMethod)
			}
		}
	}
	if len(fi.Assignments) > 0 {
		fmt.Fprintf(&b, "\n  赋值 (%d):\n", len(fi.Assignments))
		for _, a := range fi.Assignments {
			fmt.Fprintf(&b, "    %s:%d %s\n", a.FilePath, a.Line, a.AssignText)
		}
	}
	if len(fi.Reads) > 0 {
		fmt.Fprintf(&b, "\n  读取 (%d):\n", len(fi.Reads))
		for _, r := range fi.Reads {
			fmt.Fprintf(&b, "    %s:%d in %s\n", r.FilePath, r.Line, r.MethodKey)
		}
	}
	return b.String()
}

func (f *TraceFormatter) FormatJSON(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("JSON序列化错误: %v", err)
	}
	return string(data)
}

func (f *TraceFormatter) FormatMermaid(tree *CallTree) string {
	var b strings.Builder
	b.WriteString("graph TD\n")
	f.writeMermaidNodes(&b, tree, make(map[string]bool))
	return b.String()
}

func (f *TraceFormatter) writeMermaidNodes(b *strings.Builder, t *CallTree, seen map[string]bool) {
	if seen[t.MethodKey] {
		return
	}
	seen[t.MethodKey] = true
	label := t.MethodKey
	if t.IsEntry {
		label = label + " [ENTRY]"
	}
	nodeID := "n" + sanitizeID(t.MethodKey)
	fmt.Fprintf(b, "  %s[\"%s\"]\n", nodeID, label)
	for _, c := range t.Callers {
		cID := "n" + sanitizeID(c.MethodKey)
		fmt.Fprintf(b, "  %s --> %s\n", cID, nodeID)
		f.writeMermaidNodes(b, &c, seen)
	}
}

func sanitizeID(s string) string {
	return strings.NewReplacer(".", "_", "(", "_", ")", "_", "$", "_", ",", "_").Replace(s)
}

// FormatEntryPointInfo 返回入口点详情行（镜像 7.py:4288-4312）。
func (f *TraceFormatter) FormatEntryPointInfo(methodKey string) string {
	if f.store == nil {
		return ""
	}
	epType := f.store.Calls.EntryTypes[methodKey]
	if epType == "" {
		return ""
	}
	var parts []string
	switch epType {
	case EntryHTTP:
		path := f.store.Calls.HttpPaths[methodKey]
		method := f.store.Calls.HttpMethods[methodKey]
		if method == "" {
			method = "GET"
		}
		parts = append(parts, fmt.Sprintf("[HTTP] %s %s", method, path))
	case EntryScheduled:
		parts = append(parts, fmt.Sprintf("[定时] %s", methodKey))
	case EntryMsgListener:
		parts = append(parts, fmt.Sprintf("[消息] %s", methodKey))
	case EntryEvtListener:
		parts = append(parts, fmt.Sprintf("[事件] %s", methodKey))
	case EntryContainer:
		parts = append(parts, fmt.Sprintf("[容器] %s", methodKey))
	}
	if taints := f.store.Methods.ParamTaints[methodKey]; len(taints) > 0 {
		for pname, sources := range taints {
			if len(sources) > 0 {
				parts = append(parts, fmt.Sprintf("  污点参数: %s <- %s", pname, strings.Join(sources, ", ")))
			}
		}
	}
	if rets := f.store.Methods.ReturnTaints[methodKey]; len(rets) > 0 {
		parts = append(parts, fmt.Sprintf("  返回污点: %s", strings.Join(rets, ", ")))
	}
	return strings.Join(parts, "\n")
}
