//go:build !sim

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	. "appsecgo/taint/engine"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: taint <repo_path> [--force]")
		fmt.Println("  扫描 Java 仓库并进入交互式查询")
		os.Exit(1)
	}
	repoPath := os.Args[1]
	force := len(os.Args) > 2 && os.Args[2] == "--force"
	cachePath := filepath.Join(repoPath, ".java_analysis_cache.json")

	analyzer := NewJavaRepoAnalyzer(DefaultConfig())

	// 尝试加载缓存
	if !force {
		if err := analyzer.LoadAnalysis(cachePath); err == nil {
			fmt.Println("[CACHE] 已加载缓存:", cachePath)
		} else {
			if err := analyzer.Scan(repoPath); err != nil {
				fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
				os.Exit(1)
			}
			if err := analyzer.SaveAnalysis(cachePath); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] 缓存保存失败: %v\n", err)
			}
		}
	} else {
		if err := analyzer.Scan(repoPath); err != nil {
			fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
			os.Exit(1)
		}
		if err := analyzer.SaveAnalysis(cachePath); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] 缓存保存失败: %v\n", err)
		}
	}

	query := NewQueryService(analyzer.Store())
	formatter := NewTraceFormatter(analyzer.Store(), query)
	cfa := NewControlFlowAnalyzer(analyzer.Store())
	rc := NewReachabilityChecker(analyzer.Store(), analyzer.TypeResolver())
	bc := NewBlockClimber()
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n=== Java 污点分析引擎 (Go) ===")
	fmt.Println("命令: s=统计, f=查方法, d=查字段, t=追溯源, c=调用链, cc=可达链(cap+enrich), m=Mermaid, r=可达性, b=自包含切片, q=退出")

	for {
		fmt.Print("\n> ")
		line, err := reader.ReadString('\n')
		if err != nil { break }
		line = strings.TrimSpace(line)
		if line == "" { continue }
		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "q", "quit", "exit":
			return
		case "s", "stats":
			fmt.Println(query.Stats())
		case "f", "func", "function":
			if len(parts) < 2 { fmt.Println("用法: f <模式>"); continue }
			results := query.QueryFunction(parts[1], 20)
			fmt.Print(formatter.FormatFunction(results))
		case "d", "field":
			if len(parts) < 3 { fmt.Println("用法: d <类名> <字段名>"); continue }
			fi := query.QueryField(parts[1], parts[2])
			if fi == nil { fmt.Println("未找到字段"); continue }
			fmt.Print(formatter.FormatField(fi))
			// 展示修改器列表（镜像 7.py:4096-4114）
			fieldKey := parts[1] + "." + parts[2]
			mods := query.GetFieldModifiers(fieldKey)
			if len(mods) > 0 {
				fmt.Printf("\n=== 修改器列表 (%d) ===\n", len(mods))
				for _, m := range mods {
					fmt.Printf("  %s.%s  类型=%s  位置=%s:%d\n  文本: %s\n\n", m.ClassName, m.MethodName, m.AssignType, m.FilePath, m.Line, m.AssignText)
				}
			}
			// 展示有效值摘要（镜像 7.py:4093-4094）
			summary := query.GetEffectiveValueSummary(fieldKey)
			if summary != "" {
				fmt.Printf("=== 有效值摘要 ===\n  %s\n", summary)
			}
			// 展示有效初始值（镜像 7.py:4090-4091）
			initVal := query.GetFieldEffectiveInitialValue(fieldKey)
			if initVal != "" {
				fmt.Printf("\n=== 有效初始值 ===\n  %s\n", initVal)
			}
		case "t", "trace":
			if len(parts) < 2 { fmt.Println("用法: t <方法Key>"); continue }
			mk := resolveMethodKey(parts[1], reader, analyzer.Store())
			if mk == "" { continue }
			traces := query.TraceToSources(mk, 0)
			fmt.Print(formatter.FormatSources(traces))
		case "c", "callers":
			if len(parts) < 2 { fmt.Println("用法: c <方法Key>"); continue }
			mk := resolveMethodKey(parts[1], reader, analyzer.Store())
			if mk == "" { continue }
			tree := query.TraceCallersStructured(mk, 0)
			fmt.Print(formatter.FormatCallersText(tree))
		case "cc", "chain":
			// who_calls 工具的 engine 侧冒烟车辆(TraceCallersChain,带 cap/sort/enrich)。
			// 打印 found/truncated + JSON 树(含 is_entry/entry_type/http/taints/is_test/callers_truncated)。
			if len(parts) < 2 { fmt.Println("用法: cc <方法Key>"); continue }
			mk := resolveMethodKey(parts[1], reader, analyzer.Store())
			if mk == "" { continue }
			tree, found, trunc := query.TraceCallersChain(mk, 0, 0)
			fmt.Printf("found=%v truncated=%v\n", found, trunc)
			fmt.Println(formatter.FormatJSON(tree))
		case "m", "mermaid":
			if len(parts) < 2 { fmt.Println("用法: m <方法Key>"); continue }
			mk := resolveMethodKey(parts[1], reader, analyzer.Store())
			if mk == "" { continue }
			tree := query.TraceCallersStructured(mk, 0)
			fmt.Println(formatter.FormatMermaid(tree))
		case "j", "json":
			if len(parts) < 2 { fmt.Println("用法: j <方法Key>"); continue }
			mk := resolveMethodKey(parts[1], reader, analyzer.Store())
			if mk == "" { continue }
			tree := query.TraceCallersStructured(mk, 0)
			fmt.Println(formatter.FormatJSON(tree))
		case "v", "value":
			if len(parts) < 3 { fmt.Println("用法: v <类名> <字段名>"); continue }
			c := query.ResolveFieldValue(parts[1], parts[2])
			if c == nil { fmt.Println("未找到"); continue }
			fmt.Printf("  来源: %s (优先级 %d)\n  值: %s\n", c.Source, c.Priority, c.Value)
			if c.FilePath != "" { fmt.Printf("  位置: %s:%d\n", c.FilePath, c.Line) }
		case "cf", "control":
			if len(parts) < 4 { fmt.Println("用法: cf <方法Key> <源行> <汇行>"); continue }
			mk := resolveMethodKey(parts[1], reader, analyzer.Store())
			if mk == "" { continue }
			var sl, kl int
			fmt.Sscan(parts[2], &sl)
			fmt.Sscan(parts[3], &kl)
			check := cfa.CheckControlFeasibility(mk, sl, kl)
			fmt.Printf("  可行: %v, 原因: %s\n", check.IsFeasible, check.Reason)
		case "r", "reach":
			if len(parts) < 2 { fmt.Println("用法: r <方法Key>"); continue }
			mk := resolveMethodKey(parts[1], reader, analyzer.Store())
			if mk == "" { continue }
			result := rc.GetForwardReachable(mk)
			fmt.Println(formatter.FormatJSON(result))
		case "b", "block":
			if len(parts) < 2 { fmt.Println("用法: b [--json] <方法Key>"); continue }
			asJSON := false
			var keyParts []string
			for _, p := range parts[1:] {
				if p == "--json" {
					asJSON = true
				} else {
					keyParts = append(keyParts, p)
				}
			}
			mk := resolveMethodKey(strings.Join(keyParts, " "), reader, analyzer.Store())
			if mk == "" { continue }
			traces := query.TraceToSources(mk, 0)
			if len(traces) == 0 { fmt.Println("未找到追溯路径"); continue }
			cfa := NewControlFlowAnalyzer(analyzer.Store())
			for i, trace := range traces {
				fmt.Printf("--- 切片 %d ---\n", i+1)
				if asJSON {
					js, err := bc.BuildSliceJSON(analyzer.Store(), cfa, mk, trace)
					if err != nil {
						fmt.Println("JSON 生成失败:", err)
						continue
					}
					fmt.Println(js)
				} else {
					fmt.Println(bc.BuildSliceFromTraceAnnotated(analyzer.Store(), cfa, trace))
				}
			}
		case "h", "help":
			fmt.Println("命令:")
			fmt.Println("  s          统计信息")
			fmt.Println("  f <模式>   搜索方法")
			fmt.Println("  d <类> <字段>  查询字段")
			fmt.Println("  t <方法>   追溯污点源")
			fmt.Println("  c <方法>   反向调用链")
		fmt.Println("  cc <方法>  反向可达链(cap+enrich,who_calls 工具车辆)")
			fmt.Println("  m <方法>   Mermaid 图")
			fmt.Println("  j <方法>   JSON 格式调用链")
			fmt.Println("  v <类> <字段>  解析字段值")
			fmt.Println("  q          退出")
		default:
			fmt.Println("未知命令:", cmd, " (输入 h 查看帮助)")
		}
		}
		}

		// resolveMethodKey 将用户输入解析为完整方法键（含参数类型）。
		// 三级匹配：精确 → 前缀 HasPrefix(key, input+"(") → 模糊 SearchMethodsByPattern。
		// 多匹配时打印列表交互选择。返回空串表示未找到。
		func resolveMethodKey(input string, reader *bufio.Reader, store *AnalysisStore) string {
		// 含 "(" 视为完整键，直接精确匹配
		if strings.Contains(input, "(") {
			if _, ok := store.Methods.Functions[input]; ok {
				return input
			}
			fmt.Printf("未找到方法: %s\n", input)
			return ""
		}
		// 精确匹配（无参数的完整键）
		if _, ok := store.Methods.Functions[input]; ok {
			return input
		}
		// 前缀匹配：找所有 HasPrefix(key, input+"(")
		var matches []string
		for key := range store.Methods.Functions {
			if strings.HasPrefix(key, input+"(") {
				matches = append(matches, key)
			}
		}
		// 前缀无结果时走模糊搜索
		if len(matches) == 0 {
			matches = store.SearchMethodsByPattern(input, 20)
		}
		if len(matches) == 0 {
			fmt.Printf("未找到方法: %s\n", input)
			return ""
		}
		if len(matches) == 1 {
			return matches[0]
		}
		// 多匹配：打印列表让用户选择
		fmt.Printf("找到 %d 个匹配方法:\n", len(matches))
		for i, mk := range matches {
			fn := store.Methods.Functions[mk]
			loc := ""
			if fn.FilePath != "" {
				loc = fmt.Sprintf("  (%s:%d)", filepath.Base(fn.FilePath), fn.Line)
			}
			fmt.Printf("  [%d] %s%s\n", i+1, mk, loc)
		}
		fmt.Print("选择编号 (0=取消): ")
		choice, err := reader.ReadString('\n')
		if err != nil {
			return ""
		}
		choice = strings.TrimSpace(choice)
		var idx int
		fmt.Sscan(choice, &idx)
		if idx < 1 || idx > len(matches) {
			return ""
		}
		return matches[idx-1]
		}
