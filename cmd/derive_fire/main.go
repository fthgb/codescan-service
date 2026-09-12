// cmd/derive_fire — T4 §4(a) fire/control 集确定性派生（0 LLM）。
//
// 复刻 prod pre-guard 路径（realJudgeAlert:299-315 slice+enrich + judge.go:180-200
// producer+token），**跳过 JudgeOne（LLM loop）**。token = decisive_facts["forward_reachable"]，
// pre-guard 写、rejudge 不碰（D5）→ 即 prod guard 会读到的 fire 态。
//
// 为什么免费且精确（2026-08-24 8 锚点核实，详见 spec §11「回收率/硬停测量锚点」+ 本文件注释）：
//  1. EnrichMode="deterministic"（config.go:120，.env 无 APPSEC_ENRICH_MODE 覆盖）→
//     EnrichForJudge(enrich.go:189 `enrichMode=="agentic" && SupportsTools` 短路 FALSE)走
//     deterministic 分支（EnrichSlice+EnrichGuardCallees，**无 AgenticEnrichSlice，无 LLM**）= prod 同。
//  2. producer（PrejudgeCalleeReachability→judgeCalleeReachabilityWithDef，reachability.go:103/110）
//     只用 exec.searchDefinitions + exec.grepRepo（**repoIndex 工具**），不用 engine →
//     prod TaintEngineMode=on（.env:10）但 engine 只喂 LLM loop 工具，不碰 pre-guard →
//     SetEngineQuery(nil) 与 prod engine-on 的 fire 集相同。
//  3. prod 在 agenticJudge（judge.go:186 buildLoopMessages→:147）调 producer；agenticJudge 只在
//     agenticExploreActive（:70 repoIndex!=nil && SupportsTools）为真时跑。hy3=OpenAIProvider
//     SupportsTools=true（openai.go:74）+ AgenticExploreMode=on（config.go:107）→ prod 跑 producer。
//     本工具**直接调** producer（不经 agenticJudge），等价 prod 的 producer 调用，免 LLM。
//
// 用途：① pre-check 1（fire>0? → post-fix producer 写路径验于真 alert，GR-8「验 producer 写路径」）；
//      ② §4(a) fire/control 集派生（确定性，对拍 §7 计数，spec §8 harness 单测）。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"appsecgo/internal/adapter"
	"appsecgo/internal/agentic"
	"appsecgo/internal/config"
	"appsecgo/internal/cwereg"
	"appsecgo/internal/llm"
	"appsecgo/internal/slice"
	"appsecgo/internal/slice/gots"
)

type record struct {
	Bughash    string   `json:"bughash"`
	AlertID    string   `json:"alert_id"`
	VulnType   string   `json:"vuln_type"`
	Token      string   `json:"token"`      // "unknown"(fire) / "anchored"(control) / ""(not-applicable)
	HasStruct  bool     `json:"has_struct"` // forward_reachable struct 是否被 producer 写
	Definitive []string `json:"definitive,omitempty"` // struct 内 definitive callee 名（验 fire 根因：真业务方法 vs 平凡名）
	Uncertain  []string `json:"uncertain,omitempty"`  // struct 内 uncertain callee 名（fire 的直接原因）
	Truncated  bool     `json:"truncated,omitempty"`
	SliceErr   string   `json:"slice_err,omitempty"`
}

func main() {
	repoRoot := flag.String("repo-root", "", "被扫项目本地源码根目录")
	sarif := flag.String("sarif", "", "CodeSafe SARIF / all_bugs.json")
	adapterName := flag.String("adapter", "codesafe", "adapter 名（codesafe / codeql）")
	cweregPath := flag.String("cwereg", "cwe_registry.json", "cwe registry json 路径")
	out := flag.String("out", "", "输出 JSON 路径（省略=只打印摘要）")
	debugCallees := flag.Bool("debug-callees", false, "打印每 alert per-callee state（验 truncated/uncertain 根因；2× grep 调试成本）")
	flag.Parse()
	if *repoRoot == "" || *sarif == "" {
		fmt.Fprintln(os.Stderr, "usage: derive_fire --repo-root <dir> --sarif <file> [--adapter codesafe] [--out json]")
		os.Exit(2)
	}

	cfg := config.Load()

	// SARIF → []SASTResult（adapter.ByName，与 cmd/audit main.go:94 同源）
	b, err := os.ReadFile(*sarif)
	if err != nil {
		fail(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		// CodeSafe all_bugs.json 是 bare list
		var lst []any
		if e2 := json.Unmarshal(b, &lst); e2 != nil {
			fail(err)
		}
		raw = map[string]any{"bugs": lst}
	}
	reg, err := cwereg.NewRegistry(*cweregPath)
	if err != nil {
		fail(err)
	}
	results, err := adapter.ByName(*adapterName, reg).Parse(raw)
	if err != nil {
		fail(err)
	}

	// repoIndex + extractor（gots，与 realJudgeAlert:299 同）
	ext := gots.New()
	defer ext.Close()
	fmt.Fprintf(os.Stderr, "[derive_fire] building repoIndex (EnsureBuilt) for %s ...\n", *repoRoot)
	repoIndex := slice.NewRepositoryIndex(*repoRoot, ext).EnsureBuilt()
	fmt.Fprintf(os.Stderr, "[derive_fire] repoIndex built. slicing %d alerts ...\n", len(results))

	// prod pre-guard 配置（EnrichMode deterministic、EagerGuardCallees on，config.go:120/122）
	enrichMode := cfg.EnrichMode   // "deterministic"
	eager := cfg.EagerGuardCallees // "on"
	// provider=nil：EnrichMode=deterministic → enrich.go:189 短路不调 provider.SupportsTools → 不触 LLM
	var provider llm.Provider

	records := make([]record, 0, len(results))
	fire, control, neither, sliceErrs := 0, 0, 0, 0
	for i := range results {
		a := results[i] // copy（SliceAlert 可能 mutate）
		r := record{Bughash: a.Bughash, AlertID: a.AlertID, VulnType: a.VulnerabilityType}
		fmt.Fprintf(os.Stderr, "[derive_fire] [%d/%d] slice %s ...\n", i+1, len(results), a.Bughash[:min(12, len(a.Bughash))])
		sliced, err := slice.SliceAlert(&a, *repoRoot, ext, repoIndex)
		if err != nil {
			r.SliceErr = err.Error()
			sliceErrs++
			records = append(records, r)
			continue
		}
		// deterministic enrich（无 LLM）：EnrichSlice + EnrichGuardCallees（repoIndex 工具，engine 无关）
		agentic.EnrichForJudge(sliced, repoIndex, provider, "", enrichMode, eager, nil)
		// struct → map（json roundtrip，对齐 run.go:105 slicedContextToMap + judge.go 收 map 形）
		sm := toMap(sliced)
		// producer（pre-guard，repoIndex 工具，engine nil → 与 prod engine-on 同 fire 集）
		exec := agentic.NewToolExecutor(repoIndex, nil, "", nil)
		exec.SetEngineQuery(nil)
		agentic.PrejudgeCalleeReachability(sm, exec) // 写 sm["forward_reachable"]
		fr, ok := sm["forward_reachable"].(map[string]any)
		r.HasStruct = ok
		if ok {
			r.Token = slice.MapForwardReachable(fr)
			r.Definitive = calleeNames(fr["definitive"])
			r.Uncertain = calleeNames(fr["uncertain"])
			r.Truncated, _ = fr["truncated"].(bool)
		}
		fmt.Fprintf(os.Stderr, "[derive_fire] [%d/%d] %s token=%s unc=%v\n", i+1, len(results), a.Bughash[:min(12, len(a.Bughash))], or(r.Token, "(absent)"), r.Uncertain)
		if *debugCallees {
			// 逐 callee 重判（导出 API，2× grep），打印 truncated/uncertain 根因 callee。
			hops := extractHops(sm)
			callerFiles := map[string]bool{}
			for _, h := range hops {
				if fp, ok := h["file_path"].(string); ok {
					callerFiles[fp] = true
				}
			}
			for _, name := range agentic.ExtractCandidateCalleeNames(hops) {
				st, ev := agentic.JudgeCalleeReachability(exec, name, callerFiles)
				if st == "unknown" || st == "uncertain" {
					fmt.Fprintf(os.Stderr, "    [callee] %s -> %s | %s\n", name, st, ev)
				}
			}
		}
		switch r.Token {
		case "unknown":
			fire++
		case "anchored":
			control++
		default:
			neither++
		}
		records = append(records, r)
	}

	// 摘要
	fmt.Fprintf(os.Stderr, "repo=%s sarif=%s alerts=%d\n", *repoRoot, *sarif, len(results))
	fmt.Fprintf(os.Stderr, "fire(unknown)=%d  control(anchored)=%d  neither/absent=%d  slice_err=%d\n",
		fire, control, neither, sliceErrs)
	fmt.Fprintf(os.Stderr, "==> pre-check 1: fire>0? %s\n", pass(fire > 0))

	if *out != "" {
		outObj := map[string]any{
			"repo_root": *repoRoot, "sarif": *sarif, "adapter": *adapterName,
			"n_alerts": len(results),
			"fire": fire, "control": control, "neither": neither, "slice_err": sliceErrs,
			"precheck1_fire_gt_0": fire > 0,
			"records": records,
		}
		os.MkdirAll("eval/t4/derived", 0o755)
		b, _ := json.MarshalIndent(outObj, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "[derive_fire] -> %s\n", *out)
	}
}

func toMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func or(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}

// calleeNames 从 forward_reachable struct 的 definitive/uncertain（[]any of map）抽 callee 名。
func calleeNames(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// extractHops 从 sliced map 抽 hops（[]any → []map[string]any），供 debug per-callee 重判。
func extractHops(sm map[string]any) []map[string]any {
	hopsAny, _ := sm["hops"].([]any)
	out := make([]map[string]any, 0, len(hopsAny))
	for _, h := range hopsAny {
		if hm, ok := h.(map[string]any); ok {
			out = append(out, hm)
		}
	}
	return out
}

func pass(ok bool) string {
	if ok {
		return "PASS (producer post-fix writes uncertain on real alerts → P0-a alive)"
	}
	return "FAIL (fire=0 → producer 未产 uncertain / 退化 → 停，回查 reachability.go)"
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
