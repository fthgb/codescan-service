package main

import (
	"appsecgo/internal/faces"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"appsecgo/internal/adapter"
	"appsecgo/internal/appcontext"
	"appsecgo/internal/bughash"
	"appsecgo/internal/checkpoint"
	"appsecgo/internal/config"
	"appsecgo/internal/cwereg"
	"appsecgo/internal/hardexclusion"
	"appsecgo/internal/llm"
	"appsecgo/internal/pipeline"
	"appsecgo/internal/runs"
	"appsecgo/internal/sca"
	"appsecgo/internal/slice/gots"
	"appsecgo/internal/stratreg"
	"appsecgo/internal/vcache"
)

// CLI direct runner: SARIF → adapter.Parse → pipeline.Run → runs.WriteRun → stdout JSON.
// CI 友好(in-process,免客户端超时,对齐 run_scan.py 注释 + api.py:49)。
// --replay 走 ReplayProvider(重放 responses.jsonl);空 = live Anthropic。

func main() {
	repoRoot := flag.String("repo-root", "", "被扫项目本地源码根目录")
	sarif := flag.String("sarif", "", "SAST 报告(SARIF / CodeSafe all_bugs.json)")
	repoKey := flag.String("repo-key", "", "仓库标识(默认取 repo-root 目录名)")
	adapterName := flag.String("adapter", "codeql", "adapter(codeql;P6 首刀)")
	scenario := flag.String("scenario", "prod_build", "场景标签")
	replay := flag.String("replay", "", "responses.jsonl 路径(走 ReplayProvider;空=live)")
	cfgFlag := flag.String("cwereg", "cwe_registry.json", "cwe registry json 路径")
	stratregFlag := flag.String("stratreg", "data/strategies", "strategy registry 目录（③-e 评估视角；缺则 strategy 子系统全关含 general）")
	flag.Parse()
	if *repoRoot == "" || *sarif == "" {
		fmt.Fprintln(os.Stderr, "usage: audit --repo-root <dir> --sarif <file> [--replay <responses.jsonl>]")
		os.Exit(2)
	}
	rk := *repoKey
	if rk == "" {
		rk = filepathBase(*repoRoot)
	}
	if err := runScan(*repoRoot, *sarif, rk, *adapterName, *scenario, *replay, *cfgFlag, *stratregFlag); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func filepathBase(x string) string { return filepath.Base(filepath.Clean(x)) }

func runScan(repoRoot, sarifPath, repoKey, adapterName, scenario, replay, cweregPath, stratregPath string) error {
	cfg := config.Load()
	b, err := os.ReadFile(sarifPath)
	if err != nil {
		return err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		// CodeSafe all_bugs.json 是 bare list
		var lst []any
		if e2 := json.Unmarshal(b, &lst); e2 != nil {
			return err
		}
		raw = map[string]any{"bugs": lst}
	}

	// provider: --replay → ReplayProvider(包 Harness,对齐 judge parity 录制方法论);
	// 空 → live Anthropic(包 Harness retry)。
	var provider llm.Provider
	if replay != "" {
		rp, rerr := llm.NewReplayProvider(replay)
		if rerr != nil {
			return rerr
		}
		provider = llm.NewHarness(rp)
	} else {
		provider = llm.NewHarness(llm.NewProviderFromConfig(cfg))
	}

	reg, err := cwereg.NewRegistry(cweregPath)
	if err != nil {
		return err
	}

	// 适配器按 --adapter 选(adapter.ByName 是单一入口,与 cmd/server 同源)。
	// 此前这里硬写 CodeQLAdapter、flag 被忽略 → 喂 CodeSafe 导出解析出 0 条空转。
	results, err := adapter.ByName(adapterName, reg).Parse(raw)
	if err != nil {
		return err
	}
	// 同 server 路径：AllowedLanguages + MinSeverity 早期过滤（省 token，不进 judge fan-out）。
	results, skippedByLang := pipeline.FilterByLanguage(results, cfg.AllowedLanguages)
	results, skippedBySev := pipeline.FilterBySeverity(results, cfg.MinSeverity)
	// ③-e strategy 评估视角（filed-CWE 错类补正）。fail-open：strategy 是增强而非
	// 必需（cwe_registry 是 essential，NewRegistry err → hard return；strategy 是
	// augmentation，err → warn + nil → Select nil gate → inert）。盯点#2：strategy 目录
	// 缺意味着整个子系统不可用，不应只上 general——故 warn 写明 "including general disabled"。
	stratReg, serr := stratreg.NewRegistry(stratregPath)
	if serr != nil {
		fmt.Fprintln(os.Stderr, "warn: strategy registry unavailable, all strategies including general disabled (③-e 视角子系统全关；判决仍走 cwe_registry):", serr)
		stratReg = nil
	}
	store, serr := bughash.OpenBughashStore(cfg.DBPath)
	if serr != nil {
		// store 是 side-effect;开不了 → 旁路 nil(parity 路径 Store 可 nil 零回归)。
		fmt.Fprintln(os.Stderr, "warn: bughash store open failed, running without store:", serr)
		store = nil
	}
	if store != nil {
		defer store.Close()
	}
	cp, cperr := checkpoint.NewStepCheckpoint(cfg.CheckpointDir)
	if cperr != nil {
		fmt.Fprintln(os.Stderr, "warn: checkpoint dir failed, running without checkpoint:", cperr)
		cp = nil
	}
	var vc *vcache.Store
	if cfg.VerdictContentCache == "on" {
		var verr error
		vc, verr = vcache.NewStore(cfg.VerdictCacheDBPath, cfg.VerdictCacheTTLDays, time.Now)
		if verr != nil {
			fmt.Fprintln(os.Stderr, "warn: vcache open failed, running without vcache:", verr)
			vc = nil
		}
	} else {
		fmt.Fprintln(os.Stderr, "info: verdict_cache disabled (APPSEC_VERDICT_CONTENT_CACHE!=\"on\"); every alert judges fresh")
	}
	if vc != nil {
		defer vc.Close()
	}
	// extractor: Go-native slicer (pure-Go tree-sitter). Always available,
	// never nil — no Python subprocess, no config failure mode.
	slicerExt := gots.New()
	defer slicerExt.Close()

	t0 := time.Now()
	res, err := pipeline.Run(context.Background(), pipeline.RunInput{
		SAST: results, Scenario: scenario, AppContext: appcontext.Resolve(repoKey), RepoKey: repoKey,
	}, pipeline.RunOpts{
		Model:                   provider.Model(),
		Provider:                provider,
		Reg:                     reg,
		Extractor:               slicerExt,
		RepoRoot:                repoRoot,
		Store:                   store,
		VCache:                  vc,
		Checkpoint:              cp,
		Concurrency:             4,
		RunMode:                 cfg.RunMode,
		ControlFlowPrefilter:    cfg.ControlFlowPrefilter,
		JudgeTemperature:        cfg.JudgeTemperature,
		EnrichMode:              cfg.EnrichMode,
		DraftMode:               cfg.DraftMode,
		EagerGuardCallees:       cfg.EagerGuardCallees,
		FuncDistillMode:         cfg.FuncDistillMode,
		DecisiveFactRejudgeMode: cfg.DecisiveFactRejudgeMode,
		VerifyMode:              cfg.VerifyMode,
		DynamicVerifyMode:       cfg.DynamicVerifyMode,
		AgenticXmlPromote:       cfg.AgenticXmlPromote,
		TaintEngineMode:         cfg.TaintEngineMode,
		FaceLedgerMode:          cfg.FaceLedgerMode,
		FaceHistory:             faces.LoadHistory(cfg.RunsDir),
		StratReg:                stratReg,
	})
	if err != nil {
		return err
	}
	// 回填跳过计数到 summary.json（同 server 路径）。
	if res != nil && res.Report != nil {
		if len(skippedByLang) > 0 {
			res.Report.SkippedByLanguage = skippedByLang
		}
		if len(skippedBySev) > 0 {
			res.Report.SkippedBySeverity = skippedBySev
		}
	}
	alertMaps := make([]map[string]any, len(results))
	for i, r := range results {
		alertMaps[i] = toMapCLI(r)
	}
	runDir, werr := runs.WriteRun(cfg.RunsDir, repoKey, adapterName, provider.Model(),
		alertMaps, res.Report, res.Traces, time.Since(t0).Seconds())
	if werr != nil {
		return werr
	}
	// SCA 随审计触发（best-effort）：失败不阻塞审计主流程，只 stderr 留痕（spec §三）。
	// APPSEC_SCA_ENABLED=0 关闭；缺省开。repoRoot 含 pom.xml 时 osv-scanner 提取组件。
	if os.Getenv("APPSEC_SCA_ENABLED") != "0" {
		scaOpts := sca.Options{
			RepoKey:    repoKey,
			RepoRoot:   repoRoot,
			ScaRunsDir: cfg.ScaRunsDir,
			PolicyPath: cfg.ScaPolicyPath,
		}
		if scanID, serr := sca.Run(scaOpts); serr != nil {
			fmt.Fprintf(os.Stderr, "[sca] best-effort 触发失败（不阻塞审计）: %v\n", serr)
		} else {
			fmt.Fprintf(os.Stderr, "[sca] scan_id=%s\n", scanID)
		}
	}
	out := toMapCLI(res.Report)
	out["run_dir"] = runDir
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// toMapCLI = json roundtrip any → map (SASTResult / ReportOutput)。
func toMapCLI(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// ---- P0 deterministic path(供既有 TestRunDeterministic*) ----

type deterministicOut struct {
	AlertsForAI  []map[string]any `json:"alerts_for_ai"`
	HardExcluded []map[string]any `json:"hard_excluded"`
}

func runDeterministic(sarifPath string) (deterministicOut, error) {
	b, err := os.ReadFile(sarifPath)
	if err != nil {
		return deterministicOut{}, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return deterministicOut{}, err
	}
	results, err := adapter.CodeQLAdapter{}.Parse(raw)
	if err != nil {
		return deterministicOut{}, err
	}
	alerts := make([]map[string]any, 0, len(results))
	for _, r := range results {
		var m map[string]any
		rb, _ := json.Marshal(r)
		_ = json.Unmarshal(rb, &m)
		alerts = append(alerts, m)
	}
	surv, exc := hardexclusion.Partition(alerts)
	return deterministicOut{AlertsForAI: surv, HardExcluded: exc}, nil
}
