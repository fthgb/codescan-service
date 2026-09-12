package pipeline

import (
	"appsecgo/internal/faces"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"appsecgo/internal/agentic"
	"appsecgo/internal/contract"
	"appsecgo/internal/draft"
	"appsecgo/internal/funcdistill"
	"appsecgo/internal/hardexclusion"
	"appsecgo/internal/judge"
	"appsecgo/internal/report"
	"appsecgo/internal/slice"
	"appsecgo/internal/taintbridge"
)

var safeNameRe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func safeBughash(s string) string { return safeNameRe.ReplaceAllString(s, "_") }

func intPtr(i int) *int           { return &i }
func floatPtr(f float64) *float64 { return &f }

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func mapStr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

var highRiskSet = map[string]bool{
	"command_injection": true, "insecure_deserialization": true, "ssrf": true,
}

func highRisk(vt string) bool { return highRiskSet[vt] }

// sastResultToMap / mapsToSASTResults = json roundtrip contract.SASTResult ↔ map。
// map 喂 hardexclusion.Partition;survivor map 回 SASTResult 喂 fan-out(SliceAlert)。
func sastResultToMap(a contract.SASTResult) map[string]any {
	b, _ := json.Marshal(a)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func sastResultsToMaps(s []contract.SASTResult) []map[string]any {
	out := make([]map[string]any, 0, len(s))
	for _, a := range s {
		out = append(out, sastResultToMap(a))
	}
	return out
}

func mapsToSASTResults(ms []map[string]any) []contract.SASTResult {
	out := make([]contract.SASTResult, 0, len(ms))
	for _, m := range ms {
		b, _ := json.Marshal(m)
		var a contract.SASTResult
		_ = json.Unmarshal(b, &a)
		out = append(out, a)
	}
	return out
}

// mapsToJudgeResults 把 excluded alert maps 透传成最小 JudgeResult。gate fixture 无
// excluded → 空;excluded 的 alert-dict vs []JudgeResult 形状差异推增强期(见 Global Constraints)。
//
// Verdict 显式赋 "uncertain":excluded alert 没经过 judge(被硬排除),其 Verdict 字段
// 是裸 string,零值即 ""。VerdictOf 契约定为「未判定→uncertain」,此处绕过了 BuildJudgeResult,
// 必须手动对齐。统计不受影响(report.go stats 只遍历 judgements,excluded 仅计入 hard_excluded)。
//
// **为什么仍保留 "uncertain"(2026-09-01 F2 复核后的真实理由,已非"防崩页")**:
// 原注释写的是「否则前端 VerdictBadge MAP[""] → undefined → 整页崩」——该风险**已由**
// `web/src/components/VerdictBadge.tsx` 的 `FALLBACK` 兜底解掉(它注释里点名复现 run
// 2026-08-24T025908_codeup-probe-core)。现在保留 uncertain 的理由换成**兼容性**:
// 历史已落盘的 runs/*/summary.json 里这批就是 "uncertain",改生产侧不改历史 ⇒ 新旧数据
// 混读时只能靠**新增字段**区分,不能靠 verdict 值;且改 verdict 值会动 VerdictOf 契约邻域
// (CLAUDE.md 硬约束 2 那一圈)而收益为零。
//
// ⚠ 真实语义由 `ExclusionReason` 承载(F2):`hardexclusion.Partition` 已在 map 里写好
// "exclusion_reason",此处只是把它接进契约,供前端标签与 unlabelled 计数区分
// 「硬规则排除」与「LLM 不确定」。`TestMapsToJudgeResults_ExclusionReason` 双断言锁住
// (字段非空 **且** Verdict 仍为 "uncertain")—— 勿顺手改 Verdict。
//
// ⚠ 另注:`Partition` 给 excluded 设的是 `verdict="false_positive"`(hardexclusion.go:72),
// 与此处的 "uncertain" 语义相反 —— 同一批数据在两条路上不一致。本次不改(会动硬约束 2 邻域),
// 记在此处备查;`cmd/audit/main.go:223` 走 deterministicOut 不经本函数,拿到的是 false_positive。
func mapsToJudgeResults(ms []map[string]any) []contract.JudgeResult {
	out := make([]contract.JudgeResult, 0, len(ms))
	for _, m := range ms {
		out = append(out, contract.JudgeResult{
			AlertID:           mapStr(m, "alert_id"),
			Bughash:           mapStr(m, "bughash"),
			VulnerabilityType: strPtr(mapStr(m, "vulnerability_type")),
			Verdict:           "uncertain",
			ExclusionReason:   mapStr(m, "exclusion_reason"),
		})
	}
	return out
}

// slicedContextToMap 对齐 graph.py `sliced.model_dump()` (json roundtrip *SlicedContext → map)。
func slicedContextToMap(s *contract.SlicedContext) map[string]any {
	if s == nil {
		return nil
	}
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// alertDoneFromResult builds the SSE progress payload from JudgeResult + trace,
// field schema 逐字 api.py:_sse progress。
func alertDoneFromResult(jr contract.JudgeResult, agentic bool, tr map[string]any) AlertDone {
	d := AlertDone{
		AlertID:      jr.AlertID,
		Bughash:      jr.Bughash,
		VulnType:     ptrStr(jr.VulnerabilityType),
		Verdict:      strPtr(jr.Verdict),
		Disposition:  jr.Disposition,
		Confidence:   intPtr(jr.Confidence),
		JudgeAgentic: agentic,
		MissingInfo:  jr.MissingInfo,
		FailReason:   jr.FailReason,
	}
	if tr != nil {
		switch v := tr["tool_turns"].(type) {
		case int:
			d.ToolTurns = v
		case float64:
			d.ToolTurns = int(v)
		}
		if f, ok := tr["findings"].([]any); ok {
			d.FindingsCount = len(f)
		}
	}
	if jr.Verification != nil {
		if a, ok := jr.Verification["action"].(string); ok {
			d.VerificationAction = strPtr(a)
		}
	}
	return d
}

// Run 是端到端编排器(errgroup+semaphore 扇出,per-alert recover→uncertain,
// OnStart/OnAlert 回调)。sync /api/scan 与 SSE /api/scan/stream 共用——结构不分叉。
// per-alert 错走 fail-open 不冒顶;error 仅顶层编排错(adapter 前 / fan-out 前 fatal)。
func Run(ctx context.Context, in RunInput, opts RunOpts) (*RunResult, error) {
	// AGENTIC_XML_PROMOTE gate 由 config 驱动（默认 on）；replay/parity 传 "off"
	// 匹配 golden 录制时 config。空串 = 保持当前 gate（test 注入不覆盖）。
	if opts.AgenticXmlPromote != "" {
		agentic.SetXmlPromoteGate(opts.AgenticXmlPromote)
	}
	useCache := opts.RunMode != "experiment"
	// 集群5：per-run 蒸馏缓存（FUNC_DISTILL_MODE=on 时建，enrich/judge 共享，对齐 Python graph.py:64-65）。
	// nil → off 路径（read_function 返 full body，零开销）。gate 在此判，ToolExecutor 只看 store!=nil。
	if opts.FuncDistillMode == "on" && opts.SummaryStore == nil {
		opts.SummaryStore = funcdistill.NewFunctionSummaryStore()
	}
	// engine 接入 arc-1：per-scan 建一次（跨 alert 共享，spec §3.1）。gate 默认 off = 零回归。
	// fail-open：Scan 失败 → engineQuery=nil → 引擎工具 off（字节同今天，铁律 D）。
	if opts.TaintEngineMode == "on" && opts.engineQuery == nil {
		opts.engineQuery, _ = taintbridge.ScanAndBuild(opts.RepoRoot)
	}
	forAI, inherited := routerSplit(in.SAST, opts.Store, useCache)

	alertMaps := sastResultsToMaps(forAI)
	survivorMaps, excludedMaps := hardexclusion.Partition(alertMaps)
	excluded := mapsToJudgeResults(excludedMaps)

	total := len(survivorMaps)
	if opts.OnStart != nil {
		opts.OnStart(total)
	}
	survivors := mapsToSASTResults(survivorMaps)

	// production resume: 仅 useCache(production)读 checkpoint;experiment 空。
	done := map[string]bool{}
	if opts.Checkpoint != nil && useCache {
		done = opts.Checkpoint.CompletedIDs()
	}

	// nil-safe calibrate:Reg 可能为 nil(test fake);production 恒非 nil。
	// IsCalibrated 内 deref r.configs,nil Reg 直接调会 panic,故 closure 守护。
	calibrate := func(string) bool { return false }
	if opts.Reg != nil {
		calibrate = opts.Reg.IsCalibrated
	}

	var (
		mu          sync.Mutex
		judgements  []contract.JudgeResult
		traces      []map[string]any
		persistErrs []PersistError
	)
	var idx atomic.Int32
	weight := int64(opts.Concurrency)
	if weight <= 0 {
		weight = 1
	}
	sem := semaphore.NewWeighted(weight)
	g, gctx := errgroup.WithContext(ctx)
	for _, a := range survivors {
		a := a
		if _, skip := done[safeBughash(a.Bughash)]; skip {
			continue
		}
		if err := sem.Acquire(gctx, 1); err != nil {
			break
		}
		g.Go(func() error {
			defer sem.Release(1)
			aa := a
			normalizeAlert(&aa)
			var jr contract.JudgeResult
			var tr map[string]any
			// inner recover: panic → fail-open(uncertain + subgraph: <r>),tr 留 nil。
			// 对齐 graph.py:judge_subgraph 的 try/except(trace=None on fail)。
			func() {
				defer func() {
					if r := recover(); r != nil {
						jr = failOpenFromAlert(aa, opts.Model, fmt.Sprintf("subgraph: %v", r))
						tr = nil
					}
				}()
				if opts.judgeAlertOverride != nil {
					jr, tr, _ = opts.judgeAlertOverride(gctx, aa)
				} else {
					jr, tr = realJudgeAlert(gctx, aa, in, opts)
				}
			}()
			// triage fills declared vulnerability_type externally (mirror graph.py:104
			// d["vulnerability_type"]=alert["vulnerability_type"], unconditional, set
			// AFTER judge_one returns; fail-open path already sets it in failOpenFromAlert).
			{
				vt := aa.VulnerabilityType
				jr.VulnerabilityType = &vt
			}
			// 单一收尾路径(normal OR recovered):OnAlert 无条件触发恰好 total 个。
			doneAlert := alertDoneFromResult(jr, tr != nil && tr["judge_agentic"] == true, tr)
			doneAlert.Index = int(idx.Add(1))
			if opts.OnAlert != nil {
				opts.OnAlert(doneAlert)
			}
			mu.Lock()
			judgements = append(judgements, jr)
			if tr != nil {
				traces = append(traces, tr)
			}
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait() // per-alert 错走 fail-open,不冒顶;gctx cancel 由调用方/超时

	// 确定性面账（spec 2026-08-23）：矛盾是**组内**属性，单看一条永远看不出来，
	// 故必须在此汇总处算（judgements 与 traces 都已齐全）。纯函数、零 LLM、不改任何
	// verdict —— 只往 JudgeResult.Faces 写「同类兄弟已判定、本条未考虑的面」待复核项。
	if opts.FaceLedgerMode != "off" {
		attachFaces(judgements, traces, opts.FaceHistory)
	}

	rep := report.Report(judgements, inherited, excluded, calibrate)

	// persist step(移植 report_node side-effects,失败带外不阻断)。
	// TP 必写;FP 仅 confidence>=7 && !highRisk && calibrated && !reclassified 写(对齐 report.py:64)。
	for _, j := range judgements {
		if opts.Checkpoint != nil {
			if b, err := json.Marshal(j); err == nil {
				if err := opts.Checkpoint.Save(j.Bughash, b); err != nil {
					persistErrs = append(persistErrs, PersistError{j.Bughash, "checkpoint", err})
				}
			}
		}
		if opts.Store != nil {
			switch j.Verdict {
			case "true_positive":
				opts.Store.Upsert(j.Bughash, "true_positive", j.Reasoning, "ai", j.Confidence)
			case "false_positive":
				vt := ptrStr(j.VulnerabilityType)
				if j.Confidence >= 7 && !highRisk(vt) && calibrate(vt) &&
					len(j.TypeMismatchTypes) == 0 && len(j.BuriedTypes) == 0 {
					opts.Store.Upsert(j.Bughash, "false_positive", j.Reasoning, "ai", j.Confidence)
				}
			}
		}
	}

	return &RunResult{Report: &rep, Traces: traces, PersistErrors: persistErrs}, nil
}

// realJudgeAlert 跑真实 chain:SliceAlert → EnrichForJudge → DraftForJudge → JudgeOne
// (尾部含 VerifyVerdict+BuildAttackRequest)。SliceAlert 失败 → blind,JudgeOneFailOpen 兜空 slice。
// enrich/draft gate 在 RunOpts.EnrichMode/DraftMode/EagerGuardCallees（既有 fixture 传 off 零回归）。
func realJudgeAlert(_ context.Context, a contract.SASTResult, in RunInput, opts RunOpts) (contract.JudgeResult, map[string]any) {
	repoIndex := slice.NewRepositoryIndex(opts.RepoRoot, opts.Extractor).EnsureBuilt()
	// engine 由 Run 循环前建好（opts.engineQuery，per-scan 共享）；此处不 Scan。nil=off。
	engine := opts.engineQuery
	sliced, err := slice.SliceAlert(&a, opts.RepoRoot, opts.Extractor, repoIndex)
	if err != nil {
		return judge.JudgeOneFailOpen(nil, in.AppContext, opts.Provider, opts.Reg, opts.Model,
			floatPtr(opts.JudgeTemperature), repoIndex, opts.VCache, opts.DecisiveFactRejudgeMode, opts.SummaryStore, opts.VerifyMode, opts.DynamicVerifyMode,
			opts.StratReg), nil // ③-e stratReg: filed-CWE 错类补正（variadic; nil → inert, parity-safe）
	}
	// 增强期 P7: enrich → draft（对齐 graph.py:86-90 调用序）。
	// gate off / deterministic 时 EnrichForJudge 走 deterministic 分支（不调 provider，既有 fixture 零回归）；
	// agentic + SupportsTools 时 deterministic 兜底 + agentic 增补 + fail-open。
	agentic.EnrichForJudge(sliced, repoIndex, opts.Provider, opts.Model, opts.EnrichMode, opts.EagerGuardCallees, opts.SummaryStore)
	if opts.Reg != nil && opts.DraftMode != "off" {
		cweCfg, _ := opts.Reg.ConfigForSlug(sliced.VulnerabilityType)
		draft.DraftForJudge(sliced, cweCfg, opts.DraftMode)
	}
	// Phase 1 (root-2 裸名消歧, disambiguation spec §4): alert sink file (codesafe bugFile,
	// authoritative sink location, a.Sink["file"]) → SlicedContext.SinkFile → slicedMap["sink_file"]
	// (slicedContextToMap json roundtrip) → agenticJudge → exec.SetAlertSinkFile。LLM 调
	// who_calls/reachable_sinks 不带 file_path → resolveMethodKey 用 sink file 兜底消歧
	// (component.submit 而非 controller.submit)。off 路径 (engine==nil) resolveMethodKey 早返不读。
	sliced.SinkFile = contract.GetStr(a.Sink, "file")
	slicedMap := slicedContextToMap(sliced)
	temp := opts.JudgeTemperature
	jr, tr, _ := judge.JudgeOne(slicedMap, in.AppContext, opts.Provider, opts.Reg, opts.Model, &temp, repoIndex, opts.VCache, opts.DecisiveFactRejudgeMode, opts.SummaryStore, opts.VerifyMode, opts.DynamicVerifyMode,
		engine,        // NEW: 传 engine（nil→off，Run 建）
		opts.StratReg) // ③-e stratReg: filed-CWE 错类补正（variadic; nil → inert, parity-safe）
	return jr, tr
}

// attachFaces 计算确定性面账并写回 judgements[i].Faces（原地，按 bughash 对齐 trace）。
//
// authz_coverage 事实住在 trace 的 sliced 里（ComputeAuthzCoverage 写入），
// 不在 JudgeResult 上 —— 故此处需要 traces 而非只有 judgements。
// 缺 trace / 缺该事实 → 该 alert 不参与比对（fail-open，绝不猜）。
func attachFaces(judgements []contract.JudgeResult, traces []map[string]any, hist faces.History) {
	authz := map[string]*contract.AuthzCoverage{}
	upload := map[string]*contract.UploadDisposition{}
	for _, tr := range traces {
		bh, _ := tr["bughash"].(string)
		if bh == "" {
			continue
		}
		sl, _ := tr["sliced"].(map[string]any)
		if sl == nil {
			continue
		}
		b, err := json.Marshal(sl["authz_coverage"])
		if err != nil || string(b) == "null" {
			continue
		}
		var ac contract.AuthzCoverage
		if json.Unmarshal(b, &ac) == nil {
			authz[bh] = &ac
		}
		// upload 三分支事实（P1-1）：面账的第二个分组事实，同样住在 trace 的 sliced 里。
		if ub, uerr := json.Marshal(sl["upload_disposition"]); uerr == nil && string(ub) != "null" {
			var ud contract.UploadDisposition
			if json.Unmarshal(ub, &ud) == nil {
				upload[bh] = &ud
			}
		}
	}
	as := make([]faces.Alert, 0, len(judgements))
	for _, j := range judgements {
		as = append(as, faces.Alert{
			AlertID: j.AlertID, Bughash: j.Bughash, Verdict: j.Verdict,
			ActualTypes: j.ActualVulnerabilityTypes, Authz: authz[j.Bughash], Upload: upload[j.Bughash],
		})
	}
	ledger := faces.BuildWith(as, hist)
	for i := range judgements {
		if fs := ledger[judgements[i].Bughash]; len(fs) > 0 {
			judgements[i].Faces = fs
		}
	}
}
