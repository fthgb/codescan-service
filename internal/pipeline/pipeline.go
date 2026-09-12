package pipeline

import (
	"appsecgo/internal/faces"
	"context"
	"regexp"

	"appsecgo/internal/bughash"
	"appsecgo/internal/checkpoint"
	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
	"appsecgo/internal/funcdistill"
	"appsecgo/internal/llm"
	"appsecgo/internal/report"
	"appsecgo/internal/slice"
	"appsecgo/internal/stratreg"
	"appsecgo/internal/taintbridge"
	"appsecgo/internal/vcache"
)

// RunInput carries the seeded scan inputs.
type RunInput struct {
	SAST       []contract.SASTResult
	Scenario   string
	AppContext map[string]any
	RepoKey    string
}

// RunOpts wires the engine dependencies + callbacks. OnStart/OnAlert are the
// SSE seam (nil for sync /api/scan). judgeAlertOverride is an unexported test
// seam (same-package tests inject a fake; nil → real chain in Task 7).
type RunOpts struct {
	Model                string
	Provider             llm.Provider
	Reg                  *cwereg.Registry
	Extractor            slice.FunctionExtractor
	RepoRoot             string
	Store                *bughash.BughashStore
	VCache               *vcache.Store
	Checkpoint           *checkpoint.StepCheckpoint
	Concurrency          int
	OnStart              func(total int)
	OnAlert              func(AlertDone)
	RunMode              string
	ControlFlowPrefilter string
	JudgeTemperature     float64
	// Enrich/Draft gates (增强期 P7): ENRICH_MODE / DRAFT_MODE / EAGER_GUARD_CALLEES.
	// 既有 P2-P6 fixture 录制时 ENRICH_MODE=deterministic / DRAFT_MODE=off（绕过 enrich/draft）,
	// 故 e2e parity test 传 EnrichMode:"off"/DraftMode:"off" 零回归;production 传默认值接活。
	EnrichMode              string
	DraftMode               string
	EagerGuardCallees       string
	FuncDistillMode         string                            // 集群5 蒸馏缓存 gate（on→Run 建 per-run store）
	DecisiveFactRejudgeMode string                            // P7 守卫拒判后 LLM 重判 gate（default-on，P0-a §4(f) 固化 2026-08-26）
	VerifyMode              string                            // P7 falsify gate（默认 "deterministic"=off，"adversarial" 开启）
	DynamicVerifyMode       string                            // P7 动态执行验证 gate（默认 "off"，"ir" 开启 IR executor；junit deferral）
	AgenticXmlPromote       string                            // P7 post-agentic XML hop promote gate（默认 "on"；replay 传 "off" 匹配 golden）
	SummaryStore            *funcdistill.FunctionSummaryStore // per-run 蒸馏缓存（Run 建，enrich/judge 共享；nil=off）
	StratReg                *stratreg.Registry                // ③-e strategy 评估视角（filed-CWE 错类补正）；nil → Select 返 nil → strategyLayer 空 → parity 字节不变
	// engine 接入 arc-1：TaintEngineMode gate（默认 "off"）+ per-scan 引擎查询器。
	// 镜像 SummaryStore 先例：Run 循环前建一次（ScanAndBuild），跨 alert 共享；nil=off（零回归）。
	// gate 默认 off = 现有测试/replay 不触发 Scan，字节同今天；production 设 "on"。
	TaintEngineMode string // 默认 "off"；"on" → Run 建 engineQuery
	// FaceLedgerMode：确定性面账（spec 2026-08-23）。**只有显式 "off" 才关**，
	// 空串 = 开 —— 既有 fixture/test 不传该字段时应享受默认行为，与其它 gate 相反。
	FaceLedgerMode string
	// FaceHistory —— 跨 run 对照来源（nil = 只用同 run 兄弟对照）。
	// 接口而非目录路径：runs 目录只是**当前**的历史载体，换 DB/服务时 pipeline 不动（铁律 D）。
	FaceHistory        faces.History
	engineQuery        taintbridge.EngineQuerier // unexported（同 judgeAlertOverride），realJudgeAlert 读
	judgeAlertOverride func(ctx context.Context, a contract.SASTResult) (contract.JudgeResult, map[string]any, error)
}

// AlertDone is the per-alert progress payload (SSE event:progress), field schema
// mirrors api.py:_sse progress verbatim (snake_case json tags = Python field names).
// Verdict/Disposition/Confidence/... are pointers (nil = null, parity). Index is the
// 1-based completion order (Python progress.index).
type AlertDone struct {
	Index              int     `json:"index"`
	AlertID            string  `json:"alert_id"`
	Bughash            string  `json:"bughash"`
	VulnType           string  `json:"vulnerability_type"`
	Verdict            *string `json:"verdict"`
	Disposition        *string `json:"disposition"`
	Confidence         *int    `json:"confidence"`
	JudgeAgentic       bool    `json:"judge_agentic"`
	ToolTurns          int     `json:"tool_turns"`
	FindingsCount      int     `json:"findings_count"`
	MissingInfo        *string `json:"missing_info"`
	FailReason         *string `json:"fail_reason"`
	VerificationAction *string `json:"verification_action"`
}

// PersistError is a带外 persist failure (checkpoint.Save / store.Upsert) —
// 不阻断 Run(报告已生成);caller 收集 + 结构化 log。
type PersistError struct {
	Bughash string
	Stage   string
	Err     error
}

// RunResult is the orchestrator output. Report is parity-pure; PersistErrors
// carries side-effect failures out-of-band (不污染 ReportOutput/meta/summary)。
type RunResult struct {
	Report        *report.ReportOutput
	Traces        []map[string]any
	PersistErrors []PersistError
}

// ---- helpers (ports of graph.py seams) ----

var parenRe = regexp.MustCompile(`\(`)

// stripSig 移植 graph.py:_strip_sig: 'getUser(String)' -> 'getUser'。
func stripSig(name string) string {
	if i := parenRe.FindStringIndex(name); i != nil {
		return name[:i[0]]
	}
	return name
}

func strPtr(s string) *string { return &s }

// normalizeAlert 移植 graph.py:_normalize_alert:
// taint_path hop method→function、strip 签名;source/sink function strip 签名。
// 对 codeql(function 不带签名)是 no-op;对 codesafe(method)生效。
func normalizeAlert(a *contract.SASTResult) {
	for _, h := range a.TaintPath {
		if h == nil {
			continue
		}
		if _, ok := h["function"]; !ok {
			if m, ok := h["method"].(string); ok {
				h["function"] = stripSig(m)
				delete(h, "method")
			}
		} else if f, ok := h["function"].(string); ok {
			h["function"] = stripSig(f)
		}
	}
	for _, key := range []string{"source", "sink"} {
		var m map[string]any
		if key == "source" {
			m = a.Source
		} else {
			m = a.Sink
		}
		if m == nil {
			continue
		}
		if f, ok := m["function"].(string); ok {
			m["function"] = stripSig(f)
		}
	}
}

// maybePrune 移植 graph.py:maybe_prune_control_flow。annotate(默认)→ nil 不短路。
// prune 模式推增强期(此处返回 nil)。
func maybePrune(sliced map[string]any, mode, model string) (*contract.JudgeResult, map[string]any) {
	_ = sliced
	_ = model
	if mode == "prune" {
		// prune 短路 deferred;default path 不进
		return nil, nil
	}
	return nil, nil // annotate / off → 不短路
}

// failOpenFromAlert 移植 graph.py:96-102 catch:
// JudgeResult(alert_id, bughash, verdict=uncertain, confidence=0,
// exploit_path entry_point="?", reasoning="local fail-open", model_used=model,
// fail_reason),返回前 d["vulnerability_type"]=alert.vt。
func failOpenFromAlert(a contract.SASTResult, model, reason string) contract.JudgeResult {
	ep := "?"
	return contract.JudgeResult{
		AlertID:           a.AlertID,
		Bughash:           a.Bughash,
		VulnerabilityType: strPtr(a.VulnerabilityType),
		Verdict:           "uncertain",
		Confidence:        0,
		ExploitPath:       contract.ExploitPath{EntryPoint: ep},
		Reasoning:         "local fail-open",
		ModelUsed:         model,
		FailReason:        strPtr(reason),
	}
}

// routerSplit 移植 bughash_router_node:useCache=RunMode!="experiment";
// 命中且 verdict∈{fp,tp} → inherited(JudgeResult{verdict, ...});否则 forAI。
// 注:JudgeResult 无 judged_by/source 字段(保 report parity);inherited 只填
// 现有字段 —— inherited 的 judged_by/source 形状差异推增强期(见 Global Constraints)。
func routerSplit(sast []contract.SASTResult, store *bughash.BughashStore, useCache bool) (forAI []contract.SASTResult, inherited []contract.JudgeResult) {
	for _, a := range sast {
		if useCache && store != nil {
			if row, ok := store.Get(a.Bughash); ok {
				if v, _ := row["verdict"].(string); v == "false_positive" || v == "true_positive" {
					inherited = append(inherited, contract.JudgeResult{
						AlertID:           a.AlertID,
						Bughash:           a.Bughash,
						VulnerabilityType: strPtr(a.VulnerabilityType),
						Verdict:           v,
					})
					continue
				}
			}
		}
		forAI = append(forAI, a)
	}
	return forAI, inherited
}
