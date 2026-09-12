package main

import (
	"appsecgo/internal/faces"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"appsecgo/internal/adapter"
	"appsecgo/internal/appcontext"
	"appsecgo/internal/bughash"
	"appsecgo/internal/checkpoint"
	"appsecgo/internal/codescan"
	"appsecgo/internal/config"
	"appsecgo/internal/cwereg"
	"appsecgo/internal/discover"
	"appsecgo/internal/labels"
	"appsecgo/internal/llm"
	"appsecgo/internal/pandora"
	"appsecgo/internal/pipeline"
	"appsecgo/internal/report"
	"appsecgo/internal/reportpdf"
	"appsecgo/internal/runs"
	"appsecgo/internal/runsread"
	"appsecgo/internal/sca"
	"appsecgo/internal/sca/dbstore"
	"appsecgo/internal/slice"
	"appsecgo/internal/slice/gots"
	"appsecgo/internal/storage"
	"appsecgo/internal/stratreg"
	"appsecgo/internal/vcache"
)

type scanRequest struct {
	RepoKey    string         `json:"repo_key"`
	RepoRoot   string         `json:"repo_root"`
	Adapter    string         `json:"adapter"`
	Scenario   string         `json:"scenario"`
	SastReport map[string]any `json:"sast_report"`
	// PkTask — sec-service 代码卫士任务主键。非空时 runPipeline 落 cmdb_link.json，
	// 供 push-to-cmdb 关联（手动模式必填，否则推送 400）。Trigger 选 codescan 任务时携带。
	PkTask string `json:"pk_task,omitempty"`
}

// discoverRequest — 移植 appsec/api.py:discover payload。Line B diff-seeded
// discovery：无 SAST 输入，提交统一 git diff。scenario 默认 "pr_review"
// （payload 携带但 RunDiscovery 不消费——discovery 无 SAST alert/scenario 概念）。
type discoverRequest struct {
	Diff     string `json:"diff"`
	RepoKey  string `json:"repo_key"`
	RepoRoot string `json:"repo_root"`
	Scenario string `json:"scenario"`
}

// discoverMaxTokens 对齐 internal/judge.llmMaxTokens=8192（config.LLM_MAX_TOKENS）。
// discover 包无法 import judge 的私有 const（铁律 A：跨包只走公开契约），在 server
// 层定义同值常量。discovery 用 text 路径（无 tools），max_tokens 语义一致。
const discoverMaxTokens = 8192

// serverCfg is loaded once at package init (env-gated,密钥只走 env)。
var serverCfg = config.Load()

// ossUploader is the OSS upload client (nil = not configured; handlers gracefully degrade).
var ossUploader storage.Uploader

// codescanAPI is the interface codescan handlers depend on (6 public methods).
// Production wires *codescan.Client; tests inject a fake to mock the client layer
// (对齐 Python test_workbench_router_codescan.py 的 monkeypatch 模式——捕获 levels/
// rule_codes 参数而非重复 mock HTTP)。
type codescanAPI interface {
	DiscoverProjects(keyword string, pageIndex, pageSize int) (codescan.ProjectPage, error)
	DiscoverTasks(pjName string) ([]codescan.Task, error)
	DiscoverBugs(pkTask string, pageIndex, pageSize int) (codescan.BugPage, error)
	SummarizeBugs(pkTask string, forceRefresh bool) (codescan.BugTypeSummary, error)
	FetchAll(pkTask string, limit int, levels []int, ruleCodes []string) ([]map[string]any, error)
	CloneSource(svnGitUri, branch, commitID string) (string, error)
}

// codescanClient is the codescan REST client (boundary adapter, 铁律 D).
// Package-level so handlers share it + its TTL caches. Initialized from serverCfg.
var codescanClient codescanAPI = codescan.New(codescan.Options{
	BaseURL:          serverCfg.CodescanBaseURL,
	AuthToken:        serverCfg.CodescanAuthToken,
	AuthCookie:       serverCfg.CodescanAuthCookie,
	InsecureSSL:      serverCfg.CodescanInsecureSSL,
	Timeout:          time.Duration(serverCfg.CodescanTimeoutSec) * time.Second,
	RepoCacheDir:     serverCfg.CodescanRepoCacheDir,
	DetailCacheTTL:   time.Duration(serverCfg.CodescanDetailCacheTTLSec) * time.Second,
	RepoCacheTTL:     time.Duration(serverCfg.RepoCacheTTLHours) * time.Hour,
	FetchWorkers:     serverCfg.CodescanFetchWorkers,
	GitAdminUser:     serverCfg.CodescanGitAdminUser,
	GitAdminPassword: serverCfg.CodescanGitAdminPassword,
})

// runPipeline is the engine assembly seam. Package-level var so same-package
// tests inject a fake (validation/SSE tests override it). Real impl assembles
// deps + pipeline.Run + runs.WriteRun (对齐 Python write_run 在 api.py 而非 graph)。
// Returns (res, runDir, err); WriteRun 失败 → (res, "", wErr)。
var runPipeline = func(ctx context.Context, cfg config.Config, req *scanRequest,
	onStart func(int), onAlert func(pipeline.AlertDone)) (*pipeline.RunResult, string, error) {
	reg, err := cwereg.NewRegistry(cfg.CweregPath)
	if err != nil {
		return nil, "", err
	}
	// ③-e strategy 评估视角（filed-CWE 错类补正）。fail-open：strategy 是增强
	// 而非必需（cwe_registry essential，NewRegistry err → hard return；strategy
	// augmentation，err → warn + nil → Select nil gate → inert）。镜像 cmd/audit 接法。
	// 盯点#2：Step 2b 漏接 server → web run 0-emit 策略层；此补接修复。
	stratReg, serr := stratreg.NewRegistry(cfg.StratregPath)
	if serr != nil {
		fmt.Fprintln(os.Stderr, "warn: strategy registry unavailable, all strategies including general disabled (③-e 视角子系统全关；判决仍走 cwe_registry):", serr)
		stratReg = nil
	}
	// 按 req.Adapter 选 adapter（codesafe 需 reg 做 CWE→slug；
	// codeql/空/未知 → codeql 兜底，对齐 Python _ADAPTERS 但 Go 不 KeyError）
	results, err := adapter.ByName(req.Adapter, reg).Parse(req.SastReport)
	if err != nil {
		return nil, "", err
	}
	// AllowedLanguages 过滤:codescan 扫到的非 Java(.vue/.html/.js/.xml)在早期丢弃,
	// 不进 alertMaps(alerts_input.json)也不进 judge fan-out(省 token);只留计数到
	// summary.json.skipped_by_language。default ["java"];APPSEC_ALLOWED_LANGUAGES=* 关。
	results, skippedByLang := pipeline.FilterByLanguage(results, cfg.AllowedLanguages)
	results, skippedBySev := pipeline.FilterBySeverity(results, cfg.MinSeverity)
	provider := llm.NewHarness(llm.NewProviderFromConfig(cfg))
	store, _ := bughash.OpenBughashStore(cfg.DBPath)
	if store != nil {
		defer store.Close()
	}
	cp, _ := checkpoint.NewStepCheckpoint(cfg.CheckpointDir)
	var vc *vcache.Store
	if cfg.VerdictContentCache == "on" {
		vc, _ = vcache.NewStore(cfg.VerdictCacheDBPath, cfg.VerdictCacheTTLDays, time.Now)
	}
	if vc != nil {
		defer vc.Close()
	}
	t0 := time.Now()
	res, err := pipeline.Run(ctx, pipeline.RunInput{
		SAST: results, Scenario: req.Scenario, AppContext: appcontext.Resolve(req.RepoKey), RepoKey: req.RepoKey,
	}, pipeline.RunOpts{
		Model:                   provider.Model(),
		Provider:                provider,
		Reg:                     reg,
		Extractor:               slicerPool(),
		RepoRoot:                req.RepoRoot,
		Store:                   store,
		VCache:                  vc,
		Checkpoint:              cp,
		Concurrency:             4,
		OnStart:                 onStart,
		OnAlert:                 onAlert,
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
		return res, "", err
	}
	// 回填跳过计数到 summary.json.skipped_by_language(非 Java alert 可见性,不污染 verdict)。
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
		alertMaps[i] = toMapSrv(r)
	}
	runDir, wErr := runs.WriteRun(cfg.RunsDir, req.RepoKey, req.Adapter, provider.Model(),
		alertMaps, res.Report, res.Traces, time.Since(t0).Seconds())
	// cmdb_link.json：关联 codescan 任务主键，供 push-to-cmdb 读取。
	// 仅 PkTask 非空且扫描已落盘时写——无 PkTask（discovery/纯本地）无推送目标，不落 link。
	// 手动模式 dispatch_id 留空（sec-service 砍了该字段，设计文档 §七-3）。
	if wErr == nil && req.PkTask != "" && runDir != "" {
		link := map[string]any{
			"pk_task":     req.PkTask,
			"app_name":    req.RepoKey,
			"dispatch_id": "",
			"callback_url": cfg.CmdbPushURL,
			"source":      "manual",
			"run_id":      filepath.Base(runDir),
		}
		if lerr := runs.WriteJSONFile(filepath.Join(runDir, "cmdb_link.json"), link); lerr != nil {
			// 非致命：扫描结果已落盘；推送端会因缺 cmdb_link.json 返回 400 提示从 Trigger 选任务
			fmt.Fprintf(os.Stderr, "write cmdb_link.json failed (runDir=%s): %s\n", runDir, lerr.Error())
		}
	}
	// SCA 随审计触发（best-effort）：失败不阻塞审计主流程，只 stderr 留痕（spec §三）。
	// 与 cmd/audit 同逻辑；server 路径的审计也自动附带 SCA。
	if os.Getenv("APPSEC_SCA_ENABLED") != "0" && wErr == nil {
		scaOpts := sca.Options{
			RepoKey:    req.RepoKey,
			RepoRoot:   req.RepoRoot,
			ScaRunsDir: cfg.ScaRunsDir,
			PolicyPath: cfg.ScaPolicyPath,
		}
		if scanID, serr := sca.Run(scaOpts); serr != nil {
			fmt.Fprintf(os.Stderr, "[sca] best-effort 触发失败（不阻塞审计）: %v\n", serr)
		} else {
			fmt.Fprintf(os.Stderr, "[sca] scan_id=%s repo_key=%s\n", scanID, req.RepoKey)
		}
	}
	return res, runDir, wErr
}

// runDiscovery is the Line B assembly seam (mirror of runPipeline for Line A):
// assemble provider/harness/extractor/index → discover.RunDiscovery (sequential,
// no SAST fan-out/errgroup) → runs.WriteRun(adapter="diff"). Returns
// (*report.ReportOutput, runDir, error); error comes only from WriteRun (disk
// IO) — discover.RunDiscovery itself never errors (fail-open is inside
// DiscoverOne per changed function → uncertain). The slicer is gots (always
// non-nil), so there is no longer a nil-pool failure path here.
//
// Package-level var so same-package tests inject a fake (capture diff/repoKey
// for assertions), mirroring runPipeline's test seam.
var runDiscovery = func(ctx context.Context, cfg config.Config, req *discoverRequest) (*report.ReportOutput, string, error) {
	provider := llm.NewHarness(llm.NewProviderFromConfig(cfg))
	extractor := slicerPool()
	// RepositoryIndex 拉取 1-hop callers（includeCallers=index!=nil）。失败不阻断
	// discovery——index 为 nil 时 RunDiscovery 跳过 caller enrich，仅判定变更函数。
	var index *slice.RepositoryIndex
	func() {
		defer func() { recover() }() // Build 可能 panic（坏文件），fail-open index=nil
		index = slice.NewRepositoryIndex(req.RepoRoot, extractor).EnsureBuilt()
	}()
	appCtx := appcontext.Resolve(req.RepoKey)
	t0 := time.Now()
	rep := discover.RunDiscovery(ctx, req.Diff, req.RepoRoot, appCtx,
		provider, provider.Model(), extractor, index, discoverMaxTokens)
	// alertsInput/traces 传 nil：discovery 无 SAST alert 输入，DiscoverOne 不产 trace。
	runDir, wErr := runs.WriteRun(cfg.RunsDir, req.RepoKey, "diff", provider.Model(),
		nil, rep, nil, time.Since(t0).Seconds())
	return rep, runDir, wErr
}

// slicerPool: package-level lazy Go-native extractor (process-life reuse).
// Holds the interface, not a concrete type, so future engine swaps don't
// touch the server. gots.New() always succeeds (never nil).
var (
	slicerOnce sync.Once
	slicerExt  slice.FunctionExtractor
)

func slicerPool() slice.FunctionExtractor {
	slicerOnce.Do(func() { slicerExt = gots.New() })
	return slicerExt
}

func main() {
	// Pandora infrastructure config (OSS + DB); shared with sec-service.
	// In .env mode (home/dev): pandoraCfg is nil → try APPSEC_PANDORA_CONFIG env var.
	// In Pandora mode (prod/CI, no .env): pandoraCfg loaded by config.init() → use directly.
	cfg := config.PandoraConfig()
	if cfg == nil {
		// .env mode: try env var (set by .env file or shell export)
		if path := os.Getenv("APPSEC_PANDORA_CONFIG"); path != "" {
			if c, err := pandora.Load(path); err == nil {
				cfg = c
			} else {
				fmt.Fprintln(os.Stderr, "warn: pandora config load failed:", err)
			}
		}
	}
	if cfg != nil {
		client, err := storage.NewOSSClient(storage.OSSClientConfig{
			BucketName:       cfg.OSS.BucketName,
			ObjectPrefix:     cfg.OSS.ObjectName,
			Region:           cfg.OSS.Region,
			InternalEndpoint: cfg.OSS.Endpoint,
			ExternalEndpoint: cfg.OSS.PublicEndpoint,
			AccessKey:        cfg.OSS.AccessKey,
			SecretKey:        cfg.OSS.SecretKey,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn: OSS client init failed:", err)
		} else {
			ossUploader = client
			fmt.Fprintln(os.Stderr, "pandora OSS config loaded, bucket:", cfg.OSS.BucketName)
		}
		// DB init: same pandora config, database.link from secret platform.
		// Failure → dbstore stays nil → SCA scans degrade to JSON-only.
		if cfg.DB.DatabaseLink != "" {
			if err := dbstore.Init(cfg.DB.DatabaseLink); err != nil {
				fmt.Fprintln(os.Stderr, "warn: dbstore init failed:", err)
			} else {
				defer dbstore.Close()
				fmt.Fprintln(os.Stderr, "dbstore initialized")
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/scan", scanHandler)
	mux.HandleFunc("POST /api/scan/stream", scanStreamHandler)
	// from-codescan：sec-service Path1 出站触发(代码卫士回调后异步驱动裁决)
	mux.HandleFunc("POST /api/scan/from-codescan", scanFromCodescanHandler)
	// workbench review 路由（移植 appsec/webapp/router.py）
	mux.HandleFunc("GET /api/runs", listRunsHandler)
	mux.HandleFunc("GET /api/runs/{run_id}", getRunHandler)
	mux.HandleFunc("DELETE /api/runs/{run_id}", deleteRunHandler)
	mux.HandleFunc("GET /api/runs/{run_id}/alerts/{bughash}", getAlertHandler)
	mux.HandleFunc("GET /api/runs/{run_id}/alerts/{bughash}/report", alertReportHandler)
	mux.HandleFunc("GET /api/runs/{run_id}/report", reportHandler)
	// PDF 导出（chromedp + Edge headless，报告自动发送给开发的入口）：
	// 主报告与单条告警报告各一个 .pdf 端点。
	mux.HandleFunc("GET /api/runs/{run_id}/report.pdf", reportPDFHandler)
	mux.HandleFunc("GET /api/runs/{run_id}/alerts/{bughash}/report.pdf", alertReportPDFHandler)
	mux.HandleFunc("POST /api/labels", postLabelHandler)
	mux.HandleFunc("GET /api/labels", getLabelsHandler)
	// webhook：CI 委托扫描（移植 appsec/api.py:281-294）
	mux.HandleFunc("POST /webhook", webhookHandler)
	// discover：Line B diff-seeded discovery 审计（移植 appsec/api.py discover endpoint）
	mux.HandleFunc("POST /api/discover", discoverHandler)
	// codescan 浏览/拉取路由（移植 appsec/webapp/router.py:96-165）
	mux.HandleFunc("GET /api/codescan/projects", codescanProjectsHandler)
	mux.HandleFunc("GET /api/codescan/projects/{pj_name}/tasks", codescanTasksHandler)
	mux.HandleFunc("GET /api/codescan/tasks/{pk_task}/bugs", codescanBugsHandler)
	mux.HandleFunc("GET /api/codescan/tasks/{pk_task}/bug-summary", codescanBugSummaryHandler)
	mux.HandleFunc("GET /api/codescan/tasks/{pk_task}/all-bugs", codescanAllBugsHandler)
	mux.HandleFunc("POST /api/codescan/clone", codescanCloneHandler)
	// CMDB 推送端（设计文档 §七；sec-service → CMDB 事件闭环）
	mux.HandleFunc("GET /api/runs/{run_id}/push-preview", pushPreviewHandler)
	mux.HandleFunc("POST /api/runs/{run_id}/push-to-cmdb", pushToCMDBHandler)
	// SCA 路由（webhook 异步 + 查询 + re-evaluate + 并发护栏）
	mux.HandleFunc("POST /api/sca/scan", scaScanHandler)
	mux.HandleFunc("GET /api/sca/scans", scaListHandler)
	mux.HandleFunc("GET /api/sca/scans/{scan_id}", scaScanDetailHandler)
	mux.HandleFunc("GET /api/sca/components", scaComponentsHandler)
	mux.HandleFunc("POST /api/sca/scans/{scan_id}/re-evaluate", scaReEvaluateHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)
	addr := envOrDefault("APPSEC_SERVER_ADDR", "127.0.0.1:8000")
	fmt.Fprintln(os.Stderr, "appsec server on", addr)
	srv := &http.Server{Addr: addr, Handler: withAuth(serverCfg.ApiToken, mux), ReadHeaderTimeout: 30 * time.Second}
	_ = srv.ListenAndServe()
}

func envOrDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// not_audited / repo_root_invalid 文案逐字移植 api.py:62-86(fail-loud,不伪装 clean)。
const notAuditedReason = "No SAST input provided. /api/scan is SAST-seeded; for diff-only " +
	"auditing of changed code (no SAST) POST a unified diff to " +
	"/api/discover. These changes were NOT scanned here — do NOT interpret " +
	"this as 'clean'."

func repoRootInvalidReason(repoRoot string) string {
	return fmt.Sprintf("repo_root does not exist or is not a directory: %q. "+
		"The code slicer cannot read source files, so every alert would be "+
		"judged with no code (blind). Fix the path and re-run. Do NOT interpret "+
		"this as 'clean'.", repoRoot)
}

func writeNotAudited(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "not_audited", "audited": false, "reason": notAuditedReason,
		"summary": map[string]any{"ai_processed": 0}, "details": []any{},
	})
}

func writeRepoRootInvalid(w http.ResponseWriter, repoRoot string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "repo_root_invalid", "audited": false, "reason": repoRootInvalidReason(repoRoot),
		"summary": map[string]any{"ai_processed": 0}, "details": []any{},
	})
}

func decodeScan(r *http.Request) (*scanRequest, error) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	req, err := decodeScan(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	runScanAndWrite(r.Context(), w, req)
}

// runScanAndWrite 是 scanHandler + webhookHandler 的共享委托：校验 sast_report
// 非空 + repo_root 是目录 → runPipeline → 写 JSON 响应（附 run_dir）。
// 签名不收 *http.Request：只写 w、读 req + ctx，显式依赖更显式（YAGNI r）。
func runScanAndWrite(ctx context.Context, w http.ResponseWriter, req *scanRequest) {
	if len(req.SastReport) == 0 {
		writeNotAudited(w)
		return
	}
	if !isDir(req.RepoRoot) {
		writeRepoRootInvalid(w, req.RepoRoot)
		return
	}
	res, runDir, err := runPipeline(ctx, serverCfg, req, nil, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := toMapSrv(res.Report)
	out["run_dir"] = runDir
	_ = json.NewEncoder(w).Encode(out)
}

// webhookPayload — 移植 appsec/api.py:281 webhook payload。
// task_name 首段作 scenario；sast_report 空时 fallback xcheck_report（保旧 CI 兼容）。
// adapter 字段空时默认 "codesafe"（codescan 全链闭环，codesafe 为用户主用 SAST 方向），
// 并打 warn log 提示显式设置可消除告警；显式传 adapter 仍按原值走。
type webhookPayload struct {
	TaskName     string         `json:"task_name"`
	RepoKey      string         `json:"repo_key"`
	RepoRoot     string         `json:"repo_root"`
	Adapter      string         `json:"adapter"`
	SastReport   map[string]any `json:"sast_report"`
	XcheckReport map[string]any `json:"xcheck_report"`
	// PkTask — 透传到 scanRequest.PkTask（CI 委托扫描也落 cmdb_link.json）。
	PkTask string `json:"pk_task,omitempty"`
}

// scenarioFromTaskName — task_name split("_",2) 取首段；空 name 或空首段 → "prod_build"。
// 修正 Python quirk：Python "".split("_",2)=[""]，parts[0]="" 产空 scenario（注释本意是 prod_build）。
func scenarioFromTaskName(name string) string {
	if name == "" {
		return "prod_build"
	}
	parts := strings.SplitN(name, "_", 2)
	if parts[0] == "" {
		return "prod_build"
	}
	return parts[0]
}

// webhookHandler — POST /webhook：CI 委托扫描。
// 解析 task_name → scenario，sast_report fallback xcheck_report，构造 scanRequest 委托 runScanAndWrite。
// repo_key/repo_root 缺失 → 400（比 Python KeyError→500 更可调试）。
func webhookHandler(w http.ResponseWriter, r *http.Request) {
	var payload webhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	if payload.RepoKey == "" || payload.RepoRoot == "" {
		writeJSONError(w, 400, "repo_key and repo_root are required")
		return
	}
	sast := payload.SastReport
	if len(sast) == 0 {
		sast = payload.XcheckReport // fallback 保旧 CI 脚本兼容
	}
	adapter := payload.Adapter
	if adapter == "" {
		adapter = "codesafe" // codescan 全链闭环，codesafe 为用户主用 SAST 方向
		fmt.Fprintln(os.Stderr, "warn: webhook adapter defaulting to 'codesafe'; set adapter field explicitly to suppress this warning")
	}
	req := &scanRequest{
		RepoKey:    payload.RepoKey,
		RepoRoot:   payload.RepoRoot,
		Adapter:    adapter,
		Scenario:   scenarioFromTaskName(payload.TaskName),
		SastReport: sast,
		PkTask:     payload.PkTask,
	}
	runScanAndWrite(r.Context(), w, req)
}

// discoverHandler — POST /api/discover：Line B diff-seeded discovery 审计。
// 接收统一 git diff（无 SAST 输入）→ fail-loud 校验（empty diff → not_audited；
// repo_root 非目录 → repo_root_invalid）→ runDiscovery 装配 + RunDiscovery + WriteRun
// → 响应 {summary, details, run_dir}。fail-loud 文案复用 scan 的 helper（not_audited
// 文案已指引到 /api/discover；repo_root_invalid 同义）。
func discoverHandler(w http.ResponseWriter, r *http.Request) {
	var req discoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if strings.TrimSpace(req.Diff) == "" {
		writeNotAudited(w)
		return
	}
	if !isDir(req.RepoRoot) {
		writeRepoRootInvalid(w, req.RepoRoot)
		return
	}
	rep, runDir, err := runDiscovery(r.Context(), serverCfg, &req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := toMapSrv(rep)
	out["run_dir"] = runDir
	_ = json.NewEncoder(w).Encode(out)
}

// scanStreamHandler: SSE start/progress/done。单 channel + 单 drain goroutine
// 排他写 ResponseWriter(http.ResponseWriter 非并发安全)。total 在 Run 内
// hard_exclusion 后才知,handler 不能预建 total-capacity channel。
func scanStreamHandler(w http.ResponseWriter, r *http.Request) {
	req, err := decodeScan(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if len(req.SastReport) == 0 {
		writeNotAudited(w)
		return
	}
	if !isDir(req.RepoRoot) {
		writeRepoRootInvalid(w, req.RepoRoot)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)

	type streamEv struct {
		kind  string
		start *int
		prog  *pipeline.AlertDone
	}
	evCh := make(chan streamEv, 64)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel() // 客户端断连 → 取消 pipeline(断连=扫描丢失,parity api.py:127)

	type doneData struct {
		RunDir  string
		Summary map[string]any
		Err     string // 仅 server log,不进 SSE
	}
	var done doneData

	// drain:单 goroutine 排他写 ResponseWriter。close(evCh) happens-before
	// range 退出 → done 在 close 前写、drain 在 range 退出后读,无竞争。
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for ev := range evCh {
			switch ev.kind {
			case "start":
				sseWrite(w, "start", map[string]any{"total": *ev.start})
			case "progress":
				sseWrite(w, "progress", ev.prog)
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		// done payload schema 逐字 {run_dir, summary}(不加 error 字段,parity api.py:_sse)。
		// Run 成功 → {runDir, summary};Run 出错(res==nil)→ {runDir:"", summary:nil}。
		sseWrite(w, "done", map[string]any{"run_dir": done.RunDir, "summary": done.Summary})
		if flusher != nil {
			flusher.Flush()
		}
	}()

	res, runDir, err := runPipeline(ctx, serverCfg, req,
		func(n int) { evCh <- streamEv{kind: "start", start: &n} },
		func(d pipeline.AlertDone) { evCh <- streamEv{kind: "progress", prog: &d} },
	)
	if err != nil && res == nil {
		done.Err = err.Error() // 顶层 fatal:仅 log,done 空(schema 不变)
	} else if res != nil {
		done.RunDir = runDir
		if res.Report != nil {
			done.Summary = res.Report.Summary
		}
		if err != nil {
			done.Err = err.Error() // WriteRun 等错,仅 log
		}
	}
	// pipeline/WriteRun 失败时 done.Err 被设但 SSE schema 刻意不带 error 字段，
	// 此处显式落 stderr，否则 server 静默失败（HTTP 200 + run_dir 空），无法排查。
	if done.Err != "" {
		fmt.Fprintf(os.Stderr, "scan repo_key=%q adapter=%s: pipeline error: %s\n",
			req.RepoKey, req.Adapter, done.Err)
	}
	close(evCh)
	<-drainDone // 等 drain 发完 done 再返回(防 ResponseWriter 写后关闭 race)
}

func sseWrite(w http.ResponseWriter, event string, data any) {
	b, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
}

// ---- helpers ----

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func toMapSrv(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// ---- workbench review 路由（移植 appsec/webapp/router.py）----

// writeJSONError 对齐 Python FastAPI HTTPException 的 {"detail": "..."} 形状。
func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"detail": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// GET /api/runs — 列出所有 run（meta + counts），newest first。
func listRunsHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, runsread.ListRuns(serverCfg.RunsDir))
}

// GET /api/runs/{run_id} — run 详情 + label overlay + unlabelled 计数。
func getRunHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	data := runsread.GetRun(serverCfg.RunsDir, runID, serverCfg.LabelsPath)
	if data == nil {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	writeJSON(w, data)
}

// DELETE /api/runs/{run_id} — 路径安全删除（404 if not found）。
func deleteRunHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	if !runs.DeleteRun(serverCfg.RunsDir, runID) {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	writeJSON(w, map[string]any{"deleted": runID})
}

// GET /api/runs/{run_id}/alerts/{bughash} — 单告警：matching details + trace。
func getAlertHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	bughash := r.PathValue("bughash")
	data := runsread.GetAlert(serverCfg.RunsDir, runID, bughash)
	if data == nil {
		writeJSONError(w, 404, "alert not found: "+runID+"/"+bughash)
		return
	}
	writeJSON(w, data)
}

// GET /api/runs/{run_id}/report — 自包含 HTML 审计报告（?download=1 触发附件下载）。
// 只读 runs/ 落盘数据（复用 runsread.GetRun），渲染委托 internal/report（铁律 A）。
// reportHandler — 主报告（全量整合）。为每个确认（verdict==true_positive）detail 读其 trace，
// 注入 data_flow 步下代码切片（spec §9.6 扩展点落地；与单条报告同 matchHopsToSteps 口径）。
func reportHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	data := runsread.GetRun(serverCfg.RunsDir, runID, serverCfg.LabelsPath)
	if data == nil {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	// 逐确认 detail 读 trace（IO 在 route 层，report 包保持纯函数）。trace 缺失 → 该 detail 步仅文字。
	traces := collectTPTraces(data)
	html, err := report.RenderHTML(data, traces)
	if err != nil {
		writeJSONError(w, 500, "report render failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=\"audit-report-%s.html\"", runID))
	}
	_, _ = w.Write([]byte(html))
}

// GET /api/runs/{run_id}/alerts/{bughash}/report — 单条告警可编辑 HTML 报告
// （?download=1 触发附件下载）。用 GetRun 取 meta + details（GetAlert 不含 meta），
// 按 bughash 选 primary detail，渲染委托 internal/report（铁律 A）。
// 扩展点（本期不实现）：若后续有"已落盘修复"数据源，可加只读/已落盘模式。
func alertReportHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	bughash := r.PathValue("bughash")
	data := runsread.GetRun(serverCfg.RunsDir, runID, serverCfg.LabelsPath)
	if data == nil {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	meta, _ := data["meta"].(map[string]any)
	rawDetails, _ := data["details"].([]map[string]any)
	var primary map[string]any
	for _, d := range rawDetails {
		bh, _ := d["bughash"].(string)
		if bh == bughash {
			primary = d
			break
		}
	}
	if primary == nil {
		writeJSONError(w, 404, "alert not found: "+bughash)
		return
	}
	trace, _ := runsread.Trace(serverCfg.RunsDir, runID, bughash).(map[string]any)
	html, err := report.RenderAlertHTML(primary, meta, trace)
	if err != nil {
		writeJSONError(w, 500, "report render failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=\"alert-report-%s.html\"", bughash))
	}
	_, _ = w.Write([]byte(html))
}

// collectTPTraces — 逐确认（verdict==true_positive）detail 读 trace（IO 在 route 层，
// report 包保持纯函数）。reportHandler 与 reportPDFHandler 共用。data 的 meta.run_id
// 与路由 runID 同源（GetRun 按其目录读入），取 meta 免得再穿一层参数。
func collectTPTraces(data map[string]any) map[string]map[string]any {
	traces := map[string]map[string]any{}
	meta, _ := data["meta"].(map[string]any)
	runID, _ := meta["run_id"].(string)
	if rawDetails, ok := data["details"].([]map[string]any); ok {
		for _, d := range rawDetails {
			verdict, _ := d["verdict"].(string)
			if verdict != "true_positive" {
				continue
			}
			bh, _ := d["bughash"].(string)
			if bh == "" {
				continue
			}
			if t, ok := runsread.Trace(serverCfg.RunsDir, runID, bh).(map[string]any); ok && t != nil {
				traces[bh] = t
			}
		}
	}
	return traces
}

// GET /api/runs/{run_id}/report.pdf — 主报告 PDF（chromedp + Edge headless 打印）。
// 与 reportHandler 同源同口径（同一 RenderHTML、同一 trace 注入），
// 渲染后交 reportpdf 打印；浏览器探测失败/超时 → 500 带可操作错误信息。
func reportPDFHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	data := runsread.GetRun(serverCfg.RunsDir, runID, serverCfg.LabelsPath)
	if data == nil {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	html, err := report.RenderHTML(data, collectTPTraces(data))
	if err != nil {
		writeJSONError(w, 500, "report render failed: "+err.Error())
		return
	}
	pdf, err := reportpdf.RenderPDF(html)
	if err != nil {
		writeJSONError(w, 500, "PDF 导出失败："+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"audit-report-%s.pdf\"", runID))
	_, _ = w.Write(pdf)
}

// GET /api/runs/{run_id}/alerts/{bughash}/report.pdf — 单条告警 PDF。
// 用打印变体 RenderAlertPrintHTML（只读修复建议，不用 textarea——headless 打印
// 会按 rows 截断 textarea，PDF 里丢下半段）。
func alertReportPDFHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	bughash := r.PathValue("bughash")
	data := runsread.GetRun(serverCfg.RunsDir, runID, serverCfg.LabelsPath)
	if data == nil {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	meta, _ := data["meta"].(map[string]any)
	rawDetails, _ := data["details"].([]map[string]any)
	var primary map[string]any
	for _, d := range rawDetails {
		bh, _ := d["bughash"].(string)
		if bh == bughash {
			primary = d
			break
		}
	}
	if primary == nil {
		writeJSONError(w, 404, "alert not found: "+bughash)
		return
	}
	trace, _ := runsread.Trace(serverCfg.RunsDir, runID, bughash).(map[string]any)
	html, err := report.RenderAlertPrintHTML(primary, meta, trace)
	if err != nil {
		writeJSONError(w, 500, "report render failed: "+err.Error())
		return
	}
	pdf, err := reportpdf.RenderPDF(html)
	if err != nil {
		writeJSONError(w, 500, "PDF 导出失败："+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"alert-report-%s.pdf\"", bughash))
	_, _ = w.Write(pdf)
}

// labelRequest — 移植 router.LabelRequest（pydantic）。
// lang 服务端自动填（slicer Java-only），客户端不传。
type labelRequest struct {
	RunID                string  `json:"run_id"`
	Bughash              string  `json:"bughash"`
	Label                string  `json:"label"` // false_positive | true_positive | uncertain | needs-hardening
	Note                 *string `json:"note"`
	Labeler              *string `json:"labeler"`
	Status               string  `json:"status"` // candidate | confirmed
	NeedsHardeningReason *string `json:"needs_hardening_reason"`
}

// POST /api/labels — 追加标签。校验：alert 不存在→404；trace 缺 sliced→409；label/status 非法→422。
func postLabelHandler(w http.ResponseWriter, r *http.Request) {
	var req labelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	alert := runsread.GetAlert(serverCfg.RunsDir, req.RunID, req.Bughash)
	if alert == nil {
		writeJSONError(w, 404, "alert not found")
		return
	}
	trace, _ := alert["trace"].(map[string]any)
	if _, ok := trace["sliced"]; !ok {
		writeJSONError(w, 409, "trace has no persisted SlicedContext; re-run scan after gap-fix A")
		return
	}
	sliced, _ := trace["sliced"].(map[string]any)
	details, _ := alert["details"].([]map[string]any)
	primary := map[string]any{}
	if len(details) > 0 {
		primary = details[0]
	}
	alertID, _ := primary["alert_id"].(string)
	if alertID == "" {
		alertID, _ = sliced["alert_id"].(string)
	}
	vulnType, _ := primary["vulnerability_type"].(string)
	if vulnType == "" {
		vulnType, _ = sliced["vulnerability_type"].(string)
	}
	labeler := serverCfg.LabelerName
	if req.Labeler != nil && *req.Labeler != "" {
		labeler = *req.Labeler
	}
	var aiVerdict *string
	if v, ok := primary["verdict"].(string); ok {
		aiVerdict = &v
	}
	var aiConfidence *int
	if c, ok := primary["confidence"]; ok {
		if f, ok := c.(float64); ok {
			n := int(f)
			aiConfidence = &n
		}
	}
	rec, err := labels.AppendLabel(serverCfg.LabelsPath, labels.AppendLabelArgs{
		Sliced:               sliced,
		Label:                req.Label,
		Bughash:              req.Bughash,
		AlertID:              alertID,
		RunID:                req.RunID,
		VulnerabilityType:    vulnType,
		Labeler:              labeler,
		Note:                 req.Note,
		AIVerdict:            aiVerdict,
		AIConfidence:         aiConfidence,
		Status:               req.Status,
		NeedsHardeningReason: req.NeedsHardeningReason,
	})
	if err != nil {
		// ErrInvalidLabel / ErrInvalidStatus → 422（对齐 Python HTTPException 422）
		writeJSONError(w, 422, err.Error())
		return
	}
	writeJSON(w, rec)
}

// GET /api/labels?run_id=&bughash= — 有 bughash 返历史列表，无返 latest_by_bughash 映射。
func getLabelsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	runID := q.Get("run_id")
	bughash := q.Get("bughash")
	if bughash != "" {
		writeJSON(w, labels.HistoryFor(serverCfg.LabelsPath, runID, bughash))
		return
	}
	// 无 bughash → latest_by_bughash 映射。空映射也返 {} 非 null（对齐 Python dict）。
	writeJSON(w, labels.LatestByBughash(serverCfg.LabelsPath, runID))
}

// ---- codescan 浏览/拉取路由（移植 appsec/webapp/router.py:96-165）----
//
// 前端编排：codescan 拉取 bug 详情 → 填 sast_report → POST /api/scan adapter=codesafe。
// 所有路由失败 → 502 {"detail":"codescan 暂不可达：..."}（对齐 Python HTTPException 502）。

// atoiDefault 解析 query 参数为 int，空/非法 → def。
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// GET /api/codescan/projects?q=&page=&size= — 分页列项目。
func codescanProjectsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := codescanClient.DiscoverProjects(q.Get("q"), atoiDefault(q.Get("page"), 1), atoiDefault(q.Get("size"), 20))
	if err != nil {
		writeJSONError(w, 502, "codescan 暂不可达："+err.Error())
		return
	}
	writeJSON(w, page)
}

// GET /api/codescan/projects/{pj_name}/tasks — 项目下最新批次任务。
func codescanTasksHandler(w http.ResponseWriter, r *http.Request) {
	tasks, err := codescanClient.DiscoverTasks(r.PathValue("pj_name"))
	if err != nil {
		writeJSONError(w, 502, "codescan 暂不可达："+err.Error())
		return
	}
	writeJSON(w, tasks)
}

// GET /api/codescan/tasks/{pk_task}/bugs?page=&size= — 任务缺陷摘要列表（分页）。
func codescanBugsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := codescanClient.DiscoverBugs(r.PathValue("pk_task"), atoiDefault(q.Get("page"), 1), atoiDefault(q.Get("size"), 20))
	if err != nil {
		writeJSONError(w, 502, "codescan 暂不可达："+err.Error())
		return
	}
	writeJSON(w, page)
}

// GET /api/codescan/tasks/{pk_task}/bug-summary — 等级×类型分布聚合。
func codescanBugSummaryHandler(w http.ResponseWriter, r *http.Request) {
	summary, err := codescanClient.SummarizeBugs(r.PathValue("pk_task"), false)
	if err != nil {
		writeJSONError(w, 502, "codescan 暂不可达："+err.Error())
		return
	}
	writeJSON(w, summary)
}

// GET /api/codescan/tasks/{pk_task}/all-bugs?levels=&rule_codes= — 批量拉所有缺陷详情。
// 返回 {"bugs":[...]} 形状，前端可直接作为 sast_report POST 到 /api/scan（adapter=codesafe）。
// levels 为 1/3/5（多值），rule_codes 为规则码（可含 __UNKNOWN__ 哨兵）。
func codescanAllBugsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// 对齐 Python router.py:138-143：levels/rule_codes 是单值 query 参数，逗号分隔。
	// ?levels=1,3 → [1,3]；?levels= → nil（不过滤）；?rule_codes=A,__UNKNOWN__ → ["A","__UNKNOWN__"]。
	// 不用 q["levels"] 多值——Python 只取单值 split，前端传 ?levels=1,3 非 ?levels=1&levels=3。
	var levels []int
	if lv := q.Get("levels"); strings.TrimSpace(lv) != "" {
		for _, x := range strings.Split(lv, ",") {
			x = strings.TrimSpace(x)
			if x == "" {
				continue
			}
			if n, err := strconv.Atoi(x); err == nil {
				levels = append(levels, n)
			}
		}
	}
	var ruleCodes []string
	if rc := q.Get("rule_codes"); strings.TrimSpace(rc) != "" {
		for _, x := range strings.Split(rc, ",") {
			if x = strings.TrimSpace(x); x != "" {
				ruleCodes = append(ruleCodes, x)
			}
		}
	}
	bugs, err := codescanClient.FetchAll(r.PathValue("pk_task"), 0, levels, ruleCodes)
	if err != nil {
		writeJSONError(w, 502, "codescan 暂不可达："+err.Error())
		return
	}
	writeJSON(w, map[string]any{"bugs": bugs})
}

// codescanCloneRequest — 移植 router.CloneRequest（svnGitUri/branch/commitId）。
type codescanCloneRequest struct {
	SvnGitUri string `json:"svnGitUri"`
	Branch    string `json:"branch"`
	CommitId  string `json:"commitId"`
}

// POST /api/codescan/clone — git clone 项目源码到本地缓存目录，返回 repo_root。
func codescanCloneHandler(w http.ResponseWriter, r *http.Request) {
	var req codescanCloneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	if req.SvnGitUri == "" {
		writeJSONError(w, 400, "svnGitUri is required")
		return
	}
	repoRoot, err := codescanClient.CloneSource(req.SvnGitUri, req.Branch, req.CommitId)
	if err != nil {
		writeJSONError(w, 502, "codescan 暂不可达："+err.Error())
		return
	}
	writeJSON(w, map[string]any{"repo_root": repoRoot})
}
