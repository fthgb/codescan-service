package config

import (
	"os"
	"strconv"
	"strings"

	"appsecgo/internal/pandora"
)

// Config 镜像 Python appsec/config.py 的 committed 默认。OFF 档作前向兼容常量持有,不接线。
type Config struct {
	LLMProvider       string
	LLMBaseURL        string
	LLMModel          string
	LLMMaxTokens      int
	LLMThinkingBudget int
	LLMAPIKey         string // 只从 env APPSEC_LLM_API_KEY 读,绝不硬编
	// Hunyuan(腾讯 hy3)第二 provider：OpenAI 兼容 /chat/completions + Bearer + forceStream
	// (copilot.tencent.com 拒绝非流式)。APPSEC_LLM_PROVIDER=hunyuan 切到本组；key 只走 env。
	HunyuanBaseURL     string
	HunyuanAPIKey      string // 只从 env APPSEC_HUNYUAN_API_KEY 读,绝不硬编
	HunyuanModel       string
	HunyuanForceStream bool
	// HunyuanTemperature — hy3 采样温度(env APPSEC_HUNYUAN_TEMPERATURE)。
	// **未设置 = 不发该键**(零回归);设了则由 provider 在调用方未给温度时兜底。
	// 起因见 llm/openai.go 的 temperature 字段注释:工具路径与 agentic 循环都不传温度,
	// 走 hy3 时全程服务端默认温度采样,实测 relation-trade 三跑 92% 翻判。
	HunyuanTemperature              *float64
	RunMode                         string
	EnrichCallees                   bool
	AgenticExploreMode              string
	AgenticExploreMaxRounds         int
	AgenticExploreContextCharBudget int
	VerifyMode                      string
	VerdictContentCache             string
	VerdictCacheDBPath              string
	VerdictCacheTTLDays             int
	VerdictCacheLogicVersion        string // go-parity-v2,P5 跨语言隔离(非 Python v3)
	DBPath                          string
	CheckpointDir                   string
	RunsDir                         string
	ControlFlowPrefilter            string
	JudgeTemperature                float64
	// 增强期 P7: enrich/draft 开关（对齐 Python config.py committed 默认）。
	// ENRICH_MODE Python 默认 "agentic"，本期 gate 到 "deterministic"（agentic 推后续 task）。
	// DRAFT_MODE Python 无定义 → nodes/draft.py getattr 默认 "deterministic"。
	// EAGER_GUARD_CALLEES Python 默认 "on"。
	EnrichMode              string
	DraftMode               string
	EagerGuardCallees       string
	FuncDistillMode         string // 集群5 per-function 蒸馏缓存（默认 off，对齐 Python config.py.example:65）
	DecisiveFactRejudgeMode string // P7 守卫拒判后 LLM 重判（default-on，P0-a §4(f) 固化 2026-08-26：guard decisive-fact-unknown→rejudge drain Uncertain→Definitive）
	DynamicVerifyMode       string // P7 动态执行验证（默认 off，"ir" 开启 IR executor；junit deferral）
	AgenticXmlPromote       string // P7 post-agentic XML hop promote（潜伏 bug 已修，re-enable 默认 on）
	// TaintEngineMode：taint 引擎接入 gate（默认 "off"）。"on" → run.go 建 engineQuery
	// 走 taintbridge.ScanAndBuild，judge-explore loop 多 5 件 engine 工具 + EngineToolsSuffix。
	// 默认 off = 零回归（JudgeTools 仍 5 件，engine unavailable 兜底）。APPSEC_TAINT_ENGINE_MODE 覆盖。
	TaintEngineMode string

	// FaceLedgerMode：确定性面账 gate（spec 2026-08-23）。**默认 "on"** ——
	// 与其它 gate 相反，因为数据支持：75% 自验证率（同一 bughash+面曾被模型自己在别处
	// 判过 TP）、不改任何 verdict、只加报告独立分节、每份报告中位数 2 条。
	// 按铁律 C「漏报真漏洞比标错类型更严重」，默认关掉等于默认丢掉这些待复核项。
	// "off" 用于万一在未测过的仓上噪声大时兜底。
	FaceLedgerMode string
	// workbench review 路由：labels JSONL 路径 + 默认 labeler（对齐 Python config.py:131-132）
	LabelsPath  string
	LabelerName string
	// CweregPath 是 cwe_registry.json 路径（runPipeline 用）。默认相对 cwd；
	// 可经 APPSEC_CWEREG_PATH env 覆盖（绝对路径或相对 cwd）。
	CweregPath string
	// StratregPath 是 ③-e strategy registry 目录（评估视角，filed-CWE 错类补正）。
	// 默认 data/strategies；可经 APPSEC_STRATREG_PATH env 覆盖。fail-open：目录缺
	// → 子系统全关（含 general）→ Select nil gate → inert，判决仍走 cwe_registry。
	StratregPath string
	// codescan REST client（移植 appsec/codescan；APPSEC_CODESCAN_* env）。
	// 对齐 Python config.py.example:143-150 的 8 个 CODESCAN_* 字段。
	CodescanBaseURL           string
	CodescanAuthToken         string // 只从 env 读,绝不硬编（"Basic..."或"Bearer..."）
	CodescanAuthCookie        string
	CodescanInsecureSSL       bool
	CodescanTimeoutSec        int // 秒（main.go 转 time.Duration）
	CodescanRepoCacheDir      string
	CodescanDetailCacheTTLSec int // 秒
	CodescanFetchWorkers      int
	// RepoCacheTTLHours 控制克隆仓库的保留时长（小时）。0=不清理；48=K8s推荐。
	// 每次 CloneSource 前清理超过此时长的仓库目录，防止 codescan_repos/ 无限增长。
	RepoCacheTTLHours         int
	// Git 超级管理员账密（仅用于 CloneSource 拉私有仓库；密钥只走 env，绝不硬编）。
	// 配齐两者且 svnGitUri 为 http/https 时注入 URL userinfo 拉取；留空则用裸 URI。
	CodescanGitAdminUser     string
	CodescanGitAdminPassword string
	// AllowedLanguages: codescan 过滤白名单(sink 文件扩展名小写,如 "java")。只把白名单内
	// 语言的 alert 送 judge fan-out;其它(.vue/.html/.js/.xml 等)在 runPipeline 早期丢弃
	// 并计数到 summary.json.skipped_by_language,不烧 token。未设默认 ["java"];"*" 关过滤。
	AllowedLanguages []string
	// MinSeverity: 严重度过滤阈值（critical/high/medium/low/info）。低于此级别的
	// 告警在 runPipeline 早期丢弃，不进 LLM judge fan-out（省 token）。空串 = no-op
	// （不过滤，全审）。对齐 APPSEC_MIN_SEVERITY env。CodeSafe adapter 映射：
	// bugLevel 1→high / 3→medium / 5→low；未映射的 severity="" → fail-open 保留。
	MinSeverity string
	// CMDB 推送端（设计文档 §七；APPSEC_CMDB_* env，默认空=关闭推送）。
	// CmdbPushURL 与 CmdbPushKey 同时非空才视为开启（双保险，对齐 §五 AppsecManager.Enabled）。
	CmdbPushURL     string // APPSEC_CMDB_PUSH_URL sec-service gateway /sec/v1/codecheck/appsec/push 完整 URL
	CmdbPushKey     string // APPSEC_CMDB_KEY = sec-service CsCallBackKey
	CmdbGate        string // APPSEC_CMDB_GATE 默认 "on"；"off" 关人工闸门（全推，验证用）
	ExternalBaseURL string // APPSEC_EXTERNAL_BASE_URL appsecgo 报告页外部基址；空→reportUrl 空，sec-service 兜底
	// ApiToken 鉴权 middleware（APPSEC_API_TOKEN，空=直通，零摩擦本地）。设计文档 §七-1。
	ApiToken string
	// SCA（软件成分分析）配置。ScaRunsDir 落盘目录（仿 RunsDir）；
	// ScaPolicyPath 策略文件路径（仿 CweregPath，cwd 相对 + env 覆盖）。
	ScaRunsDir    string
	ScaPolicyPath string
}

func Load() Config {
	c := Config{
		LLMProvider:                     "anthropic",
		LLMBaseURL:                      "http://aigw-test.cathay-ins.com.cn/prod/anthropic",
		LLMModel:                        "qwen3.7-plus",
		LLMMaxTokens:                    8192,
		LLMThinkingBudget:               2048,
		HunyuanBaseURL:                  "https://copilot.tencent.com/v2",
		HunyuanModel:                    "hy3",
		HunyuanForceStream:              true, // copilot.tencent 拒绝非流式
		RunMode:                         "experiment",
		EnrichCallees:                   true,
		AgenticExploreMode:              "on",
		AgenticExploreMaxRounds:         10,
		AgenticExploreContextCharBudget: 80000,
		VerifyMode:                      "deterministic",
		VerdictContentCache:             "on",
		VerdictCacheDBPath:              "verdict_cache.db",
		VerdictCacheTTLDays:             30,
		VerdictCacheLogicVersion:        "go-parity-v2",
		DBPath:                          "bughash.db",
		CheckpointDir:                   "./checkpoints",
		RunsDir:                         "./runs",
		ControlFlowPrefilter:            "annotate",
		JudgeTemperature:                1.0,
		EnrichMode:                      "deterministic",
		DraftMode:                       "deterministic",
		EagerGuardCallees:               "on",
		FuncDistillMode:                 "off",
		DecisiveFactRejudgeMode:         "on",  // P0-a §4(f) 固化 2026-08-26：default-on rejudge drain（guard decisive-fact-unknown→RefreshForwardReachable）
		DynamicVerifyMode:               "off",
		AgenticXmlPromote:               "on",
		TaintEngineMode:                 "off",
		FaceLedgerMode:                  "on",
		LabelsPath:                      "./data/labels.jsonl",
		LabelerName:                     "unknown",
		// codescan 默认值（对齐 Python config.py.example:143-150）。
		CodescanBaseURL:           "https://codescan.cathay-ins.com.cn",
		CodescanInsecureSSL:       true,
		CodescanTimeoutSec:        30,
		CodescanRepoCacheDir:      "./codescan_repos",
		CodescanDetailCacheTTLSec: 600,
		CodescanFetchWorkers:      8,
		CweregPath:                "cwe_registry.json",
		StratregPath:              "data/strategies",
		AllowedLanguages:          []string{"java"},
		CmdbGate:                  "on",
	}
	// Pandora config fill (when .env absent; prod/CI mode).
	// Non-empty Pandora values override defaults. Env vars below still override
	// Pandora values if set (shell env > Pandora > defaults).
	if pandoraCfg != nil {
		if pandoraCfg.LLM.Provider != "" { c.LLMProvider = pandoraCfg.LLM.Provider }
		if pandoraCfg.LLM.APIKey != "" { c.LLMAPIKey = pandoraCfg.LLM.APIKey }
		if pandoraCfg.LLM.BaseURL != "" { c.LLMBaseURL = pandoraCfg.LLM.BaseURL }
		if pandoraCfg.LLM.Model != "" { c.LLMModel = pandoraCfg.LLM.Model }
		if pandoraCfg.LLM.OpenAIBaseURL != "" { c.HunyuanBaseURL = pandoraCfg.LLM.OpenAIBaseURL }
		if pandoraCfg.LLM.OpenAIAPIKey != "" { c.HunyuanAPIKey = pandoraCfg.LLM.OpenAIAPIKey }
		if pandoraCfg.LLM.OpenAIModel != "" { c.HunyuanModel = pandoraCfg.LLM.OpenAIModel }
		if s := pandoraCfg.LLM.OpenAIForceStreamStr; s != "" {
			if b, err := strconv.ParseBool(s); err == nil { c.HunyuanForceStream = b }
		}
		if s := pandoraCfg.LLM.OpenAITemperatureStr; s != "" {
			if f, err := strconv.ParseFloat(s, 64); err == nil { c.HunyuanTemperature = &f }
		}
		if pandoraCfg.Codescan.BaseURL != "" { c.CodescanBaseURL = pandoraCfg.Codescan.BaseURL }
		if pandoraCfg.Codescan.AuthToken != "" { c.CodescanAuthToken = pandoraCfg.Codescan.AuthToken }
		if pandoraCfg.Codescan.AuthCookie != "" { c.CodescanAuthCookie = pandoraCfg.Codescan.AuthCookie }
		if pandoraCfg.Codescan.GitAdminUser != "" { c.CodescanGitAdminUser = pandoraCfg.Codescan.GitAdminUser }
		if pandoraCfg.Codescan.GitAdminPassword != "" { c.CodescanGitAdminPassword = pandoraCfg.Codescan.GitAdminPassword }
		if pandoraCfg.CMDB.PushURL != "" { c.CmdbPushURL = pandoraCfg.CMDB.PushURL }
		if pandoraCfg.CMDB.Key != "" { c.CmdbPushKey = pandoraCfg.CMDB.Key }
		if pandoraCfg.CMDB.Gate != "" { c.CmdbGate = pandoraCfg.CMDB.Gate }
		if pandoraCfg.CMDB.ExternalBaseURL != "" { c.ExternalBaseURL = pandoraCfg.CMDB.ExternalBaseURL }
		if pandoraCfg.CMDB.LabelerName != "" { c.LabelerName = pandoraCfg.CMDB.LabelerName }
		if pandoraCfg.CMDB.APIToken != "" { c.ApiToken = pandoraCfg.CMDB.APIToken }
		if pandoraCfg.Feature.TaintEngineMode != "" { c.TaintEngineMode = pandoraCfg.Feature.TaintEngineMode }
		if pandoraCfg.Feature.VerdictContentCache != "" { c.VerdictContentCache = pandoraCfg.Feature.VerdictContentCache }
		if pandoraCfg.Feature.MinSeverity != "" { c.MinSeverity = pandoraCfg.Feature.MinSeverity }
	}

	// env 覆盖(密钥只走 env)
	if v := os.Getenv("APPSEC_LLM_API_KEY"); v != "" {
		c.LLMAPIKey = v
	}
	if v := os.Getenv("APPSEC_LLM_BASE_URL"); v != "" {
		c.LLMBaseURL = v
	}
	if v := os.Getenv("APPSEC_LLM_MODEL"); v != "" {
		c.LLMModel = v
	}
	// provider 选择器(默认 anthropic=qwen;"hunyuan"/"openai" 切到 OpenAI 兼容 provider)
	if v := os.Getenv("APPSEC_LLM_PROVIDER"); v != "" {
		c.LLMProvider = v
	}
	// Hunyuan 第二 provider env 覆盖(密钥只走 env)
	if v := os.Getenv("APPSEC_HUNYUAN_BASE_URL"); v != "" {
		c.HunyuanBaseURL = v
	}
	if v := os.Getenv("APPSEC_HUNYUAN_API_KEY"); v != "" {
		c.HunyuanAPIKey = v
	}
	if v := os.Getenv("APPSEC_HUNYUAN_MODEL"); v != "" {
		c.HunyuanModel = v
	}
	if v := os.Getenv("APPSEC_HUNYUAN_FORCE_STREAM"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.HunyuanForceStream = b
		}
	}
	if v := os.Getenv("APPSEC_HUNYUAN_TEMPERATURE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			c.HunyuanTemperature = &f
		}
	}
	if v := os.Getenv("APPSEC_RUN_MODE"); v != "" {
		c.RunMode = v
	}
	if v := os.Getenv("APPSEC_DB_PATH"); v != "" {
		c.DBPath = v
	}
	// verdict_cache: APPSEC_VERDICT_CONTENT_CACHE=off 关缓存（store=nil → judge.go 旁路，零回归）；
	// APPSEC_VERDICT_CACHE_DB_PATH 指向临时 db（调试/复跑 spin 时不污染常驻库）。对齐 Python VERDICT_CONTENT_CACHE。
	if v := os.Getenv("APPSEC_VERDICT_CONTENT_CACHE"); v != "" {
		c.VerdictContentCache = v
	}
	if v := os.Getenv("APPSEC_VERDICT_CACHE_DB_PATH"); v != "" {
		c.VerdictCacheDBPath = v
	}
	if v := os.Getenv("APPSEC_CHECKPOINT_DIR"); v != "" {
		c.CheckpointDir = v
	}
	if v := os.Getenv("APPSEC_RUNS_DIR"); v != "" {
		c.RunsDir = v
	}
	if v := os.Getenv("APPSEC_ENRICH_MODE"); v != "" {
		c.EnrichMode = v
	}
	if v := os.Getenv("APPSEC_DRAFT_MODE"); v != "" {
		c.DraftMode = v
	}
	if v := os.Getenv("APPSEC_EAGER_GUARD_CALLEES"); v != "" {
		c.EagerGuardCallees = v
	}
	if v := os.Getenv("APPSEC_FUNC_DISTILL_MODE"); v != "" {
		c.FuncDistillMode = v
	}
	if v := os.Getenv("APPSEC_FACE_LEDGER"); v != "" {
		c.FaceLedgerMode = v
	}
	if v := os.Getenv("APPSEC_DECISIVE_FACT_REJUDGE_MODE"); v != "" {
		c.DecisiveFactRejudgeMode = v
	}
	if v := os.Getenv("APPSEC_DYNAMIC_VERIFY_MODE"); v != "" {
		c.DynamicVerifyMode = v
	}
	if v := os.Getenv("APPSEC_AGENTIC_XML_PROMOTE"); v != "" {
		c.AgenticXmlPromote = v
	}
	if v := os.Getenv("APPSEC_TAINT_ENGINE_MODE"); v != "" {
		c.TaintEngineMode = v
	}
	if v := os.Getenv("APPSEC_LABELS_PATH"); v != "" {
		c.LabelsPath = v
	}
	if v := os.Getenv("APPSEC_LABELER_NAME"); v != "" {
		c.LabelerName = v
	}
	// codescan env 覆盖（密钥只走 env；对齐 Python CODESCAN_*）
	if v := os.Getenv("APPSEC_CODESCAN_BASE_URL"); v != "" {
		c.CodescanBaseURL = v
	}
	if v := os.Getenv("APPSEC_CODESCAN_AUTH_TOKEN"); v != "" {
		c.CodescanAuthToken = v
	}
	if v := os.Getenv("APPSEC_CODESCAN_AUTH_COOKIE"); v != "" {
		c.CodescanAuthCookie = v
	}
	if v := os.Getenv("APPSEC_CODESCAN_INSECURE_SSL"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.CodescanInsecureSSL = b
		}
	}
	if v := os.Getenv("APPSEC_CODESCAN_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.CodescanTimeoutSec = n
		}
	}
	if v := os.Getenv("APPSEC_CODESCAN_REPO_CACHE_DIR"); v != "" {
		c.CodescanRepoCacheDir = v
	}
	if v := os.Getenv("APPSEC_CODESCAN_DETAIL_CACHE_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.CodescanDetailCacheTTLSec = n
		}
	}
	if v := os.Getenv("APPSEC_REPO_CACHE_TTL_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.RepoCacheTTLHours = n
		}
	}
	if v := os.Getenv("APPSEC_CODESCAN_FETCH_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.CodescanFetchWorkers = n
		}
	}
	// Git 超级管理员账密（密钥只走 env；对齐 CODESCAN_* 命名）
	if v := os.Getenv("APPSEC_CODESCAN_GIT_ADMIN_USER"); v != "" {
		c.CodescanGitAdminUser = v
	}
	if v := os.Getenv("APPSEC_CODESCAN_GIT_ADMIN_PASSWORD"); v != "" {
		c.CodescanGitAdminPassword = v
	}
	if v := os.Getenv("APPSEC_CWEREG_PATH"); v != "" {
		c.CweregPath = v
	}
	if v := os.Getenv("APPSEC_STRATREG_PATH"); v != "" {
		c.StratregPath = v
	}
	// AllowedLanguages: 逗号分隔;"*" 关过滤(返 ["*"]→helper no-op);空串不覆盖默认 ["java"]。
	if v := os.Getenv("APPSEC_ALLOWED_LANGUAGES"); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		if len(out) > 0 {
			c.AllowedLanguages = out
		}
	}
	// MinSeverity: 空=不过滤(全审);设为 medium/high/critical → 低于阈值的告警丢弃。
	if v := os.Getenv("APPSEC_MIN_SEVERITY"); v != "" {
		c.MinSeverity = v
	}
	// CMDB 推送端 env（密钥只走 env）
	if v := os.Getenv("APPSEC_CMDB_PUSH_URL"); v != "" {
		c.CmdbPushURL = v
	}
	if v := os.Getenv("APPSEC_CMDB_KEY"); v != "" {
		c.CmdbPushKey = v
	}
	if v := os.Getenv("APPSEC_CMDB_GATE"); v != "" {
		c.CmdbGate = v
	}
	if v := os.Getenv("APPSEC_EXTERNAL_BASE_URL"); v != "" {
		c.ExternalBaseURL = v
	}
	if v := os.Getenv("APPSEC_API_TOKEN"); v != "" {
		c.ApiToken = v
	}
	// SCA 配置（缺省值与 runs/cwereg 同模式：cwd 相对）
	c.ScaRunsDir = "./sca_runs"
	c.ScaPolicyPath = "sca_policy.json"
	if v := os.Getenv("APPSEC_SCA_RUNS_DIR"); v != "" {
		c.ScaRunsDir = v
	}
	if v := os.Getenv("APPSEC_SCA_POLICY_PATH"); v != "" {
		c.ScaPolicyPath = v
	}
	return c
}

// pandoraCfg holds Pandora config when .env is absent (prod/CI mode).
// nil = .env exists (home/dev mode) or Pandora load failed.
var pandoraCfg *pandora.Config

// PandoraConfig returns the Pandora config loaded by init().
// nil in .env mode (home/dev) or if Pandora load failed.
// Used by cmd/server/main.go to init OSS + DB without needing APPSEC_PANDORA_CONFIG env var.
func PandoraConfig() *pandora.Config {
	return pandoraCfg
}

// init loads config before the first config.Load() call.
// If .env exists → home/dev mode: load env vars from .env (explicit env wins).
// If .env absent → prod/CI mode: try Pandora config, store in pandoraCfg.
// This allows working from home (no Pandora network access) with .env,
// and in prod/CI without .env using Pandora config center.
func init() {
	if _, err := os.Stat(".env"); err == nil {
		// .env exists → home/dev mode
		_ = LoadDotenv(".env")
	} else {
		// No .env → try Pandora config (prod/CI mode)
		path := os.Getenv("APPSEC_PANDORA_CONFIG")
		if path == "" {
			path = "config/config.yaml"
		}
		if cfg, err := pandora.Load(path); err == nil {
			pandoraCfg = cfg
		}
		// Pandora load failure is silent — config.Load() uses defaults,
		// and shell env vars (if any) still override.
	}
}
