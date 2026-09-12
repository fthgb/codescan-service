package contract

// ExploitPath is defined in sast.go (shared by SASTResult and JudgeResult); its shape
// mirrors appsec/state.py:ExploitPath — data_flow defaults to [] (non-nil empty for
// parity), path_broken_at is Optional[str] -> *string (nil = null).

// JudgeResult mirrors appsec/state.py:JudgeResult (lines 153-180). Optional scalars ->
// pointers (nil = Python null); Optional lists -> plain slices (nil = Python null,
// []T{} = Python []). Required scalars are plain. control_flow_mutex is bool (default false).
// attack_request/verification are P3 fields, kept for shape parity (nil in P2).
type JudgeResult struct {
	AlertID                  string           `json:"alert_id"`
	Bughash                  string           `json:"bughash"`
	Verdict                  string           `json:"verdict"`
	// Disposition — 判官对该 alert 的 disposition。*string 无 omitempty:nil = 未判定
	// (契约缺失:disposition/verdict 键全缺且 A 类回收无命中 ⇒ build.go 不设指针,序列化
	// "disposition": null),&"uncertain" = 判过但定不了(真不确定)。两者 verdict 都折
	// uncertain(VerdictOf fallback),Disposition 字段仅供归因区分
	// (spec 2026-09-01-f1 §3.2;Face:100-102 同款"空=未判定≠uncertain"语义)。
	Disposition              *string          `json:"disposition"`
	VulnerabilityType        *string          `json:"vulnerability_type"`
	CweID                    string           `json:"cwe_id"`
	ActualVulnerabilityType  *string          `json:"actual_vulnerability_type"`
	ActualVulnerabilityTypes []string         `json:"actual_vulnerability_types"`
	TypeMismatchTypes        []string         `json:"type_mismatch_types"`
	BuriedTypes              []string         `json:"buried_types"`
	Confidence               int              `json:"confidence"`
	ExploitPath              ExploitPath      `json:"exploit_path"`
	Reasoning                string           `json:"reasoning"`
	SanitizationFound        *string          `json:"sanitization_found"`
	SuggestedFix             *string          `json:"suggested_fix"`
	Severity                 *string          `json:"severity"`
	SeverityRationale        *string          `json:"severity_rationale"`
	ModelUsed                string           `json:"model_used"`
	ControlFlowMutex         bool             `json:"control_flow_mutex"`
	ExploitPayload           *string          `json:"exploit_payload"`
	AttackRequest            *string          `json:"attack_request"`
	DecisiveCheck            map[string]any   `json:"decisive_check"`
	DecisiveChecks           []map[string]any `json:"decisive_checks"`
	Verification             map[string]any   `json:"verification"`
	// DevSummary / DesignNote — 面向**不懂安全的后端开发**的两个字段(B1,2026-08-22)。
	// Reasoning / SeverityRationale 是给分析师的,保持原有语域;这两个是给开发的:
	//   DevSummary 一句话说清「谁能通过哪个接口做成什么事」(业务语言,术语须括号解释);
	//   DesignNote 先承认原设计里合理的部分、再指出缺的那一步(纯指控式表述会让开发先辩解)。
	// 可读性主因不在渲染层而在这里 —— 契约此前无任何面向开发者的字段。
	DevSummary  *string `json:"dev_summary"`
	DesignNote  *string `json:"design_note"`
	FailReason  *string `json:"fail_reason"`
	MissingInfo *string `json:"missing_info"`
	// Faces —— 确定性面账(spec 2026-08-23)。omitempty:门 off 时 nil → key 缺席 →
	// summary.json 逐字节不变(零回归门)。判决链只读不写,VerdictOf 等硬约束锚点不触碰。
	Faces []Face `json:"faces,omitempty"`
	// ExclusionReason 非空 ⇒ 该告警被**硬规则排除、从未送进 judge**,其 Verdict 是占位不是判定
	// (`pipeline.mapsToJudgeResults` 硬赋 "uncertain",见该函数头注释)。值形如
	// "HE-002 test_file: test code does not run in production"(`hardexclusion.ExclusionReason`)。
	//
	// 为什么需要这个字段(F2,spec 2026-09-01-f2-hard-excluded-verdict-attribution-design):
	// 硬排除条目与「判官真的不确定」在 details 里**形状完全相同**(verdict=uncertain /
	// fail_reason=null / confidence=0)⇒ 前端只能落到「LLM 不确定」标签 = 把工程排除说成判官犹豫;
	// `runsread` 的 unlabelled 亦把它们算作待人工标注项。实测 45/464 条受影响。
	// 消费方据此区分:前端标签(RunDetail.tsx)与 unlabelled 计数(runsread.go)。
	//
	// omitempty + 值语义三态:判过的告警无此字段 ⇒ 历史 summary.json 反序列化后为空串 ⇒
	// 行为与今天一致(向后兼容,`TestJudgeResult_ExclusionReason_BackCompat` 锁)。
	ExclusionReason string `json:"exclusion_reason,omitempty"`
}

// —— 确定性面账（spec 2026-08-23-deterministic-face-ledger-design）——————————
//
// 一条 alert 上常同时存在多个**漏洞面**(CWE face)，各自独立可证或不可证；而 verdict 是
// 标量，于是**最弱的一面决定整条**。实测：多面 alert(actual_vulnerability_types>1)
// uncertain 率 29%，单面 19%(1.5×)。
//
// 面账**不判决**：`authz_coverage` 三态全空只证明「该端点无鉴权守卫」这一个事实，
// 不等于漏洞(登录接口/健康检查本就该公开)。它的职责是保证**面不被静默丢掉** ——
// 实证 e6987920 同输入两跑对 upload 分析完全一致，差异只是模型是否碰巧枚举出
// CWE-862 面，而该面事实已由 ComputeAuthzCoverage 确定性算好并注入(铁律 C：
// 漏报真漏洞比标错类型更严重)。

// Face 来源三档，按真值性排序(GR-8)。
const (
	// FaceDeterministic —— 由确定性预计算事实支撑，**不依赖 LLM 是否枚举**。
	// 这一档是治 recall 的关键：模型没想到的面，事实自己会把它顶出来。
	FaceDeterministic = "deterministic"
	// FaceLLMAnchored —— LLM 列进 actual_vulnerability_types 且有 decisive_checks 锚到 file:line。
	FaceLLMAnchored = "llm_anchored"
	// FaceLLMListed —— LLM 列了但无锚定证据。只记录，不升级(GR-8 无锚点不作判据)。
	FaceLLMListed = "llm_listed"
)

// Face 标记(Flags)：面账发现的**待办**，不是结论。
const (
	// FlagUnjudgedDeterministic —— 有确定性事实支撑的面，本次判决压根没处理它。
	FlagUnjudgedDeterministic = "unjudged_deterministic_face"
	// FlagRegressedFromHistory —— **这条 alert 自己**在历史 run 里被判过该面 true_positive，
	// 本跑却没判。比兄弟不一致更直接：同一份代码、同一个 bughash，判决自己退了一步。
	// 治的是「同 run 对照在模型这一跑全判错时一起哑火」（实证 ceshi/SupplierController）。
	FlagRegressedFromHistory = "regressed_from_history"
	// FlagInconsistentWithinRun —— 同一次 run 内另有 alert 具备相同事实形态且被判 TP，
	// 本条具备同样事实却无该面。把「模型这次没想到」从主观猜测变成**可核实的矛盾**。
	FlagInconsistentWithinRun = "inconsistent_within_run"
)

// Face —— 一条 alert 上的一个漏洞面。
//
// Disposition 为空 = **未判定**(不是 uncertain)。二者语义不同：uncertain 是判过了但
// 定不了，空是这个面根本没进入本次判决 —— 后者才是 e6987920 那类漏报的形态。
type Face struct {
	Type        string   `json:"type"`                   // 归一后的类型 slug(走 cwereg.NormalizeVulnType)
	Source      string   `json:"source"`                 // FaceDeterministic | FaceLLMAnchored | FaceLLMListed
	Disposition string   `json:"disposition,omitempty"`  // 该面的判定；"" = 未判定
	Facts       []string `json:"facts,omitempty"`        // 支撑该面的确定性事实(人类可读)
	Anchors     []string `json:"anchors,omitempty"`      // file:line 证据锚点
	MissingInfo string   `json:"missing_info,omitempty"` // 该面缺什么才能定论
	Flags       []string `json:"flags,omitempty"`        // FlagUnjudgedDeterministic 等
	// CounterpartBughash —— FlagInconsistentWithinRun 的对照 alert(可核实,非断言)。
	CounterpartBughash string `json:"counterpart_bughash,omitempty"`
}
