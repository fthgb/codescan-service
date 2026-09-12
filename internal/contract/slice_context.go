package contract

// Slice-context contracts — the SlicedContext fed to the LLM judge and the
// HopSlice hops it carries. Mirror appsec/state.py (ClassContext / HopSlice /
// SlicedContext / HopDraft) field-for-field so JSON dumped from the Python
// reference round-trips into these structs unchanged (parity fixtures).
//
// Optional fields use pointers so a JSON null distinguishes "absent" from the
// zero value (e.g. TaintLine nil vs 0). list[dict] -> []map[string]any;
// dict[str,str] -> map[string]string, matching Python model_dump.

// ClassContext mirrors appsec/state.py:ClassContext. parent_class is carried
// for shape parity (the current extractor leaves it nil); class_level_path is
// the first class-level @RequestMapping annotation, or nil when absent.
type ClassContext struct {
	ClassName        string   `json:"class_name"`
	ClassAnnotations []string `json:"class_annotations"`
	ParentClass      *string  `json:"parent_class"`
	ClassLevelPath   *string  `json:"class_level_path"`
}

// HopSlice is one taint hop's slice: the method body (or raw snippet) + its
// 1-based line range + the taint trace line + an expansion provenance tag.
type HopSlice struct {
	HopIndex      int     `json:"hop_index"`
	FilePath      string  `json:"file_path"`
	FunctionName  string  `json:"function_name"`
	FunctionBody  string  `json:"function_body"`
	TaintVariable string  `json:"taint_variable"`
	LineRange     [2]int  `json:"line_range"`
	TaintLine     *int    `json:"taint_line"`
	ExpandedFrom  *string `json:"expanded_from"`
}

// HopDraft is a per-hop deterministic analysis draft (DRAFT_MODE) — a clue, not
// a verdict. Carried for forward-compat; the slice_alert base leaves drafts
// empty. evidence_facts relation is an English token (assign|call|return|
// concat|bypass_guard) per 铁律 E.
type HopDraft struct {
	HopIndex       int              `json:"hop_index"`
	FunctionName   string           `json:"function_name"`
	Role           string           `json:"role"`
	VulnCandidates []string         `json:"vuln_candidates"`
	Note           string           `json:"note"`
	EvidenceFacts  []map[string]any `json:"evidence_facts"`
}

// ForwardReachable 结构化可达性契约（§8.1）。镜像 raptor
// reachability.py:CalleesResult{definitive, uncertain, has_method_dispatch}
// + ClosureResult.truncated + context_map_callgraph.py:forward_reachable。
// 替代 enrichment_note 里塌成一坨的截断/未解析信号，让 judge 按字段判
// don't-demote-on-unknown（reachability.py:3638-3642），不靠 LLM 读散文。
// nil/零值 ⇒ 不渲染（指针 + omitempty），parity prompt 字节不破。
type CalleeRef struct {
	Name     string `json:"name,omitempty"`
	FilePath string `json:"file_path,omitempty"`
}

type ForwardReachable struct {
	Definitive        []CalleeRef `json:"definitive,omitempty"`          // 已解析、已入 slice 的 callee（确定可达前沿）
	Uncertain         []CalleeRef `json:"uncertain,omitempty"`           // referenced 但未入 slice 的 in-repo callee（不确定一跳前沿）
	HasMethodDispatch bool        `json:"has_method_dispatch,omitempty"` // 源含 self.foo()/未解析名分派链，callee 集不完整（待检测，默认 false）
	Truncated         bool        `json:"truncated,omitempty"`           // BFS/cap 命中预算上限（enrich cap-truncation），闭包可能不完整
}

// AuthzCoverage 结构化鉴权覆盖事实（spec 2026-08-12-missing-auth-fact-solidification §6.1）。
// 镜像 ForwardReachable 固化形：只装确定性结论；nil → key 缺席 → parity prompt 字节不破。
//
// 只固化确定性结论（§4）：MethodGuard/ClassGuard 永远 true/false（AST 本地确定性，
// 注解直接装饰端点，无覆盖歧义）；GlobalInterceptor 只写 "none"（零命中确定性），
// 命中/覆盖不明 → 留空 ""（覆盖交 LLM），绝不写 "found"/"unknown"。
// prompt 渲染读 Go struct（非 JSON）：omitempty 吞空字符串，但 live 路径直读
// struct 不 round-trip JSON，故 GlobalInterceptor==""（已发现待判定）语义不丢（§6.4）。
type AuthzCoverage struct {
	MethodGuard       bool     `json:"method_guard,omitempty"`       // 端点方法 @PreAuthorize/@Secured/@RolesAllowed/@PermitAll（AST 确定性，直接覆盖本端点）
	ClassGuard        bool     `json:"class_guard,omitempty"`        // 端点类同上（类级覆盖本类所有方法）
	GlobalInterceptor string   `json:"global_interceptor,omitempty"` // "none" only；命中→留空（覆盖交 LLM）
	Evidence          []string `json:"evidence,omitempty"`           // none: pattern 集+扫描路径；命中: match locations
}

// UploadDisposition —— CWE-434 三分支的确定性事实固化（2026-08-23 P1-1）。
//
// 镜像 AuthzCoverage 的固化形：只装确定性结论；nil → key 缺席 → parity prompt 字节不破。
//
// # 与 AuthzCoverage 的关键差异（不要照抄它的三态口径）
//
// authz 的**否定**是确定的（全仓 grep 零命中 = 真没有守卫）；upload 的否定**大多不确定**
// —— 切片可能被截断，「切片里没看到落盘」不等于「不落盘」。故本结构分两类字段：
//
//   - FileWriteSink：全仓 grep 得出，"none" 是**确定性否定**（全仓真的一处落盘 API 都没有
//     → b1 webshell 与 b3 穿越写两支同时不可达）。这条需要语料契约（internal/factguard）。
//   - 其余字段只写**确定性肯定**（"yes"），拿不准一律留空。留空 ≠ 否定 ——
//     渲染层必须写成「已确认存在 X」而非「未发现 X」，后者正是会制造假否定的措辞。
//
// # 为什么要有 TaintedPathSegment
//
// 2026-08-23 人工核实 ceshi `SystemConfigService.uploadLocal` 发现：文件名确实被
// `FileUtils.getFileName` 中和了，但**目录**来自 `request.getParameter("biz")` 且零净化，
// `new File(ctxPath + sep + bizPath).mkdirs()` 可穿越建目录。报告只查了文件名就宣布
// 「b3 不可达」，把真漏洞说成了另一回事。**路径的每一段都要查，不是只查文件名。**
type UploadDisposition struct {
	FileWriteSink       string `json:"file_write_sink,omitempty"`      // "none" only（全仓零落盘 API）；命中 → 留空
	FilenameNeutralized string `json:"filename_neutralized,omitempty"` // "yes" only（确认中和）
	// FilenameNeutralizedGrain 是上面那个结论的**归因粒度**（"变量级"/"切片级"/"仓级"）。
	//
	// 它存在的理由:该结论是**开脱性**的(下游据此宣布「经文件名的 b3 不成立」),
	// 而切片级取证只能说「切片文本里出现过这个形态」,说不了「它作用于本条污点变量」——
	// 活体反例是上传方法里生成个链路 id 就含 UUID.randomUUID。三仓实测今天判 yes 的
	// 两条**都是**切片级。粒度不落盘,渲染层就无从如实标注强度(见 factspec.Grain)。
	FilenameNeutralizedGrain string `json:"filename_neutralized_grain,omitempty"`
	TaintedPathSegment       string `json:"tainted_path_segment,omitempty"` // "yes" only（切片内确认请求参数进了路径构造）
	// —— b2 存储型 XSS 的回显上下文（2026-08-23 补）——
	//
	// 模型反复写「下载回显的响应头在切片中不可见」→ 判 uncertain。那个事实**在仓里，
	// 只是不在这条告警的切片里**，全仓扫就能答。三仓实测：attachment 都设了，
	// 但 nosniff **都没有**（0/0/0），且都有多处往响应写字节。
	NosniffHeader     string   `json:"nosniff_header,omitempty"`      // "none" only（全仓零 nosniff）
	InlineCapableSite string   `json:"inline_capable_site,omitempty"` // "yes" only（有往响应写字节却未设 attachment 的位置）
	Evidence          []string `json:"evidence,omitempty"`
}

// SlicedContext is the sliced code context fed to the judge. Mirrors
// appsec/state.py:SlicedContext. decisive_facts key/value are English tokens.
type SlicedContext struct {
	AlertID                string             `json:"alert_id"`
	Bughash                string             `json:"bughash"`
	VulnerabilityType      string             `json:"vulnerability_type"`
	CweID                  string             `json:"cwe_id"`
	EntryPointSignature    string             `json:"entry_point_signature"`
	SourceClassContext     *ClassContext      `json:"source_class_context"`
	SinkClassContext       *ClassContext      `json:"sink_class_context"`
	Hops                   []HopSlice         `json:"hops"`
	SkipReasons            []map[string]any   `json:"skip_reasons"`
	SanitizationCandidates []string           `json:"sanitization_candidates"`
	FrameworkAnnotations   []string           `json:"framework_annotations"`
	TokenCount             int                `json:"token_count"`
	Degraded               bool               `json:"degraded"`
	MaxConfidence          int                `json:"max_confidence"`
	EnrichmentNote         *string            `json:"enrichment_note"`
	ForwardReachable       *ForwardReachable  `json:"forward_reachable,omitempty"`  // §8.1 结构化截断契约（nil → key 缺席，parity 守卫）
	AuthzCoverage          *AuthzCoverage     `json:"authz_coverage,omitempty"`     // missing-auth 事实固化（§6.1；nil → key 缺席，parity 守卫）
	UploadDisposition      *UploadDisposition `json:"upload_disposition,omitempty"` // CWE-434 三分支事实固化（P1-1；nil → key 缺席）
	ControlFlowMutex       bool               `json:"control_flow_mutex"`
	Drafts                 []HopDraft         `json:"drafts"`
	NarrowHint             []map[string]any   `json:"narrow_hint"`
	DecisiveFacts          map[string]string  `json:"decisive_facts"`
	// SinkFile is the alert's sink file (codesafe bugFile = authoritative sink location,
	// set before slicing). Phase 1 plumbing (root-2 bare-name disambiguation, disambiguation
	// spec §4): Go-only field (NOT in Python SlicedContext). Populated by realJudgeAlert
	// (pipeline) from a.Sink["file"] → slicedMap["sink_file"] via slicedContextToMap json
	// roundtrip → agenticJudge reads it → exec.SetAlertSinkFile. LLM omits file_path in
	// who_calls/reachable_sinks → resolveMethodKey fallback disambiguates by sink file
	// (component.submit, not controller.submit). omitempty + slicer never sets it → absent in
	// slice golden / parity (prompt renders fixed keys, not this) → zero byte delta.
	SinkFile               string             `json:"sink_file,omitempty"`
}
