package slice

import (
	"regexp"
	"sort"
	"strings"

	"appsecgo/internal/contract"
)

// enrich.go — 移植自 appsec/nodes/enrich.py（确定性 context enrichment，ADR-0005 cheap tier）。
//
// 展开切片内 taint-path hop 调用的仓库内函数体（守卫/净化器/taint-arg callee），
// 纯源码分析 via RepositoryIndex，无 LLM，SAST-agnostic。
// agentic tier（premium）是后续 task（enrich_for_judge 的 agentic 分支 gate off）。
//
// 铁律 D：守卫相关性判定复用 ExtractSanitizersFromSlice（单一守卫模式源）。

// MaxEnrichHops 是单个切片拉入的 callee body 硬上限（对齐 Python MAX_ENRICH_HOPS）。
// 广度扩展膨胀 prompt，保持紧预算并在省略目标 callee 时告知模型。
const MaxEnrichHops = 5

// accessorNameRe 匹配 JavaBean accessor 命名（getXxx/setXxx/isXxx）。与
// internal/agentic/reachability.go 的 accessorRe 共用 contract.AccessorNamePattern
// （2026-09-08 消除重复：原两处各自 regexp.MustCompile 同一 pattern，现共用常量防漂移）。
// 过滤依据（T4 §7.1 实证）：accessor 实现是字段读写，无 sanitize 逻辑可漏判；进未解析
// 清单只会引导 judge 逐个 getter 探索（纯噪声），还会假 fire guard 的 forward_reachable=unknown。
var accessorNameRe = regexp.MustCompile(contract.AccessorNamePattern)

// AppendCalleeHops 把 callee body 内联进切片。items = (expanded_from, FunctionDef) 列表。
// 两层 enrich（确定性 + agentic）共享。dedup vs 既有 hops，重算 sanitization_candidates /
// token_count / degradation。返回实际新增的 hop 数。
func AppendCalleeHops(sliced *contract.SlicedContext, items []CalleeItem) int {
	present := map[[2]string]bool{}
	for _, h := range sliced.Hops {
		present[[2]string{h.FilePath, h.FunctionName}] = true
	}
	nextIndex := 0
	for _, h := range sliced.Hops {
		if h.HopIndex >= nextIndex {
			nextIndex = h.HopIndex + 1
		}
	}
	added := []contract.HopSlice{}
	for _, it := range items {
		key := [2]string{it.FunctionDef.FilePath, it.FunctionDef.Name}
		if present[key] {
			continue
		}
		present[key] = true
		from := it.ExpandedFrom
		added = append(added, contract.HopSlice{
			HopIndex:      nextIndex,
			FilePath:      it.FunctionDef.FilePath,
			FunctionName:  it.FunctionDef.Name,
			FunctionBody:  it.FunctionDef.Body,
			TaintVariable: it.TaintParam, // 空 = 未确定（不猜），见 CalleeItem.TaintParam
			LineRange:     it.FunctionDef.LineRange,
			ExpandedFrom:  &from,
		})
		nextIndex++
	}

	if len(added) == 0 {
		return 0
	}

	sliced.Hops = append(sliced.Hops, added...)
	sanitizers := map[string]bool{}
	for _, s := range sliced.SanitizationCandidates {
		sanitizers[s] = true
	}
	for _, hop := range added {
		low := toLowerASCII(hop.FunctionBody)
		for _, hint := range sanitizerHints {
			if contains(low, hint) {
				sanitizers[hint] = true
			}
		}
	}
	sliced.SanitizationCandidates = sortedKeys(sanitizers)
	sliced.TokenCount = approxTokens(joinBodies(sliced.Hops))
	maybeDegrade(sliced)
	return len(added)
}

// CalleeItem is an (expanded_from, FunctionDef) pair for AppendCalleeHops.
type CalleeItem struct {
	ExpandedFrom string
	FunctionDef  FunctionDef
	// TaintParam 是污点值在**被调方**的形参名；空 = 未确定（不猜）。
	//
	// 只有「知道自己是从哪个调用方、带着哪个污点变量被拉进来」的构造点才填得出它
	// （见 taintparam.go）。agentic / eager_guard 两条路拉进来的 callee 没有这个上下文，
	// 留空 —— 三态纪律，留空读作「未确定」而不是「没有污点」。
	TaintParam string
}

// applyEnrichCap 是 EnrichSlice 的 cap 截断 seam（§8.1 抽出可测）。
// candidates 超 MaxEnrichHops → 截前 N、附 free-text note + ForwardReachable.Truncated；
// 否则全拉。Truncated 是结构化截断契约（raptor ClosureResult.truncated），
// 替代仅靠散文告知 judge"还有 N 个未展开"。
func applyEnrichCap(sliced *contract.SlicedContext, candidates []CalleeItem) {
	if len(candidates) > MaxEnrichHops {
		chosen := candidates[:MaxEnrichHops]
		AppendCalleeHops(sliced, chosen)
		omitted := len(candidates) - len(chosen)
		note := "还有 " + itoaAny(omitted) + " 个目标仓库内被调用函数未展开（预算限制）。"
		setEnrichmentNote(sliced, note)
		ensureFR(sliced).Truncated = true
	} else {
		AppendCalleeHops(sliced, candidates)
	}
}

// EnrichSlice 追加目标仓库内 callee body（守卫/净化器/taint-arg callee）。
// 只展开原始 taint-path hops（depth 1），不展开新加的 callee，控成本。
// cap MaxEnrichHops，sanitizer-named 优先（ResolveCallees 返回序）。
// 设 enrichment_note 当 (a) cap 省略目标 callee，或 (b) 切片引用了未拉入的仓库内 callee。
func EnrichSlice(sliced *contract.SlicedContext, index *RepositoryIndex) *contract.SlicedContext {
	if index == nil {
		return sliced
	}
	present := map[[2]string]bool{}
	for _, h := range sliced.Hops {
		present[[2]string{h.FilePath, h.FunctionName}] = true
	}

	candidates := []CalleeItem{}
	referenced := map[[2]string]bool{} // (file, name) — defect-2 fix
	for _, hop := range sliced.Hops {
		for _, fd := range index.ResolvableCallees(hop.FunctionBody) {
			referenced[[2]string{fd.FilePath, fd.Name}] = true
		}
		for _, fd := range index.ResolveCallees(hop.FunctionBody, hop.TaintVariable, nil) {
			key := [2]string{fd.FilePath, fd.Name}
			if present[key] {
				continue
			}
			present[key] = true
			candidates = append(candidates, CalleeItem{
				ExpandedFrom: hop.FunctionName, FunctionDef: fd,
				// 污点值到了被调方是个形参 —— 把名字带下去，引擎才问得出
				// 「净化作用于这条污点吗」。歧义即留空（taintparam.go）。
				TaintParam: index.TaintParamFor(hop.FunctionBody, hop.TaintVariable, fd),
			})
		}
	}

	applyEnrichCap(sliced, candidates)

	// B2（仅标注）：被拉入的 callee hop 若声明了仓库内无 class 定义的参数类型
	// （外部/缺失模块 DTO，如 ScheduleStaffQueryRequest），告知 judge 该绑定对象字段
	// 结构未展示。接受判决漂移——只标注，不修复。
	var absent []string
	seenType := map[string]bool{}
	for _, h := range sliced.Hops {
		if h.ExpandedFrom == nil {
			continue // only callee hops (not the original taint-path hops)
		}
		params, err := index.extractor.MethodParams(h.FunctionBody)
		if err != nil {
			continue
		}
		for _, p := range params {
			t := p.Type
			if i := strings.Index(t, "<"); i >= 0 {
				t = t[:i] // strip generics: List<String> -> List
			}
			if t == "" || seenType[t] || index.ClassDeclared(t) || isScalarType(t) || isServerContainerType(t) {
				continue // I2: 标量(无字段结构,空命题)+ 服务端容器(字段非攻击者数据)不进 absent
			}
			seenType[t] = true
			absent = append(absent, t)
		}
	}
	if len(absent) > 0 {
		sortStrings(absent)
		note := "以下被调用函数的参数类型在扫描仓库内无定义（外部/缺失模块），其字段结构未展示：" +
			joinComma(absent) + "。这些类型的攻击者可控性取决于调用点绑定方式（如 @RequestBody/@PathVariable 可控，HttpServletResponse/Principal 不可控）；因类型定义缺失无法静态判定，若切片内包含调用上下文请从绑定注解推断，否则该类型的可控性按未知处理（勿据类型本身预设可控或不可控）。"
		appendEnrichmentNote(sliced, note)
	}

	// 引用 + 可解析但未拉入切片的 = judge 不可默默信任的 unseen in-repo callee。
	// 按 (file, name) dedup（缺陷2）：入口 hop 与同名跨类 callee 同名时，
	// 裸名 included 会把 callee 误判为"已包含"而漏报。
	included := map[[2]string]bool{}
	for _, h := range sliced.Hops {
		included[[2]string{h.FilePath, h.FunctionName}] = true
	}
	var unresolvedRefs []contract.CalleeRef
	seenUnr := map[[2]string]bool{}
	for k := range referenced {
		// accessor 过滤（T4 §7.1，见 accessorNameRe 注）：getter/setter 不进清单也不进
		// ForwardReachable.Uncertain——否则假 fire guard 的 unknown（降到 uncertain 的
		// 噪声源之一）。调用点仍在切片函数体内，LLM 照常可见，不丢 taint 信号。
		if included[k] || seenUnr[k] || accessorNameRe.MatchString(k[1]) {
			continue
		}
		seenUnr[k] = true
		unresolvedRefs = append(unresolvedRefs, contract.CalleeRef{Name: k[1], FilePath: k[0]})
	}
	if len(unresolvedRefs) > 0 {
		sortCalleeRefs(unresolvedRefs) // by Name then FilePath — deterministic
		// free-text note（augment，不删）：§8.1 结构化段落地后散文仍作人类可读补注；
		// 删散文是后续 phase（需 corpus 校准），本轮保持 text 不变守既有断言。
		names := make([]string, len(unresolvedRefs))
		for i, r := range unresolvedRefs {
			names[i] = r.Name
		}
		// 名单截断：>contract.MaxUnresolvedNoteNames 只罗列前 N 个（排序后确定性），其余聚合计数
		// 并明确「按同一原则整体核实、不必逐个验证」——把 70+ 项逐个验证的探索诱导降为
		// 一次整体判断（2026-09-06 根因报告 §1.4）。
		shown := names
		omittedNote := ""
		if len(names) > contract.MaxUnresolvedNoteNames {
			shown = names[:contract.MaxUnresolvedNoteNames]
			omittedNote = "（其余 " + itoaAny(len(names)-len(shown)) +
				" 个同类仓内引用已略——与上同性质，按同一原则整体核实即可，不必逐个验证。）"
		}
		note := "以下仓库内调用的函数体未展示：" + joinComma(shown) +
			omittedNote +
			"。先核实：无论这些调用如何，攻击者可控的值是否仍会到达 sink" +
			"（在别处被未经净化地使用，或这些调用守的是另一个变量）—— 若是，照常判定" +
			"（多半 true_positive）。仅当这样的调用确实位于利用路径上、且你无法判断其效果时，" +
			"才返回 uncertain（P3）。"
		appendEnrichmentNote(sliced, note)
		// §8.1 结构化截断契约：不确定一跳前沿（referenced 但未入 slice 的 in-repo
		// callee）。don't-demote-on-unknown 的结构化载体（raptor reachability.py:3638-
		// 3642），替代仅靠散文传递。Phase C 的 forwardReachableLayer 据此渲染。
		ensureFR(sliced).Uncertain = unresolvedRefs
	}
	return sliced
}

// EnrichGuardCallees 确定性前向走拉守卫 callee（depth 2、visited cap 12）。
// 对每个解析到的 callee 用 ExtractSanitizersFromSlice 判守卫相关性——其函数体含
// 可识别守卫模式即拉为 expanded_from='eager_guard' hop。守卫是叶节点（不再深走）；
// 非守卫 callee 深走一级找传递守卫。cap MaxEnrichHops。gate eagerGuardCallees=="on"。
// fail-open：任何异常返原 sliced 不崩。
func EnrichGuardCallees(sliced *contract.SlicedContext, index *RepositoryIndex, eagerGuardCallees string) *contract.SlicedContext {
	defer func() {
		recover() // fail-open：绝不致 enrich 崩
	}()
	if index == nil || eagerGuardCallees != "on" {
		return sliced
	}

	present := map[[2]string]bool{}
	for _, h := range sliced.Hops {
		present[[2]string{h.FilePath, h.FunctionName}] = true
	}
	seen := map[[2]string]bool{}
	var items []FunctionDef

	hasGuard := func(fd FunctionDef) bool {
		// 复用探针抽取（单一守卫模式源）：单 hop 伪切片，非空即守卫相关。
		pseudo := map[string]any{"hops": []map[string]any{{
			"function_body": fd.Body,
			"file_path":     fd.FilePath,
			"function_name": fd.Name,
			"line_range":    []any{float64(fd.LineRange[0]), float64(fd.LineRange[1])},
		}}}
		return len(ExtractSanitizersFromSlice(pseudo)) > 0
	}

	var walk func(body string, depth int)
	walk = func(body string, depth int) {
		for _, fd := range index.ResolvableCallees(body) {
			k := [2]string{fd.FilePath, fd.Name}
			if seen[k] || present[k] {
				continue
			}
			seen[k] = true
			if hasGuard(fd) {
				items = append(items, fd) // 守卫 callee → 拉（叶节点，不再深走）
			} else if depth > 0 && len(seen) < 12 {
				walk(fd.Body, depth-1) // 非守卫 → 深走一级找传递守卫
			}
		}
	}

	for _, h := range sliced.Hops {
		walk(h.FunctionBody, 1) // depth: callees + 1 级传递
	}

	if len(items) > MaxEnrichHops {
		items = items[:MaxEnrichHops]
	}
	if len(items) > 0 {
		calleeItems := make([]CalleeItem, len(items))
		for i, fd := range items {
			calleeItems[i] = CalleeItem{ExpandedFrom: "eager_guard", FunctionDef: fd}
		}
		AppendCalleeHops(sliced, calleeItems)
	}
	return sliced
}

// EnrichForJudge 编排入口（mirror nodes/agentic_enrich.py:enrich_for_judge deterministic 分支）。
// gate: index==nil || enrichCallees false → return sliced。
// EnrichMode=="agentic" → agentic 分支本期不接线，走 deterministic（注释占位）。
// 否则: enrich_slice → enrich_guard_callees。
func EnrichForJudge(sliced *contract.SlicedContext, index *RepositoryIndex, enrichMode, eagerGuardCallees string) *contract.SlicedContext {
	if index == nil {
		return sliced
	}
	// ENRICH_MODE=="agentic" && SupportsTools → agentic 分支（本期不接线，走 deterministic）。
	// TODO(后续 task): 接线 agentic_enrich_slice（LLM enrich loop）。
	_ = enrichMode

	EnrichSlice(sliced, index)
	EnrichStateMutatingCallees(sliced, index)
	EnrichGuardCallees(sliced, index, eagerGuardCallees)
	return sliced
}

// calleeGateByCwe maps cwe_id → 前向 transitive callee-walker 的 gate+depth
// （deeper-callee-slicing spec, GR-8 真相锚点）。enrich 时只能读 SlicedContext.CweID
// （missing_authentication 是 LLM post-judge 识别，slice 时不可得；SAST 归类的
// cwe_id 才是 slice-time 唯一可用信号）。默认 ("taint",1) = 不跑 transitive pass
// = byte-identical legacy EnrichSlice → 对所有未命中 CWE（SQLi/XSS/…）零回归。
// 仅显式 opt-in 的 CWE 走前向 walk。P1 内联 map（待外置到 cwe_registry.json §8.3）。
// 铁律 D 单点：改 CWE→gate 策略只改此 map，不动 walker/gate/enrich 逻辑。
//
// 命中 CWE（spec 2026-08-20-report-unsliced-gaps-slicer-coverage 类1a）：
//   - CWE-915：probe-core missing-auth 的 SAST 归类（攻击者改对象属性 → unauth 改状态链）。
//   - CWE-862：3de4b5c0 missing-auth（cancelTask/updateTask 改状态链，原 walker 不命中 →
//     漏切决定性 callee）。两 CWE harm 同形=unauth 到达改状态动作，非 taint 流（§8.5 deferred）。
var calleeGateByCwe = map[string]struct {
	gate  string
	depth int
}{
	"CWE-915": {"state_mutating", 3}, // 攻击者改对象属性 → unauth 改状态链
	"CWE-862": {"state_mutating", 3}, // 缺失鉴权 → unauth 到达改状态动作（cancelTask/updateTask 等）
}

func gateForCwe(cweID string) (gate string, depth int) {
	if g, ok := calleeGateByCwe[cweID]; ok {
		return g.gate, g.depth
	}
	return "taint", 1
}

// EnrichStateMutatingCallees — 前向 transitive 走（GR-8 真相锚点）：仅对 cwe_id
// 命中 calleeGateByCwe 的切片触发（CWE-915 missing-auth）。从原始 taint-path hop
// （ExpandedFrom==nil，即入口）出发，StateMutatingGate 按改状态动词名拉 callee，
// depth 走到 sink 侧代码（如 handleRevoke→lawsuitRevoke→cancelTask→deleteTask）。
// 不经 taint（missing-auth harm = unauth 到达改状态动作，非 taint 流；§8.5 deferred）。
// walker 自身 seen 去重防环 + 穿透既有 hop（lawsuitRevoke 若已被 EnrichSlice 拉入，
// present 检查只拦候选入列，walker 仍下钻其 body 到 cancelTask/deleteTask）。
// cap MaxEnrichHops + truncated 契约（applyEnrichCap）。fail-open。未命中 cwe → no-op（零回归）。
// 2026-08-28 接进 production agentic.EnrichForJudge（dormant arc 落地；arc 见 docs/superpowers/specs/2026-08-13-deeper-callee-slicing-design.md）。
func EnrichStateMutatingCallees(sliced *contract.SlicedContext, index *RepositoryIndex) {
	defer func() { recover() }() // fail-open：绝不致 enrich 崩
	if index == nil {
		return
	}
	gate, depth := gateForCwe(sliced.CweID)
	if gate != "state_mutating" || depth <= 1 {
		return // 零回归：非 missing-auth CWE 不走 transitive
	}
	present := map[[2]string]bool{}
	for _, h := range sliced.Hops {
		present[[2]string{h.FilePath, h.FunctionName}] = true
	}
	candidates := []CalleeItem{}
	seen := map[[2]string]bool{}
	// appendCallee — dedup+入列闭包(行为保持:与重构前 root-body 走同一 present/seen
	// 检查 + 同一 CalleeItem 字段 + 同一 TaintParamFor 调用)。root-body 走与 enclosing
	// 走共用此闭包,DRY(spec 2026-08-29-slicer-reachability-gap-impl-plan Phase 2)。
	appendCallee := func(fd FunctionDef, expandedFrom, taintBody, taintVar string) {
		k := [2]string{fd.FilePath, fd.Name}
		if present[k] || seen[k] {
			return
		}
		seen[k] = true
		candidates = append(candidates, CalleeItem{
			ExpandedFrom: expandedFrom, FunctionDef: fd,
			// transitive 走的是**多跳**：只有直接被调方的形参映射是可靠的，
			// 更深的跳无法从入口 body 推出来 → 非直接跳自然返 ""（不猜）。
			TaintParam: index.TaintParamFor(taintBody, taintVar, fd),
		})
	}
	for _, h := range sliced.Hops {
		if h.ExpandedFrom != nil {
			continue // 仅从原始 taint-path hop（入口）出发
		}
		// 既有:root-body 前向走(callee-of-root)。行为与重构前等价(闭包参数 = 原 inline 实参)。
		pulled, _ := index.ResolveCalleesTransitive(h.FunctionBody, depth, StateMutatingGate{}, nil)
		for _, fd := range pulled {
			appendCallee(fd, h.FunctionName, h.FunctionBody, h.TaintVariable)
		}
		// NEW Approach B(spec 2026-08-29-slicer-reachability-gap-design §3):enclosing-body
		// 第二走(sibling-scan)。CallersOf(rootFn) 1-hop 取 root 的直接 caller = enclosing
		// method(s);同 gate 同 depth 从 enclosing body 走,"save" 等命中 ⇒ 下钻 sibling
		// writer + 其 chain("delete" tier-1 等)。root 名仓内唯一 ⇒ CallersOf 精确。depth 复用
		// 非 depth-1(否则丢 chain 末端 sink —— spec §3 step2 depth 语义)。enclosing 列表
		// walk 前显式 sort(确定性:禁 map range 直接遍历;slicer 自守,不依赖 engine 侧
		// b77facb —— spec §4 determinism 编码约束)。多 caller(含 test)bound:既有 hop6
		// test-file content 已入 slice,非新策略;cap+sort+dedup 已 bound 噪声(spec §8)。
		enclosings := index.CallersOf(h.FunctionName)
		sort.Slice(enclosings, func(i, j int) bool {
			if enclosings[i].FilePath != enclosings[j].FilePath {
				return enclosings[i].FilePath < enclosings[j].FilePath
			}
			return enclosings[i].Name < enclosings[j].Name
		})
		for _, enc := range enclosings {
			sibPulled, _ := index.ResolveCalleesTransitive(enc.Body, depth, StateMutatingGate{}, nil)
			for _, fd := range sibPulled {
				// enclosing-scan provenance:标区分性 tag 便 trace 复盘;enclosing 非 taint
				// 入口 hop,taint var 不可靠推 → "" 不猜(三态纪律,同 transitive 多跳处理)。
				appendCallee(fd, "enclosing_scan:"+enc.Name, enc.Body, "")
			}
		}
	}
	if len(candidates) == 0 {
		return
	}
	// severe-first（GR-7 治一类 + R2 第二步 body-write 前置）：rank 升序 cap-5 保留真 sink。
	// body-write-signal(transactionTemplate.execute/*Tunnel.insert|update|delete)→rank0，
	// tier-1(cancel/delete/…)→1，tier-2(update/insert/…)→2，tier-0(sanitizer/其他)→3。
	// real-data 双形实证：103 orderPersistForUpdate(update 命名真 sink，body 有
	// transactionTemplate.execute)被 11 cancel 命名噪声 saturate cap-5 截 → body-write
	// promote 到 rank0 存活；3de4b5c0 0 候选含 transactionTemplate → 0 rank0 → cancelTask
	// (rank1)前置存活不位移（dump LLM-free 钉）。sanitizer 证据 EnrichSlice depth-1 已收
	// （DRY），此 pass 聚焦改状态 sink。稳定排序保 walk 序（同 rank 内先后可复现）。
	sortCalleeItemsSevereFirst(candidates)
	applyEnrichCap(sliced, candidates)
}

// stateMutatingRank 给 severe-first 排序用（R2 第二步，body-write-signal 前置 tier）：
// body-write-signal(强 DB 写事务: transactionTemplate.execute/*Tunnel.写)→0（最高优先，真 sink 拥有者），
// tier-1(irreversible: cancel/delete/…)→1，tier-2(reversible: update/insert/…)→2，
// tier-0(sanitizer/其他)→3（最低，EnrichSlice 已收 depth-1 证据）。
//
// 为何 body-write 前置（GR-7 治一类 + GR-8 实证）：severity-first name-verb 代理在「真 sink
// 名动词≠泛淹项名动词」链型反噬——103 orderPersistForUpdate 是 update 命名（旧 rank1）被
// 11 cancel 命名噪声（旧 rank0，stub/converter/validate 非 sink）saturate cap-5 截掉；
// body 写信号 promote 它到 rank0 存活。3de4b5c0 反形：0 候选含 transactionTemplate
// →0 rank0 → cancelTask（rank1）仍前置存活，不位移（dump LLM-free 钉死，spec §3.3/§4）。
// 排除 repository.update 弱信号防 3de4b5c0 updateTask-noise 位移（spec §3.1 证伪 broad pattern）。
func stateMutatingRank(name, body string) int {
	if bodyWriteSignal(body) {
		return 0
	}
	switch stateMutatingTier(name) {
	case 1:
		return 1
	case 2:
		return 2
	default:
		return 3
	}
}

// sortCalleeItemsSevereFirst 稳定排序：rank 升序（irreversible 置前）。插入排序
// （小 N，受 MaxEnrichHops/节点 cap 约束）。同 rank 保原 walk 序（稳定）。
func sortCalleeItemsSevereFirst(items []CalleeItem) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0; j-- {
			a, b := stateMutatingRank(items[j-1].FunctionDef.Name, items[j-1].FunctionDef.Body),
			stateMutatingRank(items[j].FunctionDef.Name, items[j].FunctionDef.Body)
			if a > b {
				items[j-1], items[j] = items[j], items[j-1]
			} else {
				break
			}
		}
	}
}

// --- helpers ---

func setEnrichmentNote(s *contract.SlicedContext, note string) {
	s.EnrichmentNote = &note
}

func appendEnrichmentNote(s *contract.SlicedContext, note string) {
	if s.EnrichmentNote == nil {
		s.EnrichmentNote = &note
		return
	}
	combined := *s.EnrichmentNote + " " + note
	s.EnrichmentNote = &combined
}

// ensureFR 返回 sliced 的 ForwardReachable，按需分配（§8.1）。只在确有结构信号
// （截断/未解析/方法分派）时被调用，否则 ForwardReachable 保持 nil → JSON key
// 缺席 → parity 不破（omitempty + 指针，见 contract/slice_context_test.go）。
func ensureFR(s *contract.SlicedContext) *contract.ForwardReachable {
	if s.ForwardReachable == nil {
		s.ForwardReachable = &contract.ForwardReachable{}
	}
	return s.ForwardReachable
}

// sortCalleeRefs 按 Name（then FilePath）插入排序——小 N（unresolved callees）。
// 决定性顺序，保 prompt/golden 稳定（镜像原 sortStrings 的语义）。
func sortCalleeRefs(rs []contract.CalleeRef) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0; j-- {
			a, b := rs[j-1], rs[j]
			if a.Name > b.Name || (a.Name == b.Name && a.FilePath > b.FilePath) {
				rs[j-1], rs[j] = rs[j], rs[j-1]
			} else {
				break
			}
		}
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func sortedKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	// insertion sort (small N — sanitization candidates / unresolved callees)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

// I2: B2 absent-type 过滤（spec: 2026-08-11-i2-b2-note-attacker-overclaim-design.md §3.3/§3.4）。
// "类型在仓库内无定义" 对 "攻击者可控与否" 零信息量（String 可是 @RequestParam
// 也可服务端算出；HttpServletResponse 永不可控）—— 故这两类不触发 B2 note，
// attacker-control 判断交由 note 措辞指引 judge 看调用点绑定注解。首刀硬编码 set
// （类型分类法小且稳，JDK 不变；名单膨胀再外置 data/）。
var scalarTypes = map[string]bool{
	// 原语
	"int": true, "long": true, "short": true, "byte": true,
	"float": true, "double": true, "boolean": true, "char": true, "void": true,
	// 包装类
	"Integer": true, "Long": true, "Short": true, "Byte": true,
	"Float": true, "Double": true, "Boolean": true, "Character": true, "Void": true,
	// 常用标量
	"String": true, "BigInteger": true, "BigDecimal": true,
	// 注：JDK 集合（List/Map/Set）当前未过滤——泛型剥至裸名后仍可能进 absent，
	// 但新措辞已不声称 attacker-control，属诚实信息缺口；集合过滤留作后续。
}

func isScalarType(t string) bool { return scalarTypes[t] }

var serverContainerTypes = map[string]bool{
	// servlet
	"HttpServletRequest": true, "HttpServletResponse": true, "HttpSession": true,
	"ServletContext": true, "ServletRequest": true, "ServletResponse": true,
	// security
	"Principal": true, "Authentication": true, "SecurityContext": true,
	// jpa / 容器
	"EntityManager": true, "EntityManagerFactory": true, "Connection": true,
}

func isServerContainerType(t string) bool { return serverContainerTypes[t] }
