package verifier

import (
	"regexp"
	"strings"

	"appsecgo/internal/slice"
)

// guards.go — port of verify.py evaluate_guards + _guard_in_slice + _file_basename.
// extract_sanitizers_from_slice 已下沉到 slice 包（sanitizers.go）为单一守卫模式源。

var (
	basenameSplitRe = regexp.MustCompile(`[\\/]`)
	lineNoSplitRe   = regexp.MustCompile(`:\d`)
)

// fileBasename mirrors verify.py:_file_basename: strip a trailing :<line> suffix
// then take the path basename. NOTE: Go's regexp.Split n counts the number of
// SUBSTRINGS returned (n=1 ⇒ one substring ⇒ the whole string, no split), whereas
// Python re.split(maxsplit=1) counts SPLITS (⇒ 2 pieces). To strip the first
// :<digit> match and take the part before it (Python [0]), Go must use n=2.
// Using n=1 here left "Foo.java:3" intact → guardInSlice never matched slice-hop
// basenames → every not_verifiable guard looked out-of-slice → FP alerts were
// wrongly downgraded to uncertain (probe_downgrades inflated; parity broke).
func fileBasename(p string) string {
	if p == "" {
		return ""
	}
	f := lineNoSplitRe.Split(p, 2) // n=2 ≈ Python maxsplit=1: [before-first-:digit, remainder]
	if len(f) > 0 {
		p = f[0]
	}
	parts := basenameSplitRe.Split(p, -1)
	return parts[len(parts)-1]
}

func guardInSlice(guard map[string]any, sliced map[string]any) bool {
	loc := strings.TrimSpace(strVal(guard, "location"))
	if loc == "" {
		return false
	}
	gbase := fileBasename(loc)
	if gbase == "" {
		return false
	}
	for _, h := range hopsOf(sliced) {
		if fileBasename(strVal(h, "file_path")) == gbase {
			return true
		}
	}
	return false
}

// extractSanitizersFromSlice delegates to slice.ExtractSanitizersFromSlice
// (下沉到 slice 包为单一守卫模式源，避免 slice↔verifier 循环依赖，铁律 D)。
func extractSanitizersFromSlice(sliced map[string]any) []map[string]any {
	return slice.ExtractSanitizersFromSlice(sliced)
}

// evaluateGuards ports verify.evaluate_guards (verify.py:379-463).
// Returns {guards: [...], contradiction: map[string]any|nil}.
func evaluateGuards(sliced map[string]any, verdict string, exploitPayload *string,
	llmChecks []map[string]any, actualTypes []string) map[string]any {
	base := defaultBase
	// sinkVars: exploit-sink var names the LLM cited as reaching the sink (its
	// "allows" mybatis_concat guards). Used to scope strong_type_param relevance
	// so a Long param on a sibling sink can't veto a correct TP. Empty ⇒ the
	// strong_type_param probe falls back to placeholderNames(sliced) (prior
	// behavior). See sinkTaintedVars for why LLM-cited > slice-scanned.
	sinkVars := sinkTaintedVars(llmChecks)

	guards := []map[string]any{}
	// relevant[i] 并行标记 guards[i] 是否"真守卫"（Crack C 三条件：recognized kind +
	// on-class + 非 allows-evidence）。建表时 kind/asserts 在手，就地绑定，避免事后按
	// code 回查的歧义（dedup 跳过的 llmCheck 可能与 slice-scanned 同 code 误配）。
	// guards[] 形状零变（不写 asserts/relevant 键）→ 所有 golden 不破。
	relevant := []bool{}
	for _, c := range extractSanitizersFromSlice(sliced) {
		p := probeDecisiveCheck(c, base, sliced, actualTypes, sinkVars)
		g := map[string]any{
			"kind": c["kind"], "code": c["code"], "location": c["location"],
			"source": c["source"], "status": p["status"], "reason": strVal(p, "reason"),
		}
		if w, ok := p["witness"]; ok {
			g["witness"] = w
		}
		guards = append(guards, g)
		relevant = append(relevant, guardRelevantFor(strVal(c, "kind"), "", actualTypes, strVal(p, "status")))
	}

	// LLM 声明守卫：按 kind 探针评估，dedup by code
	extractedCodes := map[string]bool{}
	for _, g := range guards {
		extractedCodes[strVal(g, "code")] = true
	}
	for _, lc := range llmChecks {
		code := strings.TrimSpace(strVal(lc, "code"))
		if code == "" || extractedCodes[code] {
			continue
		}
		p := probeDecisiveCheck(lc, base, sliced, actualTypes, sinkVars)
		kind := lc["kind"]
		if kind == nil {
			kind = "other"
		}
		kindStr, _ := kind.(string)
		if kindStr == "" {
			kindStr = "other"
		}
		g := map[string]any{
			"kind": kind, "code": code, "location": lc["location"],
			"status": p["status"], "reason": strVal(p, "reason"),
		}
		if w, ok := p["witness"]; ok {
			g["witness"] = w
		}
		guards = append(guards, g)
		// 条件(iii)：llmCheck 的 asserts 在手 → 就地绑 relevance（allows=在场证据→排除）。
		relevant = append(relevant, guardRelevantFor(kindStr, strVal(lc, "asserts"), actualTypes, strVal(p, "status")))
	}

	if verdict == "uncertain" {
		return map[string]any{"guards": guards, "contradiction": nil}
	}

	var contradiction map[string]any
	switch verdict {
	case "true_positive":
		contradiction = tpContradiction(guards, relevant, actualTypes, exploitPayload)
	case "false_positive":
		contradiction = fpContradiction(guards, relevant, actualTypes)
		// FP 的 nv-在切片外 规则需要 sliced（anyInSlice），单独接在这里：
		// 前两条（effective&bypassable / bypassable）已在 fpContradiction 内按 relevance 判完。
		if contradiction == nil {
			contradiction = fpNvOutOfSliceContradiction(guards, relevant, sliced)
		}
	}
	// Store contradiction as an untyped-nil interface when it is logically nil,
	// so callers' `if contradiction != nil` check works (a typed-nil map[string]any
	// boxed in an interface is non-nil in Go — the typed-nil trap). Mirrors Python
	// returning None: JSON-marshals to null, and `is not None` is False.
	var contradictionVal any
	if contradiction != nil {
		contradictionVal = contradiction
	}
	return map[string]any{"guards": guards, "contradiction": contradictionVal}
}

// relevance 的适用边界（重要，2026-08-22 修 FP 分支时踩过一次）：
//
// relevance 三条件回答的是「探针说 not_verifiable，这到底是『真守卫但我模拟不了』
// （真不确定）还是『我不认识这段代码』（噪音）」。它**只适用于 not_verifiable**。
//
//	guard_effective / guard_bypassable 是探针**已判定**的结果 —— 探针真模拟过并得出了
//	结论，不存在"认不出"的问题，故不经 relevance 过滤（过滤了会把真守卫当噪音丢掉：
//	实测会让 TestVerifyVerdict_TP_ExploitVarMybatisParam_Downgrades 这条 anti-miss 变红，
//	即 #{barCodes} 真参数化绑定被无视 → 漏报方向的退化）。
//
// 故下面两个 has*Nv 只对 not_verifiable 用 relevant[]，effective/bypassable 用裸 status。

// hasRelevantNvGuard 报告是否存在「not_verifiable 且 relevant」的守卫，并返回首个。
//
// **本函数是 TP 与 FP 两分支的共同入口**：Crack C 初版只在 TP 分支做了 relevance 过滤，
// FP 分支仍读裸 hasNv → 同一类噪音守卫在 FP 侧原样触发降级。这正是 GR-1「拆东墙补西墙」：
// TP 侧治好的一类在 FP 侧复发。收进一个函数后，将来再调 relevance 规则只需改
// guardRelevantFor 一处（GR-7 治一类不治一点）。
func hasRelevantNvGuard(guards []map[string]any, relevant []bool) (map[string]any, bool) {
	for i, g := range guards {
		if strVal(g, "status") == "not_verifiable" && i < len(relevant) && relevant[i] {
			return g, true
		}
	}
	return nil, false
}

// tpContradiction — 原判 true_positive 时的探针矛盾判定（nil = 不降级，回 TP）。
//
// eff/hasByp 走 on-class + exploit_payload 闸（2026-08-27，镜像 FP 407F21F 修到 TP 侧）：
// 修前 eff := firstWithStatus(guards,"guard_effective") 裸读、无 on-class —— off-class
// 守卫（如 IDOR 案里的 strong_type Long 参数）也命中 → 误降真 TP。现改用
// firstOnClassWithStatus：guard_effective/bypassable 必须守本案**真类**才反证。
//
// exploit_payload 闸（抗 slug 规范化缺口，spec §3.3）：schema 规定注入/路径穿越/上传类
// TP 必须 提供 exploit_payload、访问控制类走 decisive_checks。故 exploit_payload 为空 ⇒
// 本 TP 是访问控制类 ⇒ 所有 sanitizer 类 face（sql_injection/path_traversal）均无证据 →
// filterSanitizerClassFaces 剔之，sanitizer 守卫对本案一律 off-class。alert6（真 IDOR TP，
// actual=[idor,broken-access-control,path-traversal]，exploit_payload=null）即此形态：
// strong_type Long 守 injection/path_traversal，对 idor off-class → 不降级。无论 slug
// 规范化与否皆不降级（不靠一个 bug 修另一个 bug，GR-8）。
//
// 落空分支：仅有噪音 nv（kind=other/off-class/allows-evidence）→ 返回 nil → 不降级。
// 608ca141 假不确定的解：4 个 spurious 守卫全 not_verifiable 但无一 relevant → 站住。
func tpContradiction(guards []map[string]any, relevant []bool, actualTypes []string, exploitPayload *string) map[string]any {
	effTypes := actualTypes
	if exploitPayload == nil || *exploitPayload == "" {
		effTypes = filterSanitizerClassFaces(actualTypes) // 访问控制类 TP：sanitizer 类 face 无 payload 证据 → 剔
	}
	eff := firstOnClassWithStatus(guards, "guard_effective", effTypes)
	hasByp := firstOnClassWithStatus(guards, "guard_bypassable", effTypes) != nil
	nv, hasRelevantNv := hasRelevantNvGuard(guards, relevant)
	switch {
	case eff != nil && hasByp:
		return map[string]any{"status": "not_verifiable", "kind": eff["kind"], "sanitizer": eff["code"],
			"reason": "切片内既有有效守卫又有可绕过守卫，结论模糊；原判 TP 不该自信 → 降级"}
	case eff != nil:
		return map[string]any{"status": "guard_effective", "kind": eff["kind"], "sanitizer": eff["code"],
			"reason": "切片内存在有效守卫 " + strVal(eff, "code") + "，原判 TP(守卫拦不住) 与之矛盾 → 降级"}
	case hasRelevantNv && !hasByp:
		return map[string]any{"status": "not_verifiable", "kind": nv["kind"], "sanitizer": nv["code"],
			"reason": "决定性守卫不可验证（执行器不在切片/守卫在切片外），原判 TP 不该自信 → 降级"}
	}
	return nil
}

// filterSanitizerClassFaces 剔除 actualTypes 里属于 sanitizer 守卫类（sql_injection /
// path_traversal）的 face。仅 tpContradiction eff 分支在 exploit_payload 为空时调用：
// 访问控制类 TP（走 decisive_checks、无 exploit_payload）的 sanitizer 类 face 无 schema
// 所需证据 → 不该让 sanitizer 守卫借这些无证据 face 触发 on-class 误降（GR-8：无证据的
// asserted face 非真相）。并集取自 sanitizerClasses(all kind)。exact-match：不依赖 slug
// 规范化（hyphen 'path-traversal' 不命中 'path_traversal'，但 firstOnClassWithStatus 同样
// 不命中 → 两种情形皆不降级，spec §3.3 鲁棒性）。
func filterSanitizerClassFaces(actualTypes []string) []string {
	classSet := map[string]bool{}
	for _, kind := range []string{"regex", "string_replace", "prefix_startswith",
		"mybatis_param", "mybatis_concat", "preparedstatement_bind", "strong_type_param"} {
		classes, _ := sanitizerClasses(kind)
		for _, c := range classes {
			classSet[c] = true
		}
	}
	var out []string
	for _, at := range actualTypes {
		if !classSet[at] {
			out = append(out, at)
		}
	}
	return out
}

// fpContradiction — 原判 false_positive 时的探针矛盾判定（nil = 不降级，回 FP）。
//
// bypassable 不走完整 relevance 三条件（探针已判定，见上方 relevance 边界注释），
// 但**必须过 on-class 检查**（条件 ii）——这是本次修复的核心：
//
//	实证 407F21F(relation-trade)：`prefix_startswith` 只守 path_traversal，而该 alert
//	的 actual type 是 arbitrary_file_upload。探针把服务端路径拼接
//	`fileTempPath = getLocalFilePathPrefix() + fileName` 判成 guard_bypassable，
//	FP 分支裸读 hasBypassable → 推翻了一个 4 条 decisive_check 全可核实的 FP。
//	"一个 path_traversal 净化器可绕过" 与 "这个 upload 是否误报" 逻辑上无关 ——
//	off-class 的可绕过守卫不构成对本案 FP 的反证。
//
// 第三条 nv 规则改用 relevant[]（本次修复）见 fpNvOutOfSliceContradiction。
//
// hasEff 也走 on-class（2026-08-27 对称收尾，镜像 TP eff 分支 guards.go:199 + 407F21F byp）：
// 修前 hasEff := firstWithStatus(guards,"guard_effective") 裸读——off-class effective 守卫
// 也凑成 case1（hasEff&&byp）。但 effective 对 FP 是**支持**方向（拦得住→维持 FP），配
// on-class bypassable 才"既有有效又有可绕过→模糊"；off-class effective 与本案 FP 逻辑无关，
// 不该凑 case1。跨仓铁证(154 run / 56 FP-downgraded)：0 条真 case1 命中(status=not_verifiable
// 的 FP 全是 fpNvOutOfSlice 第三条规则)，hasEff 改动受影响集=空；单调性 hasEff 只 true→false
// ⇒ 改后仍 0 case1 ⇒ 全仓 0 副作用(verdict/action/标注/attack_request 全 0)。
func fpContradiction(guards []map[string]any, relevant []bool, actualTypes []string) map[string]any {
	hasEff := firstOnClassWithStatus(guards, "guard_effective", actualTypes) != nil
	byp := firstOnClassWithStatus(guards, "guard_bypassable", actualTypes)
	switch {
	case hasEff && byp != nil:
		return map[string]any{"status": "not_verifiable", "kind": byp["kind"], "sanitizer": byp["code"],
			"reason": "切片内既有有效守卫又有可绕过守卫，结论模糊；原判 FP 不该自信 → 降级"}
	case byp != nil:
		return map[string]any{"status": "guard_bypassable", "kind": byp["kind"], "sanitizer": byp["code"],
			"witness": witnessOr(byp, bypassPayload),
			"reason":  "守卫 " + strVal(byp, "code") + " 可绕过，原判 FP(拦得住) 与之矛盾 → 降级"}
	}
	return nil
}

// fpNvOutOfSliceContradiction — FP 的第三条规则：决定性守卫 not_verifiable 且**在切片外**
// → 原判 FP 不该自信。需 sliced 做 anyInSlice，故与前两条分开。
//
// **本次修复点**：原先读裸 `hasNv`（allWithStatus 全量 nv），把「探针认不出的代码」
// 也当成「决定性守卫不可验证」→ FP 被误降。改为只数 relevant 的 nv（与 TP 分支同源）。
// 实证：relation-trade 5 项 uncertain 的 nv reason 里探针自己写了「与本案污点无关
// （taint-relevance）」，却仍在 FP 分支参与降级计数。
func fpNvOutOfSliceContradiction(guards []map[string]any, relevant []bool, sliced map[string]any) map[string]any {
	if firstWithStatus(guards, "guard_effective") != nil {
		return nil
	}
	var relevantNv []map[string]any
	for i, g := range guards {
		if strVal(g, "status") == "not_verifiable" && i < len(relevant) && relevant[i] {
			relevantNv = append(relevantNv, g)
		}
	}
	if len(relevantNv) == 0 || anyInSlice(relevantNv, sliced) {
		return nil
	}
	g := relevantNv[0]
	return map[string]any{"status": "not_verifiable", "kind": g["kind"], "sanitizer": g["code"],
		"reason": "决定性守卫不可验证（守卫在切片外），原判 FP 不该自信 → 降级"}
}

// firstOnClassWithStatus 返回首个「status 匹配 且 kind 的适用漏洞类命中 actualTypes」
// 的守卫。用于 FP 分支的 bypassable：探针已判定其可绕过（不需 relevance 全三条件），
// 但若该 sanitizer kind 根本不守本案漏洞类，它的"可绕过"对本案 FP 无反证力（条件 ii）。
//
// kind=other / 未映射 kind：保守**保留**（回旧行为）——探针不认识的代码可能是任何东西，
// 这里不敢当噪音丢（与 not_verifiable 相反：那里"认不出"确实等于"没证据"）。
// actualTypes 为空（未知漏洞类）时同样保守保留，不凭空收窄。
func firstOnClassWithStatus(guards []map[string]any, status string, actualTypes []string) map[string]any {
	for _, g := range guards {
		if strVal(g, "status") != status {
			continue
		}
		kind := strings.TrimSpace(strVal(g, "kind"))
		classes, crossClass := sanitizerClasses(kind)
		if crossClass || len(classes) == 0 || len(actualTypes) == 0 {
			return g // 跨类守卫 / 未映射 kind / 类未知 → 保守保留
		}
		for _, at := range actualTypes {
			for _, c := range classes {
				if at == c {
					return g // on-class → 真反证
				}
			}
		}
		// off-class → 跳过，继续找下一个可绕过守卫
	}
	return nil
}

func firstWithStatus(guards []map[string]any, status string) map[string]any {
	for _, g := range guards {
		if strVal(g, "status") == status {
			return g
		}
	}
	return nil
}

// firstRelevantNvGuard 返回第一个 status==not_verifiable 且 relevant 的守卫
// （真守卫，探针模拟不了其效果）。Crack C TP 降级 contradiction 点名真守卫，
// 不再点名噪音守卫（kind=other/off-class/allows）。relevant 为建表时的并行标记。
func firstRelevantNvGuard(guards []map[string]any, relevant []bool) map[string]any {
	for i, g := range guards {
		if strVal(g, "status") == "not_verifiable" && relevant[i] {
			return g
		}
	}
	return nil
}

// guardRelevantFor — guardRelevant 的守卫状态感知包装。strong_type_param 的相关性
// 由探针结果决定：其 on-path 形态恒为 guard_effective（可判定有效），其
// not_verifiable 全是 off-path（taint-relevance：守护兄弟参数，不在本案污点上）或
// 误标（代码无 Long）——两者皆噪音，不算 relevant，不触发 hasRelevantNv 降级。
// 修前 guardRelevant 对 strong_type_param 一律 crossClass=true → 同级 Long 参数
// 即便 off-path 也 relevant → 52a2fa 的 bizId/id（非 uploadFile 污点）误触降级。
// 其他 kind 走 guardRelevant 静态判定（status 不影响）。
//
// 2026-08-27 注（去跨类后本特例仍需保留）：sanitizerClasses 已把 strong_type 去跨类
// （→sql_injection/path_traversal），但本特例不因此冗余——它判的是 on-PATH（status==
// guard_effective 作代理），与 guardRelevant 的 on-CLASS 正交：一个 strong_type NV 可能
// on-class（injection 案）却 off-path（兄弟参数）。本特例让 off-path strong_type NV 一律
// 不 relevant（不降），与 tpContradiction eff 分支的 on-class 闸（不靠 off-class 守卫降）
// 是两条独立线。简化（让 strong_type 走 guardRelevant on-class）属 spec §6.2 独立议题，不动。
func guardRelevantFor(kind, asserts string, actualTypes []string, status string) bool {
	if kind == "strong_type_param" {
		return status == "guard_effective"
	}
	return guardRelevant(kind, asserts, actualTypes)
}

// guardRelevant 判一个 not_verifiable 守卫是否"真守卫"（Crack C 三条件）：
//   (i)   recognized sanitizer kind —— kind ∈ 探针认识的 sanitizer 模式集合，
//         排除 other/空。kind=other = 探针不认识的代码（路由/硬编码值/状态检查），
//         not_verifiable 对它只是"我不认识"，不是"这是守卫但我模拟不了"。
//   (ii)  on-class —— sanitizer kind 的适用漏洞类 ∩ actualTypes 非空。
//         string_replace/regex/prefix_startswith 只对 path_traversal；mybatis_* /
//         preparedstatement_bind 只对 sql_injection；strong_type_param 守 sql_injection +
//         path_traversal 两类（2026-08-27 去跨类，见 sanitizerClasses 注）。
//         镜像 probeDecisiveCheck 内部 kind→class 校准，外提为相关性判定（R1）。
//   (iii) 非 allows-evidence —— 对 llmChecks 来源：asserts != "allows"。
//         allows = LLM 说"这检查放行攻击"（TP 在场证据），不是守卫。
//         slice-scanned 来源 asserts=""（无 LLM 标注）→ 自然过 (iii)。
//
// 三条件全满足 = 真守卫模拟不了效果 = 真不确定 → 该降 TP。任一不满足 = 噪音 → 不降。
// 入参取 kind/asserts（建表时在手），不从 guard map 回查 → guards[] 形状零变（R2）；
// 不改 probeDecisiveCheck（R3）。
func guardRelevant(kind, asserts string, actualTypes []string) bool {
	kind = strings.TrimSpace(kind)
	if kind == "" || kind == "other" {
		return false // (i)
	}
	if asserts == "allows" {
		return false // (iii)
	}
	classes, crossClass := sanitizerClasses(kind)
	if crossClass {
		return true // 跨类守卫（2026-08-27 去跨类后无 kind 命中 crossClass=true，本分支现不可达；留作防御，spec §6.2）
	}
	if len(classes) == 0 {
		return false // kind 未映射到任何类 → 保守当噪音
	}
	for _, at := range actualTypes {
		for _, c := range classes {
			if at == c {
				return true // (ii)
			}
		}
	}
	return false
}

// sanitizerClasses 把 sanitizer kind 映射到它真正能守卫的漏洞类。镜像
// probeDecisiveCheck 内部 kind→class 校准（regex/string_replace 仅 path_traversal，
// mybatis_* 仅 sql_injection）。**strong_type_param 守 injection/path_traversal 两类
// （2026-08-27 去跨类：原 crossClass=true 让它在访问控制类告警上也当 on-class → 放大
// inc27 TP eff 分支误降面，见 `tpContradiction` 注 + spec
// `2026-08-27-crack-c-tp-eff-onclass-strong-type-decross-design.md`）**。类型紧化（Long/Integer）
// 只对 sql_injection 串拼 / path_traversal 路径串拼有效，对 IDOR/越权（访问控制类）不是守卫。
// other/空/未识别 → nil（guardRelevant 条件(i) 已先挡）。
func sanitizerClasses(kind string) (classes []string, crossClass bool) {
	switch kind {
	case "regex", "string_replace", "prefix_startswith":
		return []string{"path_traversal"}, false
	case "mybatis_param", "mybatis_concat", "preparedstatement_bind":
		return []string{"sql_injection"}, false
	case "strong_type_param":
		return []string{"sql_injection", "path_traversal"}, false
	default:
		return nil, false
	}
}

func allWithStatus(guards []map[string]any, status string) []map[string]any {
	var out []map[string]any
	for _, g := range guards {
		if strVal(g, "status") == status {
			out = append(out, g)
		}
	}
	return out
}

func witnessOr(g map[string]any, dflt string) string {
	if w, ok := g["witness"].(string); ok && w != "" {
		return w
	}
	return dflt
}

func anyInSlice(nv []map[string]any, sliced map[string]any) bool {
	for _, g := range nv {
		if guardInSlice(g, sliced) {
			return true
		}
	}
	return false
}
