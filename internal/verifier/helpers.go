package verifier

import (
	"regexp"
	"strings"

	"appsecgo/internal/slice"
)

// helpers.go — map-based ports of verify.py helpers. Faithful to Python:
// verify.py has its own _executor_visible/_is_mybatis_mapper_context copies
// (only the placeholder regexes are shared with decisive_facts, 铁律 D).

var (
	preparedExecutorRe  = regexp.MustCompile(`\bprepareStatement\b|\.setString\s*\(`)
	rawConcatExecutorRe = regexp.MustCompile(`\bcreateStatement\b|\.execute\s*\(|createNativeQuery`)
	mybatisTagRe        = regexp.MustCompile(`<(?:select|insert|update|delete|foreach|if|bind|where|set)\b`)
)

func hopsOf(sliced map[string]any) []map[string]any {
	switch v := sliced["hops"].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, h := range v {
			if m, ok := h.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// hopBodies joins all hop function_body with "\n" (verify.py:139 / decisive_facts._hop_bodies).
func hopBodies(sliced map[string]any) string {
	parts := []string{}
	for _, h := range hopsOf(sliced) {
		if b, ok := h["function_body"].(string); ok {
			parts = append(parts, b)
		}
	}
	return strings.Join(parts, "\n")
}

// ExecutorVisible ports verify._executor_visible. Order-sensitive: prepared
// checked before raw_concat. Returns "prepared"/"raw_concat"/"none".
func ExecutorVisible(sliced map[string]any) string {
	if sliced == nil {
		return "none"
	}
	bodies := hopBodies(sliced)
	if preparedExecutorRe.MatchString(bodies) {
		return "prepared"
	}
	if rawConcatExecutorRe.MatchString(bodies) {
		return "raw_concat"
	}
	return "none"
}

// isMybatisMapperContext ports verify._is_mybatis_mapper_context: true if any
// hop file ends .xml OR body has a MyBatis tag. (verify.py:147)
func isMybatisMapperContext(sliced map[string]any) bool {
	if sliced == nil {
		return false
	}
	for _, h := range hopsOf(sliced) {
		fp, _ := h["file_path"].(string)
		body, _ := h["function_body"].(string)
		if strings.HasSuffix(fp, ".xml") || mybatisTagRe.MatchString(body) {
			return true
		}
	}
	return false
}

// placeholderNames ports verify._placeholder_names: #{x}∪${x} across all hops.
func placeholderNames(sliced map[string]any) map[string]bool {
	names := map[string]bool{}
	if sliced == nil {
		return names
	}
	for _, h := range hopsOf(sliced) {
		body, _ := h["function_body"].(string)
		for _, m := range slice.ConcatPlaceholderRe.FindAllStringSubmatch(body, -1) {
			names[m[1]] = true
		}
		for _, m := range slice.ParamPlaceholderRe.FindAllStringSubmatch(body, -1) {
			names[m[1]] = true
		}
	}
	return names
}

// hopTaintVariables 收集所有 hop 的非空 taint_variable——本案真污点源变量集合。
// strong_type_param 在 sinkVars 为空（非 MyBatis 漏洞，LLM 未给 mybatis_concat
// "allows" sink 指针）时用它做相关性回退：使同级 Long 参数（如文件上传场景的
// @RequestParam("bizId") Long bizId，不属 uploadFile 污点路径）被判 not_verifiable
// 而非 guard_effective，不再误否决 TP（52a2fa）。placeholderNames 只收 ${}/#{}
// 占位符，文件上传切片里没有，旧回退等于空集 → 相关性检查被整段跳过 → 任何
// 同级 Long 参数默认 guard_effective。hopTaintVariables 取切片真污点变量，修正之。
func hopTaintVariables(sliced map[string]any) map[string]bool {
	names := map[string]bool{}
	if sliced == nil {
		return names
	}
	hops := hopsOf(sliced)
	// 收口 cross-file eager 链形参污染(a01 退化 root,见 spec
	// 2026-08-31-a01-strongtype-crosstaint-degradation-design.md):184b8c9 把
	// cross-file eager delete 链形参(如 deleteByPrimaryKey 的 id,非本案 sink)
	// 带到下游 hop taint_variable → 灌入本函数 → strong_type placeholders 含 id
	// → 兄弟 Long 参数误匹配 guard_effective → tpContradiction eff 分支降真 TP
	// (a01 4/5→0/5)。过滤:不收 ef ∈ eager 标记(eager_callee/eager_guard/
	// mybatis_xml_eager)的 hop,也不收这些 eager hop 拉的下游 callee
	// (ef ∈ eagerFns)的 taint。reverse_caller/enclosing_scan 的 taint 切片器
	// 本就标 ""(三态纪律,非 taint 入口不猜)→ 空不计,无需过滤。本函数只被
	// strong_type placeholders fallback(probe.go:197)一处消费,
	// filename_neutralized 走 sanitizer 扫描(extractSanitizersFromSlice)不走它
	// → 收窄不伤 184b8c9 改善(GR-1 反向验证)。
	eagerMark := map[string]bool{"eager_callee": true, "eager_guard": true, "mybatis_xml_eager": true}
	eagerFns := map[string]bool{}
	for _, h := range hops {
		if ef, _ := h["expanded_from"].(string); ef != "" && eagerMark[ef] {
			if fn, _ := h["function_name"].(string); fn != "" {
				eagerFns[fn] = true
			}
		}
	}
	for _, h := range hops {
		ef, _ := h["expanded_from"].(string)
		if ef != "" && (eagerMark[ef] || eagerFns[ef]) {
			continue
		}
		if tv, ok := h["taint_variable"].(string); ok {
			if tv = strings.TrimSpace(tv); tv != "" {
				names[tv] = true
			}
		}
	}
	return names
}

// sinkTaintedVars returns the exploit-sink variable names the LLM identified as
// reaching the sink — the names extracted from its decisive_checks that assert
// "allows" and are MyBatis concat placeholders, e.g. a check whose code is
// "and me.bar_code in (${barCodes})" contributes "barCodes". These are the
// authoritative on-path sink vars, used to scope strong_type_param taint-relevance
// so a Long param guarding a *sibling* sink (a different data flow) cannot veto a
// correct true_positive. Empty when the LLM cited no such guard; callers then
// fall back to placeholderNames(sliced) (the prior all-hops union behavior).
//
// Why LLM-cited over slice-scanned: the real exploit sink is frequently NOT a
// slice hop (the agentic LLM finds it via read_file/grep_repo), so the slice can
// neither supply the true sink var nor exclude sibling-sink vars. The LLM's own
// "allows" concat guard is the only authoritative pointer to which var actually
// reaches the sink. The probe still independently verifies each guard's
// effectiveness — only the sink-var anchor changes.
func sinkTaintedVars(llmChecks []map[string]any) map[string]bool {
	names := map[string]bool{}
	for _, c := range llmChecks {
		kind := strings.ToLower(strVal(c, "kind"))
		if kind != "mybatis_concat" {
			continue
		}
		asserts := strings.ToLower(strVal(c, "asserts"))
		if asserts != "" && asserts != "allows" {
			continue
		}
		code := strVal(c, "code")
		for _, m := range slice.ConcatPlaceholderRe.FindAllStringSubmatch(code, -1) {
			names[m[1]] = true
		}
		for _, m := range slice.ParamPlaceholderRe.FindAllStringSubmatch(code, -1) {
			names[m[1]] = true
		}
	}
	return names
}

func strVal(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}
