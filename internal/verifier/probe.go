package verifier

import (
	"path"
	"regexp"
	"strings"

	"appsecgo/internal/slice"
)

// probe.go — port of verify.py probe_decisive_check + _apply_sanitizer +
// _escapes_base + _extract_base_literal_from_slice + PATH_TRAVERSAL_CORPUS.

var pathTraversalCorpus = []string{
	"..", "../", "../../", "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
	"....//etc/passwd", "..../", "a/../../etc/passwd", `..\..\x`, "foo/../../bar",
	"./../secret",
}

const defaultBase = "/var/data/"

// bypassPayload — generic witness for re-concat bypass (verify.py:36).
const bypassPayload = "../../etc/passwd"

var quotedRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// pathClean ports posixpath.normpath. Uses path.Clean (NOT filepath.Clean —
// filepath is OS-dependent and would flip / to \ on Windows, breaking parity).
func pathClean(p string) string { return path.Clean(p) }

// EscapesBase ports verify._escapes_base: normpath(base+name) lands outside base.
func EscapesBase(base, name string) bool {
	full := pathClean(base + name)
	b := pathClean(base)
	return full != b && !strings.HasPrefix(full, b+"/")
}

// fullMatch replaces Python re.fullmatch: entire string must match.
func fullMatch(re *regexp.Regexp, s string) bool {
	loc := re.FindStringIndex(s)
	return loc != nil && loc[0] == 0 && loc[1] == len(s)
}

// applySanitizer ports verify._apply_sanitizer: emulate guard on name.
// Returns (sanitized string, rejected bool). out="__UNVERIFIABLE__" when the
// guard cannot be faithfully emulated; rejected=true means the guard rejects
// the name (Python None).
func applySanitizer(check map[string]any, name string) (string, bool) {
	kind := strings.ToLower(strVal(check, "kind"))
	code := strVal(check, "code")
	if kind == "regex" {
		m := quotedRe.FindStringSubmatch(code)
		pattern := code
		if m != nil {
			pattern = m[1]
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return "__UNVERIFIABLE__", false
		}
		if fullMatch(re, name) {
			return name, false // fullmatch filter -> accepted
		}
		return "", true // no fullmatch -> reject = None
	}
	if kind == "string_replace" {
		m := regexp.MustCompile(`replace\(\s*` + `"((?:[^"\\]|\\.)*)"` + `\s*,\s*` + `"((?:[^"\\]|\\.)*)"` + `\s*\)`).FindStringSubmatch(code)
		if m == nil {
			return "__UNVERIFIABLE__", false
		}
		return strings.ReplaceAll(name, m[1], m[2]), false
	}
	return "__UNVERIFIABLE__", false
}

// probeDecisiveCheck ports verify.probe_decisive_check (verify.py:176-307).
// Returns {status, kind, reason, witness?, after?}.
// sinkVars is the LLM-cited exploit-sink var set (see sinkTaintedVars); it
// scopes the strong_type_param taint-relevance test so a Long param on a sibling
// sink cannot veto a correct TP. nil/empty ⇒ fall back to all-hops placeholders.
func probeDecisiveCheck(check map[string]any, base string, sliced map[string]any, actualTypes []string, sinkVars map[string]bool) map[string]any {
	if base == "" {
		base = defaultBase
	}
	if check == nil {
		return map[string]any{"status": "not_verifiable", "reason": "无 decisive_check，无法模拟守卫"}
	}
	kind := strings.ToLower(strVal(check, "kind"))

	switch kind {
	case "prefix_startswith":
		code := strVal(check, "code")
		appendsSep := regexp.MustCompile(`\+\s*"[/\\]"`).MatchString(code) || strings.Contains(strings.ToLower(code), "separator")
		if appendsSep {
			return map[string]any{"status": "guard_effective", "kind": kind,
				"reason": "守卫比较时含路径分隔符（base+sep），startsWith 拦得住同级目录绕过（如 <base>EVIL）"}
		}
		realBase := ExtractBaseLiteralFromSlice(sliced)
		if realBase != "" {
			parent := strings.TrimSuffix(realBase, "/")
			if parent == "" {
				return map[string]any{"status": "not_verifiable", "kind": kind,
					"reason": "base 为根路径，无同级目录可绕过（/ 之下皆预期目录）"}
			}
			bypass := parent + "EVIL"
			return map[string]any{"status": "guard_bypassable", "kind": kind, "witness": bypass, "after": bypass,
				"reason": "从切片提取真实 base=" + realBase + "，构造同级目录 " + bypass + "：仍 startsWith(base) 但指向 <base> 的同级目录（CWE-23 partial traversal），守卫可绕过"}
		}
		return map[string]any{"status": "guard_bypassable", "kind": kind,
			"witness": "sibling dir (e.g. <base>EVIL): startsWith has no trailing separator (CWE-22 partial path traversal)",
			"reason":  "startsWith(base) 无尾分隔符，<base>EVIL 仍 startsWith(base) 但指向同级目录（CWE-23 partial traversal），守卫可绕过（无法从切片提取真实 base 字面量，未合成具体 PoC）"}

	case "mybatis_param":
		// #{} 在已确认的 MyBatis mapper 上下文里就是 PreparedStatement 绑定的定义
		// （编译期生成 ? 占位符 + setX），等价 preparedstatement_bind，无须 Java 执行器
		// 在切片——它本是 MyBatis 生成代码。
		//
		// sinkVars scope（Crack C relevance 半扇门 格一 + 格一补全）：
		// LLM 已给 sink 变量指针（sinkVars 非空）时，只有 #{exploit-var}（var ∈ sinkVars，
		// 因 sinkTaintedVars 从 mybatis_concat "allows" decisive 抽到该变量）才保
		// guard_effective → anti-miss 降级语义不破；#{兄弟变量} → not_verifiable。
		// sinkVars 空（LLM 未给指针，如 missing-auth 案 LLM 未引 mybatis_concat）→
		// 此 #{var} 疑为 lookup/辅助参数（非本案 SQLi sink 路径），不假设其参数化
		// 守护本案 harm → not_verifiable，保留原判不武断 safe（never-upgrade-TP）。
		if len(sinkVars) > 0 {
			code := strVal(check, "code")
			onPath := false
			for _, m := range slice.ParamPlaceholderRe.FindAllStringSubmatch(code, -1) {
				if sinkVars[m[1]] {
					onPath = true
					break
				}
			}
			if !onPath {
				return map[string]any{"status": "not_verifiable", "kind": kind,
					"reason": "#{} 参数化绑定不是本案 sink 变量（LLM 已指 sink 为 " +
						strings.Join(sortedKeys(sinkVars), ", ") +
						"）——守护另一条数据流/兄弟 sink，与本案污点无关，不能据此翻案（taint-relevance）"}
			}
			// on-path exploit-var：真参数化绑定
			if isMybatisMapperContext(sliced) {
				return map[string]any{"status": "guard_effective", "kind": kind,
					"reason": "MyBatis mapper 上下文里 #{} 按定义为 PreparedStatement 参数化绑定，值不入 SQL 文本，守卫有效"}
			}
			ex := ExecutorVisible(sliced)
			if ex == "prepared" {
				return map[string]any{"status": "guard_effective", "kind": kind,
					"reason": "切片内可见 PreparedStatement/setString 执行器，#{} 经参数化绑定，值不入 SQL 文本，守卫有效"}
			}
			return map[string]any{"status": "not_verifiable", "kind": kind,
				"reason": "#{} 不在已确认的 MyBatis mapper 上下文、且执行器不在切片内，无法确认是否真参数化，保留原判不武断 safe"}
		}
		// sinkVars 空：LLM 未引用 mybatis_concat SQLi 漏洞 sink（无 ${} allows decisive）。
		// 此 #{var} 疑为 lookup/辅助参数（如 missing-auth 案的 #{id} WHERE-bind），不在
		// 本案 SQLi 利用路径上——不假设其参数化守护本案 harm，保留原判（anti-miss：不武断 safe）。
		return map[string]any{"status": "not_verifiable", "kind": kind,
			"reason": "LLM 未引用 SQLi 漏洞 sink（无 ${} allows decisive），#{} 疑为 lookup/辅助参数非本案 sink 路径，无法确认守护本案 harm，保留原判不武断 safe"}

	case "mybatis_concat":
		ex := ExecutorVisible(sliced)
		if ex == "raw_concat" {
			return map[string]any{"status": "guard_bypassable", "kind": kind, "witness": "' OR '1'='1",
				"reason": "切片内可见原生 Statement.execute/createNativeQuery 字符串拼接，${} 拼入 SQL 文本，守卫可绕过"}
		}
		if ex == "prepared" {
			return map[string]any{"status": "not_verifiable", "kind": kind,
				"reason": "${} 出现在 PreparedStatement SQL 文本里，是否被字符串替换取决于上游，切片内不可判定"}
		}
		if isMybatisMapperContext(sliced) {
			return map[string]any{"status": "guard_bypassable", "kind": kind, "witness": "' OR '1'='1",
				"reason": "MyBatis mapper XML 上下文里 ${} 按定义为字符串替换（raw concat），值拼入 SQL 文本，守卫可绕过"}
		}
		return map[string]any{"status": "not_verifiable", "kind": kind,
			"reason": "${} 占位符的执行器不在切片内，无法确认是 MyBatis 字符串替换还是字面文本，保留原判"}

	case "preparedstatement_bind":
		return map[string]any{"status": "guard_effective", "kind": kind,
			"reason": "PreparedStatement 参数化绑定，值经 setX 注入、不入 SQL 文本，守卫有效"}

	case "strong_type_param":
		// Relevance set: the LLM-cited sink vars are authoritative (the real
		// exploit sink is often not a slice hop, so placeholderNames(sliced)
		// would union sibling-sink placeholders and wrongly pass a Long param on
		// a different data flow as "relevant"). Fall back to the all-hops union
		// only when the LLM gave no sink pointer, preserving prior behavior.
		placeholders := sinkVars
		if len(placeholders) == 0 {
			// sinkVars 空（非 MyBatis 漏洞，LLM 未引用 mybatis_concat sink）：用 hop
			// taint_variable（本案真污点源变量）做相关性回退。
			// 不并集 placeholderNames——兄弟流的 ${}/#{} 占位符非 taint 证据，会把无关
			// 兄弟 Long 参数（如兄弟 mapper 的 #{bizId}）判进 placeholders → 该 Long 参数
			// 被当 on-path → guard_effective → 误降非 SQLi TP（IDOR/missing-auth/path-traversal，
			// 8a6fddf7/429eb112）。旧实现只回退 placeholderNames，对文件上传等非 MyBatis切片为空集
			// → len==0 → 相关性检查被跳过 → 同级 Long 参数默认 guard_effective → 误否决 TP
			// （52a2fa：bizId/id 非 uploadFile 污点却被当有效守卫）；加 hopTaintVariables 修 52a2fa，
			// 但并集 placeholderNames 又漏进兄弟占位符——本格二-B 去并集收口。
			placeholders = hopTaintVariables(sliced)
		}
		varname := strVal(check, "varname")
		if varname == "" {
			code := strVal(check, "code")
			vm := regexp.MustCompile(`\b(?:Long|Integer|Short|Byte|Float|Double|Boolean|BigInteger|BigDecimal)\s+([A-Za-z_]\w*)`).FindStringSubmatch(code)
			if vm == nil {
				return map[string]any{"status": "not_verifiable", "kind": kind,
					"reason": "声称为 strong_type_param 但代码 " + truncate(code, 60) + " 无 Long/Integer 等强类型（可能把 String 参数误标），不能据此判 effective"}
			}
			varname = vm[1]
		}
		if len(placeholders) > 0 && !placeholders[varname] {
			keys := sortedKeys(placeholders)
			return map[string]any{"status": "not_verifiable", "kind": kind,
				"reason": "强类型参数 " + varname + " 不是本案 sink 变量（" + strings.Join(keys, ", ") + "）——守护另一条数据流/兄弟 sink，与本案污点无关，不能据此翻案（taint-relevance）"}
		}
		if len(placeholders) == 0 {
			// 完全无 taint 证据（sinkVars 空 + hop taint_variable 空）：不假设 strong_type
			// 守了本案注入流 → not_verifiable（保留原判，never-upgrade-TP 保守方向，verify.go:15）。
			// 杀 77278948：空-taint 切片的 Long 参数被默认 guard_effective 误降非 injection TP
			// （如 CWE-338 弱随机：@RequestParam Long id 不挡随机数生成）。
			return map[string]any{"status": "not_verifiable", "kind": kind,
				"reason": "无可核实 taint 证据（sinkVars 与 hop taint_variable 均空），不能假设强类型参数 " + varname + " 守了本案注入流，保留原判"}
		}
		return map[string]any{"status": "guard_effective", "kind": kind,
			"reason": "Spring 对 @PathVariable/@RequestParam 强类型（Long/Integer 等）强制转型，阻断注入载荷，守卫有效"}
	}

	if kind != "regex" && kind != "string_replace" {
		k := kind
		if k == "" {
			k = "unknown"
		}
		return map[string]any{"status": "not_verifiable", "kind": k,
			"reason": "守卫类型 " + k + " 不可确定性模拟，保留原判"}
	}

	// regex/string_replace: only calibrated for path_traversal.
	actual := []string{}
	for _, t := range actualTypes {
		actual = append(actual, strings.ToLower(t))
	}
	declaredVT := strings.ToLower(strVal(sliced, "vulnerability_type"))
	vt := declaredVT
	if containsString(actual, "path_traversal") {
		vt = "path_traversal"
	}
	if vt != "" && vt != "path_traversal" {
		return map[string]any{"status": "not_verifiable", "kind": kind,
			"reason": "regex/string_replace 守卫模拟仅对 path_traversal 校准；本案 " + vt + " 的黑名单绕过需 inc12 动态验证，探针不武断模拟（防穿越语料误判 SQL 守卫）"}
	}
	code := strVal(check, "code")
	for _, payload := range pathTraversalCorpus {
		out, rejected := applySanitizer(check, payload)
		if out == "__UNVERIFIABLE__" {
			return map[string]any{"status": "not_verifiable", "kind": kind,
				"reason": "守卫 " + code + " 无法可靠模拟（正则/替换解析失败）"}
		}
		if rejected {
			continue
		}
		if (strings.Contains(out, "/") || strings.Contains(out, `\`)) && EscapesBase(base, out) {
			return map[string]any{"status": "guard_bypassable", "kind": kind, "witness": payload, "after": out,
				"reason": "模拟 payload " + payload + " 经守卫 " + code + " 后得 " + out + "，逃出 base 目录，守卫可绕过"}
		}
	}
	return map[string]any{"status": "guard_effective", "kind": kind,
		"reason": "所有绕过语料经守卫 " + code + " 后均未逃出 base 目录，守卫有效"}
}

// ExtractBaseLiteralFromSlice ports verify._extract_base_literal_from_slice (verify.py:361).
func ExtractBaseLiteralFromSlice(sliced map[string]any) string {
	if sliced == nil {
		return ""
	}
	for _, h := range hopsOf(sliced) {
		body, _ := h["function_body"].(string)
		if m := regexp.MustCompile(`\bBASE\s*=\s*` + `"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
		if m := regexp.MustCompile(`startsWith\(\s*` + `"((?:[^"\\]|\\.)*)"` + `\s*\)`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// stable sort
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
