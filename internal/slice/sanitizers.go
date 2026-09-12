package slice

import (
	"regexp"
	"strings"
)

// sanitizers.go — 守卫抽取与 bypass 检测的单一源（铁律 D）。
//
// 从 verifier/guards.go + verifier/bypass.go 下沉到此，以避免 slice↔verifier
// 循环依赖：enrich（slice 包内）与 draft（draft 包）都要复用守卫抽取/bypass
// 检测，而 verifier 已 import slice（refresh.go/helpers.go 用占位符正则）。
// 下沉后依赖方向统一为 verifier→slice、draft→slice，无环。
//
// 移植自 verify.py: extract_sanitizers_from_slice + detect_guard_variable_bypass。

var (
	matchesRe        = regexp.MustCompile(`\.matches\(\s*` + `"((?:[^"\\]|\\.)*)"` + `\s*\)`)
	replaceCallRe    = regexp.MustCompile(`\.replace\(\s*` + `"((?:[^"\\]|\\.)*)"` + `\s*,\s*` + `"((?:[^"\\]|\\.)*)"` + `\s*\)`)
	replaceAllVarRe  = regexp.MustCompile(`\.replaceAll\(\s*"((?:[^"\\]|\\.)*)"\s*\+\s*(\w+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)`)
	preparedScanRe   = regexp.MustCompile(`\bprepareStatement\b|\.setString\s*\(|\.setObject\s*\(`)
	strongTypeScanRe = regexp.MustCompile(`@(PathVariable|RequestParam)\b[^\n;]*\b(Long|Integer|Short|Byte|Float|Double|Boolean|BigInteger|BigDecimal)\b\s+(\w+)`)
	basenameSplitRe  = regexp.MustCompile(`[\\/]`)
	lineNoSplitRe   = regexp.MustCompile(`:\d`)
	quotedStringRe   = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

var sanitizeAssignRe = regexp.MustCompile(`(\w+)\s*=\s*([\w.]+)\(\s*(\w+)\s*\)`)

// bypassPayload is the witness shown when a guard is bypassable.
// Mirrors verify.py: bypassPayload (shared by probe + bypass detection).
// path_traversal-flavored: "../../etc/passwd" (verify.py:36).
const bypassPayload = "../../etc/passwd"

// hopsOfAny returns hops from a map[string]any sliced, tolerating both
// []map[string]any (focused) and []any (JSON-roundtripped) shapes.
func hopsOfAny(sliced map[string]any) []map[string]any {
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

func strValAny(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func hopStartAny(h map[string]any) int {
	lr, ok := h["line_range"].([]any)
	if !ok || len(lr) == 0 {
		return 0
	}
	if s, ok := lr[0].(float64); ok {
		return int(s)
	}
	return 0
}

func locOfAny(filePath string, start int, body string, matchStart int) string {
	lineInBody := strings.Count(body[:matchStart], "\n") + 1
	return filePath + ":" + itoaAny(start+lineInBody-1)
}

func itoaAny(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func captureQuotedAny(body string, m []int) string {
	sub := matchesRe.FindStringSubmatch(body[m[0]:m[1]])
	if len(sub) >= 2 {
		return sub[1]
	}
	return body[m[0]:m[1]]
}

func submatchAny(body string, m []int, group int) string {
	gi := 2 * group
	if gi+1 < len(m) && m[gi] >= 0 {
		return body[m[gi]:m[gi+1]]
	}
	return ""
}

// ExtractSanitizersFromSlice ports verify.extract_sanitizers_from_slice (verify.py:310).
// 下沉到 slice 包为单一守卫模式源（铁律 D），enrich_guard_callees 与 draft_slice 跨包复用。
func ExtractSanitizersFromSlice(sliced map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, h := range hopsOfAny(sliced) {
		body, _ := h["function_body"].(string)
		src := strValAny(h, "function_name")
		filePath := strValAny(h, "file_path")
		if filePath == "" {
			filePath = "?"
		}
		start := hopStartAny(h)

		// path_traversal 族
		for _, m := range matchesRe.FindAllStringSubmatchIndex(body, -1) {
			out = append(out, map[string]any{
				"kind": "regex", "code": captureQuotedAny(body, m), "location": locOfAny(filePath, start, body, m[0]), "source": src,
			})
		}
		for _, m := range replaceCallRe.FindAllStringSubmatchIndex(body, -1) {
			out = append(out, map[string]any{
				"kind": "string_replace", "code": `replace("` + submatchAny(body, m, 1) + `","` + submatchAny(body, m, 2) + `")`,
				"location": locOfAny(filePath, start, body, m[0]), "source": src,
			})
		}
		// replaceAll("prefix" + var, "replacement") — 变量拼接的 replaceAll
		// 当 first arg 含变量引用时，从同一 function_body 解析变量值并内联到 code 字段，
		// 让 LLM/探针直接看到正则内容，无需自行关联第 N 行的变量定义。
		for _, m := range replaceAllVarRe.FindAllStringSubmatchIndex(body, -1) {
			prefix := submatchAny(body, m, 1)
			varName := submatchAny(body, m, 2)
			replacement := submatchAny(body, m, 3)
			resolved := resolveStringVar(body, varName)
			code := `replaceAll("` + prefix + `" + ` + varName + `, "` + replacement + `")`
			if resolved != "" {
				code = `replaceAll("` + prefix + resolved + `", "` + replacement + `")`
			}
			out = append(out, map[string]any{
				"kind": "string_replace", "code": code,
				"location": locOfAny(filePath, start, body, m[0]), "source": src,
			})
		}
		if strings.Contains(body, ".startsWith(") && strings.Contains(body, "getCanonicalPath") {
			appendsSep := regexp.MustCompile(`\+\s*"[/\\]"`).MatchString(body)
			code := "startsWith(base)"
			if appendsSep {
				code = `startsWith(base + "/")`
			}
			out = append(out, map[string]any{
				"kind": "prefix_startswith", "code": code, "location": locOfAny(filePath, start, body, 0), "source": src,
			})
		}
		// SQL 族 (MyBatis 占位符 / PreparedStatement / 强类型)
		for _, m := range ParamPlaceholderRe.FindAllStringIndex(body, -1) {
			out = append(out, map[string]any{
				"kind": "mybatis_param", "code": body[m[0]:m[1]], "location": locOfAny(filePath, start, body, m[0]), "source": src,
			})
		}
		for _, m := range ConcatPlaceholderRe.FindAllStringIndex(body, -1) {
			out = append(out, map[string]any{
				"kind": "mybatis_concat", "code": body[m[0]:m[1]], "location": locOfAny(filePath, start, body, m[0]), "source": src,
			})
		}
		if m := preparedScanRe.FindStringIndex(body); m != nil {
			out = append(out, map[string]any{
				"kind": "preparedstatement_bind", "code": "PreparedStatement/setString",
				"location": locOfAny(filePath, start, body, m[0]), "source": src,
			})
		}
		for _, m := range strongTypeScanRe.FindAllStringSubmatchIndex(body, -1) {
			out = append(out, map[string]any{
				"kind": "strong_type_param", "code": strings.TrimSpace(body[m[0]:m[1]]),
				"location": locOfAny(filePath, start, body, m[0]), "source": src, "varname": submatchAny(body, m, 3),
			})
		}
	}
	return out
}

// DetectGuardVariableBypass ports verify.detect_guard_variable_bypass (verify.py:89).
// 下沉到 slice 包为 RC-A bypass 检测单一源，draft_slice 跨包复用。
func DetectGuardVariableBypass(sliced map[string]any) map[string]any {
	guardCallees := map[string]bool{}
	for _, c := range ExtractSanitizersFromSlice(sliced) {
		if s, ok := c["source"].(string); ok && s != "" {
			guardCallees[s] = true
		}
	}
	if len(guardCallees) == 0 {
		return nil
	}
	for _, h := range hopsOfAny(sliced) {
		body, _ := h["function_body"].(string)
		for _, m := range sanitizeAssignRe.FindAllStringSubmatchIndex(body, -1) {
			safeVar := body[m[2]:m[3]]
			callee := body[m[4]:m[5]]
			taintVar := body[m[6]:m[7]]
			if taintVar == safeVar {
				continue
			}
			lastSeg := callee
			if idx := strings.LastIndex(callee, "."); idx >= 0 {
				lastSeg = callee[idx+1:]
			}
			if !guardCallees[lastSeg] {
				continue
			}
			tail := body[m[1]:]
			if reassignedDownstreamAny(taintVar, tail) {
				return nil
			}
			if reconcatMatchAny(safeVar, taintVar, tail) {
				return map[string]any{
					"status": "guard_bypassable", "kind": "reconcat_bypass",
					"by":       strValAny(h, "function_name"),
					"sanitizer": callee + "(" + taintVar + ")",
					"witness":  bypassPayload,
					"reason":   "净化后变量 " + safeVar + " 又与原始污点 " + taintVar + " 在下游表达式中共用/拼接，守卫仅作用于 " + safeVar + "、未覆盖到达 sink 的值（铁律 RC-A 反漏报：原判 TP 成立，探针不得推翻）",
				}
			}
		}
	}
	return nil
}

func reconcatMatchAny(safeVar, taintVar, tail string) bool {
	re1 := regexp.MustCompile(`\b` + regexp.QuoteMeta(safeVar) + `\b[\s\S]*\b` + regexp.QuoteMeta(taintVar) + `\b`)
	re2 := regexp.MustCompile(`\b` + regexp.QuoteMeta(taintVar) + `\b[\s\S]*\b` + regexp.QuoteMeta(safeVar) + `\b`)
	return re1.MatchString(tail) || re2.MatchString(tail)
}

// resolveStringVar searches the same function_body for a String variable definition
// (e.g. `public final static String regex = "'|#|%|;|--|..." + "\n| use |...";`) and
// returns the concatenated value of all quoted string literals in the definition.
// Supports multi-line `+` concatenation. Returns "" if not found.
// Key: terminator is "\s*; (closing quote + optional ws + semicolon), not bare ;,
// to avoid stopping at ; inside the string value (e.g. regex blacklists "'|#|%|;|--").
func resolveStringVar(body, varName string) string {
	defRe := regexp.MustCompile(`(?s)\bString\s+` + regexp.QuoteMeta(varName) + `\s*=\s*(.*?"\s*);`)
	m := defRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	parts := quotedStringRe.FindAllStringSubmatch(m[1], -1)
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString(p[1])
	}
	return sb.String()
}

func reassignedDownstreamAny(taintVar, tail string) bool {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(taintVar) + `\s*=`)
	loc := re.FindStringIndex(tail)
	if loc == nil {
		return false
	}
	if loc[1] < len(tail) && tail[loc[1]] == '=' {
		return false
	}
	return true
}
