package poc

import (
	"fmt"
	"regexp"
	"strings"

	"appsecgo/internal/contract"
)

// Port of appsec/poc.py — deterministic route-inference PoC builder. No LLM.
// Reads sliced (hops[0] = entry hop) but does NOT modify it.

var (
	mappingRe       = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Request)Mapping\s*(?:\(([^)]*)\))?`)
	pathLiteralRe   = regexp.MustCompile(`"([^"]*)"`)
	requestMethodRe = regexp.MustCompile(`RequestMethod\.(GET|POST|PUT|DELETE|PATCH)`)
	multiSlashRe    = regexp.MustCompile(`/+`)
)

var methodOf = map[string]string{
	"Get": "GET", "Post": "POST", "Put": "PUT",
	"Delete": "DELETE", "Patch": "PATCH",
}

func classPrefix(classPath string) string {
	if classPath == "" {
		return ""
	}
	cp := strings.TrimSpace(classPath)
	if strings.HasPrefix(cp, "@") {
		if m := pathLiteralRe.FindStringSubmatch(cp); m != nil {
			cp = m[1]
		} else {
			cp = ""
		}
	}
	return strings.TrimSuffix(cp, "/")
}

// route returns (method, path) from the body's mapping annotation, prefixed
// with the class-level path. ("","") when no mapping annotation. (poc.py:41)
func route(body, classPath string) (string, string) {
	m := mappingRe.FindStringSubmatch(body)
	if m == nil {
		return "", ""
	}
	kind, args := m[1], m[2]
	var method string
	if kind == "Request" {
		if rm := requestMethodRe.FindStringSubmatch(args); rm != nil {
			method = rm[1]
		} else {
			method = "GET"
		}
	} else {
		method = methodOf[kind]
	}
	path := ""
	if pm := pathLiteralRe.FindStringSubmatch(args); pm != nil {
		path = pm[1]
	}
	prefix := classPrefix(classPath)
	full := ""
	if path != "" || prefix != "" {
		full = prefix + "/" + strings.TrimLeft(path, "/")
	}
	if !strings.HasPrefix(full, "/") {
		full = "/" + full
	}
	full = multiSlashRe.ReplaceAllString(full, "/")
	return method, full
}

// bindings returns ordered (kind, name) param bindings (poc.py:62).
func bindings(body string) []binding {
	var out []binding
	multipartNames := map[string]bool{}
	for _, m := range regexp.MustCompile(`MultipartFile\s+(\w+)`).FindAllStringSubmatch(body, -1) {
		out = append(out, binding{"multipart", m[1]})
		multipartNames[m[1]] = true
	}
	for _, m := range regexp.MustCompile(
		`@RequestParam(?:\s*\(\s*(?:value\s*=\s*)?"([^"]+)"[^)]*\))?\s+(\w[\w<>\[\].]*)\s+(\w+)`).FindAllStringSubmatch(body, -1) {
		type_, var_ := m[2], m[3]
		if type_ == "MultipartFile" || multipartNames[var_] {
			continue
		}
		name := m[1]
		if name == "" {
			name = var_
		}
		out = append(out, binding{"query", name})
	}
	for _, m := range regexp.MustCompile(
		`@PathVariable(?:\s*\(\s*(?:value\s*=\s*)?"([^"]+)"[^)]*\))?\s+\w[\w<>\[\].]*\s+(\w+)`).FindAllStringSubmatch(body, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		out = append(out, binding{"path", name})
	}
	for _, m := range regexp.MustCompile(`@RequestBody\s+\w[\w<>\[\].]*\s+(\w+)`).FindAllStringSubmatch(body, -1) {
		out = append(out, binding{"body", m[1]})
	}
	return out
}

type binding struct{ kind, name string }

// quoteEscape ports urllib.parse.quote(s, safe=''). Byte-iteration (NOT rune):
// Python quote encodes each UTF-8 byte as %XX. isUnreserved = RFC 3986
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~".
func quoteEscape(s string) string {
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if isUnreserved(b) {
			buf.WriteByte(b)
		} else {
			fmt.Fprintf(&buf, "%%%02X", b)
		}
	}
	return buf.String()
}

func isUnreserved(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '-' || b == '.' || b == '_' || b == '~'
}

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

func strVal(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// BuildAttackRequest ports poc.py:93. Renders a raw HTTP request injecting
// exploitPayload at the entry point. nil when no payload / no hops / no route.
func BuildAttackRequest(sliced map[string]any, exploitPayload string) *string {
	// nullish 载荷 = 没有载荷(微语法契约 I3)。原守卫只判 ""，字符串 "null" 非空 →
	// 生成「# 注入点：null」的假 PoC(三 run 7/15 条 TP 中招)。复用 contract 单一解析器，
	// 不在本包重写词表(GR-7)；GR-8：没有载荷就不该有 PoC，而非展示一个编的注入点。
	if contract.IsNullish(exploitPayload) {
		return nil
	}
	hops := hopsOf(sliced)
	if len(hops) == 0 {
		return nil
	}
	entry := hops[0]
	body := strVal(entry, "function_body")
	classPath := ""
	if scc, ok := sliced["source_class_context"].(map[string]any); ok {
		classPath, _ = scc["class_level_path"].(string)
	}
	method, path := route(body, classPath)
	if method == "" && path == "" {
		return nil
	}
	bs := bindings(body)
	payload := exploitPayload
	if len(bs) > 0 {
		kind, name := bs[0].kind, bs[0].name
		switch kind {
		case "query":
			s := fmt.Sprintf("%s %s?%s=%s HTTP/1.1\nHost: target", method, path, name, quoteEscape(payload))
			return &s
		case "path":
			tmpl := "{" + name + "}"
			var filled string
			if strings.Contains(path, tmpl) {
				filled = strings.ReplaceAll(path, tmpl, quoteEscape(payload))
			} else {
				filled = strings.TrimSuffix(path, "/") + "/" + quoteEscape(payload)
			}
			s := fmt.Sprintf("%s %s HTTP/1.1\nHost: target", method, filled)
			return &s
		case "multipart":
			boundary := "----PoCBoundary"
			crlf := "\r\n"
			parts := "--" + boundary + crlf +
				`Content-Disposition: form-data; name="` + name + `"; filename="` + payload + `"` + crlf +
				"Content-Type: application/octet-stream" + crlf + crlf +
				"<file content>" + crlf +
				"--" + boundary + "--" + crlf
			s := fmt.Sprintf("%s %s HTTP/1.1\nHost: target\nContent-Type: multipart/form-data; boundary=%s\n\n%s",
				method, path, boundary, parts)
			return &s
		case "body":
			s := fmt.Sprintf("%s %s HTTP/1.1\nHost: target\nContent-Type: application/json\n\n%s", method, path, payload)
			return &s
		}
	}
	if method == "GET" {
		s := fmt.Sprintf("%s %s HTTP/1.1\nHost: target   # 注入点：%s", method, path, payload)
		return &s
	}
	s := fmt.Sprintf("%s %s HTTP/1.1\nHost: target\n\n%s", method, path, payload)
	return &s
}
