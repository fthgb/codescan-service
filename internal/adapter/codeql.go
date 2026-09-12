// Package adapter — CodeQL SARIF adapter, ported from appsec/adapters/codeql.py.
package adapter

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"appsecgo/internal/bughash"
	"appsecgo/internal/contract"
)

// ruleTypeEntry preserves the exact insertion order of Python's _RULE_TO_TYPE
// dict, which _infer_vuln_type relies on for its "first substring match wins"
// fallback. A Go map would iterate in randomized order and break parity.
type ruleTypeEntry struct {
	K, V string
}

var ruleToType = []ruleTypeEntry{
	{"sql-injection", "sql_injection"},
	{"stored-sql-injection", "sql_injection"},
	{"sql-injection-local", "sql_injection"},
	{"path-injection", "path_traversal"},
	{"tainted-permissions-check", "path_traversal"},
	{"partial-path-traversal", "path_traversal"},
	{"partial-path-traversal-from-remote", "path_traversal"},
	{"command-line-injection", "command_injection"},
	{"os-command-injection", "command_injection"},
	{"ssrf", "ssrf"},
	{"request-forgery", "ssrf"},
	{"xss", "xss"},
	{"unsafe-deserialization", "insecure_deserialization"},
	{"insecure-deserialization", "insecure_deserialization"},
	{"xxe", "xxe"},
	{"xxe-local", "xxe"},
	{"groovy-injection", "code_injection"},
	{"jexl-expression-injection", "code_injection"},
	{"ognl-injection", "code_injection"},
	{"spel-expression-injection", "code_injection"},
	{"server-side-template-injection", "code_injection"},
	{"jndi-injection", "code_injection"},
	{"weak-cryptographic-algorithm", "weak_crypto"},
	{"potentially-weak-cryptographic-algorithm", "weak_crypto"},
	{"unvalidated-url-redirection", "open_redirect"},
	{"unvalidated-url-redirect", "open_redirect"},
	{"ldap-injection", "ldap_injection"},
	{"unrestricted-file-upload", "arbitrary_file_upload"},
	{"information-exposure-through-an-error-message", "error_message_exposure"},
	{"stack-trace-exposure", "error_message_exposure"},
	{"error-message-exposure", "error_message_exposure"},
}

var ruleToTypeExact = func() map[string]string {
	m := make(map[string]string, len(ruleToType))
	for _, e := range ruleToType {
		if _, ok := m[e.K]; !ok {
			m[e.K] = e.V
		}
	}
	return m
}()

var (
	cweRE = regexp.MustCompile(`(?i)^external/cwe/cwe-(\d+)`)

	funcPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)in method (\S+)`),
		regexp.MustCompile(`(?i)call to (\S+)`),
		regexp.MustCompile(`(?i)(\S+\([^)]*\))`),
	}
)

var severityMap = map[string]string{
	"error":          "high",
	"warning":        "medium",
	"note":           "low",
	"recommendation": "low",
}

func extractCWE(tags []string) string {
	for _, t := range tags {
		if m := cweRE.FindStringSubmatch(t); m != nil {
			return "CWE-" + m[1]
		}
	}
	return "CWE-UNKNOWN"
}

// inferVulnType mirrors _infer_vuln_type. The `tags` parameter is unused in
// the Python source (dead parameter) so it is intentionally omitted here.
func inferVulnType(ruleID string) string {
	short := ruleID
	if idx := strings.LastIndex(ruleID, "/"); idx != -1 {
		short = ruleID[idx+1:]
	}
	if v, ok := ruleToTypeExact[short]; ok {
		return v
	}
	for _, e := range ruleToType {
		if strings.Contains(short, e.K) {
			return e.V
		}
	}
	return strings.ReplaceAll(short, "-", "_")
}

// securitySeverityScore mirrors Python's `sec_sev = props.get("security-severity", "");
// if sec_sev: score = float(sec_sev)`. It returns (score, true) only when the raw
// value is Python-truthy AND parses to a float:
//   - JSON string "8.1"  -> parse float; empty "" is falsy -> (0, false)
//   - JSON number 8.1    -> decodes as float64, use directly; 0/0.0 is falsy -> (0, false)
//   - absent / other type -> (0, false)
func securitySeverityScore(v any) (float64, bool) {
	switch n := v.(type) {
	case string:
		// Truthiness is on the raw value: any non-empty string is truthy, so
		// "0" is truthy -> float("0")=0.0 -> falls through thresholds to "low".
		if n == "" {
			return 0, false
		}
		score, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, false
		}
		return score, true
	case float64:
		// A bare JSON number 0/0.0 is falsy in Python's `if sec_sev:`.
		if n == 0 {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func severityFromRule(rule map[string]any, levelOverride string) string {
	// Python: sec_sev = props.get("security-severity", ""); if sec_sev: score = float(sec_sev)
	// `if sec_sev:` is a truthiness check, so BOTH a JSON string "8.1" and a bare
	// JSON number 8.1 flow into float(sec_sev). Empty string, absent, and 0/0.0
	// are all falsy in Python -> fall through to the level path.
	props := asMap(rule["properties"])
	if score, ok := securitySeverityScore(props["security-severity"]); ok {
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		default:
			return "low"
		}
	}
	level := levelOverride
	if level == "" {
		defConf := asMap(rule["defaultConfiguration"])
		if v, ok := defConf["level"]; ok {
			level = asString(v)
		} else {
			level = "warning"
		}
	}
	if v, ok := severityMap[level]; ok {
		return v
	}
	return "medium"
}

func locToDict(loc map[string]any) map[string]any {
	phys := asMap(loc["physicalLocation"])
	art := asMap(phys["artifactLocation"])
	region := asMap(phys["region"])
	msgObj := asMap(loc["message"])
	msg := asString(msgObj["text"])

	line := 0
	if v, ok := region["startLine"]; ok {
		if f, ok2 := v.(float64); ok2 {
			line = int(f)
		}
	}

	fn := ""
	if msg != "" {
		for _, re := range funcPatterns {
			if m := re.FindStringSubmatch(msg); m != nil {
				fn = m[1]
				break
			}
		}
	}

	return map[string]any{
		"file":     asString(art["uri"]),
		"line":     line,
		"function": fn,
		"variable": "",
		"message":  msg,
	}
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

// CodeQLAdapter parses a CodeQL SARIF JSON document into []contract.SASTResult.
// This is a faithful port of appsec/adapters/codeql.py:CodeQLAdapter.parse.
type CodeQLAdapter struct{}

func (CodeQLAdapter) Capabilities() map[string]bool {
	return map[string]bool{
		"guarantees_function_name": false,
		"guarantees_taint_path":    false,
		"guarantees_line_number":   true,
	}
}

func (CodeQLAdapter) Parse(raw map[string]any) ([]contract.SASTResult, error) {
	out := []contract.SASTResult{}

	runsAny := asSlice(raw["runs"])
	if len(runsAny) == 0 {
		return out, nil
	}
	run := asMap(runsAny[0])

	driver := asMap(asMap(run["tool"])["driver"])
	rulesList := asSlice(driver["rules"])

	rulesByID := map[string]map[string]any{}
	rulesByIdx := map[int]map[string]any{}
	for i, rAny := range rulesList {
		r := asMap(rAny)
		id := asString(r["id"])
		rulesByID[id] = r
		rulesByIdx[i] = r
	}

	for _, resultAny := range asSlice(run["results"]) {
		result := asMap(resultAny)
		ruleID := asString(result["ruleId"])

		var ruleIdx int
		hasRuleIdx := false
		if v, ok := result["ruleIndex"]; ok {
			if f, ok2 := v.(float64); ok2 {
				ruleIdx = int(f)
				hasRuleIdx = true
			}
		}

		rule, ok := rulesByID[ruleID]
		if !ok && hasRuleIdx {
			rule, ok = rulesByIdx[ruleIdx]
		}
		if !ok {
			rule = map[string]any{}
		}

		props := asMap(rule["properties"])
		tagsAny := asSlice(props["tags"])
		tags := make([]string, 0, len(tagsAny))
		for _, t := range tagsAny {
			tags = append(tags, asString(t))
		}
		cweID := extractCWE(tags)
		vulnType := inferVulnType(ruleID)

		level := ""
		if v, ok := result["level"]; ok {
			level = asString(v)
		}
		severity := severityFromRule(rule, level)

		// locations := result.get("locations", [{}])
		var locs []any
		if v, ok := result["locations"]; ok {
			locs = asSlice(v)
		} else {
			locs = []any{map[string]any{}}
		}
		var primary map[string]any
		if len(locs) > 0 {
			primary = locToDict(asMap(locs[0]))
		} else {
			primary = map[string]any{"file": "", "line": 0, "function": "", "variable": ""}
		}

		// Emit one alert PER codeFlow — dropping flows[1:] would silently hide
		// distinct vulnerable entry points (a false negative).
		var threadFlows [][]any
		for _, cfAny := range asSlice(result["codeFlows"]) {
			cf := asMap(cfAny)
			var tf0 map[string]any
			if tfList, ok := cf["threadFlows"]; ok {
				tfSlice := asSlice(tfList)
				if len(tfSlice) > 0 {
					tf0 = asMap(tfSlice[0])
				} else {
					tf0 = map[string]any{}
				}
			} else {
				tf0 = map[string]any{}
			}
			var locsList []any
			if v, ok := tf0["locations"]; ok {
				locsList = asSlice(v)
			}
			threadFlows = append(threadFlows, locsList)
		}
		filtered := make([][]any, 0, len(threadFlows))
		for _, tl := range threadFlows {
			if len(tl) > 0 {
				filtered = append(filtered, tl)
			}
		}
		hasFlow := len(filtered) > 0
		if !hasFlow {
			filtered = [][]any{nil}
		}

		rawResult, _ := json.Marshal(result)

		for idx, threadLocs := range filtered {
			var pathComplete bool
			var sourceLoc, sinkLoc map[string]any
			var taintPath []map[string]any

			if len(threadLocs) > 0 {
				pathComplete = true
				first := asMap(threadLocs[0])
				last := asMap(threadLocs[len(threadLocs)-1])
				sourceLoc = locToDict(asMap(first["location"]))
				sinkLoc = locToDict(asMap(last["location"]))
				taintPath = make([]map[string]any, 0, len(threadLocs))
				for _, tlAny := range threadLocs {
					tl := asMap(tlAny)
					hop := locToDict(asMap(tl["location"]))
					taintPath = append(taintPath, map[string]any{
						"file":     hop["file"],
						"function": hop["function"],
						"line":     hop["line"],
						"message":  hop["message"],
					})
				}
			} else {
				pathComplete = false
				sourceLoc = copyMap(primary)
				sinkLoc = copyMap(primary)
				taintPath = []map[string]any{}
			}

			suffix := ""
			if len(filtered) > 1 {
				suffix = "#" + strconv.Itoa(idx)
			}
			alertID := "codeql-" + ruleID + "-" + asString(primary["file"]) + ":" + strconv.Itoa(intFromAny(primary["line"])) + suffix

			bh := bughash.ComputeBughash(
				vulnType, cweID,
				asString(sourceLoc["file"]), asString(sourceLoc["function"]),
				asString(sinkLoc["file"]), asString(sinkLoc["function"]),
				"", "",
				intFromAny(sourceLoc["line"]), intFromAny(sinkLoc["line"]),
				bughash.PathSignature(taintPath),
			)

			out = append(out, contract.SASTResult{
				AlertID:           alertID,
				Bughash:           bh,
				VulnerabilityType: vulnType,
				CweID:             cweID,
				Severity:          severity,
				Source:            sourceLoc,
				Sink:              sinkLoc,
				TaintPath:         taintPath,
				TaintPathComplete: pathComplete,
				RawOutput:         json.RawMessage(rawResult),
			})
		}
	}

	return out, nil
}
