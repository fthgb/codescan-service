package hardexclusion

import (
	"regexp"
	"strconv"

	"appsecgo/internal/paths"
)

var (
	reMarkdown = regexp.MustCompile(`(?i)\.md$`)
	reBuildDir = regexp.MustCompile(`(?i)(^|/)(target|build|generated|generated-sources|node_modules|vendor)/`)
	reCWE      = regexp.MustCompile(`(?i)CWE-(\d+)`)
)

var memorySafetyCWEs = map[int]bool{
	119: true, 120: true, 121: true, 122: true, 125: true, 126: true,
	415: true, 416: true, 476: true, 787: true, 788: true, 824: true,
}
var nativeExts = map[string]bool{
	"c": true, "cc": true, "cpp": true, "cxx": true, "h": true, "hpp": true, "m": true, "mm": true,
}

func srcFile(alert map[string]any) string {
	if src, ok := alert["source"].(map[string]any); ok {
		if f, ok := src["file"].(string); ok {
			return f
		}
	}
	return ""
}

func ExclusionReason(alert map[string]any) string {
	f := srcFile(alert)
	if reMarkdown.MatchString(f) {
		return "HE-101 markdown_file: doc files produce no executable code"
	}
	if paths.IsTestFile(f) {
		return "HE-002 test_file: test code does not run in production"
	}
	if gen, _ := alert["is_generated"].(bool); gen {
		return "HE-010 generated_code: generator owns the security of its output"
	}
	if reBuildDir.MatchString(f) {
		return "HE-102 build_or_vendored: built/generated/vendored code, not team-owned source"
	}
	cwe, _ := alert["cwe_id"].(string)
	if m := reCWE.FindStringSubmatch(cwe); m != nil {
		n, _ := strconv.Atoi(m[1])
		if memorySafetyCWEs[n] {
			ext := ""
			if i := lastDot(f); i >= 0 {
				ext = toLower(f[i+1:])
			}
			if !nativeExts[ext] {
				return "HE-201 lang_mismatch: memory-safety CWE cannot occur in managed-memory code"
			}
		}
	}
	return ""
}

func Partition(alerts []map[string]any) (survivors, excluded []map[string]any) {
	survivors, excluded = []map[string]any{}, []map[string]any{}
	for _, a := range alerts {
		if reason := ExclusionReason(a); reason != "" {
			out := map[string]any{}
			for k, v := range a {
				out[k] = v
			}
			out["exclusion_reason"] = reason
			out["verdict"] = "false_positive"
			excluded = append(excluded, out)
		} else {
			survivors = append(survivors, a)
		}
	}
	return survivors, excluded
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
		if s[i] == '/' {
			return -1
		}
	}
	return -1
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
