package pipeline

import (
	"strings"

	"appsecgo/internal/contract"
)

// FilterByLanguage keeps SASTResults whose sink (fallback source) file
// extension is in `allowed` (lowercased language labels, e.g. "java"). Non-matching
// alerts are dropped and counted by extension in `skipped` — they never reach the
// LLM judge fan-out (saves tokens on languages not yet supported, e.g. .vue/.html).
//
// `allowed` empty or containing "*" => no-op (returns input unchanged, nil map):
// parity/test escape and the "disable filter" lever.
//
// A file with no extension is kept (fail-open: never silently drop a possibly-Java file).
// Extension match is case-insensitive.
func FilterByLanguage(in []contract.SASTResult, allowed []string) (kept []contract.SASTResult, skipped map[string]int) {
	if !filterEnabled(allowed) {
		return in, nil
	}
	set := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		set[strings.ToLower(strings.TrimSpace(a))] = true
	}
	kept = make([]contract.SASTResult, 0, len(in))
	skipped = map[string]int{}
	for _, r := range in {
		lang := alertLanguage(r)
		if lang == "" {
			// no extension: fail-open, keep (never silently drop a possibly-Java file)
			kept = append(kept, r)
			continue
		}
		if set[lang] {
			kept = append(kept, r)
		} else {
			skipped[lang]++
		}
	}
	return kept, skipped
}

// filterEnabled: false when allowed is empty or contains "*" (no-op / disable).
func filterEnabled(allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if strings.TrimSpace(a) == "*" {
			return false
		}
	}
	return true
}

// alertLanguage returns the lowercased file extension (no dot) of the alert's
// authoritative sink location (codesafe bugFile), falling back to the source file
// when the sink has none. "" if neither has an extension.
func alertLanguage(r contract.SASTResult) string {
	f := fileField(r.Sink)
	if f == "" {
		f = fileField(r.Source)
	}
	return extOf(f)
}

func fileField(m map[string]any) string {
	if m == nil {
		return ""
	}
	if s, ok := m["file"].(string); ok {
		return s
	}
	return ""
}

// extOf returns the lowercased extension (no dot) of a path, "" if none.
// Suffix-based (after last '.'), stops at path separator so "a/b.c/Foo" has no ext.
func extOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		switch path[i] {
		case '.':
			return strings.ToLower(path[i+1:])
		case '/', '\\':
			return ""
		}
	}
	return ""
}

// severityRank 给严重度字符串一个可比较的数值。CodeSafe adapter 映射
// bugLevel 1→high / 3→medium / 5→low；未映射的 bugLevel 原样保留 severity=""。
// "critical" 排在 high 之上（SAST 平台可能输出）；空串 = 0（同 info，fail-open）。
var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// FilterBySeverity 丢弃严重度低于 minSeverity 的告警。低于阈值的告警不进
// LLM judge fan-out（省 token），也不进 alerts_input.json；只在
// summary.json.skipped_by_severity 里计数。空 minSeverity = no-op（同
// FilterByLanguage 的 "*" / 空 allowlist）。
//
// fail-open：severity 为空串或未知值时保留（不静默丢弃可能有效的告警），
// 对齐 FilterByLanguage 的 no-extension-keep 策略。
func FilterBySeverity(in []contract.SASTResult, minSeverity string) (kept []contract.SASTResult, skipped map[string]int) {
	if minSeverity == "" {
		return in, nil
	}
	minRank, ok := severityRank[strings.ToLower(strings.TrimSpace(minSeverity))]
	if !ok {
		return in, nil // unknown minSeverity → no-op (fail-open)
	}
	kept = make([]contract.SASTResult, 0, len(in))
	skipped = map[string]int{}
	for _, r := range in {
		sev := strings.ToLower(strings.TrimSpace(r.Severity))
		rank, ok := severityRank[sev]
		if !ok {
			// 空串或未知严重度：fail-open，保留
			kept = append(kept, r)
			continue
		}
		if rank >= minRank {
			kept = append(kept, r)
		} else {
			skipped[sev]++
		}
	}
	return kept, skipped
}
