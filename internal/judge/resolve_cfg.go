package judge

import (
	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
)

// resolveCfg resolves the judge prompt cfg for a slice (judge.py:701-714 P5).
//
// Primary: ConfigForSlug on the declared vuln_type. Fallback (915 coverage arc A,
// spec 2026-08-29-cwe915-coverage-arc-design.md §6.4): when the slug misses — i.e.
// the alert carries a numeric codesafe rule code as vulnerability_type (CWE-915
// mass-assignment alerts do; no registry slug matches a digit string) — resolve
// via sliced["cwe_id"] → SlugForCwe → ConfigForSlug. report.vulnTypeLabel uses the
// same resolve-by-cwe_id precedent (vulntype_label.go).
//
// 落点 = registry 侧(非 adapter):查实 566→sql_injection 是 adapter.go:149 的
// mapper-SQL-concat 语义覆写,非通用 cwe→slug 表;915(无 SQL-concat)不触该覆写,
// 无 adapter 通用表可扩 → 走 registry 侧 SlugForCwe(cwe_id) fallback(cweToSlug 由
// cwe_aliases 在 NewRegistry 时填充)。cwe_id 是 slice-time 一等信号(enrich.go
// calleeGateByCwe 已读 SlicedContext.CweID;915 显式命中),sliced["cwe_id"] 在
// judge 时已填充(无须另 thread)。
//
// GR-1 安全:decisive-fact 门闸(guard.go:71)键 declared=sliced["vulnerability_type"]
// (此处不改),非 cfg。fallback 只重解 LLM-prompt cfg(long_desc/conclusion_template/
// filter_hints = prong B 的 steer 杠杆),不触发 downgrade 门闸(prong D 杠杆)。故
// 对已 uncertain no-op,对置信 TP/FP 不降——A 单独对 915 零行为变更(915 pre-B 未
// 注册 → SlugForCwe 返 "" → fallback no-op → cfg 恒 zero);B 加 registry 条目后经
// 此 fallback engage,D(required_decisive_facts 门闸)另议、先不 ship。
func resolveCfg(reg *cwereg.Registry, vulnType string, sliced map[string]any) (contract.CweConfig, bool) {
	if cfg, ok := reg.ConfigForSlug(vulnType); ok {
		return cfg, true
	}
	cweID, _ := sliced["cwe_id"].(string)
	if cweID == "" {
		return contract.CweConfig{}, false
	}
	if slug := reg.SlugForCwe(cweID); slug != "" {
		return reg.ConfigForSlug(slug)
	}
	return contract.CweConfig{}, false
}
