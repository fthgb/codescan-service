// Package types — SCA 子系统共享模型（scanner/policy/store/run 四方共用的唯一类型层）。
// 独立成包原因：sca 根包（编排）import scanner，scanner import 本包，若模型放根包会成 import 环。
// 设计文档：docs/superpowers/specs/2026-09-05-sca-integration-design.md §四。
package types

// Finding — 不合规项统一输出，五类规则一个模型（RuleID 前缀区分）。
type Finding struct {
	RuleID    string         `json:"rule_id"`
	Category  string         `json:"category"`  // vulnerability | license | blacklist | stale | copyright
	Severity  string         `json:"severity"`  // critical/high/medium/low（与现有 severity 词表同构）
	Component string         `json:"component"` // 组件坐标，如 org.apache.commons:commons-text
	Version   string         `json:"version"`
	Ecosystem string         `json:"ecosystem"` // OSV 规范命名：Maven / npm / PyPI ...
	Evidence  string         `json:"evidence"`  // 人可读证据（CVE / 许可证名 / 黑名单条款）
	SourceFile string       `json:"source_file,omitempty"` // 来源文件路径（pom.xml）
	Detail    map[string]any `json:"detail,omitempty"`
}

// SBOMComponent — sbom.json 行模型（内部精简台账，非 CycloneDX 全文）。
type SBOMComponent struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	Ecosystem          string `json:"ecosystem"`
	License            string `json:"license,omitempty"`
	DirectOrTransitive string `json:"direct_or_transitive"` // direct | transitive | unknown
	SourceFile         string `json:"source_file,omitempty"` // 组件来源清单文件相对路径
}

// VulnFindingData — 单条漏洞命中的原始数据（policy 消费，阈值过滤前）。
type VulnFindingData struct {
	Component  string `json:"component"`
	Version    string `json:"version"`
	Ecosystem  string `json:"ecosystem"`
	OSVID      string `json:"osv_id"`               // OSV 原始 ID（GHSA-xxx / CVE-xxx）
	CVE        string `json:"cve,omitempty"`         // CVE 编号（从 Aliases 提取，可能为空）
	Severity   string `json:"severity"`
	CVSSScore  string `json:"cvss_score,omitempty"`  // CVSS 分数字符串（如 "9.8"，来自 GroupInfo.MaxSeverity）
	Summary    string `json:"summary,omitempty"`
}

// LicenseData — 组件许可证（policy 消费，白名单过滤前）。
type LicenseData struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	License   string `json:"license"` // SPDX id 或 osv-scanner 原始字符串
}

// ScanResult — scanner 的输出 / policy 的输入 / raw_osv.json 的落盘内容。
// raw 存 Translate 后的此结构（非 osv-scanner 原始 JSON）：re-evaluate 重判只需 policy，
// 排障看结构化数据更快；原始输出可随时重扫获得（spec §五决策，Task 5 落实）。
type ScanResult struct {
	RepoKey    string            `json:"repo_key"`
	ScannerVer string            `json:"scanner_ver"`
	Components []SBOMComponent   `json:"components"`
	Vulns      []VulnFindingData `json:"vulns"`
	Licenses   []LicenseData     `json:"licenses"`
}

// SeverityFromScore — CVSS 分数映射（>9.0 critical / ≥7 high / ≥4 medium / 其余 low）。
// 归本包：severity 词表是全子系统共享语义（scanner 算分 + policy 阈值 + 前端排序）。
func SeverityFromScore(score float64) string {
	switch {
	case score > 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}
