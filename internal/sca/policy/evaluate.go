package policy

import (
	"strings"

	"appsecgo/internal/sca/types"
)

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// Evaluate — 对一份 ScanResult 跑全部规则，输出不合规 Finding 列表。
// stale-upgrade 规则 P1 实现（spec §八），RuleID 前缀 "stale-upgrade" 已在类型层预留。
func Evaluate(pol *Policy, res *types.ScanResult) []types.Finding {
	var out []types.Finding
	out = append(out, evalVulns(pol, res)...)
	out = append(out, evalLicenses(pol, res)...)
	out = append(out, evalBlacklist(pol, res)...)
	out = append(out, evalCopyright(pol, res)...)

	// Fill SourceFile from SBOM components by component name lookup
	sourceMap := make(map[string]string)
	for _, c := range res.Components {
		if c.SourceFile != "" && sourceMap[c.Name] == "" {
			sourceMap[c.Name] = c.SourceFile
		}
	}
	for i := range out {
		if sf, ok := sourceMap[out[i].Component]; ok {
			out[i].SourceFile = sf
		}
	}

	return out
}

// evalVulns — 漏洞命中按 vuln_min_severity 过滤，RuleID=vuln-<severity>。
func evalVulns(pol *Policy, res *types.ScanResult) []types.Finding {
	var out []types.Finding
	for _, v := range res.Vulns {
		if severityRank[v.Severity] < severityRank[pol.VulnMinSeverity] {
			continue
		}
			// Evidence 优先用 CVE（用户更熟悉），无 CVE 回退到 OSV ID
		// 前端据此决定链接指向 NVD 还是 OSV
		evidenceID := v.CVE
		if evidenceID == "" {
			evidenceID = v.OSVID
		}
		detail := map[string]any{
			"osv_id":    v.OSVID,
			"summary":   v.Summary,
			"cvss_score": v.CVSSScore,
		}
		if v.CVE != "" {
			detail["cve"] = v.CVE
		}
		out = append(out, types.Finding{
			RuleID: "vuln-" + v.Severity, Category: "vulnerability",
			Severity: v.Severity, Component: v.Component, Version: v.Version,
			Ecosystem: v.Ecosystem, Evidence: evidenceID,
			Detail: detail,
		})
	}
	return out
}

// evalLicenses — 白名单外许可证，RuleID=license-<spdx 小写规范化>。
// severity 一律 high（白名单外即版权红线，保守；运营期可按规则细化，spec §四）。
func evalLicenses(pol *Policy, res *types.ScanResult) []types.Finding {
	allow := make(map[string]bool, len(pol.LicenseAllowlist))
	for _, l := range pol.LicenseAllowlist {
		allow[l] = true
	}
	var out []types.Finding
	for _, l := range res.Licenses {
		if allow[l.License] {
			continue
		}
		out = append(out, types.Finding{
			RuleID: "license-" + ruleIDSuffix(l.License), Category: "license",
			Severity: "high",
			Component: l.Component, Version: l.Version, Ecosystem: l.Ecosystem,
			Evidence: l.License,
		})
	}
	return out
}

// evalBlacklist — name+ecosystem 双键匹配 SBOM 组件。
func evalBlacklist(pol *Policy, res *types.ScanResult) []types.Finding {
	var out []types.Finding
	for _, c := range res.Components {
		for _, r := range pol.Blacklist {
			if c.Name == r.Name && c.Ecosystem == r.Ecosystem {
				out = append(out, types.Finding{
					RuleID: "blacklist-" + r.Name, Category: "blacklist",
					Severity: r.Severity, Component: c.Name, Version: c.Version,
					Ecosystem: c.Ecosystem, Evidence: r.Reason,
				})
			}
		}
	}
	return out
}

// evalCopyright — match 为 SPDX 前缀通配（如 GPL-*），作用于许可证字符串。
// 数据源用 Licenses 数组；SBOM 组件的 License 字段是 scanner 从同一数据回填的，
// 不做二次兜底扫描（避免双数据源去重问题，spec §四单一权威）。
func evalCopyright(pol *Policy, res *types.ScanResult) []types.Finding {
	var out []types.Finding
	for _, l := range res.Licenses {
		for _, r := range pol.CopyrightRules {
			if licMatch(l.License, r.Match) {
				out = append(out, types.Finding{
					RuleID: "copyright-" + ruleIDSuffix(r.Match), Category: "copyright",
					Severity: r.Severity, Component: l.Component, Version: l.Version,
					Ecosystem: l.Ecosystem, Evidence: r.Reason + "（" + l.License + "）",
				})
			}
		}
	}
	return out
}

// licMatch — SPDX 前缀通配："GPL-*" 命中 "GPL-3.0-only"；无通配符则全等。
func licMatch(license, pattern string) bool {
	if !strings.HasSuffix(pattern, "-*") {
		return license == pattern
	}
	return strings.HasPrefix(license, strings.TrimSuffix(pattern, "*"))
}

// ruleIDSuffix — RuleID 片段规范化：小写、非字母数字折叠为单连字符。
// "GPL-3.0-only" → "gpl-3-0-only"；"GPL-*" → "gpl"。
func ruleIDSuffix(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}
