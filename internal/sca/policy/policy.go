// Package policy — 纯函数合规判定层：输入 ScanResult + 策略文件，输出 []Finding。
// 五类规则全部数据化（sca_policy.json 驱动），运营期增改规则不改代码。
// 加载失败必须报错——合规检查不能悄悄失效（spec §四）。
package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// Policy — sca_policy.json 的内存形态。
type Policy struct {
	Version          int             `json:"version"`
	LicenseAllowlist []string        `json:"license_allowlist"`
	VulnMinSeverity  string          `json:"vuln_min_severity"`
	Blacklist        []BlacklistRule `json:"blacklist"`
	CopyrightRules   []CopyrightRule `json:"copyright_rules"`
}

// BlacklistRule — 内部黑名单组件规则（name+ecosystem 双键匹配，防跨生态误伤）。
type BlacklistRule struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Reason    string `json:"reason"`
	Severity  string `json:"severity"`
}

// CopyrightRule — 版权类规则：match 为 SPDX 通配（如 GPL-*），type=license-family。
type CopyrightRule struct {
	Match    string `json:"match"`
	Type     string `json:"type"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
}

// Load — 读策略文件。缺文件/解析失败/黑名单缺 name 或 ecosystem → error。
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("策略文件读取失败（合规检查不能静默跳过）: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("策略文件解析失败: %w", err)
	}
	for i, r := range p.Blacklist {
		if r.Name == "" || r.Ecosystem == "" {
			return nil, fmt.Errorf("blacklist[%d] 缺 name 或 ecosystem（双键防跨生态误伤）", i)
		}
	}
	return &p, nil
}
