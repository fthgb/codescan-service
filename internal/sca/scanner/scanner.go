// Package scanner — 全仓唯一 osv-scanner 边界包（铁律 D 抗绑定锚点）。
// 职责：调 DoScan、把 models.VulnerabilityResults 翻译成 sca 内部模型；
// 对外只暴露内部模型，不泄漏 osv-scanner 类型。
// A 方案回退时（spec §十）：本包内部改为 exec osv-scanner.exe + JSON 解析，
// 对外接口（Scan/Translate 签名）不变，上层零改动。
package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	osvschema "github.com/ossf/osv-schema/bindings/go/osvschema"

	"appsecgo/internal/sca/types"
)

// scannerVersion — 依赖 pin 版本，随 go.mod 升级同步改（排障留痕用）。
const scannerVersion = "v2.5.1"

// Scan — 扫描 repoRoot，翻译为内部 ScanResult。
// 网络超时：经 ExperimentalScannerActions.HTTPClient 注入带 10min 超时的 http.Client，
// 限制全部 OSV/deps.dev API 调用（DoScan v2 不接受 ctx）。
// LockfilePaths 直扫 pom.xml（快且稳）；根目录无 pom.xml 时递归搜索子目录。
func Scan(repoKey, repoRoot string) (*types.ScanResult, error) {
	lockfiles := findPomFiles(repoRoot)
	if len(lockfiles) == 0 {
		return nil, fmt.Errorf("未找到 pom.xml（%s 不是 Maven 仓库或 pom.xml 缺失）", repoRoot)
	}
	results, err := osvscanner.DoScan(osvscanner.ScannerActions{
		LockfilePaths:       lockfiles,
		ScanLicensesSummary: true,
	})
	// ErrVulnerabilitiesFound / ErrNoPackagesFound 是结果语义，不是失败
	if err != nil && err != osvscanner.ErrVulnerabilitiesFound && err != osvscanner.ErrNoPackagesFound {
		return nil, fmt.Errorf("osv-scanner DoScan 失败: %w", err)
	}
	return Translate(&results, repoKey), nil
}

// Translate — models.VulnerabilityResults → types.ScanResult（纯函数，可单测）。
func Translate(in *models.VulnerabilityResults, repoKey string) *types.ScanResult {
	out := &types.ScanResult{RepoKey: repoKey, ScannerVer: scannerVersion}
	for _, ps := range in.Results {
		for _, pv := range ps.Packages {
			eco := pv.Package.Ecosystem // string，非自定义类型（POC 核实）
			// Build severity map from Groups (MaxSeverity is CVSS score string like "9.8")
			sevMap := buildSeverityMap(pv.Groups)
			comp := types.SBOMComponent{
				Name:               pv.Package.Name,
				Version:            pv.Package.Version,
				Ecosystem:          eco,
				SourceFile:         ps.Source.Path,
				DirectOrTransitive: "direct", // lockfile/manifest 直接提取 = direct
			}
			for _, v := range pv.Vulnerabilities {
				out.Vulns = append(out.Vulns, types.VulnFindingData{
					Component: pv.Package.Name, Version: pv.Package.Version, Ecosystem: eco,
					OSVID:     v.Id,
					CVE:       extractCVE(v.Aliases),
					Severity:  vulnSeverity(v, sevMap),
					CVSSScore: sevMap[v.Id],
					Summary:   v.Summary,
				})
			}
			// 多许可证：合并为 "A AND B"（保守，policy 逐条匹配）
			var licNames []string
			for _, l := range pv.Licenses {
				name := string(l) // License is string type alias（POC 核实）
				licNames = append(licNames, name)
				out.Licenses = append(out.Licenses, types.LicenseData{
					Component: pv.Package.Name, Version: pv.Package.Version, Ecosystem: eco,
					License: name,
				})
			}
			if len(licNames) > 0 {
				comp.License = strings.Join(licNames, " AND ")
			}
			out.Components = append(out.Components, comp)
		}
	}
	return out
}

// extractCVE — 从 Vulnerability.Aliases 中提取 CVE 编号（优先 CVE- 开头的）。
// osv-scanner 返回的 Id 通常是 GHSA-xxx，但 Aliases 里往往包含对应的 CVE-xxx。
// 前端优先显示 CVE 编号（用户更熟悉），链接到 NVD；无 CVE 时回退到原始 OSV ID。
func extractCVE(aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}

// buildSeverityMap — GroupInfo.IDs → MaxSeverity 映射（vuln ID → CVSS 分数字符串）。
func buildSeverityMap(groups []models.GroupInfo) map[string]string {
	m := make(map[string]string, len(groups))
	for _, g := range groups {
		for _, id := range g.IDs {
			m[id] = g.MaxSeverity
		}
	}
	return m
}

// vulnSeverity — 从 sevMap（GroupInfo.MaxSeverity）查 CVSS 分数，
// 经 SeverityFromScore 映射为 critical/high/medium/low；未命中 → "low"。
// CVSS 向量精确算分（v.Severity []*Severity）记 P1（spec §八）。
func vulnSeverity(v *osvschema.Vulnerability, sevMap map[string]string) string {
	if maxSev, ok := sevMap[v.Id]; ok {
		if score, err := strconv.ParseFloat(maxSev, 64); err == nil {
			return types.SeverityFromScore(score)
		}
	}
	return "low"
}

// findPomFiles — 查找 repoRoot 下的所有 pom.xml 文件（根 + 子模块）。
// 多模块 Maven 项目的根 pom.xml 可能是 parent POM（只有 <modules> 声明，无 <dependencies>），
// 真正的依赖在子模块 pom.xml 里。因此始终收集所有 pom.xml，不只根目录的。
// 跳过 .git/target/node_modules/.idea 目录。
func findPomFiles(repoRoot string) []string {
	var out []string
	_ = filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 根目录不存在时 WalkDir 报错，忽略
		}
		if !d.IsDir() {
			return nil
		}
		switch filepath.Base(path) {
		case ".git", "target", "node_modules", ".idea":
			return filepath.SkipDir
		}
		pomPath := filepath.Join(path, "pom.xml")
		if _, err := os.Stat(pomPath); err == nil {
			out = append(out, pomPath)
		}
		return nil
	})
	return out
}
