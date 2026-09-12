// Package store — SCA 结果落盘 + 查询（目录即记录，与 runs/ 模式一致，spec §五）。
// 结构：<scaRunsDir>/<scan_id>/{meta.json, sbom.json, findings.json, raw_osv.json}
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"appsecgo/internal/runs"
	"appsecgo/internal/sca/types"
)

// Meta — meta.json 形状。status 是持久化断点：queued|running|done|failed。
type Meta struct {
	ScanID              string         `json:"scan_id"`
	RepoKey             string         `json:"repo_key"`
	Status              string         `json:"status"`
	ScannerVersion      string         `json:"scanner_version"`
	PolicyVersion       int            `json:"policy_version"`
	StartedAt           string         `json:"started_at,omitempty"`
	FinishedAt          string         `json:"finished_at,omitempty"`
	DurationSec         float64        `json:"duration_seconds,omitempty"`
	Error               string         `json:"error,omitempty"`
	FindingsCount       int            `json:"findings_count,omitempty"`
	FindingsBySeverity  map[string]int `json:"findings_by_severity,omitempty"`
	ReEvaluatedAt       string         `json:"re_evaluated_at,omitempty"`
	PolicyVersionOnReEval int         `json:"policy_version_on_re_eval,omitempty"`
}

// Save — 落四文件。FindingsCount/FindingsBySeverity 由 findings 就地计算。
func Save(scaRunsDir string, meta Meta, res *types.ScanResult, findings []types.Finding) error {
	scanDir := filepath.Join(scaRunsDir, meta.ScanID)
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		return err
	}
	meta.FindingsCount = len(findings)
	meta.FindingsBySeverity = map[string]int{}
	for _, f := range findings {
		meta.FindingsBySeverity[f.Severity]++
	}
	if err := runs.WriteJSONFile(filepath.Join(scanDir, "meta.json"), meta); err != nil {
		return err
	}
	if err := runs.WriteJSONFile(filepath.Join(scanDir, "sbom.json"), res.Components); err != nil {
		return err
	}
	if err := runs.WriteJSONFile(filepath.Join(scanDir, "findings.json"), findings); err != nil {
		return err
	}
	// raw_osv.json = ScanResult 序列化（re-evaluate 数据源，spec §五决策）
	return runs.WriteJSONFile(filepath.Join(scanDir, "raw_osv.json"), res)
}

// Load — 读一个 scan 的 meta + sbom + findings。
func Load(scaRunsDir, scanID string) (*Meta, *types.ScanResult, []types.Finding, error) {
	scanDir := filepath.Join(scaRunsDir, scanID)
	var meta Meta
	if err := readJSON(filepath.Join(scanDir, "meta.json"), &meta); err != nil {
		return nil, nil, nil, err
	}
	var comps []types.SBOMComponent
	if err := readJSON(filepath.Join(scanDir, "sbom.json"), &comps); err != nil {
		return nil, nil, nil, err
	}
	var findings []types.Finding
	if err := readJSON(filepath.Join(scanDir, "findings.json"), &findings); err != nil {
		return nil, nil, nil, err
	}
	res := &types.ScanResult{RepoKey: meta.RepoKey, Components: comps}
	return &meta, res, findings, nil
}

// LoadRaw — 读 raw_osv.json（re-evaluate 用）。
func LoadRaw(scaRunsDir, scanID string) (*types.ScanResult, error) {
	var res types.ScanResult
	if err := readJSON(filepath.Join(scaRunsDir, scanID, "raw_osv.json"), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListScans — 全部（或按 repo_key 过滤）的 meta 列表，按 scanID 倒序（新在前）。
func ListScans(scaRunsDir, repoKey string) ([]Meta, error) {
	entries, err := os.ReadDir(scaRunsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var m Meta
		if err := readJSON(filepath.Join(scaRunsDir, e.Name(), "meta.json"), &m); err != nil {
			continue // 破损目录跳过（与 runsread 容错一致）
		}
		if repoKey != "" && m.RepoKey != repoKey {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScanID > out[j].ScanID })
	return out, nil
}

// ComponentHit — QueryComponents 返回行：哪次扫描哪个仓库用了哪个版本。
type ComponentHit struct {
	ScanID    string `json:"scan_id"`
	RepoKey   string `json:"repo_key"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	License   string `json:"license,omitempty"`
}

// QueryComponents — 跨仓库组件回溯（spec §五）：name 必填，ecosystem 可选；
// 只回溯 status==done 的扫描（failed 的 sbom 不全）；返回顺序 scanID 倒序。
// 性能：P0 全量目录扫描 O(总组件数)，12 仓库×几百组件可接受；
// scan 量级增长后记 P1 优化——Save 时同步维护 name→scanID 倒排索引文件。
func QueryComponents(scaRunsDir, name, ecosystem string) []ComponentHit {
	entries, err := os.ReadDir(scaRunsDir)
	if err != nil {
		return nil
	}
	var hits []ComponentHit
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var m Meta
		if err := readJSON(filepath.Join(scaRunsDir, e.Name(), "meta.json"), &m); err != nil {
			continue
		}
		if m.Status != "done" {
			continue
		}
		var comps []types.SBOMComponent
		if err := readJSON(filepath.Join(scaRunsDir, e.Name(), "sbom.json"), &comps); err != nil {
			continue
		}
		for _, c := range comps {
			if c.Name != name {
				continue
			}
			if ecosystem != "" && c.Ecosystem != ecosystem {
				continue
			}
			hits = append(hits, ComponentHit{
				ScanID: m.ScanID, RepoKey: m.RepoKey,
				Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, License: c.License,
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].ScanID > hits[j].ScanID })
	return hits
}

// UpdateMeta — 重写 meta（状态迁移 queued→running→done/failed 用）。
// 幂等建目录：handler 预写 queued meta 时 <scanID>/ 尚不存在（Save 的 MkdirAll 在
// Run 内部才调），WriteJSONFile → os.WriteFile 不建父目录会报错。此处先建目录再写——
// 对已存在目录是 no-op，不伤已有逻辑；goroutine 错误路径（Run 失败后写 failed meta）
// 同理受益（Save 可能未被调到，目录照样能建）。
func UpdateMeta(scaRunsDir, scanID string, m Meta) error {
	scanDir := filepath.Join(scaRunsDir, scanID)
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		return err
	}
	return runs.WriteJSONFile(filepath.Join(scanDir, "meta.json"), m)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// readFileBytes — 测试辅助（raw_osv.json 内容断言用）。
func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}
