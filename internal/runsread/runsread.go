// Package runsread — read-only views over runs/ artifacts.
//
// 1:1 移植 appsec/webapp/runs_read.py。Iron rule 2：只读 runs/ 产物 + labels JSONL，
// 绝不 import graph/pipeline/judge 等编排内部。
//
// Layout (internal/runs): runs/<id>/{meta.json, summary.json, traces/<bughash16>.json}
// summary.json = {"summary":{...}, "details":[...]}。
package runsread

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"appsecgo/internal/labels"
	"appsecgo/internal/runs"
)

func readJSON(path string) (map[string]any, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return m, true
}

// ListRuns — 所有 run（newest first）；每条 = meta.json 字段 + "counts"（summary block）。
// 1:1 移植 runs_read.list_runs。按 run_id 降序（string sort reverse）。
func ListRuns(runsDir string) []map[string]any {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return []map[string]any{} // 不存在 → 空（对齐 Python base.exists() False → []）
	}
	var out []map[string]any
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		runPath := filepath.Join(runsDir, e.Name())
		metaFile := filepath.Join(runPath, "meta.json")
		meta, ok := readJSON(metaFile)
		if !ok {
			continue
		}
		summaryFile := filepath.Join(runPath, "summary.json")
		counts := map[string]any{}
		if s, ok := readJSON(summaryFile); ok {
			if c, ok := s["summary"].(map[string]any); ok {
				counts = c
			}
		}
		merged := map[string]any{}
		for k, v := range meta {
			merged[k] = v
		}
		merged["counts"] = counts
		out = append(out, merged)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, _ := out[i]["run_id"].(string)
		rj, _ := out[j]["run_id"].(string)
		return strings.Compare(ri, rj) > 0 // reverse = newest first
	})
	return out
}

// GetRun — run 详情 + 人工标签 overlay。run 不存在返 nil。
// 1:1 移植 runs_read.get_run。逐 detail 查 LatestByBughash：命中 merge label/labeler/labelled_at；
// 未命中三字段设 nil。summary 加 "unlabelled" = 去重 unlabelled bughash 数
// （**F2 起排除带 `exclusion_reason` 的硬排除条目** —— 它们从未送进 judge，不该占人工标注预算）。
func GetRun(runsDir, runID, labelsPath string) map[string]any {
	summaryFile := filepath.Join(runsDir, runID, "summary.json")
	report, ok := readJSON(summaryFile)
	if !ok {
		return nil
	}
	metaFile := filepath.Join(runsDir, runID, "meta.json")
	meta, _ := readJSON(metaFile) // meta 缺失 → nil（对齐 Python _read_json if is_file else {}）

	latest := labels.LatestByBughash(labelsPath, runID)
	rawDetails, _ := report["details"].([]any)
	details := make([]map[string]any, 0, len(rawDetails))
	unlabelled := map[string]struct{}{}
	for _, d := range rawDetails {
		dm, _ := d.(map[string]any)
		if dm == nil {
			dm = map[string]any{}
		}
		bh, _ := dm["bughash"].(string)
		// copy detail 不 mutate 原 report（对齐 Python {**alert, ...}）
		merged := map[string]any{}
		for k, v := range dm {
			merged[k] = v
		}
		if lbl, ok := latest[bh]; ok {
			merged["label"] = lbl["label"]
			if l, ok := lbl["labeler"]; ok {
				merged["labeler"] = l
			} else {
				merged["labeler"] = nil
			}
			if la, ok := lbl["labelled_at"]; ok {
				merged["labelled_at"] = la
			} else {
				merged["labelled_at"] = nil
			}
		} else {
			merged["label"] = nil
			merged["labeler"] = nil
			merged["labelled_at"] = nil
			// F2:硬排除告警**从未送进 judge**(verdict 是占位),不构成待人工标注项。
			// 实测虚高 underwrite 43 / codeup 2(spec 2026-09-01-f2-...-design §1)。
			// 仍 append 进 details(供表格展示与追溯),只是不计入 unlabelled。
			// 老 run 无该字段 → 空串 → 走 else → 行为与今天一致(向后兼容)。
			if reason, _ := dm["exclusion_reason"].(string); reason == "" {
				unlabelled[bh] = struct{}{}
			}
		}
		details = append(details, merged)
	}

	rawSummary, _ := report["summary"].(map[string]any)
	summary := map[string]any{}
	for k, v := range rawSummary {
		summary[k] = v
	}
	summary["unlabelled"] = len(unlabelled)

	return map[string]any{
		"meta":    meta,
		"summary": summary,
		"details": details,
	}
}

// GetAlert — 单告警（按 bughash）：所有匹配 details + 其 trace。不存在返 nil。
// 1:1 移植 runs_read.get_alert。同一 bughash 多 alert（collision）→ details 列表。
func GetAlert(runsDir, runID, bughash string) map[string]any {
	summaryFile := filepath.Join(runsDir, runID, "summary.json")
	report, ok := readJSON(summaryFile)
	if !ok {
		return nil
	}
	rawDetails, _ := report["details"].([]any)
	var matching []map[string]any
	for _, d := range rawDetails {
		dm, _ := d.(map[string]any)
		bh, _ := dm["bughash"].(string)
		if bh == bughash {
			matching = append(matching, dm)
		}
	}
	if len(matching) == 0 {
		return nil
	}
	trace := Trace(runsDir, runID, bughash)
	return map[string]any{
		"bughash": bughash,
		"details": matching,
		"trace":   trace,
	}
}

// Trace — 读 traces/<bh16>.json；不存在/损坏返 nil。GetRun/GetAlert 形状不变。
// 供 alertReportHandler 取单条报告所需 trace（铁律 A：IO 在此，report 包仍纯函数）。
func Trace(runsDir, runID, bughash string) any {
	traceFile := filepath.Join(runsDir, runID, "traces", runs.TraceFilename(bughash))
	if t, ok := readJSON(traceFile); ok {
		return t
	}
	return nil
}
