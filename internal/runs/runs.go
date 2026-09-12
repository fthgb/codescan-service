package runs

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"appsecgo/internal/report"
)

var safeRunRe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func safe(s string) string { return safeRunRe.ReplaceAllString(s, "_") }

// timeNowUTCStamped = Python strftime("%Y-%m-%dT%H%M%S") UTC。
func timeNowUTCStamped() string { return time.Now().UTC().Format("2006-01-02T150405") }

// TraceFilename 移植 runs.py:trace_filename = safe(bughash)[:16]+".json"。
// Python s[:16] 在 s 短于 16 时返回整串;Go 切片越界会 panic,故显式截断。
func TraceFilename(bughash string) string {
	s := safe(bughash)
	if len(s) > 16 {
		s = s[:16]
	}
	return s + ".json"
}

// WriteRun 移植 runs.py:write_run。写 meta/alerts_input/summary + traces/<file>。
func WriteRun(runsDir, repoKey, adapter, model string, alertsInput []map[string]any,
	report *report.ReportOutput, traces []map[string]any, durationSec float64) (string, error) {
	ts := timeNowUTCStamped() // strftime("%Y-%m-%dT%H%M%S") UTC
	runID := ts + "_" + safe(repoKey)
	runDir := filepath.Join(runsDir, runID)
	if err := os.MkdirAll(filepath.Join(runDir, "traces"), 0o755); err != nil {
		return "", err
	}
	meta := map[string]any{
		"run_id":           runID,
		"timestamp":        ts,
		"adapter":          adapter,
		"model":            model,
		"repo_key":         repoKey,
		"total_alerts":     len(alertsInput),
		"duration_seconds": math.Round(durationSec*100) / 100, // Python round(_,2)
	}
	if err := writeJSON(filepath.Join(runDir, "meta.json"), meta); err != nil {
		return "", err
	}
	if err := writeJSON(filepath.Join(runDir, "alerts_input.json"), alertsInput); err != nil {
		return "", err
	}
	if err := writeJSON(filepath.Join(runDir, "summary.json"), report); err != nil {
		return "", err
	}
	for _, tr := range traces {
		bh, _ := tr["bughash"].(string)
		if bh == "" {
			bh = "unknown"
		}
		if err := writeJSON(filepath.Join(runDir, "traces", TraceFilename(bh)), tr); err != nil {
			return "", err
		}
	}
	return runDir, nil
}

// DeleteRun 路径安全移植 runs.py:delete_run。
func DeleteRun(runsDir, runID string) bool {
	if runID == "" || strings.ContainsAny(runID, `/\`) || runID == "." || runID == ".." {
		return false
	}
	base, err := filepath.Abs(runsDir)
	if err != nil {
		return false
	}
	runDir, err := filepath.Abs(filepath.Join(base, runID))
	if err != nil {
		return false
	}
	if filepath.Dir(runDir) != base {
		return false
	}
	if info, err := os.Stat(runDir); err != nil || !info.IsDir() {
		return false
	}
	return os.RemoveAll(runDir) == nil
}

// WriteJSONFile 导出 JSON 落盘（MarshalIndent+WriteFile），供 cmd/server 写
// cmdb_link.json / cmdb_push.json 复用——不改 WriteRun 签名（避开 runs_test.go 形状回归）。
func WriteJSONFile(path string, v any) error { return writeJSON(path, v) }

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
