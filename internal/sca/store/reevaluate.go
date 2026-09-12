package store

import (
	"path/filepath"
	"time"

	"appsecgo/internal/runs"
	"appsecgo/internal/sca/policy"
)

// ReEvaluate — 离线重判（spec §五）：读 raw_osv.json（ScanResult 序列化）→
// 跑 policy → 覆盖 findings.json + 重算 meta 计数 → meta 追加 re_evaluated_at +
// policy_version_on_re_eval。不做 findings 多版本快照（raw 永不变 + 策略文件进 git，
// 历史结论可确定性重建，YAGNI）。幂等：重复重判结果一致。
func ReEvaluate(scaRunsDir, scanID string, pol *policy.Policy) error {
	scanDir := filepath.Join(scaRunsDir, scanID)
	meta, _, _, err := Load(scaRunsDir, scanID)
	if err != nil {
		return err
	}
	res, err := LoadRaw(scaRunsDir, scanID)
	if err != nil {
		return err
	}
	newFindings := policy.Evaluate(pol, res)
	meta.FindingsCount = len(newFindings)
	meta.FindingsBySeverity = map[string]int{}
	for _, f := range newFindings {
		meta.FindingsBySeverity[f.Severity]++
	}
	meta.ReEvaluatedAt = time.Now().UTC().Format(time.RFC3339)
	meta.PolicyVersionOnReEval = pol.Version
	if err := runs.WriteJSONFile(filepath.Join(scanDir, "findings.json"), newFindings); err != nil {
		return err
	}
	return UpdateMeta(scaRunsDir, scanID, *meta)
}
