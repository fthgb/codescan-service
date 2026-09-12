// Package cmdbpush — 推送到 CMDB 前的人工闸门判定（纯函数，便于单测）。
//
// 规则（设计文档 §七-5 折中 + F2 hard-excluded verdict attribution）：
//   - 跳过 exclusion_reason != "" 的硬排除条目（F2：它们从未送进 judge，verdict 是占位）
//   - AI verdict ∈ {true_positive, uncertain} 且 (无人工标注 或 标注=uncertain) → 拦住推送
//   - AI verdict = false_positive 且无标注 → 放行（信 AI，噪音低），计入 confirmedFp
//   - 进 CMDB 的 alert = 人工标注 true_positive 或 needs-hardening
//   - confirmedFp = 最终判定为误报的条数：人工标 false_positive，或（无标注时）AI verdict=false_positive
//
// sec-service appsec-api.go:75 的 all-FP 跳事件只看 confirmed_tp==0 && confirmed_hardening==0，
// 不看 confirmed_fp；confirmed_fp 仅进事件详情"误报%d个"（line 192），故须含 AI 信任的 FP。
//
// 一句话：AI 判 TP 或 uncertain 的 alert，必须有人工标注且标注不是 uncertain。
package cmdbpush

// severity 词表两侧同（JudgeResult.Severity / CMDB risk_level，设计文档 §一-5），无需映射层。
var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// GateResult — 闸门判定结果。handler 据此决定 409 / 组装 payload。
type GateResult struct {
	Blocked            bool
	BlockingCount      int
	ConfirmedTp        int
	ConfirmedFp        int
	ConfirmedHardening int
	ConfirmedCount     int // latest 中 status=="confirmed" 的条数
	MaxSeverity        string
	ToPush             []map[string]any // label∈{true_positive,needs-hardening} 的 alert
}

// EvaluateGate 判定能否推送 + 凑计数。
//   - details：runsread.GetRun 返回的 details（已 overlay label/labeler/labelled_at）
//   - latest：labels.LatestByBughash 返回的 run 内每 bughash 最新标签 record（含 status）
func EvaluateGate(details []map[string]any, latest map[string]map[string]any) GateResult {
	var res GateResult
	for _, d := range details {
		if reason, _ := d["exclusion_reason"].(string); reason != "" {
			continue // 硬排除条目：从未送进 judge，不占人工标注预算
		}
		verdict, _ := d["verdict"].(string)
		label, _ := d["label"].(string) // nil → ""（runsread overlay：未命中设 nil）
		hasLabel := label != ""

		// 闸门：AI 判 TP/uncertain 必须有人工标注且标注不是 uncertain
		if verdict == "true_positive" || verdict == "uncertain" {
			if !hasLabel || label == "uncertain" {
				res.Blocked = true
				res.BlockingCount++
			}
		}
		// false_positive 无标注 → 放行（信 AI）

		// 按"最终判定"凑计数（信任模型：信 AI 的 FP，不信 AI 的 TP/uncertain）。
		// 进 CMDB：label∈{true_positive,needs-hardening}；FP = 人工标 false_positive 或（无标注时）AI verdict=false_positive。
		switch {
		case label == "true_positive":
			res.ConfirmedTp++
			res.ToPush = append(res.ToPush, d)
		case label == "needs-hardening":
			res.ConfirmedHardening++
			res.ToPush = append(res.ToPush, d)
		case label == "false_positive", !hasLabel && verdict == "false_positive":
			res.ConfirmedFp++
		}

		// confirmed count：detail overlay 没带 status，从 latest record 取
		if hasLabel {
			if bh, _ := d["bughash"].(string); bh != "" {
				if rec, ok := latest[bh]; ok {
					if st, _ := rec["status"].(string); st == "confirmed" {
						res.ConfirmedCount++
					}
				}
			}
		}
	}
	res.MaxSeverity = maxSeverity(res.ToPush)
	return res
}

// maxSeverity 取 ToPush 中最高 severity（critical>high>medium>low）；空返 ""。
func maxSeverity(alerts []map[string]any) string {
	best := 0
	var bestName string
	for _, a := range alerts {
		sev, _ := a["severity"].(string)
		if r := severityRank[sev]; r > best {
			best = r
			bestName = sev
		}
	}
	return bestName
}
