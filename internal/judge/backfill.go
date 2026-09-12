package judge

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/llm"
)

// backfill.go —— B1:确认漏洞缺必填展示字段时补问一次(spec 见 2026-08-23 报告完整性 TODO)。
//
// # 事实
//
// rt 实测 2/7 条确认漏洞,模型**根本没输出** dev_summary / design_note / suggested_fix /
// severity 这几个键(原始输出无污染、无解析失败、fail_reason 为空)。报告里那两条有标题、
// 有数据流、有判据,却没有成因、没有修复、没有严重度 —— 读者看到半张卡。
// 根因不是解析丢失,所以渲染层修不了。
//
// # 为什么是「补问」
//
// 用户 2026-08-21 定过铁律级口径:dev 报告不得暴露「未证实/缺失」叙述(开发看到反手不修)。
// 标「模型未提供」会撞该口径;把缺字段的 TP 降格展示又违背铁律 C(漏报比标错更严重)。
// 故补问 —— **只要字段,不重判**。
//
// # 红线(有测试反向钉住)
//
// verdict / confidence / disposition / exploit_path 一律不得被补问结果改动。
// 补问是**展示层补全**,不是第二次判决 —— 让它能改判就等于给模型一次翻案机会,
// 会绕过所有守卫(EnforceEvidenceOnTp / EnforceGroundedDataFlow / falsify …)。

// backfillMode —— B1 gate。**默认 "on"**:它只在「确认漏洞缺必填展示字段」时才触发
// (实测约 1/7 的 TP),而那正是报告出现半张卡的唯一成因;默认关等于默认接受半张卡。
// APPSEC_BACKFILL_DEV_FIELDS=off 兜底。
//
// 用包级 gate 而非 JudgeOne 参数:该签名已有 14 个参数,再加一个会波及全部调用方与
// fixture,而这个门与判决语义无关(纯展示补全),不值得那个代价(铁律 D 耦合点最小化)。
var backfillMode = func() string {
	if v := os.Getenv("APPSEC_BACKFILL_DEV_FIELDS"); v != "" {
		return v
	}
	return "on"
}()

// SetBackfillMode 供测试与调用方显式覆盖 gate。
func SetBackfillMode(m string) { backfillMode = m }

// backfillFields —— 会被补问的字段(全部是**展示用**自由文本/枚举,无一进入判决链)。
var backfillFields = []string{"dev_summary", "design_note", "suggested_fix", "severity", "severity_rationale"}

// needsBackfill 报告该结果是否缺任一必填展示字段。
// 只管会进报告的判决:true_positive(确认节)与 likely_tp(疑似节)。
func needsBackfill(r contract.JudgeResult) []string {
	if r.Verdict != "true_positive" && ptrStr(r.Disposition) != "likely_tp" {
		return nil
	}
	var missing []string
	for _, f := range backfillFields {
		if contract.IsNullish(fieldOf(r, f)) {
			missing = append(missing, f)
		}
	}
	return missing
}

func fieldOf(r contract.JudgeResult, f string) string {
	switch f {
	case "dev_summary":
		return ptrStr(r.DevSummary)
	case "design_note":
		return ptrStr(r.DesignNote)
	case "suggested_fix":
		return ptrStr(r.SuggestedFix)
	case "severity":
		return ptrStr(r.Severity)
	case "severity_rationale":
		return ptrStr(r.SeverityRationale)
	}
	return ""
}

// BackfillDevFields 在缺必填展示字段时补问一次,只写回缺的那几个字段。
//
// mode != "on" → 零行为(零回归门)。任何失败(provider 错/解析失败/补问仍不遵从)
// → 原样返回,绝不阻断判决链(fail-open)。
func BackfillDevFields(result contract.JudgeResult, sliced map[string]any,
	harness llm.Provider, model, mode string) (contract.JudgeResult, map[string]any) {
	info := map[string]any{}
	if mode != "on" || harness == nil {
		return result, info
	}
	missing := needsBackfill(result)
	if len(missing) == 0 {
		return result, info
	}
	info["backfill_missing"] = missing
	resp, err := harness.Complete(context.Background(), llm.Request{
		Messages: buildBackfillMessages(result, sliced, missing), MaxTokens: 2048,
	})
	if err != nil {
		info["backfill_error"] = err.Error()
		return result, info
	}
	data, perr := ParseJudgeOutput(resp.Text)
	if perr != nil {
		info["backfill_error"] = "parse: " + perr.Error()
		return result, info
	}
	RecoverArgFramingInto(data) // 补问同样可能撞 I6 provider 框架标记
	filled := 0
	for _, f := range missing {
		v, _ := data[f].(string)
		if contract.IsNullish(v) {
			continue // 补问也不遵从 → 不把 "null" 当真值写回(GR-8)
		}
		if f == "severity" {
			v = strings.ToLower(strings.TrimSpace(v))
			if v != "critical" && v != "high" && v != "medium" && v != "low" {
				continue // 枚举外的值一律不收(与 BuildJudgeResult 同口径)
			}
		}
		setField(&result, f, v)
		filled++
	}
	// **刻意只读 backfillFields**:data 里若带了 verdict/confidence/exploit_path 一律无视。
	info["backfill_run"] = true
	info["backfill_filled"] = filled
	return result, info
}

func setField(r *contract.JudgeResult, f, v string) {
	switch f {
	case "dev_summary":
		r.DevSummary = &v
	case "design_note":
		r.DesignNote = &v
	case "suggested_fix":
		r.SuggestedFix = &v
	case "severity":
		r.Severity = &v
	case "severity_rationale":
		r.SeverityRationale = &v
	}
}

// buildBackfillMessages —— 补问 prompt(中文,铁律 E)。
//
// 必须携带**已定的判决**并明令不要重判:不给的话模型会重新推理,可能产出与判决矛盾的成因
// (「这段代码现在会发生什么」写成「不构成漏洞」)。
func buildBackfillMessages(r contract.JudgeResult, sliced map[string]any, missing []string) []map[string]any {
	b, _ := json.Marshal(sliced)
	sys := `你在补全一份已完成的安全判定报告。判定**已经做完并且不可更改** —— 你的唯一任务是把下面列出的缺失字段补上。
不要重新判定，不要质疑判定结论，不要输出 verdict / confidence / disposition / exploit_path（输出了也会被丢弃）。
只输出一个 JSON 对象，键就是要补的字段名。`
	usr := "已判定结果（不可更改）：\n" +
		"- verdict: " + r.Verdict + "\n" +
		"- disposition: " + ptrStr(r.Disposition) + "\n" +
		"- 漏洞类型: " + ptrStr(r.VulnerabilityType) + "\n" +
		"- 判定理由: " + r.Reasoning + "\n\n" +
		"缺失字段：" + strings.Join(missing, "、") + "\n\n" +
		fieldSpecs(missing) + "\n" +
		"代码切片：\n" + string(b)
	return []map[string]any{
		{"role": "system", "content": sys},
		{"role": "user", "content": usr},
	}
}

// fieldSpecs —— 各字段的填写口径,与 JudgeSchema 同源语义(勿另造一套说法)。
func fieldSpecs(missing []string) string {
	spec := map[string]string{
		"dev_summary":        `dev_summary：给不懂安全的后端开发的一句话——谁（未登录的人/任意登录用户）能通过哪个接口做成什么事；术语首次出现须括号解释。`,
		"design_note":        `design_note：先承认原设计里合理的部分、再指出缺的那一步，句式「……本身没问题，问题是……」。`,
		"suggested_fix":      `suggested_fix：①首选锚点补丁 "[file:line] 修改前片段 → 修改后片段" 换行接 "说明：一句话"，修改前须从切片逐字摘取，改后代码里被判为 sink 的那处写法必须消失；②切片里连一行可摘取的锚点代码都没有时退到 "[file:line] 说明：应在此处补上 X"，X 点名具体控制。不得只给一侧，不得空泛。`,
		"severity":           `severity：critical|high|medium|low 之一（相对本应用的暴露面）。`,
		"severity_rationale": `severity_rationale：说明定级依据，并写出什么额外证据会让它升级或降级；禁止循环论证。`,
	}
	var out []string
	for _, f := range missing {
		if s, ok := spec[f]; ok {
			out = append(out, "- "+s)
		}
	}
	return strings.Join(out, "\n")
}
