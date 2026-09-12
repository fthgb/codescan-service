package prompts

import (
	"strings"

	"appsecgo/internal/cwereg"
)

// falsify.go — 移植 appsec/prompts.py:467-502 的 falsify prompt。
// VERIFY_MODE=adversarial 时 judge.VerifyVerdict 后跑 falsify 二次验证轮。
//
// falsify 是"证伪"（falsify），不是"证实"（verify）：只删能直接证伪的，绝不删仅仅无法证实的。
// 输出 {exploitable, exploit_path, rationale} 证据（非 verdict），judge 按矩阵决定降级。

// falsifySystem 移植 _FALSIFY_SYSTEM (prompts.py:467-472)。逐字中文。
var falsifySystem = "你是一名渗透测试员，扮演攻击者。你只有浏览器，目标系统把下面这条数据流标成了若干漏洞类型。" +
	"逐步尝试构造利用路径，证明它**真能造成**其中至少一类的危害——危害须落在攻击者以外的人身上" +
	"（自害不算）。证不出利用就明确说证不出。**你是在证伪（falsify）一个判定，不是在证实（verify）" +
	"它对不对**：只删你能直接证伪的，绝不删仅仅无法证实的。\n\n" +
	UntrustedMaterial

// falsifySchema 移植 _FALSIFY_SCHEMA (prompts.py:474-475)。
var falsifySchema = `{"exploitable": true|false, "exploit_path": "利用路径字符串或 null", "rationale": "≤2 句, 引用 file:line"}`

// BuildFalsifyMessages 移植 build_falsify_messages (prompts.py:478-502)。
// 加载 actualTypes 各自 CWE 完整专家层（补 judge 轮盲区）；输出 {exploitable, exploit_path, rationale} 证据。
// 丢类型专家（yaml 缺失）跳过，不致命（铁律 D）。
func BuildFalsifyMessages(sliced map[string]any, actualTypes []string, declared string,
	reg *cwereg.Registry) []map[string]any {

	// CWE 专家层：actualTypes 去重保序，各加载 cweLayer
	var expertise strings.Builder
	seen := map[string]bool{}
	for _, t := range actualTypes {
		if seen[t] {
			continue
		}
		seen[t] = true
		if reg == nil {
			continue
		}
		cfg, ok := reg.ConfigForSlug(t)
		if !ok {
			continue
		}
		if cfg.CweID == "" || cfg.CweID == "UNKNOWN" {
			continue
		}
		expertise.WriteString("\n\n")
		expertise.WriteString(cweLayer(cfg))
	}

	// user message：声明类型 + actual + hops + schema 格式要求
	var u strings.Builder
	u.WriteString("## 声明类型：")
	u.WriteString(declared)
	u.WriteString("  AI 自产类型：")
	u.WriteString(formatStringList(actualTypes))
	hops, _ := sliced["hops"].([]map[string]any)
	for _, h := range hops {
		fb, _ := h["function_body"].(string)
		fence := SafeCodeFence(fb)
		fp, _ := h["file_path"].(string)
		fn, _ := h["function_name"].(string)
		tv, _ := h["taint_variable"].(string)
		lr, _ := h["line_range"].([]any)
		line0 := "0"
		if len(lr) > 0 {
			if v, ok := lr[0].(float64); ok {
				line0 = itoa(int(v))
			}
		}
		u.WriteString("\n\n### ")
		u.WriteString(fp)
		u.WriteString(":")
		u.WriteString(line0)
		u.WriteString(" fn=")
		u.WriteString(fn)
		u.WriteString(" taint_var=")
		u.WriteString(tv)
		u.WriteString("\n")
		u.WriteString(fence)
		u.WriteString("java\n")
		u.WriteString(fb)
		u.WriteString("\n")
		u.WriteString(fence)
	}
	u.WriteString("\n\n逐步构造利用路径证明上述类型里至少一类真能造成危害；证不出就说证不出。")
	u.WriteString("\n只输出 JSON：")
	u.WriteString(falsifySchema)

	return []map[string]any{
		{"role": "system", "content": falsifySystem + expertise.String()},
		{"role": "user", "content": u.String()},
	}
}

// formatStringList 渲染 []string 为 Python list 形 ["a","b"]。
func formatStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, s := range ss {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteByte('"')
		b.WriteString(s)
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return b.String()
}

// itoa 简单整数转字符串（避免 strconv import 冗余）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
