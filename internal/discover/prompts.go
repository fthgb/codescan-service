package discover

import (
	"fmt"
	"strconv"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/prompts"
)

// DiscoverySchema mirrors prompts.py:DISCOVERY_SCHEMA (the JSON contract a
// discovery judge returns). disposition is 3-value (no likely_fp/out_of_scope —
// discovery is skeptical-but-binary-ish); vulnerability_type is an OUTPUT.
// The literal "\n" inside suggested_fix is a backslash-n (two chars), matching
// the Python `\\n` source byte-for-byte.
const DiscoverySchema = `{"disposition": "true_positive|likely_tp|false_positive", "vulnerability_type": "如 sql_injection|xss|path_traversal|command_injection|ssrf|… 或 none", "confidence": 1-10, "exploit_path": {"entry_point": "file:line", "data_flow": ["..."], "sink_reached": bool, "attacker_control_at_sink": "full|partial|none", "path_broken_at": "字符串或 null"}, "reasoning": "≤3 句", "severity": "critical|high|medium|low 或 null", "severity_rationale": "字符串或 null", "suggested_fix": "[file:line] 修改前片段 → 修改后片段\n说明：一句话；前/后从切片逐字摘取，无法给具体补丁则 null"}`

// discoverySystemBody is the task-specific body of the discovery system prompt
// (prompts.py:408-417). It ends with a blank line (trailing "\n\n") so that
// concatenating UntrustedMaterial lands on its own paragraph — byte-exact with
// the Python `"""...\n\n""" + UNTRUSTED_MATERIAL` source.
const discoverySystemBody = `你是一名安全分析师，正在审查来自代码 diff 的一个变更（CHANGED）函数，找其中新引入的漏洞（没有给定 SAST 发现 —— 需要你自己找）。

保持怀疑（skeptical）：大多数代码并无漏洞。只有当你能 (1) 构造一个具体（concrete）的攻击者载荷、(2) 证明它在本函数内到达一个危险操作、(3) 说明攻击者得到什么时，才报告漏洞。若做不到，disposition 为 false_positive（无漏洞）。按对应用暴露面/威胁模型的可利用性判断，不要靠表面模式。只输出一个 JSON 对象。

守卫/净化器只有在污点值确实流经（passes through）它、再到达 sink 时才算数；作用在另一个变量上的检查，或被该值绕过的检查（原始值另被使用，或事后重新拼接），都不能使其安全。若某个未展示的仓库内调用（见下方任何「注意」）位于利用路径上、而你无法判断其效果，返回 likely_tp —— 不要 false_positive。

- disposition：true_positive（已展示具体攻击）、likely_tp（看似可能但可达性不明 —— 优先选它，而不是猜安全）、或 false_positive（这里没发现漏洞）。
- vulnerability_type：若发现漏洞则填其 CWE 类别 slug，否则填 "none"。
- severity（仅在发现漏洞时），相对暴露面：critical=RCE/认证绕过/远程读写他人数据；high=敏感泄露/打到内网的 SSRF/稳定远程 DoS；medium=有限/有条件；low=仅本地/理论性/被强力缓解。

`

// DiscoverySystemPrompt mirrors prompts.py:DISCOVERY_SYSTEM_PROMPT: the
// skeptical discovery body + the shared UNTRUSTED_MATERIAL / CHINESE_OUTPUT
// directives (single source of truth across judge / discovery / arbitration,
// 铁律 E) + the JSON schema.
var DiscoverySystemPrompt = discoverySystemBody +
	prompts.UntrustedMaterial + "\n\n" + prompts.ChineseOutput +
	"\n\n所需 JSON schema：" + DiscoverySchema

// BuildDiscoveryMessages mirrors prompts.py:build_discovery_messages (Line B
// prompt). hops[0] is the changed function (tag "（变更的函数）"); later hops are
// enriched callees (tag "（被拉入 —— 由 X 调用）"). enrichment_note flags unseen
// in-repo callees so the judge follows P3. Returns OpenAI-shape [system, user].
func BuildDiscoveryMessages(sliced *contract.SlicedContext, appCtx map[string]any) []map[string]any {
	entry := sliced.EntryPointSignature
	if entry == "" {
		entry = "?"
	}
	parts := []string{
		prompts.RenderAppContext(appCtx),
		"## 待审查的变更函数：" + entry,
	}
	for _, h := range sliced.Hops {
		tag := "（变更的函数）"
		if h.ExpandedFrom != nil && *h.ExpandedFrom != "" {
			tag = fmt.Sprintf("（被拉入 —— 由 %s 调用）", *h.ExpandedFrom)
		}
		line := strconv.Itoa(h.LineRange[0])
		fence := prompts.SafeCodeFence(h.FunctionBody)
		parts = append(parts, fmt.Sprintf(
			"### %s:%s fn=%s%s\n%sjava\n%s\n%s",
			h.FilePath, line, h.FunctionName, tag, fence, h.FunctionBody, fence))
	}
	if sliced.EnrichmentNote != nil && *sliced.EnrichmentNote != "" {
		parts = append(parts, "注意："+*sliced.EnrichmentNote)
	}
	return []map[string]any{
		{"role": "system", "content": DiscoverySystemPrompt},
		{"role": "user", "content": strings.Join(parts, "\n\n")},
	}
}
