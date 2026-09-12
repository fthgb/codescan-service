package main

// cmd/server/cmdb_push_envexempt.go — 派发时按应用网络环境剔除 SSRF/越权（非公网不报）。
//
// 业务口径（2026-09-02）：内网/办公网系统的 SSRF、越权漏洞不派发工单——
// 应用间调用本不该有权限校验，SSRF 也打不到公网元数据。口径简化为公网 vs 非公网二分：
// 只要不是公网（办公网/内网/查无 ingress）的 SSRF/越权 TP，派发时剔除。
//
// 数据流：cmdb_push.go 派发时用 cmdb_link.app_name 调 sec-service app-is-public 接口实时查
// （不建表、不依赖 trigger 带值，Path1/Path2 两路径 cmdb_link.json 都有 app_name）。
//
// 降误杀三层（核心，详见 plan jaunty-soaring-kahn.md）：
//  1. 只用主类型 actual_vulnerability_type（不用多面 actual_vulnerability_types[]）——防"SQL注入顺带提 IDOR"被误剔
//  2. 只剔 verdict==true_positive——uncertain 的越权/SSRF 保留人工看
//  3. 时机 C 可挽回——漏洞仍在 run 数据/前端；force_push_bughashes 强制派发 + env_exempted 留痕

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// envExemptTypes — 非公网环境豁免的漏洞主类型族（LLM 归一 slug，NormalizeVulnType 原样保留不校验白名单）。
// SSRF：打不到公网元数据；越权族：应用间调用无鉴权。
// 同时收 `-` 与 `_` 两种分隔（LLM 自产 slug 不保证统一）。
var envExemptTypes = map[string]bool{
	"ssrf": true,
	// 越权族（LLM 归一 slug；- 与 _ 两种分隔都收，LLM 自产 slug 不保证统一）
	"idor":                             true,
	"missing-auth":                     true,
	"missing-authorization":            true,
	"missing-authz":                    true,
	"missing-authentication":           true,
	"broken-access-control":            true,
	"broken_access_control":            true,
	"privilege-escalation":             true,
	"privilege_escalation":             true,
	"missing_auth":                     true, // _ 形式（实测 runs 数据）
	"missing_authorization":            true,
	"authorization-bypass":             true, // 越权变体（实测）
	"authorization_bypass":             true,
	"excessive-granularity-permission": true, // 权限过宽（实测 cwe-1060 系）
	"excessive_granularity_permission": true,
	// CWE 编号形式（NormalizeVulnType 未转的越权相关 cwe，registry 缺映射原样保留）
	"cwe-862": true, // Missing Authorization（越权）
	"cwe-639": true, // IDOR（越权）
	"cwe-1060-excessive-granularity-permission": true, // 权限过宽（无独立 slug）
	"cwe-1060": true,
}

// envExemptMatch 判定主类型是否属非公网豁免族。
// 先精确匹配；再对 "cwe-xxx: desc" 形式取冒号前缀匹配（实测有 "cwe-862: missing authorization"）。
// 未覆盖的变体（含数字编码如 "02000010070033"、非标准 slug）→ 不匹配 → 保留不剔（保守，宁漏剔不误杀）。
func envExemptMatch(vt string) bool {
	if envExemptTypes[vt] {
		return true
	}
	if i := strings.IndexByte(vt, ':'); i > 0 {
		return envExemptTypes[vt[:i]]
	}
	return false
}

// queryAppIsPublic 调 sec-service app-is-public 接口查 appName 是否公网暴露。
// URL 从 serverCfg.CmdbPushURL 推导（同 host，path 改 /sec/v1/codecheck/appsec/app-is-public），
// query 带 key=CmdbPushKey&appName=。
// **调用失败/非 200/解析失败 → 返 true（保守：保留不剔，不因查询故障误剔真漏洞）**。
func queryAppIsPublic(appName string) bool {
	if appName == "" || serverCfg.CmdbPushURL == "" || serverCfg.CmdbPushKey == "" {
		return true // 空名/未配置 → 保守保留不剔
	}
	u, err := url.Parse(serverCfg.CmdbPushURL)
	if err != nil || u.Host == "" {
		return true
	}
	u.Path = "/sec/v1/codecheck/appsec/app-is-public"
	q := u.Query()
	q.Set("key", serverCfg.CmdbPushKey)
	q.Set("appName", appName)
	u.RawQuery = q.Encode()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return true
	}
	var res struct {
		IsPublic bool `json:"isPublic"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return true
	}
	return res.IsPublic
}

// envExemptRecord 构造一条留痕记录（写 cmdb_push.json env_exempted）。
func envExemptRecord(d map[string]any, vt, reason string, forced bool) map[string]any {
	bh, _ := d["bughash"].(string)
	sev, _ := d["severity"].(string)
	return map[string]any{
		"bughash":  bh,
		"type":     vt,
		"severity": sev,
		"reason":   reason,
		"forced":   forced,
	}
}

// filterEnvExemption 按应用网络环境剔除非公网的 SSRF/越权 TP。
//
// 返回 (kept, exempted)：
//   - kept：实际派发子集（含强制派发的豁免条）
//   - exempted：被豁免条留痕（强制派发的也在此，forced=true）
//
// 规则（保守口径，降误杀）：
//   - isPublic（查 sec-service 失败→true）→ 全保留，无豁免
//   - 非公网 + 主类型 actual_vulnerability_type ∈ 豁免族 + verdict==true_positive → 豁免
//   - 主类型空 / verdict 非 TP / 类型不在豁免族 → 保留不剔
//   - forceBughashes 命中的豁免条 → 并入 kept 派发，但仍在 exempted 留痕(forced=true)
func filterEnvExemption(toPush []map[string]any, forceBughashes []string, appName string) (kept, exempted []map[string]any) {
	isPublic := queryAppIsPublic(appName)
	if isPublic {
		return toPush, []map[string]any{} // 公网应用：全派发，无环境豁免（空切片序列化为 []）
	}
	forceSet := make(map[string]bool, len(forceBughashes))
	for _, b := range forceBughashes {
		forceSet[b] = true
	}
	for _, d := range toPush {
		bh, _ := d["bughash"].(string)
		vt, _ := d["actual_vulnerability_type"].(string) // 主类型（LLM 归一真值），空→保留不剔
		verdict, _ := d["verdict"].(string)
		// 只剔 TP；uncertain/FP 的越权 SSRF 保留人工看（降误杀②）
		if vt == "" || verdict != "true_positive" || !envExemptMatch(vt) {
			kept = append(kept, d)
			continue
		}
		// 非公网 + 豁免族 + TP → 豁免（强制派发则并入 kept 但留痕 forced）
		rec := envExemptRecord(d, vt, "非公网环境 SSRF/越权豁免", forceSet[bh])
		exempted = append(exempted, rec)
		if forceSet[bh] {
			kept = append(kept, d)
		}
	}
	if kept == nil {
		kept = []map[string]any{}
	}
	if exempted == nil {
		exempted = []map[string]any{}
	}
	return
}
