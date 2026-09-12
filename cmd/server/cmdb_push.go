package main

// cmd/server/cmdb_push.go — appsecgo → sec-service → CMDB 推送端 handlers。
//
// 设计文档 §七 + 2026-09-01-appsecgo-cmdb-event-linkage-design.md。
// 两个路由（main.go 注册）：
//   - GET  /api/runs/{run_id}/push-preview  返推送状态 + 闸门计数，前端按钮态用这一个端点
//   - POST /api/runs/{run_id}/push-to-cmdb  三阶段写 cmdb_push.json + POST sec-service
//
// 契约（按 sec-service appsec-api.go 实际实现，非设计文档完整版）：
//   - sec-service 砍了 dispatch_id（proto+handler 都不校验）→ 手动模式 cmdb_link.dispatch_id 留空
//   - sec-service 没做 OSS report_html → 只发 reportUrl 链接
//   - JSON lowerCamelCase；key 在 body（= sec-service CsCallBackKey，env 配，密钥只走 env）
//   - all-FP 跳事件由 sec-service 判定（appsec-api.go:75 confirmed_tp==0&&confirmed_hardening==0），
//     appsecgo 照常 POST，sec-service 落 pushed_empty 并返 EventCreated:false

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"appsecgo/internal/cmdbpush"
	"appsecgo/internal/labels"
	"appsecgo/internal/report"
	"appsecgo/internal/reportpdf"
	"appsecgo/internal/runs"
	"appsecgo/internal/runsread"
	"appsecgo/internal/storage"
)

// cmdbLink — cmdb_link.json 形状（runPipeline 在 PkTask 非空时落盘）。
// dispatch_id 手动模式留空（sec-service 不校验，设计文档 §七-3）。
type cmdbLink struct {
	PkTask      string `json:"pk_task"`
	AppName     string `json:"app_name"`
	DispatchID  string `json:"dispatch_id"`
	CallbackURL string `json:"callback_url"`
	Source      string `json:"source"`
	RunID       string `json:"run_id"`
}

// cmdbPushResponse — sec-service AppsecAuditPush 响应 {eventId, eventCreated, alreadyPushed}。
type cmdbPushResponse struct {
	EventId       int32 `json:"eventId"`
	EventCreated  bool  `json:"eventCreated"`
	AlreadyPushed bool  `json:"alreadyPushed"`
}

// pushBody — push-to-cmdb 请求体（方案3：人工逐条勾选的 bughash 子集）。
// ForcePushBughashes：前端"强制派发"勾选——绕过非公网环境豁免（SSRF/越权仍派发），但仍留痕 env_exempted。
type pushBody struct {
	Bughashes          []string `json:"bughashes"`
	ForcePushBughashes []string `json:"force_push_bughashes"`
}

// readCMDBLink 读 <runDir>/cmdb_link.json。缺文件/pk_task 空 → error（handler 据 400 提示）。
func readCMDBLink(runDir string) (*cmdbLink, error) {
	b, err := os.ReadFile(filepath.Join(runDir, "cmdb_link.json"))
	if err != nil {
		return nil, err
	}
	var l cmdbLink
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	if l.PkTask == "" {
		return nil, fmt.Errorf("cmdb_link.pk_task empty")
	}
	return &l, nil
}

// readPushState 读 <runDir>/cmdb_push.json。缺文件 → (nil, err)（handler 视为 unpushed）。
func readPushState(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m, nil
}

// pickPrimaryAlert 取 ToPush 中 severity == maxSev 的首条（缺则 ToPush[0]，再缺 nil），
// 用于 dev_summary/severity_rationale/data_flow/suggested_fix（sec-service 兜底 [未提供]/修复漏洞，空不阻塞）。
func pickPrimaryAlert(toPush []map[string]any, maxSev string) map[string]any {
	for _, a := range toPush {
		if s, _ := a["severity"].(string); s == maxSev && maxSev != "" {
			return a
		}
	}
	if len(toPush) > 0 {
		return toPush[0]
	}
	return nil
}

// severityRank 本地严重度排序（critical>high>medium>low>其它=0）。
// cmdbpush.severityRank 未导出（gate.go），此处复制一份用于 countSelected 选最高严重度条。
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// countSelected 按勾选 bughash 子集算派发计数（方案3：人工勾选=背书真漏洞）。
// 口径：label==needs-hardening→hardening++；其它→tp++；confirmedFp=0（派发的非误报）；
// confirmedCount=勾选中 latest label status==confirmed 条数；maxSev/primary 取最高严重度条。
// 硬排除条（exclusion_reason!=""）即便被勾也跳过——从未进 judge，派发无意义。
func countSelected(details []map[string]any, latest map[string]map[string]any, bughashes []string) (tp, hardening, confirmedCount int, toPush []map[string]any, maxSev string, primary map[string]any) {
	set := make(map[string]bool, len(bughashes))
	for _, b := range bughashes {
		set[b] = true
	}
	for _, d := range details {
		b, _ := d["bughash"].(string)
		if !set[b] {
			continue
		}
		if er, _ := d["exclusion_reason"].(string); er != "" {
			continue
		}
		toPush = append(toPush, d)
		label := ""
		if lbl, hasLbl := latest[b]; hasLbl {
			label, _ = lbl["label"].(string)
			if st, _ := lbl["status"].(string); st == "confirmed" {
				confirmedCount++
			}
		}
		if label == "needs-hardening" {
			hardening++
		} else {
			tp++
		}
		if sev, _ := d["severity"].(string); severityRank(sev) > severityRank(maxSev) {
			maxSev = sev
		}
	}
	primary = pickPrimaryAlert(toPush, maxSev)
	return
}

// writeFailedState 落 cmdb_push.json failed 状态。httpCode=0 表示传输层失败（无响应码）。
func writeFailedState(path, errMsg string, httpCode int) {
	_ = runs.WriteJSONFile(path, map[string]any{
		"status":    "failed",
		"failed_at": time.Now().UTC().Format(time.RFC3339),
		"error":     errMsg,
		"http_code": httpCode,
	})
}

// resolveReportURL determines the report URL based on OSS availability and HTML content.
// When uploader is non-nil and reportHtml is non-empty, uploads HTML to OSS.
// On upload failure, returns error (caller should fail the push).
// When uploader is nil or HTML is empty, falls back to ExternalBaseURL or example.com.
// PDF upload is NOT handled here (reportpdf.RenderPDF is not mockable) — caller does it separately.
func resolveReportURL(uploader storage.Uploader, reportHtml, runID, externalBaseURL string) (string, error) {
	if uploader == nil || reportHtml == "" {
		reportUrl := "https://example.com/appsec-report-" + runID
		if externalBaseURL != "" {
			reportUrl = strings.TrimRight(externalBaseURL, "/") + "/api/runs/" + runID + "/report"
		}
		return reportUrl, nil
	}
	htmlUrl, err := uploader.UploadFile(runID+"-report.html", []byte(reportHtml))
	if err != nil {
		return "", err
	}
	return htmlUrl, nil
}

// GET /api/runs/{run_id}/push-preview — 推送状态 + 闸门信息计数。前端按钮态用这一个端点。
//
// status：unpushed | pushed | failed（pushing 卡住视为 failed，允许重试）。
// can_push：status!=pushed 且无阻塞理由（已关联任务、推送端已配）。
// 方案3：派发由人工勾选驱动，闸门不再阻塞——blocking_count/confirmed_* 仅作信息计数保留。
// reason：can_push=false 时的可读原因（前端禁用按钮 + tooltip）。
func pushPreviewHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	runDir := filepath.Join(serverCfg.RunsDir, runID)

	push, _ := readPushState(filepath.Join(runDir, "cmdb_push.json"))
	status := "unpushed"
	if push != nil {
		switch s, _ := push["status"].(string); s {
		case "pushed":
			status = "pushed"
		case "pushing": // pushing 卡住视为失败，允许重试（sec-service 幂等兜底）
			status = "failed"
		case "failed":
			status = "failed"
		}
	}

	data := runsread.GetRun(serverCfg.RunsDir, runID, serverCfg.LabelsPath)
	if data == nil {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	details, _ := data["details"].([]map[string]any)
	latest := labels.LatestByBughash(serverCfg.LabelsPath, runID)
	gate := cmdbpush.EvaluateGate(details, latest)

	reason := ""
	if status != "pushed" {
		if _, linkErr := readCMDBLink(runDir); linkErr != nil {
			reason = "未关联 codescan 任务（请从 Trigger 选任务触发）"
		} else if serverCfg.CmdbPushURL == "" || serverCfg.CmdbPushKey == "" {
			reason = "推送端未配置（APPSEC_CMDB_PUSH_URL / APPSEC_CMDB_KEY）"
		}
	}
	canPush := status != "pushed" && reason == ""

	out := map[string]any{
		"status":              status,
		"can_push":            canPush,
		"reason":              reason,
		"blocking_count":      gate.BlockingCount,
		"confirmed_tp":        gate.ConfirmedTp,
		"confirmed_fp":        gate.ConfirmedFp,
		"confirmed_hardening": gate.ConfirmedHardening,
		"confirmed_count":     gate.ConfirmedCount,
		"max_severity":        gate.MaxSeverity,
		"to_push_count":       len(gate.ToPush),
	}
	if push != nil {
		if v, ok := push["event_id"]; ok {
			out["event_id"] = v
		}
		if v, ok := push["error"]; ok {
			out["error"] = v
		}
	}
	writeJSON(w, out)
}

// POST /api/runs/{run_id}/push-to-cmdb — 方案3：接收人工勾选的 bughash 子集，三阶段写 + POST sec-service。
//
//  1. 幂等：cmdb_push.json==pushed → 透传现有结果，不重复 POST（sec-service AppsecStatus 亦兜底）
//  2. 解析 body {bughashes:[]}；空 → 400 未勾选待派发漏洞
//  3. 读 cmdb_link.json（无 → 400：未关联 codescan 任务）
//  4. runsread + countSelected（按勾选子集算 tp/hardening/confirmedCount/maxSev/primary）
//     全部硬排除/不在本 run → 400；闸门不再阻塞派发（仅 preview 信息用）
//  5. 组装 payload（reviewer=LabelerName, auditId=runID, reportUrl=ExternalBaseURL+report, confirmedFp=0）
//  6. 写 {status:pushing, bughashes}（写失败 → 500 阻塞，防半推）
//  7. POST sec-service（key 在 body，超时 30s）
//  8. 成功 → {status:pushed, event_id, bughashes, ...}；失败 → {status:failed, error}
//  9. 透传 sec-service 响应
func pushToCMDBHandler(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	runDir := filepath.Join(serverCfg.RunsDir, runID)
	pushPath := filepath.Join(runDir, "cmdb_push.json")

	// 1. 幂等：已推送直接返，不重复 POST
	if existing, _ := readPushState(pushPath); existing != nil {
		if s, _ := existing["status"].(string); s == "pushed" {
			writeJSON(w, existing)
			return
		}
		// pushing/failed → 继续重试
	}

	// 2. 解析勾选子集（方案3：人工逐条勾选→一次提交派发）
	var pb pushBody
	if err := json.NewDecoder(r.Body).Decode(&pb); err != nil {
		writeJSONError(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if len(pb.Bughashes) == 0 {
		writeJSONError(w, 400, "未勾选待派发漏洞（请逐条勾选「待派发」后提交）")
		return
	}

	// 3. cmdb_link.json
	link, err := readCMDBLink(runDir)
	if err != nil {
		writeJSONError(w, 400, "未关联 codescan 任务，请从 Trigger 选任务触发（缺 cmdb_link.json: "+err.Error()+"）")
		return
	}

	// 4. runsread + 按勾选子集算计数（gate 不再阻塞派发，仅 preview 信息用）
	data := runsread.GetRun(serverCfg.RunsDir, runID, serverCfg.LabelsPath)
	if data == nil {
		writeJSONError(w, 404, "run not found: "+runID)
		return
	}
	details, _ := data["details"].([]map[string]any)
	latest := labels.LatestByBughash(serverCfg.LabelsPath, runID)
	tp, hardening, confirmedCount, toPush, maxSev, _ := countSelected(details, latest, pb.Bughashes)
	if len(toPush) == 0 {
		writeJSONError(w, 400, "勾选的漏洞均无效（硬排除或不在本 run），请重新勾选")
		return
	}

	// 环境豁免：非公网应用的 SSRF/越权(TP)不派发（应用间调用无鉴权、SSRF 打不到公网元数据）。
	// 强制派发(force_push_bughashes)绕过豁免但仍留痕。sec-service app-is-public 查询失败→视作公网保留不剔。
	toPush, envExempted := filterEnvExemption(toPush, pb.ForcePushBughashes, link.AppName)
	if len(toPush) == 0 {
		// 全豁免且无强制 → 400 返豁免留痕给前端（前端可据 env_exempted 一键 force_push 补救）
		w.WriteHeader(400)
		writeJSON(w, map[string]any{
			"detail":       "勾选漏洞均因非公网环境豁免，无需派发工单",
			"env_exempted": envExempted,
		})
		return
	}
	// 剔除后重算计数，payload 反映实际派发子集（剔掉的 TP 不计入 confirmedTp，避免 sec-service 全 FP 误判跳事件）
	keptHashes := make([]string, 0, len(toPush))
	for _, d := range toPush {
		if b, _ := d["bughash"].(string); b != "" {
			keptHashes = append(keptHashes, b)
		}
	}
	tp, hardening, confirmedCount, _, maxSev, _ = countSelected(toPush, latest, keptHashes)

	// 5. 配置 + payload
	if serverCfg.CmdbPushURL == "" || serverCfg.CmdbPushKey == "" {
		writeJSONError(w, 503, "推送端未配置（APPSEC_CMDB_PUSH_URL / APPSEC_CMDB_KEY）")
		return
	}
	pkTaskInt, ierr := strconv.Atoi(link.PkTask)
	if ierr != nil {
		writeJSONError(w, 400, "cmdb_link.pk_task 非整数: "+link.PkTask)
		return
	}
	// 渲染派发子集 HTML 报告(只含勾选待派发条，复用 report.RenderHTML；报告内 isConfirmed 过滤 TP)。
	// 浅拷贝 data 替换 details=toPush，逐条读 trace 注入代码切片(trace 缺则步仅文字)。
	filtered := make(map[string]any, len(data))
	for k, v := range data {
		filtered[k] = v
	}
	filtered["details"] = toPush
	traces := map[string]map[string]any{}
	for _, a := range toPush {
		bh, _ := a["bughash"].(string)
		if bh == "" {
			continue
		}
		if t, ok := runsread.Trace(serverCfg.RunsDir, runID, bh).(map[string]any); ok && t != nil {
			traces[bh] = t
		}
	}
	reportHtml := ""
	if html, herr := report.RenderHTML(filtered, traces); herr == nil {
		reportHtml = html
	} else {
		fmt.Fprintf(os.Stderr, "warn: HTML render failed for run %s: %s (reportUrl fallback may be dead)\n",
			runID, herr.Error())
	}

	// 报告链接：OSS 上传 or 旧兜底（纯函数，可单测）
	reportUrl, htmlUploadErr := resolveReportURL(ossUploader, reportHtml, runID, serverCfg.ExternalBaseURL)
	if htmlUploadErr != nil {
		writeFailedState(pushPath, "OSS上传HTML失败: "+htmlUploadErr.Error(), 0)
		writeJSONError(w, 500, "报告上传失败(OSS): "+htmlUploadErr.Error())
		return
	}

	// PDF 附件（best-effort：失败不阻塞推送，reportPdfUrl 留空）
	reportPdfUrl := ""
	if ossUploader != nil && reportHtml != "" {
		if pdf, renderErr := reportpdf.RenderPDF(reportHtml); renderErr == nil {
			if pdfUrl, pdfUploadErr := ossUploader.UploadFile(runID+"-report.pdf", pdf); pdfUploadErr == nil {
				reportPdfUrl = pdfUrl
			} else {
				fmt.Fprintf(os.Stderr, "warn: OSS PDF upload failed for run %s: %s\n", runID, pdfUploadErr.Error())
			}
		} else {
			fmt.Fprintf(os.Stderr, "warn: PDF render failed for run %s: %s\n", runID, renderErr.Error())
		}
	}

	payload := map[string]any{
		"key":                serverCfg.CmdbPushKey,
		"pkTask":             pkTaskInt, // proto int32，须发数字非字符串
		"auditId":            runID,
		"reviewer":           serverCfg.LabelerName,
		"reviewedAt":         time.Now().UTC().Format(time.RFC3339),
		"confirmedTp":        tp,
		"confirmedFp":        0, // 派发的非误报（方案3：勾选=人工背书真漏洞）
		"confirmedHardening": hardening,
		"confirmedCount":     confirmedCount,
		"maxSeverity":        maxSev,
		"reportHtml":         reportHtml,
		"alertsTotal":        len(details),
		"reportUrl":          reportUrl,
		"reportPdfUrl":       reportPdfUrl,
		"appName":            link.AppName, // Path2 兜底：sec-service 不认识该 task 时按名建事件/登记
	}

	// 6. stage1：写 pushing + bughashes（写失败 → 500 阻塞，防半推）
	if werr := runs.WriteJSONFile(pushPath, map[string]any{
		"status":     "pushing",
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"pk_task":    link.PkTask,
		"audit_id":   runID,
		"bughashes":  pb.Bughashes,
	}); werr != nil {
		writeJSONError(w, 500, "写 cmdb_push.json(pushing) 失败: "+werr.Error())
		return
	}

	// 7. POST sec-service
	body, _ := json.Marshal(payload)
	httpReq, herr := http.NewRequestWithContext(r.Context(), http.MethodPost, serverCfg.CmdbPushURL, bytes.NewReader(body))
	if herr != nil {
		writeFailedState(pushPath, "构造请求失败: "+herr.Error(), 0)
		writeJSONError(w, 500, "推送失败: "+herr.Error())
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, perr := client.Do(httpReq)
	if perr != nil {
		writeFailedState(pushPath, "HTTP 请求失败: "+perr.Error(), 0)
		writeJSONError(w, 502, "推送失败: "+perr.Error())
		return
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)

	// 8. 非 2xx → failed
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeFailedState(pushPath, fmt.Sprintf("sec-service %d: %s", resp.StatusCode, string(rb)), resp.StatusCode)
		writeJSONError(w, 502, fmt.Sprintf("sec-service 返回 %d: %s", resp.StatusCode, string(rb)))
		return
	}

	// 9. stage2：写 pushed + 透传
	var pr cmdbPushResponse
	_ = json.Unmarshal(rb, &pr)
	pushed := map[string]any{
		"status":              "pushed",
		"pushed_at":           time.Now().UTC().Format(time.RFC3339),
		"event_id":            pr.EventId,
		"event_created":       pr.EventCreated,
		"already_pushed":      pr.AlreadyPushed,
		"confirmed_tp":        tp,
		"confirmed_hardening": hardening,
		"max_severity":        maxSev,
		"bughashes":           pb.Bughashes,
		"env_exempted":        envExempted, // 非公网豁免留痕（强制派发的 forced=true）
	}
	_ = runs.WriteJSONFile(pushPath, pushed)
	writeJSON(w, pushed)
}

// healthzHandler — K8s/反代存活探针（withAuth 直通，设计文档 §七-1）。
func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
