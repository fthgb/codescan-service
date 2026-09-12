package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	filePath := "D:\\neibu\\sec-service\\internal\\codescan\\appsec_push.go"
	b, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read failed:", err)
		os.Exit(1)
	}
	content := string(b)

	// 1. Add ReportPdfUrl field after ReportUrl line
	oldField := `ReportUrl          string ` + "`" + `json:"reportUrl"` + "`" + ``
	newFields := `ReportUrl          string ` + "`" + `json:"reportUrl"` + "`" + `
	ReportPdfUrl       string ` + "`" + `json:"reportPdfUrl"` + "`" + ``
	content = strings.Replace(content, oldField, newFields, 1)

	// 2. Don't write OSS URL to cs_report_url in registerAppsecTaskOnMiss
	content = strings.Replace(content,
		`CsReportUrl: req.ReportUrl,`,
		`CsReportUrl:  "", // changed: OSS URL goes to t_sec_code_appsec_report table`,
		1)

	// 3. Add AddAppsecReport call after createAppsecEvent, before SetTaskEvent
	insertPoint := `// 4. 回写 task.EventID 幂等。`
	insertCode := `// 3.5 存 appsec 报告链接到新表（不阻塞：失败只记日志，事件已建成功）
	if aerr := s.Database.AddAppsecReport(task.Id, req.AuditId, req.ReportUrl, req.ReportPdfUrl, req.Reviewer, req.ConfirmedTp, req.ConfirmedHardening, req.MaxSeverity); aerr != nil {
		s.Logger.Error("存 appsec 报告链接失败", zap.Int("taskId", task.Id), zap.Error(aerr))
	}

	// 4. 回写 task.EventID 幂等。`
	content = strings.Replace(content, insertPoint, insertCode, 1)

	// Write back
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write failed:", err)
		os.Exit(1)
	}
	fmt.Println("✓ appsec_push.go: 3 changes applied")
	fmt.Println("  1. Added ReportPdfUrl field to AppsecAuditPushRequest")
	fmt.Println("  2. Removed CsReportUrl: req.ReportUrl from registerAppsecTaskOnMiss")
	fmt.Println("  3. Added AddAppsecReport call after createAppsecEvent")
}
