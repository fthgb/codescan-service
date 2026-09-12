package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"appsecgo/internal/pandora"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	cfg, err := pandora.Load("config/config.yaml")
	if err != nil {
		fmt.Fprintln(os.Stderr, "pandora load failed:", err)
		os.Exit(1)
	}
	db, err := sql.Open("mysql", cfg.DB.DatabaseLink)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sql.Open failed:", err)
		os.Exit(1)
	}
	defer db.Close()

	// 1. 更新 report_url：把外网地址改为内网地址
	old := "https://cathay-ops-sh.oss-cn-shanghai-finance-1.aliyuncs.com/"
	newURL := "https://cathay-ops-sh.oss-cn-shanghai-finance-1-internal.aliyuncs.com/"
	_, err = db.Exec("UPDATE t_sec_code_task_codescan SET cs_report_url = REPLACE(cs_report_url, ?, ?) WHERE cs_report_url LIKE ?",
		old, newURL, old+"%")
	if err != nil {
		fmt.Fprintln(os.Stderr, "UPDATE report_url failed:", err)
		os.Exit(1)
	}
	fmt.Println("✓ Updated report_url: external → internal")

	// 2. 重置 task 1601 的 event_id 为 0，让下次派发能创建新事件（带新的内网URL）
	_, err = db.Exec("UPDATE t_sec_code_task SET event_id = 0 WHERE id = 1601")
	if err != nil {
		fmt.Fprintln(os.Stderr, "UPDATE event_id failed:", err)
		os.Exit(1)
	}
	fmt.Println("✓ Reset event_id=0 for task 1601 (next push will create new event)")

	// 3. 验证
	var url string
	db.QueryRow("SELECT cs_report_url FROM t_sec_code_task_codescan WHERE cs_task_id = 68618").Scan(&url)
	fmt.Println("\nNew report_url:", url)
	if strings.Contains(url, "-internal") {
		fmt.Println("✓ URL confirmed as internal endpoint")
	} else {
		fmt.Println("⚠ URL does not contain -internal, check manually")
	}
}
