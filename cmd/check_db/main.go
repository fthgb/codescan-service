package main

import (
	"database/sql"
	"fmt"
	"os"

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

	// 查 task_codescan 表（pk_task=68618）
	fmt.Println("=== task_codescan (cs_task_id=68618) ===")
	rows, err := db.Query("SELECT id, task_id, cs_task_id, cs_task_status, cs_report_url, gmt_create FROM t_sec_code_task_codescan WHERE cs_task_id = 68618")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query task_codescan failed:", err)
	} else {
		for rows.Next() {
			var id, taskID, csTaskID, csStatus int
			var csReportUrl string
			var gmtCreate sql.NullString
			rows.Scan(&id, &taskID, &csTaskID, &csStatus, &csReportUrl, &gmtCreate)
			fmt.Printf("id=%d task_id=%d cs_task_id=%d status=%d report_url=%s\n", id, taskID, csTaskID, csStatus, csReportUrl)
		}
		rows.Close()
	}

	// 查 task 表（event_id）
	fmt.Println("\n=== task (look for event_id) ===")
	rows2, err := db.Query("SELECT id, app_name, event_id, giturl FROM t_sec_code_task WHERE id IN (SELECT task_id FROM t_sec_code_task_codescan WHERE cs_task_id = 68618) UNION SELECT id, app_name, event_id, giturl FROM t_sec_code_task WHERE app_name = 'ff-underwrite-offline' ORDER BY id DESC LIMIT 5")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query task failed:", err)
	} else {
		for rows2.Next() {
			var id, eventID int
			var appName, giturl string
			rows2.Scan(&id, &appName, &eventID, &giturl)
			fmt.Printf("id=%d app=%s event_id=%d git=%s\n", id, appName, eventID, giturl)
		}
		rows2.Close()
	}

	// 查所有 ff-underwrite-offline 相关的 task
	fmt.Println("\n=== all tasks with app_name=ff-underwrite-offline ===")
	rows3, err := db.Query("SELECT id, app_name, event_id FROM t_sec_code_task WHERE app_name = 'ff-underwrite-offline'")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query all tasks failed:", err)
	} else {
		for rows3.Next() {
			var id, eventID int
			var appName string
			rows3.Scan(&id, &appName, &eventID)
			fmt.Printf("id=%d app=%s event_id=%d\n", id, appName, eventID)
		}
		rows3.Close()
	}
}
