package main

import (
	"database/sql"
	"fmt"
	"os"

	"appsecgo/internal/pandora"
	"appsecgo/internal/sca/dbstore"
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

	ddl := `CREATE TABLE IF NOT EXISTS t_sec_code_appsec_report (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  task_id     INT NOT NULL              COMMENT '关联 t_sec_code_task.id',
  audit_id    VARCHAR(255) NOT NULL     COMMENT 'appsecgo runID',
  report_html_url VARCHAR(1024)         COMMENT 'OSS HTML 报告链接',
  report_pdf_url  VARCHAR(1024)         COMMENT 'OSS PDF 报告链接',
  reviewer    VARCHAR(255)             COMMENT '复查人',
  reviewed_at DATETIME                  COMMENT '复查时间',
  confirmed_tp        INT DEFAULT 0     COMMENT '确认 TP 数',
  confirmed_hardening INT DEFAULT 0     COMMENT '确认需加固数',
  max_severity  VARCHAR(20)             COMMENT 'critical/high/medium/low',
  gmt_create  DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_audit_id (audit_id),
  INDEX idx_task_id (task_id)
) COMMENT='appsecgo 智能裁决报告链接'`

	_, err = db.Exec(ddl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CREATE TABLE failed:", err)
		os.Exit(1)
	}
	fmt.Println("✓ Table t_sec_code_appsec_report created (or already exists)")

	// Verify
	var name string
	err = db.QueryRow("SHOW TABLES LIKE 't_sec_code_appsec_report'").Scan(&name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify failed:", err)
		os.Exit(1)
	}
	fmt.Println("✓ Verified: table exists")

	// Create SCA tables (DDL from dbstore single source)
	for _, scaDDL := range dbstore.TableDDLs() {
		_, err = db.Exec(scaDDL)
		if err != nil {
			fmt.Fprintln(os.Stderr, "CREATE SCA TABLE failed:", err)
			os.Exit(1)
		}
	}
	fmt.Println("✓ SCA tables created (t_sec_sca_scan, t_sec_sca_component, t_sec_sca_finding)")
}
