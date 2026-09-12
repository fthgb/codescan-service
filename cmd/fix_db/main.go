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
	if cfg.DB.DatabaseLink == "" {
		fmt.Fprintln(os.Stderr, "database.link is empty in pandora config")
		os.Exit(1)
	}
	fmt.Println("DB link loaded, connecting...")

	db, err := sql.Open("mysql", cfg.DB.DatabaseLink)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sql.Open failed:", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, "db.Ping failed:", err)
		os.Exit(1)
	}
	fmt.Println("Connected to MySQL.")

	// 1. 查看当前列定义
	var createStmt string
	err = db.QueryRow("SHOW CREATE TABLE t_sec_code_task_codescan").Scan(&ignore, &createStmt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SHOW CREATE TABLE failed:", err)
		os.Exit(1)
	}
	fmt.Println("\n--- Current table DDL (cs_report_url line) ---")
	for _, line := range splitLines(createStmt) {
		if contains(line, "cs_report_url") {
			fmt.Println(line)
		}
	}

	// 2. 改列长度为 VARCHAR(1024)
	fmt.Println("\n--- Altering cs_report_url to VARCHAR(1024) ---")
	_, err = db.Exec("ALTER TABLE t_sec_code_task_codescan MODIFY COLUMN cs_report_url VARCHAR(1024) DEFAULT ''")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ALTER TABLE failed:", err)
		os.Exit(1)
	}
	fmt.Println("Done! cs_report_url is now VARCHAR(1024).")

	// 3. 也改 task_lists 表的同名列（如果有）
	_, err = db.Exec("ALTER TABLE t_sec_code_task MODIFY COLUMN cs_report_url VARCHAR(1024) DEFAULT ''")
	if err != nil {
		fmt.Fprintln(os.Stderr, "task_lists ALTER (may not exist, safe to ignore):", err)
	} else {
		fmt.Println("task_lists.cs_report_url also altered to VARCHAR(1024).")
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var ignore any
