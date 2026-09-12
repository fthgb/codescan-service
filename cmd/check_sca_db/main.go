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

	// 1. List all SCA scans
	fmt.Println("=== t_sec_sca_scan ===")
	rows, err := db.Query("SELECT scan_id, repo_key, status, findings_count, findings_critical, findings_high, findings_medium, findings_low, gmt_create FROM t_sec_sca_scan ORDER BY gmt_create DESC LIMIT 20")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query scans failed:", err)
	} else {
		for rows.Next() {
			var scanID, repoKey, status string
			var fc, fcr, fh, fm, fl int
			var gmtCreate sql.NullString
			rows.Scan(&scanID, &repoKey, &status, &fc, &fcr, &fh, &fm, &fl, &gmtCreate)
			fmt.Printf("scan_id=%s repo=%s status=%s total=%d (C%d/H%d/M%d/L%d) created=%s\n",
				scanID, repoKey, status, fc, fcr, fh, fm, fl, gmtCreate.String)
		}
		rows.Close()
	}

	// 2. Count components and findings per scan
	fmt.Println("\n=== component/finding counts ===")
	rows2, err := db.Query(`
		SELECT s.scan_id, s.repo_key,
		  (SELECT COUNT(*) FROM t_sec_sca_component c WHERE c.scan_id = s.scan_id) AS comp_count,
		  (SELECT COUNT(*) FROM t_sec_sca_finding f WHERE f.scan_id = s.scan_id) AS finding_count
		FROM t_sec_sca_scan s ORDER BY s.gmt_create DESC LIMIT 20
	`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query counts failed:", err)
	} else {
		for rows2.Next() {
			var scanID, repoKey string
			var compCount, findingCount int
			rows2.Scan(&scanID, &repoKey, &compCount, &findingCount)
			fmt.Printf("scan_id=%s repo=%s components=%d findings=%d\n", scanID, repoKey, compCount, findingCount)
		}
		rows2.Close()
	}

	// 3. Recent findings (if any)
	fmt.Println("\n=== recent findings ===")
	rows3, err := db.Query(`
		SELECT f.scan_id, f.severity, f.category, f.component, f.version, f.evidence
		FROM t_sec_sca_finding f
		ORDER BY f.gmt_create DESC LIMIT 10
	`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query findings failed:", err)
	} else {
		for rows3.Next() {
			var scanID, severity, category, component, version, evidence string
			rows3.Scan(&scanID, &severity, &category, &component, &version, &evidence)
			fmt.Printf("[%s] %s %s %s@%s — %s\n", severity, scanID, category, component, version, evidence)
		}
		rows3.Close()
	}
}
