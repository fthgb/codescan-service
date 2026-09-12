package dbstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"appsecgo/internal/sca/store"
	"appsecgo/internal/sca/types"
)

// toDatetime converts an RFC3339 string to MySQL DATETIME format ("2006-01-02 15:04:05").
// Empty or unparseable input returns empty string (MySQL inserts NULL for nullable columns).
func toDatetime(rfc3339 string) string {
	if rfc3339 == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

// severityCounts extracts the 4 severity counts from a FindingsBySeverity map.
// Nil map → all zeros (no panic).
func severityCounts(m map[string]int) (critical, high, medium, low int) {
	if m == nil {
		return 0, 0, 0, 0
	}
	return m["critical"], m["high"], m["medium"], m["low"]
}

// ---- Connection management ----

// pkgDB is the shared DB connection. nil = not configured (graceful degradation).
var pkgDB *sql.DB

// Init opens the DB connection, verifies with Ping, and auto-creates tables.
// Called from cmd/server/main.go after pandora.Load.
// On failure, pkgDB stays nil (Init resets first to prevent stale connections).
func Init(dsn string) error {
	pkgDB = nil // reset before attempt
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}
	if err := ensureTables(db); err != nil {
		db.Close()
		return err
	}
	pkgDB = db
	return nil
}

// IsConfigured returns true if Init succeeded.
func IsConfigured() bool {
	return pkgDB != nil
}

// Close closes the DB connection. Defer in main().
func Close() error {
	if pkgDB != nil {
		return pkgDB.Close()
	}
	return nil
}

// ResetForTest sets pkgDB to nil. Test-only.
func ResetForTest() {
	pkgDB = nil
}

// ---- Write functions ----

// Save persists a completed SCA scan to the database.
// Transaction: upsert scan (done) + delete+insert components + delete+insert findings.
// Returns nil silently if DB not configured (graceful degradation).
// Uses context.WithTimeout(10s) to prevent DB slowness from blocking the scan pipeline.
func Save(meta store.Meta, res *types.ScanResult, findings []types.Finding) error {
	if pkgDB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := pkgDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() // safe: no-op after Commit

	// 1. Upsert scan record — compute counts from findings slice (self-contained,
	//    not dependent on whether caller pre-filled meta.FindingsBySeverity).
	sevMap := map[string]int{}
	for _, f := range findings {
		sevMap[f.Severity]++
	}
	c, h, med, l := severityCounts(sevMap)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO t_sec_sca_scan
		  (scan_id, repo_key, status, scanner_version, policy_version, started_at, finished_at,
		   duration_seconds, findings_count, findings_critical, findings_high, findings_medium,
		   findings_low, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		  repo_key=VALUES(repo_key), status=VALUES(status), scanner_version=VALUES(scanner_version),
		  policy_version=VALUES(policy_version), started_at=VALUES(started_at),
		  finished_at=VALUES(finished_at), duration_seconds=VALUES(duration_seconds),
		  findings_count=VALUES(findings_count), findings_critical=VALUES(findings_critical),
		  findings_high=VALUES(findings_high), findings_medium=VALUES(findings_medium),
		  findings_low=VALUES(findings_low), error=VALUES(error)
	`, meta.ScanID, meta.RepoKey, meta.Status, meta.ScannerVersion, meta.PolicyVersion,
		toDatetime(meta.StartedAt), toDatetime(meta.FinishedAt), meta.DurationSec,
		len(findings), c, h, med, l, meta.Error)
	if err != nil {
		return fmt.Errorf("upsert scan: %w", err)
	}

	// 2. Delete + insert components
	_, err = tx.ExecContext(ctx, "DELETE FROM t_sec_sca_component WHERE scan_id=?", meta.ScanID)
	if err != nil {
		return fmt.Errorf("delete components: %w", err)
	}
	for _, comp := range res.Components {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO t_sec_sca_component
			  (scan_id, name, version, ecosystem, license, direct_or_transitive, source_file)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, meta.ScanID, comp.Name, comp.Version, comp.Ecosystem, comp.License,
			comp.DirectOrTransitive, comp.SourceFile)
		if err != nil {
			return fmt.Errorf("insert component %s: %w", comp.Name, err)
		}
	}

	// 3. Delete + insert findings
	_, err = tx.ExecContext(ctx, "DELETE FROM t_sec_sca_finding WHERE scan_id=?", meta.ScanID)
	if err != nil {
		return fmt.Errorf("delete findings: %w", err)
	}
	for _, f := range findings {
		detailJSON, _ := json.Marshal(f.Detail)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO t_sec_sca_finding
			  (scan_id, rule_id, category, severity, component, version, ecosystem,
			   evidence, source_file, detail)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, meta.ScanID, f.RuleID, f.Category, f.Severity, f.Component, f.Version,
			f.Ecosystem, f.Evidence, f.SourceFile, string(detailJSON))
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.RuleID, err)
		}
	}

	return tx.Commit()
}

// MarkFailed upserts a scan record with status=failed.
// Does NOT delete existing components/findings (preserves previous successful scan data,
// consistent with JSON behavior where UpdateMeta only touches meta.json).
// Returns nil silently if DB not configured.
func MarkFailed(scanID, repoKey, errMsg string) error {
	if pkgDB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := pkgDB.ExecContext(ctx, `
		INSERT INTO t_sec_sca_scan (scan_id, repo_key, status, error)
		VALUES (?, ?, 'failed', ?)
		ON DUPLICATE KEY UPDATE status='failed', error=VALUES(error)
	`, scanID, repoKey, errMsg)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}
