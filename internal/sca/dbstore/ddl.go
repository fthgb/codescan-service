package dbstore

import (
	"database/sql"
	"fmt"
)

// tableSpec binds a table name to its CREATE TABLE DDL.
// Single source of truth — Init() and cmd/create_table both use this.
type tableSpec struct {
	name string
	ddl  string
}

// tableSpecs — the 3 SCA tables. Full DDL from spec §3.
// To add a column: ALTER TABLE manually + update the DDL here (spec §3.5).
var tableSpecs = []tableSpec{
	{"t_sec_sca_scan", `CREATE TABLE IF NOT EXISTS t_sec_sca_scan (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  scan_id     VARCHAR(255) NOT NULL UNIQUE COMMENT 'appsecgo scanID',
  repo_key    VARCHAR(255) NOT NULL        COMMENT '项目名',
  status      VARCHAR(20) DEFAULT 'queued' COMMENT 'queued/running/done/failed',
  scanner_version  VARCHAR(50),
  policy_version   INT,
  started_at  DATETIME,
  finished_at DATETIME,
  duration_seconds FLOAT,
  findings_count   INT DEFAULT 0,
  findings_critical INT DEFAULT 0,
  findings_high     INT DEFAULT 0,
  findings_medium   INT DEFAULT 0,
  findings_low      INT DEFAULT 0,
  re_evaluated_at   DATETIME               COMMENT 're-evaluate 时间',
  policy_version_on_re_eval INT           COMMENT 're-evaluate 时策略版本',
  error       TEXT,
  gmt_create  DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_repo_key (repo_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='SCA 扫描记录'`},

	{"t_sec_sca_component", `CREATE TABLE IF NOT EXISTS t_sec_sca_component (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  scan_id     VARCHAR(255) NOT NULL,
  name        VARCHAR(500) NOT NULL     COMMENT '组件名',
  version     VARCHAR(255) NOT NULL,
  ecosystem   VARCHAR(50)               COMMENT 'Maven/npm/PyPI',
  license     VARCHAR(500)               COMMENT 'SPDX 许可证',
  direct_or_transitive VARCHAR(20)      COMMENT 'direct/transitive',
  source_file VARCHAR(1024)             COMMENT '来源 pom.xml 路径',
  gmt_create  DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_scan_id (scan_id),
  INDEX idx_name (name(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='SCA 组件台账'`},

	{"t_sec_sca_finding", `CREATE TABLE IF NOT EXISTS t_sec_sca_finding (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  scan_id     VARCHAR(255) NOT NULL,
  rule_id     VARCHAR(255) NOT NULL,
  category    VARCHAR(50) NOT NULL       COMMENT 'vulnerability/license/blacklist/stale/copyright',
  severity    VARCHAR(20) NOT NULL,
  component   VARCHAR(500) NOT NULL,
  version     VARCHAR(255),
  ecosystem   VARCHAR(50),
  evidence    TEXT                        COMMENT 'CVE/许可证名/黑名单条款',
  source_file VARCHAR(1024)              COMMENT '来源文件',
  detail      JSON,
  gmt_create  DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_scan_id (scan_id),
  INDEX idx_severity (severity),
  INDEX idx_component (component(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='SCA 不合规发现'`},
}

// TableDDLs returns the DDL statements for all SCA tables.
// Used by Init() internally and by cmd/create_table for manual DDL.
func TableDDLs() []string {
	out := make([]string, len(tableSpecs))
	for i, t := range tableSpecs {
		out[i] = t.ddl
	}
	return out
}

// ensureTables creates all SCA tables if they don't exist (idempotent).
// Error includes the table name for easy troubleshooting.
func ensureTables(db *sql.DB) error {
	for _, t := range tableSpecs {
		if _, err := db.Exec(t.ddl); err != nil {
			return fmt.Errorf("ensure table %s: %w", t.name, err)
		}
	}
	return nil
}
