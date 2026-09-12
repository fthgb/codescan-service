package bughash

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// bughashSchema 逐字移植 appsec/bughash/store.py:_SCHEMA。
// bughash_version DEFAULT 3 是 store schema 版本,非 fingerprint 的 bughashVersion=5。
const bughashSchema = `
CREATE TABLE IF NOT EXISTS bughash_history (
    bughash TEXT PRIMARY KEY,
    bughash_version INTEGER NOT NULL DEFAULT 3,
    verdict TEXT NOT NULL,
    judge_reason TEXT,
    judged_by TEXT,
    judged_at TEXT,
    confidence INTEGER
);
`

// BughashStore wraps the bughash_history sqlite table (verdict inheritance).
type BughashStore struct {
	db *sql.DB
}

// OpenBughashStore opens (creating the schema) the bughash sqlite db.
func OpenBughashStore(dbPath string) (*BughashStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(bughashSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &BughashStore{db: db}, nil
}

// Get returns the stored row (verdict/judge_reason/judged_by/judged_at/confidence/...) or miss.
func (s *BughashStore) Get(bughash string) (map[string]any, bool) {
	row := s.db.QueryRow(
		`SELECT bughash, bughash_version, verdict, judge_reason, judged_by, judged_at, confidence
		 FROM bughash_history WHERE bughash = ?`, bughash)
	var b, verdict, judgedBy, judgedAt string
	var reason sql.NullString
	var version, confidence sql.NullInt64
	if err := row.Scan(&b, &version, &verdict, &reason, &judgedBy, &judgedAt, &confidence); err != nil {
		return nil, false
	}
	m := map[string]any{
		"bughash":         b,
		"bughash_version": version.Int64,
		"verdict":         verdict,
		"judge_reason":    reason.String,
		"judged_by":       judgedBy,
		"judged_at":       judgedAt,
		"confidence":      confidence.Int64,
	}
	return m, true
}

// Upsert inserts-or-replaces a verdict row. judged_at = now (UTC RFC3339);
// store 是 side-effect,非 report parity 门槛,格式不 byte-gate。
func (s *BughashStore) Upsert(bughash, verdict, judgeReason, judgedBy string, confidence int) {
	s.db.Exec(
		`INSERT INTO bughash_history (bughash, verdict, judge_reason, judged_by, judged_at, confidence)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(bughash) DO UPDATE SET
		   verdict=excluded.verdict, judge_reason=excluded.judge_reason,
		   judged_by=excluded.judged_by, judged_at=excluded.judged_at, confidence=excluded.confidence`,
		bughash, verdict, judgeReason, judgedBy,
		time.Now().UTC().Format(time.RFC3339), confidence)
}

// Close 防 Windows sqlite 句柄泄漏致 t.TempDir 清理失败(同 vcache 教训)。
func (s *BughashStore) Close() error { return s.db.Close() }
