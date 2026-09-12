package vcache

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite" // pure-Go sqlite driver (no CGO)
)

// Store ports appsec/verdict_cache/store.py — pure-Go sqlite (no CGO).
// Fail-open: any open/SQL error degrades to "cache disabled" (Get→miss,
// Upsert→no-op), never breaks the scan.

const schema = `
CREATE TABLE IF NOT EXISTS verdict_cache (
    key_hash TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    model TEXT
);
CREATE INDEX IF NOT EXISTS idx_vc_created ON verdict_cache(created_at);
CREATE TABLE IF NOT EXISTS cache_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
)`

type Store struct {
	db      *sql.DB
	ttl     time.Duration
	nowFunc func() time.Time
}

// NewStore opens (or fail-opens) the cache db. ttlDays = TTL. nowFunc injected
// for deterministic TTL tests (prod passes time.Now). Open failure → returns
// a db==nil store (cache disabled) + error; caller treats as fail-open.
func NewStore(dbPath string, ttlDays int, nowFunc func() time.Time) (*Store, error) {
	s := &Store{ttl: time.Duration(ttlDays) * 24 * time.Hour, nowFunc: nowFunc}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return s, err // fail-open: db stays nil
	}
	// SQLite single-writer: force serialization (mirrors Python threading.Lock).
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return s, err // fail-open
	}
	s.db = db
	// Throttled eviction: cheap meta read per open; DELETE of expired rows ~once
	// per hour per db. Stops unbounded growth across 10万 repos without a costly
	// background goroutine. Fail-open (MaybeExpire no-ops on any SQL error).
	s.MaybeExpire(time.Hour)
	return s, nil
}

// Close releases the underlying db handle. Safe to call on a fail-opened
// (db==nil) store. Tests MUST call this so t.TempDir cleanup can remove the
// sqlite file (modernc.org/sqlite holds the handle open otherwise — on Windows
// that blocks RemoveAll). Prod stores live for the process lifetime.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Get returns the cached row (result_json/model/created_at) or (!ok) on
// miss / TTL expiry / bad row (fail-open: bad row treated as miss).
func (s *Store) Get(keyHash string) (map[string]any, bool) {
	if s.db == nil {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT key_hash, result_json, created_at, model FROM verdict_cache WHERE key_hash = ?`, keyHash)
	var kh, rj, ca string
	var model sql.NullString
	if err := row.Scan(&kh, &rj, &ca, &model); err != nil {
		return nil, false // miss / not found
	}
	created, err := time.Parse(time.RFC3339Nano, ca)
	if err != nil {
		return nil, false // bad row → miss
	}
	if s.nowFunc().Sub(created) > s.ttl {
		return nil, false // TTL expired
	}
	return map[string]any{
		"key_hash":    kh,
		"result_json": rj,
		"created_at":  ca,
		"model":       model.String,
	}, true
}

// Upsert writes/overwrites a cached verdict. Fail-open: error → skip.
func (s *Store) Upsert(keyHash, resultJSON, model string) {
	if s.db == nil {
		return
	}
	ca := s.nowFunc().UTC().Format(time.RFC3339Nano)
	_, _ = s.db.Exec(
		`INSERT INTO verdict_cache (key_hash, result_json, created_at, model)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(key_hash) DO UPDATE SET
		   result_json=excluded.result_json, created_at=excluded.created_at, model=excluded.model`,
		keyHash, resultJSON, ca, model)
}

// DeleteExpired removes rows whose created_at is older than the TTL. Returns the
// count deleted. Fail-open: nil db / SQL error → 0.
//
// SQLite does NOT shrink the file on DELETE — freed pages go to a free-list and
// are reused by future INSERTs. So periodic DeleteExpired stops *unbounded
// growth* (steady-state: insert churn ≈ delete churn) without a costly VACUUM.
// Use Vacuum() to physically shrink the file (manual maintenance only — it
// rewrites + locks the whole db, expensive at GB scale).
func (s *Store) DeleteExpired() int64 {
	if s.db == nil {
		return 0
	}
	cutoff := s.nowFunc().Add(-s.ttl).UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`DELETE FROM verdict_cache WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// MaybeExpire runs DeleteExpired at most once per minInterval per db (throttled
// via a cache_meta row). Each scan opens a fresh Store; this keeps the expire
// check cheap (one meta read) while bounding the DELETE to ~once per interval
// regardless of scan count. Returns the count deleted this call. Fail-open.
// minInterval <= 0 → always run (used by tests).
func (s *Store) MaybeExpire(minInterval time.Duration) int64 {
	if s.db == nil {
		return 0
	}
	now := s.nowFunc()
	if minInterval > 0 {
		var lastStr string
		_ = s.db.QueryRow(`SELECT v FROM cache_meta WHERE k = 'last_expire'`).Scan(&lastStr)
		if last, err := time.Parse(time.RFC3339Nano, lastStr); err == nil && now.Sub(last) < minInterval {
			return 0 // throttled
		}
	}
	n := s.DeleteExpired()
	_, _ = s.db.Exec(
		`INSERT INTO cache_meta (k, v) VALUES ('last_expire', ?)
		 ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		now.UTC().Format(time.RFC3339Nano))
	return n
}

// Vacuum rewrites the db file to reclaim space freed by DeleteExpired. MANUAL
// maintenance only — never auto-called (locks the db for the whole rewrite,
// expensive at scale). Online/offline maintenance tooling may call this.
func (s *Store) Vacuum() error {
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`VACUUM`)
	return err
}
