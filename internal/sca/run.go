// Package sca — SCA 编排入口：scanner → policy → store（spec §三）。
// 两条触发链路共用本入口：随审计 best-effort 触发 + server webhook（spec §三）。
package sca

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"appsecgo/internal/sca/dbstore"
	"appsecgo/internal/sca/policy"
	"appsecgo/internal/sca/scanner"
	"appsecgo/internal/sca/store"
	"appsecgo/internal/sca/types"
)

// safeRunRe — 与 runs.safe 同规则（runs.safe 未导出，此处复刻；两处规则若漂移以 runs 为准同步）。
var safeRunRe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// ScanFunc — scanner 注入点（生产 nil → scanner.Scan；单测/handler 测试注入桩，避免涉网）。
type ScanFunc func(repoKey, repoRoot string) (*types.ScanResult, error)

// Options — Run 入参。ScanID 供 webhook handler 预写 queued meta 时传入
// （scanID 一致性：Run 必须落 handler 已返给客户端的那个目录）；空 → Run 内部生成。
type Options struct {
	RepoKey    string
	RepoRoot   string
	ScaRunsDir string
	PolicyPath string
	ScanID     string
	ScanFn     ScanFunc
}

// NewScanID — scan_id 生成：只用 repoKey（去掉时间戳，同项目覆盖而非累积）。
// 导出给 cmd/server 的 queued-meta 预写用（handler 先落 queued 再 go Run）。
func NewScanID(repoKey string) string {
	return safeRunRe.ReplaceAllString(repoKey, "_")
}

// Run — 编排：加载策略 → 扫描翻译 → 策略判定 → 落盘。返回 scanID。
// scanID 一致性：优先用 o.ScanID（webhook handler 预写 queued meta 时已生成并返给客户端，
// Run 必须落同一目录，否则磁盘出现孤儿 queued 目录 + 客户端拿到的 ID 永不 done）；
// 空 → 内部生成。
// 失败返回 error 由调用方决定处理（随审计触发时 best-effort，只留痕不阻塞）。
func Run(o Options) (string, error) {
	pol, err := policy.Load(o.PolicyPath)
	if err != nil {
		return "", err // 策略加载失败必须报错（spec §四）
	}
	scan := o.ScanFn
	if scan == nil {
		scan = scanner.Scan
	}
	scanID := o.ScanID
	if scanID == "" {
		scanID = NewScanID(o.RepoKey)
	}
	start := time.Now().UTC()
	res, err := scan(o.RepoKey, o.RepoRoot)
	if err != nil {
		return scanID, err
	}
	findings := policy.Evaluate(pol, res)
	meta := store.Meta{
		ScanID: scanID, RepoKey: o.RepoKey, Status: "done",
		ScannerVersion: res.ScannerVer, PolicyVersion: pol.Version,
		StartedAt:  start.Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		DurationSec: time.Since(start).Seconds(),
	}
	if err := store.Save(o.ScaRunsDir, meta, res, findings); err != nil {
		return scanID, err
	}
	// DB dual-write: JSON already saved, DB failure only warns (does not block scan).
	if dbstore.IsConfigured() {
		if derr := dbstore.Save(meta, res, findings); derr != nil {
			fmt.Fprintf(os.Stderr, "[sca] DB write failed (JSON saved OK): %v\n", derr)
		}
	}
	return scanID, nil
}
