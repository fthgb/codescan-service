package main

// cmd/server/sca_scan.go — SCA HTTP 层（路由在 main.go 注册）：
//   POST /api/sca/scan                        触发扫描（异步，立即返 scan_id）
//   GET  /api/sca/scans?repo_key=             扫描历史列表
//   GET  /api/sca/scans/{scan_id}             单次结果（meta+sbom+findings）
//   GET  /api/sca/components?name=&ecosystem= 跨仓库组件回溯（ecosystem 可选，缺省按生态分组）
//   POST /api/sca/scans/{scan_id}/re-evaluate 离线重判（读 raw → 跑 policy → 覆盖 findings）
// 认证走 withAuth 现有 token 机制；并发护栏：同 repo_key 进行中 → 409（spec §五）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"appsecgo/internal/sca"
	"appsecgo/internal/sca/dbstore"
	"appsecgo/internal/sca/policy"
	"appsecgo/internal/sca/store"
)

// scaInFlight — 同 repo_key 并发护栏（repo_key → true）。
var scaInFlight sync.Map

// scaScanFn — scanner 注入点（生产 nil 走 sca.Run 内部默认；handler 测试注桩）。
var scaScanFn sca.ScanFunc

// POST /api/sca/scan — 异步：写 queued meta → go 执行 → 状态迁移落盘。
func scaScanHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RepoKey string `json:"repo_key"`
		Path    string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RepoKey == "" {
		writeJSONError(w, 400, "repo_key 必填")
		return
	}
	// 并发护栏：同 repo 进行中 → 409（防发布流水线重试风暴，spec §五）
	if _, loaded := scaInFlight.LoadOrStore(body.RepoKey, true); loaded {
		writeJSONError(w, 409, "同仓库扫描进行中，请稍后")
		return
	}
	repoRoot := body.Path
	if repoRoot == "" {
		repoRoot = filepath.Join(serverCfg.CodescanRepoCacheDir, body.RepoKey)
	}
	// 立即落 queued meta（断点续查的持久化状态）
	scanID := sca.NewScanID(body.RepoKey)
	if err := store.UpdateMeta(serverCfg.ScaRunsDir, scanID, store.Meta{
		ScanID: scanID, RepoKey: body.RepoKey, Status: "queued",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		scaInFlight.Delete(body.RepoKey)
		writeJSONError(w, 500, "写 queued meta 失败: "+err.Error())
		return
	}
	go func() {
		defer scaInFlight.Delete(body.RepoKey)
		opts := sca.Options{
			RepoKey: body.RepoKey, RepoRoot: repoRoot,
			// ScanID 用 handler 预生成并已返给客户端的那个：Run 落同一目录，
			// 覆盖 queued meta 为 done（否则孤儿 queued 目录 + 客户端 ID 永不 done）
			ScanID:     scanID,
			ScaRunsDir: serverCfg.ScaRunsDir,
			PolicyPath: serverCfg.ScaPolicyPath,
			ScanFn:     scaScanFn,
		}
		if _, err := sca.Run(opts); err != nil {
			// 失败 → failed + error 字段（spec §五）；同 scanID，覆盖 queued meta
			_ = store.UpdateMeta(serverCfg.ScaRunsDir, scanID, store.Meta{
				ScanID: scanID, RepoKey: body.RepoKey, Status: "failed",
				StartedAt: time.Now().UTC().Format(time.RFC3339),
				Error:    err.Error(),
			})
			if dbstore.IsConfigured() {
				if derr := dbstore.MarkFailed(scanID, body.RepoKey, err.Error()); derr != nil {
					fmt.Fprintf(os.Stderr, "[sca] DB markFailed failed: %v\n", derr)
				}
			}
		}
	}()
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"scan_id": scanID, "status": "queued"})
}

// GET /api/sca/scans?repo_key= — 历史列表。
func scaListHandler(w http.ResponseWriter, r *http.Request) {
	scans, err := store.ListScans(serverCfg.ScaRunsDir, r.URL.Query().Get("repo_key"))
	if err != nil {
		writeJSONError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"scans": scans})
}

// GET /api/sca/scans/{scan_id} — 单次结果。
func scaScanDetailHandler(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("scan_id")
	meta, res, findings, err := store.Load(serverCfg.ScaRunsDir, scanID)
	if err != nil {
		writeJSONError(w, 404, "scan not found: "+scanID)
		return
	}
	writeJSON(w, map[string]any{"meta": meta, "sbom": res.Components, "findings": findings})
}

// GET /api/sca/components?name=&ecosystem= — 跨仓库回溯。
// ecosystem 可选：缺省跨生态但响应按 ecosystem 分组（spec §五）。
func scaComponentsHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeJSONError(w, 400, "name 必填")
		return
	}
	eco := r.URL.Query().Get("ecosystem")
	hits := store.QueryComponents(serverCfg.ScaRunsDir, name, eco)
	grouped := map[string][]store.ComponentHit{}
	for _, h := range hits {
		grouped[h.Ecosystem] = append(grouped[h.Ecosystem], h)
	}
	writeJSON(w, map[string]any{"name": name, "ecosystems": grouped})
}

// POST /api/sca/scans/{scan_id}/re-evaluate — 离线重判（spec §五）。
func scaReEvaluateHandler(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("scan_id")
	pol, err := policy.Load(serverCfg.ScaPolicyPath)
	if err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	if err := store.ReEvaluate(serverCfg.ScaRunsDir, scanID, pol); err != nil {
		writeJSONError(w, 500, "re-evaluate 失败: "+err.Error())
		return
	}
	_, _, findings, _ := store.Load(serverCfg.ScaRunsDir, scanID)
	writeJSON(w, map[string]any{"scan_id": scanID, "findings_count": len(findings)})
}
