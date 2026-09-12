package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// fromCodescanRequest — sec-service Path1 出站触发体。
// sec-service CodescanCallBack 在摄取 代码卫士漏洞后 POST 此端点，
// 由 codescan_repos 自己的 codescan client CloneSource+FetchAll 拉数据 → runPipeline 裁决。
type fromCodescanRequest struct {
	PkTask  int32  `json:"pk_task"`
	AppName string `json:"app_name"`
	RepoURL string `json:"repo_url"`
	Branch  string `json:"branch"`
	Commit  string `json:"commit,omitempty"`
}

// scanFromCodescanHandler — POST /api/scan/from-codescan：sec-service 驱动的外部触发（Path1）。
//
// 与人工 Trigger 的区别：来源是 sec-service 回调（已持 pk_task/app_name/repo_url/branch），
// 无需前端选任务。复用 codescan client(CloneSource/FetchAll) + runPipeline，落 run + cmdb_link.json，
// run 出现在前端供人工勾选派发 → 推回 sec-service 建 CMDB 事件。
//
// 全异步：克隆+拉取+裁决都在 goroutine(分钟级 LLM judge 不能阻塞 sec-service 回调)。
// 立即返 accepted；用 context.Background() 而非 r.Context()（handler 返回后 ctx 取消）。
func scanFromCodescanHandler(w http.ResponseWriter, r *http.Request) {
	var req fromCodescanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求体解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PkTask == 0 || req.RepoURL == "" {
		http.Error(w, "pk_task/repo_url 为空", http.StatusBadRequest)
		return
	}
	branch := req.Branch
	if branch == "" {
		branch = "master"
	}
	pkTaskStr := fmt.Sprintf("%d", req.PkTask)
	appName := req.AppName
	if appName == "" {
		appName = fmt.Sprintf("task-%d", req.PkTask)
	}

	go func() {
		repoRoot, err := codescanClient.CloneSource(req.RepoURL, branch, req.Commit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "from-codescan: 克隆失败 app=%s pk=%s: %s\n", appName, pkTaskStr, err)
			return
		}
		raw, err := codescanClient.FetchAll(pkTaskStr, 0, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "from-codescan: 拉取漏洞失败 app=%s pk=%s: %s\n", appName, pkTaskStr, err)
			return
		}
		if len(raw) == 0 {
			fmt.Fprintf(os.Stderr, "from-codescan: 无漏洞跳过 app=%s pk=%s\n", appName, pkTaskStr)
			return
		}
		// raw 是 []map[string]any，但 adapter 的 asSlice 只认 []any，
		// Go 里 []map[string]any != []any，直接传会导致 asSlice 返回 nil -> 0 alerts。
		// 必须显式转换。
		bugsAny := make([]any, len(raw))
		for i, b := range raw {
			bugsAny[i] = b
		}
		_, _, _ = runPipeline(context.Background(), serverCfg, &scanRequest{
			RepoKey:    appName,
			RepoRoot:   repoRoot,
			Adapter:    "codesafe",
			SastReport: map[string]any{"bugs": bugsAny},
			PkTask:     pkTaskStr,
		}, nil, nil)
		fmt.Fprintf(os.Stderr, "from-codescan run done: app=%s pk=%s alerts=%d\n", appName, pkTaskStr, len(raw))
	}()

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "accepted",
		"pk_task":  pkTaskStr,
		"app_name": appName,
	})
}
