package faces

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// history.go —— 跨 run 对照（2026-08-23，spec §7 之外的追加）。
//
// # 为什么需要
//
// 同 run 内的兄弟对照有个硬局限：**只在模型这一跑里至少在一个兄弟上判对了才触发**。
// 以 42–75% 的判决抖动，那是掷硬币。实证：ceshi/SupplierController 三条端点，
// 历史上 `cce1a7fa` 被判过 missing-auth true_positive，而 2026-08-23 那一跑三条全判
// false_positive → 面账一条都出不来，恰恰在最该出的时候哑火。
//
// 跨 run 对照把「对照来源」从「这一跑的兄弟」扩到「这一跑的兄弟 ∪ 历史上判过该面的
// 同组成员」。历史是**已落盘的既成事实**，可核实（GR-8），不是推测。
//
// # 边界（铁律 D）
//
// 本包只认 History 接口。runs 目录是**当前**的历史载体，将来换成 DB / 服务
// 只需换一个实现，Build 与 pipeline 一行不动。

// History —— 跨 run 对照来源。返回该 bughash 历史上被判为 true_positive 的**面族**。
type History interface {
	ConfirmedFaces(bughash string) []string
}

// mapHistory 是 History 的内存实现（也是测试夹具）。
type mapHistory map[string][]string

func (m mapHistory) ConfirmedFaces(bh string) []string { return m[bh] }

// NewHistory 由 bughash → 面族列表 直接构造（测试/其它载体用）。
func NewHistory(m map[string][]string) History { return mapHistory(m) }

// maxHistoryRuns 限制回看的 run 数（按目录名倒序 = 时间倒序）。
// 有上限是刻意的：历史越久远越可能对应已改过的代码，且扫描成本随 run 数线性涨。
const maxHistoryRuns = 60

// LoadHistory 从 runs 目录扫出「历史上被判 true_positive 的 bughash+面族」。
//
// 不按 repo 过滤：bughash 是内容哈希，跨仓撞车实际上不可能，按 repo_key 过滤反而会被
// 同一个仓在不同 run 用了不同 repo-key（ceshi-final2 / ceshi-faces / …）绊倒。
//
// 任何读失败一律跳过该 run（fail-open，绝不让历史缺失阻断判决链）。
func LoadHistory(runsDir string) History {
	dirs, err := filepath.Glob(filepath.Join(runsDir, "*"))
	if err != nil {
		return mapHistory{}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	if len(dirs) > maxHistoryRuns {
		dirs = dirs[:maxHistoryRuns]
	}
	out := mapHistory{}
	seen := map[string]bool{} // bughash|family 去重
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, "summary.json"))
		if err != nil {
			continue
		}
		var top struct {
			Details []struct {
				Bughash string   `json:"bughash"`
				Verdict string   `json:"verdict"`
				Types   []string `json:"actual_vulnerability_types"`
			} `json:"details"`
		}
		if json.Unmarshal(b, &top) != nil {
			continue
		}
		for _, x := range top.Details {
			if x.Verdict != "true_positive" || x.Bughash == "" {
				continue
			}
			for _, t := range x.Types {
				ft := norm(t)
				if ft == "" || seen[x.Bughash+"|"+ft] {
					continue
				}
				seen[x.Bughash+"|"+ft] = true
				out[x.Bughash] = append(out[x.Bughash], ft)
			}
		}
	}
	return out
}
