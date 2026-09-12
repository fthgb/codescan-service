// Package vulntax 提供漏洞类型的**展示**词表:内部码/slug/CWE → 给开发看的中文名,
// 以及 slug 变体归一。
//
// # 单一权威
//
// 词表在同目录 vuln_taxonomy.json,本包 go:embed 读入,前端 web/src/lib/vulnTaxonomy.ts
// import **同一个文件**(铁律 D:一处改动两侧生效,勿在任一侧另建映射)。
//
// # 为什么是 embed 而不是运行时读 repo root
//
// cwe_registry.json 走 cmd 层加载再逐层传参;但 report.RenderHTML 的签名是渲染层边界,
// 为一张展示词表穿参会波及路由与两个 main。embed 无路径依赖、无全局状态、无签名变更。
//
// # 只管展示,不碰判决
//
// 本包**不参与** verdict/mismatch/gating —— 那些走 cwereg + judge 的既有路径(硬约束)。
// 归一只作用于展示与类型分布聚合。
package vulntax

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed vuln_taxonomy.json
var taxonomyJSON []byte

var taxonomy struct {
	CweDisplay  map[string]string `json:"cwe_display"`
	SlugDisplay map[string]string `json:"slug_display"`
	SlugAliases map[string]string `json:"slug_aliases"`
}

func init() {
	if err := json.Unmarshal(taxonomyJSON, &taxonomy); err != nil {
		// embed 的是仓库内固定资产,解析失败=构建期就该发现的错误,不静默降级。
		panic("vulntax: vuln_taxonomy.json 解析失败: " + err.Error())
	}
}

// Canonical 把 slug 变体归一到规范形式。
//
// 连字符↔下划线由代码统一(不入表:三 run 实测同一类漏洞出现 missing_authorization /
// missing-authorization / missing-auth / broken-access-control 四种写法,前三种只是
// 分隔符与缩写差异);**换了名字**的变体走 slug_aliases 表。
// 认不出的原样返回 —— 不猜也不丢(GR-8)。
func Canonical(slug string) string {
	s := strings.ToLower(strings.TrimSpace(slug))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "-", "_")
	if c, ok := taxonomy.SlugAliases[s]; ok {
		return c
	}
	return s
}

// DisplaySlug 返回 slug 的中文名;词表没有则返回空(调用方决定回退)。
func DisplaySlug(slug string) string { return taxonomy.SlugDisplay[Canonical(slug)] }

// DisplayCwe 返回 CWE 编号的中文名;词表没有则返回空。
func DisplayCwe(cweID string) string {
	return taxonomy.CweDisplay[strings.ToUpper(strings.TrimSpace(cweID))]
}

// Display 按真值优先级给出展示名:
//
//	① vulnerability_type 本身是已知 slug   → 用它(最贴近该条告警的结论)
//	② 否则(SAST 内部码如 02000010070033)   → 取 actual_vulnerability_types 首个已知项
//	③ 再否则                                → 退回 cwe_id 的中文名
//	④ 都没有                                → 空串
//
// ② 存在的原因:三 run 15 条 TP 里 8 条的 vulnerability_type 是适配器规则码,且其
// cwe_id(CWE-915/CWE-338)不在 cwe_registry.json 的 19 条内,靠 registry 反查补不上;
// 而 LLM 判出的 actual_vulnerability_types 是现成真值。
//
// ④ 返回空而非原样吐内部码:内部码是实现细节,不是给开发看的结论(GR-8)。
func Display(vulnType string, actualTypes []string, cweID string) string {
	if d := DisplaySlug(vulnType); d != "" {
		return d
	}
	for _, at := range actualTypes {
		if d := DisplaySlug(at); d != "" {
			return d
		}
	}
	return DisplayCwe(cweID)
}
