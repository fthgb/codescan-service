// Package faces —— 确定性面账（spec 2026-08-23-deterministic-face-ledger-design）。
//
// # 为什么存在
//
// 一条 alert 上常同时存在多个漏洞面（CWE face），各自独立可证或不可证；而 verdict 是
// 标量，于是**最弱的一面决定整条**。实测：多面 alert uncertain 率 29%，单面 19%（1.5×）。
//
// # 唯一主力规则：同类兄弟判决不一致
//
// 原设计想用「确定性事实直接顶出被漏掉的面」，已被离线全量回放**否决**：
// `authz_coverage` 三态全空 = 469/469 = 100%，事实为真但**零区分度**，命中 67% = 噪声。
//
// 修正后的原理：
//
//	确定性事实本身没有区分度时，区分度来自「同类同伴的判决不一致」。
//
// 不需要事实稀有，只需要**共享同一事实形态的兄弟之间判决不一致** —— 那是可核实的矛盾
// （GR-8：判据必须可核实），不是猜测。实测命中 16%（vs R2 的 67%）。
//
// # 本包不做什么
//
//   - **不判决**：标出的面 Disposition 恒为空 = 未判定。替模型下判决会制造大批误报
//     （`authz_coverage` 三态全空只证明「无鉴权守卫」，不等于漏洞 —— 登录接口本就该公开）。
//   - **不碰判决链**：纯函数，输入判决产物，输出账本。VerdictOf / TypeMismatchTypes /
//     自动抑制 / falsify / verdict_cache 六个硬约束锚点一律不触碰。
//   - **不跨类比对**：不同 controller 的端点职责不同，比了就是噪声（R2 的教训）。
package faces

import (
	"regexp"
	"strconv"
	"strings"

	"appsecgo/internal/contract"
)

// Alert —— 面账的输入（判决产物的只读视图，不含任何可写状态）。
type Alert struct {
	AlertID     string
	Bughash     string
	Verdict     string
	ActualTypes []string
	Authz       *contract.AuthzCoverage     // nil = 事实缺失 → 不参与比对（fail-open，绝不猜）
	Upload      *contract.UploadDisposition // 同上；只在上传流上有值
}

// classRe 从 alert_id 抠出 Java 类名（`.../SupplierController.java:306` → SupplierController）。
var classRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.java:`)

// Build 计算整个 run 的面账，返回 bughash → 该 alert 被标出的面。
//
// 需要 run 级视图（而非逐条）：矛盾是**组内**属性，单看一条永远看不出来。
// Build 只用**同 run** 对照（向后兼容签名）。跨 run 请用 BuildWith。
func Build(alerts []Alert) map[string][]contract.Face { return BuildWith(alerts, nil) }

// BuildWith 计算面账。hist=nil → 只用同 run 兄弟对照。
//
// 对照来源 = 这一跑判 TP 的同组成员 ∪ 历史上判过该面的同组成员。历史是**已落盘的
// 既成事实**，可核实（GR-8），不是推测 —— 它治的是「同 run 对照在模型这一跑全判错时
// 一起哑火」这个硬局限（实证 ceshi/SupplierController）。
func BuildWith(alerts []Alert, hist History) map[string][]contract.Face {
	out := map[string][]contract.Face{}
	// 每个**分组事实**各自成组（见 grouping.go）：加一个事实 = 往 groupingFacts 加一条，
	// 本函数一行不动。分组键 = 事实名 + 类名 + 该事实的形态指纹，三者都同才算「同类兄弟」。
	for _, gf := range groupingFacts {
		buildForFact(out, alerts, hist, gf)
	}
	return out
}

// buildForFact —— 按单个分组事实做「同类兄弟判决不一致」比对，结果并进 out。
func buildForFact(out map[string][]contract.Face, alerts []Alert, hist History, gf GroupingFact) {
	groups := map[string][]int{}
	for i, a := range alerts {
		shape := gf.Shape(a)
		if shape == "" {
			continue // 事实缺失：不参与比对（fail-open，绝不猜）
		}
		cls := className(a.AlertID)
		if cls == "" {
			continue
		}
		groups[gf.Name+"|"+cls+"|"+shape] = append(groups[gf.Name+"|"+cls+"|"+shape], i)
	}
	for _, idx := range groups {
		if len(idx) < 2 {
			continue // 单条无兄弟，无从比对
		}
		// 组内每个「被判 true_positive 的面族」→ 对照 bughash 列表（本跑）。
		judged := map[string][]string{}
		for _, i := range idx {
			if alerts[i].Verdict != "true_positive" {
				continue
			}
			seen := map[string]bool{}
			for _, t := range alerts[i].ActualTypes {
				if ft := norm(t); ft != "" && !seen[ft] {
					seen[ft] = true
					judged[ft] = append(judged[ft], alerts[i].Bughash)
				}
			}
		}
		// 跨 run：历史上判过该面的同组成员同样算对照（面族已在 LoadHistory 归一）。
		histFaces := map[string]map[string]bool{} // bughash → 历史确认过的面族
		if hist != nil {
			for _, i := range idx {
				hf := map[string]bool{}
				for _, ft := range hist.ConfirmedFaces(alerts[i].Bughash) {
					if ft == "" || !gf.Inferable[ft] {
						continue // 鉴权事实推不出的面不得借历史冒出来
					}
					hf[ft] = true
					if !contains(judged[ft], alerts[i].Bughash) {
						judged[ft] = append(judged[ft], alerts[i].Bughash)
					}
				}
				histFaces[alerts[i].Bughash] = hf
			}
		}
		if len(judged) == 0 {
			continue // 无 TP 对照 → 不凭空造面
		}
		for _, i := range idx {
			a := alerts[i]
			// 门 A：已被判 true_positive 的 alert 不标 —— 它已在报告的确认节里，
			// 多一个未判定面不改变「是否被报出」，属锦上添花而非漏报（实测该门去掉 49%）。
			if a.Verdict == "true_positive" {
				continue
			}
			has := map[string]bool{}
			for _, t := range a.ActualTypes {
				has[norm(t)] = true
			}
			for ft, cps := range judged {
				if has[ft] {
					continue // 已用同族别名枚举过 —— 看过并否掉，不是漏掉
				}
				// 门 C：只有当该面的**决定性证据就是分组所依据的共享事实**时，
				// 兄弟推断才成立。本分组键是「类名 + 鉴权事实形态」，故只能推出访问控制面。
				//
				// 实测教训：不设此门时会推出 cwe-798(硬编码凭据) / rce / es-injection ——
				// 「兄弟端点有硬编码凭据所以你也有」是无效推理，authz_coverage 跟它毫无关系。
				// 加门后自验证率 57%→75%（83→52 条）。
				if !gf.Inferable[ft] {
					continue
				}
				// 自身回退：这条 alert 自己在历史上判过该面，本跑没判。
				// 没有「对照条目」可给 —— 对照就是它自己，编一个反而误导（GR-8）。
				if histFaces[a.Bughash][ft] {
					out[a.Bughash] = append(out[a.Bughash], contract.Face{
						Type: ft, Source: contract.FaceDeterministic,
						Facts: []string{
							"**这条 alert 自己**在历史 run 里被判定存在该面（true_positive），本跑未枚举该面",
							"鉴权事实：" + authzHuman(a.Authz),
						},
						Flags: []string{contract.FlagRegressedFromHistory},
					})
					continue
				}
				counterpart := ""
				for _, c := range cps {
					if c != a.Bughash {
						counterpart = c
						break
					}
				}
				if counterpart == "" {
					continue
				}
				// 对照数是**强度标注**，不是过滤器。曾试过「要求 ≥2 个对照」把命中率从
				// 17.7% 压到 6.0%，但它会压掉真信号 —— 驱动本设计的 ceshi/SupplierController
				// 漏报恰好只有 1 个对照。按铁律 C「漏报真漏洞比标错类型更严重」，
				// 宁可多标一条待复核，不可压掉一条真漏报；强度交给读者判断（GR-8 给证据不给结论）。
				out[a.Bughash] = append(out[a.Bughash], contract.Face{
					Type:   ft,
					Source: contract.FaceDeterministic,
					// Disposition 刻意留空 = 未判定。本包不替模型下判决。
					Facts: []string{
						"同类兄弟 " + shortAll(cps) + "（共 " + itoa(len(cps)) + " 条" + histNote(cps, histFaces, judgedThisRun(alerts, idx, ft)) + "）在**相同的事实形态**下被判定存在该面（true_positive），本条未枚举该面",
						factsHuman(gf, a),
					},
					Flags:              []string{contract.FlagInconsistentWithinRun},
					CounterpartBughash: counterpart,
				})
			}
		}
	}
}

func className(alertID string) string {
	if m := classRe.FindStringSubmatch(alertID); m != nil {
		return m[1]
	}
	return ""
}

// authzShape —— 确定性事实的**形态指纹**。形态不同的兄弟本就可以判得不同，不构成矛盾。
func authzShape(a *contract.AuthzCoverage) string {
	return boolTok(a.MethodGuard) + boolTok(a.ClassGuard) + "|" + a.GlobalInterceptor
}

func boolTok(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func authzHuman(a *contract.AuthzCoverage) string {
	parts := []string{}
	parts = append(parts, "方法级守卫="+cn(a.MethodGuard), "类级守卫="+cn(a.ClassGuard))
	if a.GlobalInterceptor == "none" {
		parts = append(parts, "全局拦截器=零命中")
	} else {
		parts = append(parts, "全局拦截器=有命中待判定")
	}
	return strings.Join(parts, "，")
}

func cn(b bool) string {
	if b {
		return "有"
	}
	return "无"
}

// faceFamily —— 面**族**归一：把同一个漏洞面的各种 slug 写法收敛成一个可比较的键。
//
// # 为什么不复用 cwereg.NormalizeVulnType（重要）
//
// 那个函数只做 `CWE-xxx → slug`，不归一同义 slug；而**扩充它会改 TypeMismatchTypes**
// （`judge/build.go:37-74`，硬约束 2 锚点），进而改 `report.go:99-100` 的自动抑制
// （它读 `len(TypeMismatchTypes)`）。两者语义也不同：NormalizeVulnType 是为**知识查表**
// 归一，本函数是为**等价比较**归一。故刻意分开，且本表只在面账内使用，绝不外泄。
//
// 表由 2026-08-23 全量回放实测的 33 个真实 slug 反推（不是拍脑袋列的）：同一个访问控制面
// 出现过 19 种写法，未归一时命中率 119%（5.6 面/alert）= 纯噪声。
//
// **合并 authn 与 authz 是有意的**：本账本问的是「这条 alert 有没有考虑过访问控制这一面」，
// 不是「是 401 还是 403」。在本批仓库里两者描述的是同一个底层事实（端点零守卫）。
var faceFamilies = map[string]string{
	// —— 访问控制族（CWE-862 / 863 / 639 / 284）——
	"missing_authorization": "access_control", "missing-authorization": "access_control",
	"missing_authentication": "access_control", "missing-authentication": "access_control",
	"missing_auth": "access_control", "missing-auth": "access_control",
	"missing-authz": "access_control", "missing_authz": "access_control",
	"cwe-862": "access_control", "cwe-862-missing-authorization": "access_control",
	"cwe-863": "access_control", "cwe-639": "access_control",
	"broken_access_control": "access_control", "broken-access-control": "access_control",
	"improper_access_control": "access_control", "improper-access-control": "access_control",
	"broken_object_level_authorization": "access_control", "broken-object-level-authorization": "access_control",
	"idor": "access_control", "id_or": "access_control", "idr": "access_control",
	"insecure-direct-object-reference": "access_control", "insecure_direct_object_reference": "access_control",
	"id_or_broken_access_control": "access_control",
	// —— 上传族（CWE-434）——
	"arbitrary_file_upload": "file_upload", "arbitrary-file-upload": "file_upload",
	"unrestricted_file_upload": "file_upload", "unrestricted-file-upload": "file_upload",
	// —— 穿越族（CWE-22）——
	"path_traversal": "path_traversal", "path-traversal": "path_traversal",
	"arbitrary-file-read": "path_traversal", "arbitrary_file_read": "path_traversal",
	// —— 存储型 XSS 族（CWE-79）——
	"stored_xss": "stored_xss", "stored-xss": "stored_xss",
	"stored_xss_via_upload": "stored_xss", "stored-xss-via-upload": "stored_xss",
}

// norm 归一到面族键。表外的 slug 原样返回（自成一族）—— 绝不猜测归属（GR-8）。
func norm(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if fam, ok := faceFamilies[s]; ok {
		return fam
	}
	return s
}

func short(bh string) string {
	if len(bh) > 8 {
		return bh[:8]
	}
	return bh
}

func hasFlag(fs []string, want string) bool {
	for _, f := range fs {
		if f == want {
			return true
		}
	}
	return false
}

// shortAll 拼接对照 bughash 短码 —— 判据必须可核实(GR-8)，故全部列出而非只给一个。
func shortAll(bhs []string) string {
	out := make([]string, 0, len(bhs))
	for _, b := range bhs {
		out = append(out, short(b))
	}
	return strings.Join(out, "、")
}

func itoa(n int) string { return strconv.Itoa(n) }

// FamilyOf 导出面族归一，供离线校验/评估 harness 复用同一张表 ——
// 校验脚本自写一份同义词表就等于在测它自己（成因②：解析器散落各写各的）。
func FamilyOf(slug string) string { return norm(slug) }

// contains —— 小工具（避免引入依赖）。
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// judgedThisRun 返回本跑内判过该面的 bughash 集合（用于区分对照来自同跑还是历史）。
func judgedThisRun(alerts []Alert, idx []int, ft string) map[string]bool {
	out := map[string]bool{}
	for _, i := range idx {
		if alerts[i].Verdict != "true_positive" {
			continue
		}
		for _, t := range alerts[i].ActualTypes {
			if norm(t) == ft {
				out[alerts[i].Bughash] = true
			}
		}
	}
	return out
}

// histNote —— 读者需能区分「对照是这一跑判的」还是「翻历史翻出来的」(GR-8 判据来源透明)。
func histNote(cps []string, histFaces map[string]map[string]bool, thisRun map[string]bool) string {
	onlyHist := 0
	for _, c := range cps {
		if !thisRun[c] {
			onlyHist++
		}
	}
	switch {
	case onlyHist == 0:
		return ""
	case onlyHist == len(cps):
		return "，均来自历史 run"
	default:
		return "，其中 " + itoa(onlyHist) + " 条来自历史 run"
	}
}
