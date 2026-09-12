package faces

import (
	"strings"

	"appsecgo/internal/contract"
)

// grouping.go —— 分组事实契约（2026-08-23 P2）。
//
// # 为什么要这层
//
// 面账的推理是：「共享同一确定性事实形态的同类兄弟，判决不一致 = 可核实的矛盾」。
// 这条推理**只在该面的决定性证据就是分组所依据的那个事实时成立**（门 C）——
// 实测不设门时会推出 cwe-798（硬编码凭据）/rce，而「兄弟端点有硬编码凭据所以你也有」
// 是无效推理，authz_coverage 跟它毫无关系（自验证率 57% → 75% 就是加了这道门）。
//
// 首版把这条写成一张写死的表 `inferableFromAuthzShape`。加第二个分组事实
// （upload 三分支固化）时，那会变成散落各处的 if —— 每加一个事实就要在
// 分组、推断、门 C 三处各改一遍，正是铁律 D 说的「耦合代价随耦合点涨」。
//
// 改成显式契约后：**加一个分组事实 = 往 groupingFacts 加一条**，Build 一行不动。
//
// # 不变量
//
// 一个分组事实必须同时给出两样东西，缺一不可：
//   - Shape：事实的**形态指纹**。形态不同的兄弟本就可以判得不同，不构成矛盾。
//   - Inferable：该事实**能支撑推断**的面族。这是门 C 的落点，绝不允许留空表示"全部"——
//     留空即意味着该事实能推出任意面，那正是自验证率从 75% 掉回 57% 的那条路。

// GroupingFact —— 一个可用于「同类兄弟比对」的确定性事实。
type GroupingFact struct {
	// Name 用于分组键前缀与调试；不同事实的组互不混淆。
	Name string
	// Shape 返回该 alert 在此事实上的形态指纹；"" = 该 alert 缺此事实，不参与本组比对
	//（fail-open：没有确定性事实就不比，绝不猜）。
	Shape func(Alert) string
	// Inferable —— 该事实能支撑推断的面族（门 C）。
	Inferable map[string]bool
}

// groupingFacts —— 已登记的分组事实。
//
// 加新事实的检查清单：
//  1. Shape 只读**确定性**事实（authz_coverage 这类预计算），不读 LLM 叙述；
//  2. Inferable 只列「决定性证据就是该事实」的面族 —— 拿不准就不列，
//     漏列只是少标一条待复核，错列会制造无效推理（后者不可逆地降低面账可信度）；
//  3. 补一条 table test 钉住 Inferable 的边界（哪个面能推、哪个不能）。
var groupingFacts = []GroupingFact{
	{
		Name: "authz",
		Shape: func(a Alert) string {
			if a.Authz == nil {
				return "" // 事实缺失 → 不参与比对
			}
			return authzShape(a.Authz)
		},
		// 访问控制面的决定性证据正是「端点有无鉴权守卫」= authz_coverage 本身，故可推。
		// 硬编码凭据/RCE/注入类的决定性证据是各自的具体代码，与鉴权形态无关。
		Inferable: map[string]bool{"access_control": true},
	},
	{
		Name: "upload_disposition",
		Shape: func(a Alert) string {
			if a.Upload == nil {
				return "" // 非上传流或无确定结论 → 不参与比对
			}
			return a.Upload.FileWriteSink + "|" + a.Upload.FilenameNeutralized + "|" + a.Upload.TaintedPathSegment
		},
		// **按每一支逐个判，不是整族放开**：
		//   file_upload(b1 webshell) —— 决定性证据正是「有无落盘 + 落在哪」= 本事实，可推。
		//   path_traversal(b3)       —— 决定性证据正是「文件名/路径段是否中和」= 本事实，可推。
		// 刻意**不含** stored_xss(b2)：它的决定性证据是**回显端点的响应头**
		// （Content-Disposition / nosniff / Content-Type），本事实一个字都没说到那里。
		// 把 b2 放进来就是「用落盘事实去推渲染上下文」，正是门 C 要挡的无效推理。
		Inferable: map[string]bool{"file_upload": true, "path_traversal": true},
	},
}

// factsHuman —— 把分组事实渲染成人类可读的依据行（进报告的「依据」列）。
func factsHuman(f GroupingFact, a Alert) string {
	switch f.Name {
	case "authz":
		return "鉴权事实：" + authzHuman(a.Authz)
	case "upload_disposition":
		return "上传处置事实：" + uploadHuman(a.Upload)
	}
	return f.Name + " 事实形态：" + f.Shape(a)
}

// uploadHuman —— 上传处置事实的人类可读形态。只陈述**已确认**的，留空的说成「未确定」
// 而不是「否」（假否定的措辞红线，见 agentic/upload_disposition.go）。
func uploadHuman(u *contract.UploadDisposition) string {
	if u == nil {
		return "未计算"
	}
	parts := []string{}
	if u.FileWriteSink == "none" {
		parts = append(parts, "全仓零落盘 API")
	} else {
		parts = append(parts, "落盘 API 存在或未确定")
	}
	if u.FilenameNeutralized == "yes" {
		parts = append(parts, "文件名已确认中和")
	} else {
		parts = append(parts, "文件名中和未确定")
	}
	if u.TaintedPathSegment == "yes" {
		parts = append(parts, "已确认请求参数进入路径构造")
	} else {
		parts = append(parts, "路径段污染未确定")
	}
	return strings.Join(parts, "，")
}
