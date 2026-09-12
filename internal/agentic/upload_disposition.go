package agentic

import (
	"regexp"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/factspec"
	"appsecgo/internal/slice"
	"appsecgo/internal/taintbridge"
)

// upload_disposition.go —— CWE-434 三分支的确定性事实固化（2026-08-23 P1-1）。
//
// # 为什么做这个
//
// 全量缺口分类：upload 三分支占 uncertain 缺口的 **73%**，是最大的一块，且三个问题**固定**
// （b1 落盘目录 / b2 回显响应头 / b3 文件名与路径中和），却每次让模型自由重问、自由回答，
// 于是同一份代码跨 run 判决翻来覆去。照抄 ComputeAuthzCoverage 已验证的模式把它固化。
//
// # 与 authz 固化的关键差异（照抄它的三态口径会出错）
//
// authz 的**否定**是确定的（全仓 grep 零命中 = 真没守卫）；upload 的否定**大多不确定**
// —— 切片可能被截断，「切片里没看到落盘」不等于「不落盘」。故：
//
//   - FileWriteSink 走全仓 grep，"none" 是确定性否定（真的一处落盘 API 都没有
//     → b1 与 b3-写 两支同时不可达）。它是 NEGATIVE-FACT，有语料契约兜底。
//   - 其余只写确定性**肯定**，拿不准留空。**留空 ≠ 否定** —— 渲染措辞必须是
//     「已确认存在 X」，绝不能写「未发现 X」（那正是制造假否定的说法）。
//
// # 人工核实喂出来的三条口径（2026-08-23，非臆测）
//
//  1. ceshi SupplierController：Excel 仅 `getInputStream()` 内存解析，全仓层面仍有落盘
//     API（uploadLocal），故 FileWriteSink 不写 none —— 该条的 FP 结论靠切片内无落盘，
//     那是**模型**该下的判断，本固化不越界替它下。
//  2. rt RelateTaskServiceImpl：`lastIndexOf("/")` 确实剥了斜杠 → FilenameNeutralized=yes。
//     历史某跑判「未剥离」是错误确认，正是这条要钉死的抖动。
//  3. ceshi uploadLocal：文件名中和了，**但目录来自 `request.getParameter("biz")` 且零净化**
//     → TaintedPathSegment=yes。报告只查文件名就宣布 b3 不可达，把真漏洞说成了另一回事。
//     **路径的每一段都要查。**

var (
	// EXCULPATORY-FACT: upload_file_write_sink
	//
	// 语料契约在 internal/factguard —— 该 pattern 会写出**确定性的** FileWriteSink="none",
	// 而 none 直接推出「b1 webshell 与 b3 穿越写两支不可达」。漏认某个落盘 API 族
	// 就等于对那类项目产假否定,把真的 webshell 面藏掉(2026-08-23 类:未经证明的确定性事实)。
	fileWriteSinkPattern = `\.transferTo\(|Files\.(write|copy|newOutputStream|newBufferedWriter)|` +
		`new\s+FileOutputStream|new\s+RandomAccessFile|FileUtils\.(copyInputStreamToFile|writeByteArrayToFile|copyFile)|` +
		`\.createNewFile\(|FileCopyUtils\.copy`

	// filenameNeutralizeRe —— 文件名中和的形态（**切片级**证据，仅肯定，不推否定）。
	//
	// `lastIndexOf("/")`+substring 是 rt 的真实写法；FilenameUtils.getName 是 commons-io 标准；
	// UUID/随机重命名等于丢弃客户端名。
	//
	// **删过一条**：`System.currentTimeMillis()\s*\+\s*` 当初按「服务端重命名 = 丢弃客户端名」
	// 收进来，是个**事实错误** —— 重命名是**替换**，拼时间戳是**保留**。活体原文
	// （ceshi SystemConfigService:197）里客户端名 orgName 原封不动还在拼接结果中。
	// 任何拼时间戳但没中和的仓库都会被它假开脱。删掉后该仓仍判 yes（靠 lastIndexOf
	// 那条真信号，命中的是 FileUtils.getFileName 的实现体，被 eager_guard 拉进了切片）。
	//
	// 剩下这些**仍然只是切片级**证据：只说明「切片文本里出现过这个形态」，不说明它
	// 作用于本条污点变量（活体反例：上传方法里生成个链路 id 就含 UUID.randomUUID）。
	// 故 factspec 给它们挂弱证据标注，见 factspec.weakEvidenceNote。
	filenameNeutralizeRe = regexp.MustCompile(
		`FilenameUtils\.getName|` +
			`lastIndexOf\("[/\\]+"\)|lastIndexOf\('[/\\]'\)|` +
			`UUID\.randomUUID|RandomStringUtils\.random`)

	// requestParamRe / pathBuildRe —— TaintedPathSegment 的两个共现条件。
	// 单独任一都不说明问题(取参数很常见、拼路径也很常见),**同一函数体内同时出现**
	// 才构成「请求参数可能进了路径构造」这个可核实的textual事实,交由模型去确认哪一段。
	requestParamRe = regexp.MustCompile(`\.getParameter\(|@RequestParam|@PathVariable`)
	pathBuildRe    = regexp.MustCompile(`new\s+File\(|File\.separator|\.mkdirs?\(|Paths\.get\(`)

	// EXCULPATORY-FACT: upload_nosniff_header
	//
	// nosniff 缺席会让浏览器按内容嗅探类型 —— 上传的 .html/.svg 即使 Content-Type 不对
	// 也可能被当标记渲染(b2 存储型 XSS)。"none" 是确定性否定,漏认某种设置方式
	// 就会对那类项目谎报「没有 nosniff」,把已被防住的 b2 说成可达。
	// contentTypeOptions 不带 set 前缀 —— Spring Security 的写法是
	// `http.headers().contentTypeOptions()`。首版写成 setContentTypeOptions,
	// **被语料当场抓出**(这正是语料契约存在的意义:注释说得再满也保证不了 pattern 写对)。
	nosniffPattern = `X-Content-Type-Options|(?i)nosniff|contentTypeOptions`

	// attachmentRe / respWriteRe —— InlineCapableSite 的两个条件。
	// 往响应写字节、却在同文件内**找不到** attachment 设置 → 该处可能内联回显。
	attachmentRe = regexp.MustCompile(`(?i)content-disposition`)
	respWriteRe  = regexp.MustCompile(`getOutputStream\(\)|ServletOutputStream|write\(\s*buffer|StreamUtils\.copy`)

	// uploadSourceRe —— 该切片是否真的在处理上传(避免对无关告警写这组事实)。
	uploadSourceRe = regexp.MustCompile(`MultipartFile|getOriginalFilename|@RequestPart|Part\s+\w+|getSubmittedFileName`)
)

// ComputeUploadDisposition 计算 CWE-434 三分支事实 + 写 sliced["upload_disposition"]。
//
// 与 ComputeAuthzCoverage 同位置调用（JudgeOne sr.Select 之前）。sliced/repoIndex nil、
// 非上传类切片、或任何一步失败 → no-op（fail-open，绝不写半截事实）。
func ComputeUploadDisposition(sliced map[string]any, repoIndex *slice.RepositoryIndex, engine taintbridge.EngineQuerier) {
	defer func() { recover() }() // fail-open（铁律 D）
	if sliced == nil || repoIndex == nil || repoIndex.RepoRoot() == "" {
		return
	}
	bodies := hopBodies(sliced)
	if len(bodies) == 0 {
		return
	}
	joined := strings.Join(bodies, "\n")
	if !uploadSourceRe.MatchString(joined) {
		return // 不是上传流 → 不写这组事实（无关告警不该被塞无关事实）
	}

	ud := &contract.UploadDisposition{}

	// FileWriteSink：全仓 grep（唯一的确定性否定）。
	exec := NewToolExecutor(repoIndex, nil, "", nil)
	grAny := exec.grepRepo(map[string]any{"pattern": fileWriteSinkPattern, "file_glob": "*.java"})
	gr, ok := grAny.(grepRepoResult)
	if !ok || gr.Truncated {
		return // grep 失败或截断 → 不下 none 结论 → 整体 fail-open
	}
	if len(gr.Matches) == 0 {
		ud.FileWriteSink = "none"
		ud.Evidence = append(ud.Evidence,
			"全仓扫 *.java 零落盘 API 命中（b1 webshell 与 b3 穿越写两支不可达）")
	}

	// FilenameNeutralized：走 factspec（引擎优先，文本扫兜底）。
	//
	// 这条是**第一条**从手写取证迁到可替换边界上的事实。区别不是省代码：文本扫命中
	// 只说明「切片里有中和」，引擎命中说明「中和作用于这条污点变量」，且带可核实锚点。
	// 引擎缺席/问不出 → 退回文本扫；两者都答不上 → Unknown（留空，**不是否定**）。
	if r := factspec.Evaluate(SpecFilenameNeutralized, newFactCtx(sliced, repoIndex.RepoRoot(), engine)); r.Verdict == factspec.Yes {
		ud.FilenameNeutralized = "yes"
		ud.FilenameNeutralizedGrain = r.Grain.CN()
		ud.Evidence = append(ud.Evidence,
			"确认存在文件名中和："+r.Evidence+"（取证:"+r.By+"，"+r.Grain.CN()+"）")
	}

	// TaintedPathSegment：「取请求参数」与「构造路径」在**切片内**共现。
	//
	// 首版要求同一函数体 —— 活体验证当场打脸：ceshi ca15851d 的污点**跨 hop**，
	// hop0 控制器 `request.getParameter("biz")`，hop5 服务层 `new File(ctx + sep + bizPath).mkdirs()`
	// （bizPath 是**入参**）。同体要求恰好漏掉了这条事实存在的理由本身。
	//
	// 切片本身就是这条告警的污点路径、hop 由调用关系相连，故切片级共现是恰当粒度。
	// 同体命中是更紧的证据，与跨 hop 分开记进 evidence，让读者知道强弱。
	sameBody := false
	for _, b := range bodies {
		if requestParamRe.MatchString(b) && pathBuildRe.MatchString(b) {
			sameBody = true
			break
		}
	}
	if sameBody || (requestParamRe.MatchString(joined) && pathBuildRe.MatchString(joined)) {
		ud.TaintedPathSegment = "yes"
		where := "跨 hop（控制器取参 → 服务层拼路径，经调用传递）"
		if sameBody {
			where = "同一方法体内"
		}
		ud.Evidence = append(ud.Evidence,
			"切片内确认既取请求参数又构造文件路径（"+where+"）——**路径的每一段都要查，不能只看文件名**"+
				"（活体：ceshi uploadLocal 文件名已中和，但目录来自 request.getParameter(\"biz\") 且零净化，"+
				"报告只查文件名就宣布 b3 不可达，把真漏洞说成了另一回事）")
	}

	// —— b2 回显上下文：全仓扫，答模型答不了的那个问题 ——
	//
	// 模型反复写「下载回显的响应头在切片中不可见」→ 判 uncertain。那个事实**在仓里**，
	// 只是不在这条告警的切片里。三仓实测：attachment 都设了，nosniff **都没有**。
	grNs := exec.grepRepo(map[string]any{"pattern": nosniffPattern, "file_glob": "*.java"})
	if ns, ok := grNs.(grepRepoResult); ok && !ns.Truncated && len(ns.Matches) == 0 {
		ud.NosniffHeader = "none"
		ud.Evidence = append(ud.Evidence,
			"全仓扫 *.java 零 X-Content-Type-Options/nosniff 命中：浏览器可能按内容嗅探类型，"+
				"上传的 .html/.svg 若被内联返回即可渲染（b2 的必要条件之一成立）")
	}
	// 往响应写字节、却在同文件内找不到 attachment 设置的位置 = 可能内联回显。
	if sites := inlineCapableFiles(exec); len(sites) > 0 {
		ud.InlineCapableSite = "yes"
		ud.Evidence = append(ud.Evidence,
			"全仓扫确认存在**往响应写字节却未在同文件设置 Content-Disposition** 的位置："+
				strings.Join(sites, "、")+"——b2 的渲染上下文可能就在那里，请据此核实而非判「不可见」")
	}

	if ud.FileWriteSink == "" && ud.FilenameNeutralized == "" && ud.TaintedPathSegment == "" &&
		ud.NosniffHeader == "" && ud.InlineCapableSite == "" {
		return // 一条确定结论都没有 → 不写空壳（key 缺席，parity 守卫）
	}
	sliced["upload_disposition"] = map[string]any{
		"file_write_sink":            ud.FileWriteSink,
		"filename_neutralized":       ud.FilenameNeutralized,
		"filename_neutralized_grain": ud.FilenameNeutralizedGrain,
		"tainted_path_segment":       ud.TaintedPathSegment,
		"nosniff_header":             ud.NosniffHeader,
		"inline_capable_site":        ud.InlineCapableSite,
		"evidence":                   ud.Evidence,
	}
}

// RenderUploadNote 读 sliced["upload_disposition"] 返软注记。
//
// **不再手写字符串** —— 组装成 []factspec.Result 交给 factspec.Render 渲染。
// 格式（XML 结构、粒度属性、措辞红线）只定义一处，将来加事实自动继承；
// 三处手写 = 三种格式各自漂移，正是要避免的。
//
// **措辞红线**：只说「已确认存在 X」，绝不说「未发现 X」。留空是不确定不是否定，
// 写成否定会让模型据此排除掉真实存在的分支。
func RenderUploadNote(sliced map[string]any) string {
	m, ok := sliced["upload_disposition"].(map[string]any)
	if !ok || m == nil {
		return ""
	}
	str := func(k string) string { v, _ := m[k].(string); return v }
	var rs []factspec.Result

	if str("file_write_sink") == "none" {
		rs = append(rs, factspec.Result{
			Fact: "file_write_sink", Verdict: factspec.No, Grain: factspec.GrainRepo, By: "repo_grep",
			Evidence:    "全仓扫描零落盘 API 命中",
			Implication: "b1(webshell) 与 b3(穿越写) 两支不可达，请勿再据此判 true_positive。",
		})
	}
	if str("filename_neutralized") == "yes" {
		g := factspec.GrainSlice
		if str("filename_neutralized_grain") == "变量级" {
			g = factspec.GrainVariable
		}
		rs = append(rs, factspec.Result{
			Fact: "filename_neutralized", Verdict: factspec.Yes, Grain: g, By: "slice_scan",
			// 开脱方向：这条判成「是」会让模型排除 b3。粗粒度时 Render 会补边界说明。
			Exculpatory: true,
			Evidence:    "切片内出现文件名中和形态（getName / 分隔符截断 / 服务端重命名）",
			Implication: "据此复核经文件名的 b3。",
		})
	}
	if str("nosniff_header") == "none" {
		rs = append(rs, factspec.Result{
			Fact: "nosniff_header", Verdict: factspec.No, Grain: factspec.GrainRepo, By: "repo_grep",
			Evidence: "全仓扫描零 X-Content-Type-Options/nosniff 命中",
			Implication: "浏览器可能按内容嗅探类型，上传的 .html/.svg 若被内联返回即可渲染 —— " +
				"b2 的必要条件之一成立。",
		})
	}
	if str("inline_capable_site") == "yes" {
		rs = append(rs, factspec.Result{
			Fact: "inline_capable_site", Verdict: factspec.Yes, Grain: factspec.GrainRepo, By: "repo_grep",
			Evidence: "全仓扫描确认存在往响应写字节却未设 Content-Disposition 的位置",
			Implication: "b2 的渲染上下文可能就在那里。请据此核实，**不要再判「回显响应头不可见」**" +
				"——那个事实在仓里，只是不在本条切片里。",
		})
	}
	if str("tainted_path_segment") == "yes" {
		rs = append(rs, factspec.Result{
			Fact: "tainted_path_segment", Verdict: factspec.Yes, Grain: factspec.GrainSlice, By: "slice_scan",
			Evidence: "切片内确认请求参数与路径构造共现",
			Implication: "文件名中和不代表 b3 不可达 —— 请**逐段**核实路径" +
				"（目录段常来自 getParameter，历史上正是这里漏判过真漏洞）。",
		})
	}
	return factspec.Render("上传处置", rs)
}

// hopBodies 取切片各 hop 的函数体文本。
func hopBodies(sliced map[string]any) []string {
	raw, ok := sliced["hops"]
	if !ok || raw == nil {
		return nil
	}
	var out []string
	add := func(m map[string]any) {
		if b, _ := m["function_body"].(string); b != "" {
			out = append(out, b)
		}
	}
	switch hs := raw.(type) {
	case []map[string]any:
		for _, h := range hs {
			add(h)
		}
	case []any:
		for _, h := range hs {
			if m, ok := h.(map[string]any); ok {
				add(m)
			}
		}
	}
	return out
}

// inlineCapableFiles —— 找出「往响应写字节、却在同文件内没有设置 Content-Disposition」的文件。
//
// 这是 b2(存储型 XSS)渲染上下文的可核实线索:文件被内联返回(而非强制下载)时,
// 浏览器可能把 .html/.svg 当标记渲染。**文件级粒度**是刻意的 ——
// attachment 常在同一个下载方法里设,跨文件的 helper 设置会被漏判成「可内联」;
// 这是**肯定向线索**(提示去核实),不是判决,漏判方向安全、误判只是多让模型看一眼。
//
// 返回至多 5 个文件名(证据要能读完,不是倾倒清单)。
func inlineCapableFiles(exec *ToolExecutor) []string {
	wr := exec.grepRepo(map[string]any{"pattern": respWriteRe.String(), "file_glob": "*.java"})
	wres, ok := wr.(grepRepoResult)
	if !ok || wres.Truncated {
		return nil
	}
	at := exec.grepRepo(map[string]any{"pattern": attachmentRe.String(), "file_glob": "*.java"})
	ares, ok := at.(grepRepoResult)
	if !ok || ares.Truncated {
		return nil // 拿不全 attachment 集合 → 不下「可内联」结论(否则会误报)
	}
	hasAttach := map[string]bool{}
	for _, m := range ares.Matches {
		if f, _ := m["file"].(string); f != "" {
			hasAttach[f] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range wres.Matches {
		f, _ := m["file"].(string)
		if f == "" || hasAttach[f] || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, fileBaseName(f))
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func fileBaseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
