package agentic

import (
	"appsecgo/internal/factspec"
	"os"
	"regexp"
	"strings"

	"appsecgo/internal/slice"
	"appsecgo/internal/slice/gots"
)

// authz_coverage.go — missing-auth 事实固化 + A1 auth-weaponization（spec
// 2026-08-12-missing-auth-fact-solidification + 2026-08-12-auth-weaponization-strategy-token）。
// 确定性 pre-judge：把 LLM 非确定性跑的鉴权搜索（@PreAuthorize/@Secured/@RolesAllowed
// + @EnableWebSecurity/SecurityFilterChain/SecurityConfig repo-wide grep）确定性重跑。
//
// A1 两步拆分（spec §1.1/§1.2）：
//   - ComputeAuthzCoverage：前移到 JudgeOne sr.Select 之前，写 sliced["authz_coverage"]
//     struct（无渲染层 → messages/cache key 不含 → parity 稳；repoIndex=nil → no-op）。
//     供 authz_none trigger 读事实 fire missing_auth。
//   - RenderAuthzNote：原位在 buildLoopMessages（BuildMessages 之后）读 struct 注入软注记。
//
// 只固化确定性结论（spec §4）：MethodGuard/ClassGuard 永远 true/false（AST 本地确定性）；
// GlobalInterceptor 只写 "none"（零命中确定性）或 ""（命中/覆盖不明）；绝不写 "found"/"unknown"。
// 任何维度 error/panic → 整体 fail-open（不写字段）。无 guard、无 rejudge、never-upgrade-TP。

// authzAnnotationRe 匹配方法/类级鉴权注解。
//
// EXCULPATORY-FACT: authz_method_annotation
//
// 语料契约在 internal/factguard —— 该 pattern 会写出**确定性的** method_guard=false,
// 漏认某个框架的注解族就等于对那类项目产假否定(2026-08-23 类:未经证明的确定性事实)。
// 原集只有 Spring 四注解,漏 Shiro(@Requires*)/Sa-Token(@SaCheck*)/JSR-250 @DenyAll/
// Spring 自己的 @PostAuthorize —— Shiro 是国内常见选型,这不是理论风险。
//
// **移除 @PermitAll**:它字面意思是「允许所有人」= 明确**不需要**鉴权,算作守卫会把真的
// 未授权端点藏掉(方向恰好反了)。三仓零用量,故修它零活体影响;方向也安全(多报不少报)。
var authzAnnotationRe = regexp.MustCompile(
	`@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|@DenyAll|` + // Spring Security / JSR-250
		`@Requires(Permissions|Roles|Authentication|User|Guest)|` + // Apache Shiro
		`@SaCheck(Login|Role|Permission|Safe|DisableLogin)`) // Sa-Token

// globalInterceptorPattern = LLM 自跑 pattern 集的确定性超集。含裸 "SecurityConfig" 会
// 过度匹配，但过度匹配只把 "none" 降为 "found-but-unclear"（安全方向，不产假 "none"）。
//
// **2026-08-23 补 servlet Filter 与拦截器实现**：原集只有 Spring Security 与
// addInterceptor 注册式，**不含 `@WebFilter` / `implements Filter` / HandlerInterceptor
// 实现**，于是对真有全局鉴权 Filter 的仓库写出了确定性的 "none" —— 正是本注释明令
// 禁止的**假 none**。活体：ceshi(jshERP) 的 `LogCostFilter` 是
// `@WebFilter(urlPatterns={"/*"})`，未登录直接 500 + "loginOut" 不放行；而 authz_coverage
// 对该仓每条告警都注入 `global_interceptor:"none"` + 证据「zero matches」，
// 模型据此判出错误的缺失鉴权 TP，面账的分组事实也一并被污染。
//
// 假 none 比漏判危险得多：它是**确定性事实**，判决链与面账都会当真值采信（GR-8）。
// 「超集」这个自我声称必须靠测试兑现，不能靠注释 —— 已加两条回归锁（正反各一）。
//
// **2026-08-27 M1：preHandle\b 右边界锚定（治「过匹配→假开脱」类，活体）**：上方
// 「过度匹配只把 none 降为 found-but-unclear（安全方向）」对 precision 成立（不产假
// none）但对 recall 不成立 —— found-but-unclear 即 global_interceptor=""，被
// authzNote case "" 渲染成 Exculpatory-Yes「拦截器存在（开脱性）」，当命中的是非
// security 业务文件时（活体：underwrite ChannelPremiumSplitComponent 的业务方法
// preHandleForCalcPolicyTax 含子串 "preHandle" ×7 行）即**假开脱事实**，压制真 IDOR
// 召回（#22/#25）。preHandle\b 使「preHandle 作独立词/后缀」（preHandle(、preHandle
// + 空格）才命中，排除 preHandleForCalcPolicyTax（e 后 F 均词字符，无 \b）。
// 短/歧义分支系统化 \b 右边界锚定（治一类，非一点 —— preHandle 活体只是最先暴露的
// 一个；GR-7）：preHandle\b / addInterceptors?\b / permitAll\b / requestMatchers\b / antMatchers\b /
// SecurityConfig(uration)?\b / implements\s+Filter\b。逐条边界由 factguard 语料正反
// fixture 驱动（internal/factguard/corpus.go 的 authz_global_interceptor）：正须命中
// （SecurityConfiguration 长形 → 取 SecurityConfig(uration)?\b 而非裸 SecurityConfig\b，
// 否则漏；WebMvcConfigurer addInterceptors 复数 → 取 addInterceptors?\b 而非 addInterceptor\b，
// 否则漏），反须不命中（SecurityConfigHolder / SecurityConfigUtil / addInterceptorForAudit /
// permitAllCheck / requestMatchersFor / implements Filterable —— 均业务标识符含 security 子串，
// 假开脱与 preHandle 同类）。antMatchers\b（2026-08-27 GR-7 补，与 requestMatchers\b 同形）：
// 5 仓全 antMatchers 0 命中（含 underwrite #22/#25）→ inert，零 authz_coverage delta、零归因
// 影响；锚 \b 防 future 仓 antMatchersFor 业务假命中（spec §3.1.1 + §7.3 判据 2 实证）。
// 锁：活体回归 TestAuthzCoverage_PreHandleBusinessMethodIsNone（authz_coverage_m1_test.go）
// + 语料 TestFactCorpus_GlobalInterceptor + 真拦截器不误杀 TestAuthzCoverage_ServletFilterIsNotNone。
// spec `docs/superpowers/specs/2026-08-27-m1-authz-false-exculpatory-m2-per-axis-design.md` §3.1。
// EXCULPATORY-FACT: authz_global_interceptor
const globalInterceptorPattern = `@EnableWebSecurity|SecurityFilterChain|WebSecurityConfigurerAdapter|addInterceptors?\b|permitAll\b|antMatchers\b|requestMatchers\b|SecurityConfig(uration)?\b|@WebFilter|implements\s+Filter\b|OncePerRequestFilter|HandlerInterceptor|preHandle\b`

// F4a SOFA RPC facade 检测(spec docs/superpowers/specs/2026-09-03-f4a-entry-nature-rpc-facade-suppress-design.md)。
// <sofa:service interface="FQCN" ref="beanId"><sofa:binding.bolt/></sofa:service> = 本仓**发布**的内部 RPC
// facade(bolt=RPC internal);<sofa:binding.rest/http> = HTTP 公网发布(非 internal,排除);<sofa:reference>
// = 出站消费(非入口,排除)。interface/ref 属性序变(真 zeus-facade-service.xml:19 interface 先、:59 ref 先)
// ⇒ 从开标签提 interface。RE2 无 backref ⇒ open/close 前缀同 alternation(实务同前缀,异前缀不现于真文件)。
var sofaServiceBlockRe = regexp.MustCompile(`<(?:soa|sofa):service\b[^>]*>([\s\S]*?)</(?:soa|sofa):service>`)
var sofaInterfaceAttrRe = regexp.MustCompile(`interface="([^"]*)"`)

// hasAuthzAnnotation 报 s 是否含方法/类级鉴权注解。
func hasAuthzAnnotation(s string) bool {
	return authzAnnotationRe.MatchString(s)
}

// readEntryFileFacts self-parses the entry file via gots 导出 helper,**一次 DFS 取两事实**:
//   - methodGuard:入口方法 fn 的鉴权注解(原 readMethodGuard 逻辑,methodHasAuthz)
//   - implInterfaces:入口类(hops[0] 所在文件**首个/最外层** class_declaration)的 implements 短名集
//     (F4a:供 computeEntryNature 匹配 SOFA RPC facade)
// ok=false 表示 read/parse 失败**或方法未找到**(caller fail-open 整体不写 authz_coverage,保
// readMethodGuard 既有契约:method-not-found → 不写整个 struct)。单次 parse 复用(避免对大入口
// 文件 double-parse);DFS 中首个遇到的 class_declaration = 最外层类(impl 类),nested 不覆盖。
func readEntryFileFacts(filePath, fn string) (methodGuard bool, implInterfaces []string, ok bool) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return false, nil, false
	}
	tr, err := gots.ParseJavaUTF8(src)
	if err != nil {
		return false, nil, false
	}
	root := gots.RootNode(tr)
	var classDecl gots.Node
	classDeclFound := false
	methodFound := false
	stack := []gots.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		// 首个(最外层)class_declaration = 入口 impl 类(nested 不覆盖)。
		if !classDeclFound && gots.NodeType(n) == "class_declaration" {
			classDecl = n
			classDeclFound = true
		}
		if gots.NodeType(n) == "method_declaration" {
			if ident, found := gots.FieldChild(n, "name"); found && gots.NodeText(src, ident) == fn {
				methodGuard = methodHasAuthz(src, n)
				methodFound = true
			}
		}
		stack = append(stack, gots.Children(n)...)
	}
	if !methodFound {
		return false, nil, false // 方法未找到 → fail-open(保 readMethodGuard 既有契约)
	}
	if classDeclFound {
		implInterfaces = implInterfaceShortNames(src, classDecl)
	}
	return methodGuard, implInterfaces, true
}

// implInterfaceShortNames 取 class_declaration 的 implements 短名集(F4a:SOFA RPC facade 匹配用)。
// tree-sitter-java:class_declaration 的 implements 经 field "interfaces" → implements_clause;field 缺
// 则回退按 NodeType=="implements_clause" 扫直子(容 grammar 版本差)。interface 引用为 type_identifier
// (短名,如 TaskService,经 import 解析);FQCN(scoped_type_identifier)在 implements 罕见(多用短名)
// ⇒ 只收 type_identifier。无 implements / parse 失败 → nil(fail-open,computeEntryNature 见 nil 不下 rpc)。
func implInterfaceShortNames(src []byte, classDecl gots.Node) []string {
	implClause, found := gots.FieldChild(classDecl, "interfaces")
	if !found {
		for _, c := range gots.Children(classDecl) {
			if gots.NodeType(c) == "implements_clause" {
				implClause = c
				found = true
				break
			}
		}
	}
	if !found {
		return nil
	}
	var out []string
	var walk func(gots.Node)
	walk = func(n gots.Node) {
		if gots.NodeType(n) == "type_identifier" {
			if t := gots.NodeText(src, n); t != "" {
				out = append(out, t)
			}
		}
		for _, c := range gots.Children(n) {
			walk(c)
		}
	}
	walk(implClause)
	return out
}

// methodHasAuthz walks a method_declaration's modifiers for authz annotations.
func methodHasAuthz(src []byte, method gots.Node) bool {
	for _, child := range gots.Children(method) {
		if gots.NodeType(child) != "modifiers" {
			continue
		}
		for _, mod := range gots.Children(child) {
			mt := gots.NodeType(mod)
			if mt == "annotation" || mt == "marker_annotation" {
				if hasAuthzAnnotation(gots.NodeText(src, mod)) {
					return true
				}
			}
		}
	}
	return false
}

// computeEntryNature 产 F4a entry_nature:若入口 impl 类 implements 某 SOFA-bolt-发布接口
// → "rpc_internal_facade";否则 ""(fail-open,missing_auth trigger fire 保现状)。生产铁律:须
// **正向证据**(grep 到 SOFA service XML + 解析出 bolt-发布接口 + impl implements 之一匹配)才下 rpc
// 结论;任一环节不确定 → ""(绝不产假「非公网」反向混淆,GR-8;同 GlobalInterceptor 三态精神)。
// trigger-only(不渲染,见 ComputeAuthzCoverage 写 struct + RenderAuthzNote 不读)⇒ messages/cacheKey 不含。
func computeEntryNature(exec *ToolExecutor, implInterfaces []string) string {
	if len(implInterfaces) == 0 {
		return ""
	}
	// 1. 找含 <sofa:service/<soa:service 的 XML(SOFA 发布配置;*.xml)。
	grAny := exec.grepRepo(map[string]any{"pattern": `<soa:service|<sofa:service`, "file_glob": "*.xml"})
	gr, ok := grAny.(grepRepoResult)
	if !ok || gr.Truncated {
		return "" // grep error / 截断 → fail-open(不下 rpc)
	}
	// 2. 累计所有命中 XML 的 bolt-发布接口短名集。
	published := map[string]bool{}
	for _, m := range gr.Matches {
		rel, _ := m["file"].(string)
		if rel == "" {
			continue
		}
		abs, ok := exec.safeResolve(rel)
		if !ok {
			continue
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		for _, pub := range sofaPublishedBoltInterfaceShortNames(string(data)) {
			published[pub] = true
		}
	}
	if len(published) == 0 {
		return ""
	}
	// 3. impl implements 任一短名 ∈ 发布集 → rpc_internal_facade。
	for _, ii := range implInterfaces {
		if published[ii] {
			return "rpc_internal_facade"
		}
	}
	return ""
}

// sofaPublishedBoltInterfaceShortNames 解析 SOFA XML,返 <sofa:service ...><sofa:binding.bolt/></sofa:service>
// 发布的 interface FQCN **末段**集。排除:<sofa:binding.rest/http>(HTTP 公网发布,非 internal RPC)、
// 无 binding.bolt 的 service、<sofa:reference>(出站消费,非发布——regex 只配 service 块,reference 不入)。
// interface/ref 属性序变 ⇒ 从开标签(首个 > 之前)提 interface。块跨行(真文件:63-66)⇒ [\s\S] 跨行。
func sofaPublishedBoltInterfaceShortNames(xml string) []string {
	var out []string
	for _, m := range sofaServiceBlockRe.FindAllStringSubmatch(xml, -1) {
		whole := m[0] // 含开标签 + 块内 + 闭标签
		gt := strings.Index(whole, ">")
		if gt < 0 {
			continue
		}
		openTag := whole[:gt] // 首个 > 之前 = 开标签(含 interface/ref 属性,容序容跨行)
		block := m[1]          // 块内文(含 <sofa:binding.bolt/>)
		if !strings.Contains(block, "binding.bolt") {
			continue // 非 bolt(无绑定或 rest/http)
		}
		if strings.Contains(block, "binding.rest") || strings.Contains(block, "binding.http") {
			continue // 亦 HTTP 公网发布 → 非 internal RPC
		}
		ia := sofaInterfaceAttrRe.FindStringSubmatch(openTag)
		if ia == nil || ia[1] == "" {
			continue
		}
		out = append(out, lastSegment(ia[1]))
	}
	return out
}

// lastSegment 取 FQCN 末段:"cn.com.x.TaskService" → "TaskService"(无点则原样)。
func lastSegment(fqcn string) string {
	if i := strings.LastIndex(fqcn, "."); i >= 0 {
		return fqcn[i+1:]
	}
	return fqcn
}

// ComputeAuthzCoverage 计算鉴权覆盖事实 + 写 sliced["authz_coverage"]（不返软注记——
// render 由 RenderAuthzNote 读结构渲染）。前移到 JudgeOne sr.Select 之前，供 authz_none
// trigger 读事实（spec A1 §1.1）。sliced/repoIndex nil 或 repoRoot 空 → no-op（parity 门）。
// 任何维度 error/panic → 整体 fail-open（不写字段）——保证 GlobalInterceptor==""（非 nil
// struct）无歧义 = grep 成功命中但覆盖待判定（spec §4 三态）。
func ComputeAuthzCoverage(sliced map[string]any, repoIndex *slice.RepositoryIndex) {
	defer func() { recover() }() // fail-open（铁律 D）
	if sliced == nil || repoIndex == nil {
		return
	}
	repoRoot := repoIndex.RepoRoot()
	if repoRoot == "" {
		return
	}
	hopsAny, _ := sliced["hops"].([]any)
	if len(hopsAny) == 0 {
		return
	}
	hop, _ := hopsAny[0].(map[string]any)
	if hop == nil {
		return
	}
	fp, _ := hop["file_path"].(string)
	fn, _ := hop["function_name"].(string)
	if fp == "" {
		return
	}

	// ClassGuard：读已填的 source_class_context.class_annotations（slicer 经
	// classContextFromNode（extractor.go:95-132）填充，含入口类 AST 注解；非
	// FrameworkAnnotations stub——后者恒 []string{}（slicealert.go:205），ClassGuard 不读）。
	classGuard := false
	if scc, ok := sliced["source_class_context"].(map[string]any); ok {
		if anns, ok := scc["class_annotations"].([]any); ok {
			for _, a := range anns {
				if as, ok := a.(string); ok && hasAuthzAnnotation(as) {
					classGuard = true
					break
				}
			}
		}
	}

	// MethodGuard：self-parse entry file。复用 ToolExecutor 的 safeResolve/grepRepo
	// （技术债，spec §1.1：构造整个 ToolExecutor 只为复用两方法；未来 grep 独立为
	// standalone 函数后应消除此隐性依赖）。
	exec := NewToolExecutor(repoIndex, nil, "", nil)
	abs, ok := exec.safeResolve(fp)
	if !ok {
		return // 路径解析失败 → 整体 fail-open
	}
	// readEntryFileFacts 单次 gots-DFS 取 methodGuard + 入口类 implements 短名集
	// (F4a:供 computeEntryNature 匹配 SOFA-bolt 发布接口)。method-not-found → fail-open
	// 整体不写(保 readMethodGuard 既有契约)。
	methodGuard, implInterfaces, found := readEntryFileFacts(abs, fn)
	if !found {
		return // parse/find 失败 → 整体 fail-open（spec §4）
	}

	// GlobalInterceptor：repo-wide grep（确定性镜像 LLM 的搜索）。
	var evidence []string
	globalInterceptor := ""
	grAny := exec.grepRepo(map[string]any{"pattern": globalInterceptorPattern, "file_glob": "*.java"})
	gr, ok := grAny.(grepRepoResult)
	if !ok {
		return // grep error（返 map 形 error）→ 整体 fail-open
	}
	if gr.Truncated {
		return // 截断 → 不下"none"结论 → 整体 fail-open
	}
	if len(gr.Matches) == 0 {
		globalInterceptor = "none"
		evidence = []string{"patterns: " + globalInterceptorPattern, "scanned *.java, zero matches"}
	} else {
		// 命中、覆盖不明 → GlobalInterceptor 留 ""（不写 "found"），Evidence 记位置。
		for _, m := range gr.Matches {
			if file, _ := m["file"].(string); file != "" {
				evidence = append(evidence, file)
			}
		}
	}

	// F4a entry_nature:impl implements 某 SOFA-bolt-发布接口 → "rpc_internal_facade";
	// 否则 ""(fail-open,missing_auth trigger fire 保现状)。trigger-only:写 struct、
	// 不渲染(RenderAuthzNote 不读)⇒ 不进 messages/cacheKey(§1.1/§3.4)。
	entryNature := computeEntryNature(exec, implInterfaces)

	sliced["authz_coverage"] = map[string]any{
		"method_guard":       methodGuard,
		"class_guard":        classGuard,
		"global_interceptor": globalInterceptor, // "" when found-but-unclear
		"entry_nature":       entryNature,       // F4a: "rpc_internal_facade" | ""(trigger-only)
		"evidence":           evidence,
	}
}

// RenderAuthzNote 读 sliced["authz_coverage"] 返软注记串（注入 loopMessages）。
// 纯函数：无 exec、无 I/O、无 repoIndex。struct 缺失/类型畸形 → ""（不注入）。
// spec A1 §1.2。ACTIVE 通道（messages.go 结构渲染在 v1 是 dormant，YAGNI 砍）。
func RenderAuthzNote(sliced map[string]any) string {
	if sliced == nil {
		return ""
	}
	ac, ok := sliced["authz_coverage"].(map[string]any)
	if !ok || ac == nil {
		return ""
	}
	methodGuard, _ := ac["method_guard"].(bool)
	classGuard, _ := ac["class_guard"].(bool)
	globalInterceptor, _ := ac["global_interceptor"].(string)
	evidence, _ := ac["evidence"].([]string)
	return authzNote(methodGuard, classGuard, globalInterceptor, evidence)
}

// authzNote 构建软注记（spec §6.4 措辞）。
func authzNote(methodGuard, classGuard bool, globalInterceptor string, evidence []string) string {
	// 走 factspec.Render —— 格式只定义一处（见 RenderUploadNote 头注）。
	//
	// 三个维度的开脱方向不同，逐个想清楚而不是笼统标：
	//   方法级/类级守卫 = true  → 开脱（有守卫 ⇒ 模型排除 missing-auth）
	//   全局拦截器 = none       → **不开脱**（说「没守卫」只会让判定更严，不会藏漏洞）
	// 反向也成立：guard=false 不是开脱，它让判定更严。故只在 true 时标 Exculpatory。
	ev := strings.Join(evidence, "; ")
	rs := []factspec.Result{
		{
			Fact: "method_guard", Verdict: boolVerdict(methodGuard),
			Grain: factspec.GrainVariable, By: "ast", Exculpatory: methodGuard,
			Evidence: ev,
		},
		{
			Fact: "class_guard", Verdict: boolVerdict(classGuard),
			Grain: factspec.GrainVariable, By: "ast", Exculpatory: classGuard,
			Evidence: ev,
		},
	}
	switch globalInterceptor {
	case "none":
		rs = append(rs, factspec.Result{
			Fact: "global_interceptor", Verdict: factspec.No,
			Grain: factspec.GrainRepo, By: "repo_grep",
			Evidence:    "全仓 pattern 集零命中",
			Implication: "无全局鉴权拦截器。",
		})
	case "":
		// 命中但覆盖不明 —— 这是 Unknown，不是 Yes。写成 Yes 就是拿「存在」冒充「生效」。
		rs = append(rs, factspec.Result{
			Fact: "global_interceptor", Verdict: factspec.Yes,
			Grain: factspec.GrainRepo, By: "repo_grep", Exculpatory: true,
			Evidence:    "已发现全局拦截器配置",
			Implication: "**覆盖范围待你判定** —— 存在不等于对本端点生效。",
		})
	}
	note := factspec.Render("鉴权覆盖（预计算，确定性扫描得出，非你自行搜索）", rs)
	if note == "" {
		return ""
	}
	return note + "\n你不必重复搜索鉴权配置；如重搜发现本扫描遗漏的非标准配置，以你所见为准。"
}

func boolVerdict(b bool) factspec.Verdict {
	if b {
		return factspec.Yes
	}
	return factspec.No
}
