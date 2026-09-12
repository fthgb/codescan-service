package factguard

// corpus.go —— 各确定性否定事实的语料。样本取自真实框架的实现形态，不虚构。
//
// 新增一个否定事实时：源码处写 `// NEGATIVE-FACT: <name>`，这里登记同名语料。
// 两者不齐 → TestEveryNegativeFactHasCorpus 红。

var corpora = []Corpus{
	{
		Fact:        "filename_neutralized",
		Exculpatory: "yes",
		Why: "Spec 级(切片文本扫 + 引擎)的「已中和」结论,下游产出「经文件名的 b3 不成立」。" +
			"与 engine_sanitizer_effective 的分工:那条guard引擎在**一个方法体内**的判定," +
			"这条guard整条 Spec 在**一条切片**上的判定 —— 今天实际干活的是文本扫(引擎三仓 0/18)。",
		MustRecognize: []Sample{
			{
				Name: "commons-io 标准中和",
				Src:  `String name = FilenameUtils.getName(mf.getOriginalFilename());`,
				Note: "最常见的正确形态。",
			},
			{
				Name: "分隔符截断",
				Src:  `String p = mf.getOriginalFilename(); String n = p.substring(p.lastIndexOf("/") + 1);`,
				Note: "rt 的真实写法。",
			},
			{
				Name: "服务端重命名(丢弃客户端名)",
				Src:  `String ext = mf.getOriginalFilename(); String n = UUID.randomUUID().toString() + ext;`,
				Note: "重命名等于丢弃客户端提供的名字。",
			},
		},
		MustNotRecognize: []Sample{
			{
				Name: "裸用原始文件名",
				Src:  `String p = dir + "/" + mf.getOriginalFilename();`,
				Note: "一点中和都没有 —— 真的 b3。",
			},
			{
				Name: "① 身份:时间戳后缀不是重命名(活体,当前正则在此误判)",
				Src:  `fileName = orgName.substring(0, orgName.lastIndexOf(".")) + "_" + System.currentTimeMillis() + orgName.substring(orgName.indexOf("."));`,
				Note: "**活体原文**:ceshi SystemConfigService:197。`System.currentTimeMillis() + ` 这条模式" +
					"当初是按「服务端重命名 = 丢弃客户端名」收进来的,但**重命名是替换,时间戳后缀是保留**" +
					"—— 客户端名 orgName 原封不动还在里面。" +
					"该仓当时靠**两条**模式判 yes:这条(假信号)+ `lastIndexOf('/')`(真信号 —— " +
					"命中的是 `FileUtils.getFileName` 的实现体,它被 eager_guard 拉进了切片)。" +
					"故删掉本条后该仓仍判 yes,零损失;而任何拼时间戳但没中和的仓库不再被假开脱。" +
					"(首次核查我只看了这条就断言「证据全错」,是看漏了另一条 —— 记此以免重犯。)",
			},
		},
		// 下面三条不是 pattern 写错,是**切片级粒度看不见** —— 改正则修不了。
		// 结论不删(三仓实测删了会误伤一条本来正确的判断,而假开脱 0 例),
		// 但必须挂弱证据标注,见 VerifyGrainLimited。
		GrainLimited: []Sample{
			{
				Name: "① 身份:UUID 用在别处(链路 id),文件名裸用",
				Src: `String traceId = UUID.randomUUID().toString();
String path = dir + "/" + mf.getOriginalFilename();`,
				Note: "**当前实现在这里误判**:文本扫只认「切片里出现过 UUID.randomUUID」这几个字," +
					"不知道它作用在谁身上。上传方法里生成个链路 id 是极常见的写法,于是一条真的 b3 被开脱掉。",
			},
			{
				Name: "① 身份:中和作用于另一个变量",
				Src: `String other = FilenameUtils.getName(cfgName);
String path = dir + "/" + mf.getOriginalFilename();`,
				Note: "**当前实现在这里误判**:同上,文本扫认字不认变量。这正是引擎(精确到变量)" +
					"应该比文本扫强的地方 —— 也是为什么 EngineSanitizer 排在 SliceScan 前面。",
			},
			{
				Name: "② 时序/③ 路径/④ 持久:文本扫**原理上**看不见",
				Src: `String n = mf.getOriginalFilename(); String path = dir + "/" + n;
if (flag) { n = FilenameUtils.getName(n); }`,
				Note: "**当前实现在这里误判**,且不是可以靠改正则修好的 —— 顺序、分支、重新污染" +
					"都需要语义而非文本。这条样本的存在是为了把一个架构结论钉住:" +
					"**文本扫没有资格独自产出开脱性结论**。要么由引擎定调,要么留 Unknown 交给 LLM。",
			},
		},
	},

	{
		Fact:        "engine_sanitizer_effective",
		Exculpatory: "yes",
		Why: "「已中和」这个**肯定**结论是开脱性的：下游据此宣布「经文件名的 b3 不成立」，" +
			"错一次就静默删掉一处真的路径穿越。危险方向在 yes 一侧，不在 no 一侧 —— " +
			"这正是 factguard 首版判据（只有否定结论才要语料）漏掉的那一类。" +
			"本语料按**净化生效的五个必要条件**穷举（身份/时序/路径/持久/族），" +
			"每个条件各出一条负样本 —— 不是攒四个想得到的坑，是把「净化器存在却不生效」" +
			"这个类拆完（GR-7 治一类不治一点）。任何一条不成立，净化器都在那儿，但到 sink 的值没被中和。",
		MustRecognize: []Sample{
			{
				Name: "五条件全满足:派生一跳 + 自赋值净化",
				Src: `package t;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;
public class T {
    public String up(MultipartFile mf) throws Exception {
        String orgName = mf.getOriginalFilename();
        orgName = FilenameUtils.getName(orgName);
        return "/data/" + orgName;
    }
}
`,
				Note: "活体形态(ceshi SystemConfigService:191-192)。mf 派生出 orgName,orgName 自赋值净化," +
					"原件被覆盖、无副本存活、无分支、无重新污染、族对 —— 五条件齐,应认。",
			},
		},
		MustNotRecognize: []Sample{
			{
				Name: "① 身份:净化结果存到新变量,原件还活着",
				Src: `package t;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;
public class T {
    public String up(MultipartFile mf) throws Exception {
        String orgName = mf.getOriginalFilename();
        String safe = FilenameUtils.getName(orgName);
        return "/data/" + orgName;
    }
}
`,
				Note: "safe 被净化,到 sink 的却是未净化的 orgName。这是 DetectGuardVariableBypass " +
					"专门猎的 reconcat_bypass 形态 —— 说明它在真实代码里出现过。",
			},
			{
				Name: "② 身份:覆盖前先复制出副本(alias 逃逸)",
				Src: `package t;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;
public class T {
    public String up(MultipartFile mf) throws Exception {
        String orgName = mf.getOriginalFilename();
        String alias = orgName;
        orgName = FilenameUtils.getName(orgName);
        return "/data/" + alias;
    }
}
`,
				Note: "自赋值确实覆盖了原件,但覆盖**之前**已经复制出 alias。" +
					"⚠ 现有的 DetectGuardVariableBypass **兜不住这条**:它的 sanitizeAssignRe 匹到 " +
					"`orgName = f(orgName)` 后 taintVar==safeVar 直接 continue,而 `alias = orgName` " +
					"没有括号调用也匹不上。所以「自赋值天然安全」这个直觉是错的,必须由本规则自己挡。",
			},
			{
				Name: "③ 时序:净化发生在 sink 使用之后",
				Src: `package t;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;
public class T {
    public String up(MultipartFile mf) throws Exception {
        String orgName = mf.getOriginalFilename();
        String path = "/data/" + orgName;
        orgName = FilenameUtils.getName(orgName);
        return path;
    }
}
`,
				Note: "净化器就在方法体里,但它在 sink 之后才执行。engine.scanSanitizer 遍历整个方法体、" +
					"命中即返回,**不比行号** —— 这是当前实现的默认行为,不是理论风险。",
			},
			{
				Name: "④ 路径:只在一个分支上净化",
				Src: `package t;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;
public class T {
    public String up(MultipartFile mf) throws Exception {
        String orgName = mf.getOriginalFilename();
        if (mf.getSize() > 0) {
            orgName = FilenameUtils.getName(orgName);
        }
        return "/data/" + orgName;
    }
}
`,
				Note: "flag 为假时到 sink 的是未净化值。scanSanitizer **不看分支**,同样会命中。",
			},
			{
				Name: "⑤ 持久:净化后又被重新污染",
				Src: `package t;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;
public class T {
    public String up(MultipartFile mf) throws Exception {
        String orgName = mf.getOriginalFilename();
        orgName = FilenameUtils.getName(orgName);
        orgName = mf.getOriginalFilename();
        return "/data/" + orgName;
    }
}
`,
				Note: "净化过,然后又被原始值覆盖回去。净化器的存在与它是否仍然有效是两回事。",
			},
			{
				Name: "⑥ 族:净化器属于别的漏洞族",
				Src: `package t;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;
public class T {
    public String up(MultipartFile mf) throws Exception {
        String orgName = mf.getOriginalFilename();
        orgName = java.net.URLEncoder.encode(orgName, "UTF-8");
        return "/data/" + orgName;
    }
}
`,
				Note: "URLEncoder 是 XSS/编码族,对路径穿越不构成中和(`..%2F` 编码后仍可被解码还原)。" +
					"引擎的净化器目录是**漏洞族无关的平表**,故族收窄不能省(factspec 的 AcceptAt 是第一道," +
					"这里是第二道)。",
			},
		},
	},

	{
		Fact:        "authz_global_interceptor",
		Exculpatory: "no", // 确定性否定 —— 开脱的最常见形态
		Why:         "该仓每条告警都会被注入「无全局鉴权」这个假事实，模型据此判出错误的 missing-auth TP，面账的分组事实也一并被污染",
		MustRecognize: []Sample{
			{
				Name: "servlet @WebFilter 全局过滤器（活体：ceshi/jshERP LogCostFilter）",
				Src: `@WebFilter(filterName = "LogCostFilter", urlPatterns = {"/*"},
        initParams = {@WebInitParam(name = "filterPath", value = "/user/login#/user/register")})
public class LogCostFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        Object userId = redisService.getObjectFromSessionByKey(servletRequest, "userId");
        if (userId != null) { chain.doFilter(request, response); return; }
        servletResponse.setStatus(500);
    }
}`,
				Note: "这条就是 2026-08-23 的活体缺陷本身：原 pattern 集只有 Spring Security 与 addInterceptor 注册式，对它零命中",
			},
			{
				Name: "Spring OncePerRequestFilter",
				Src: `public class JwtAuthFilter extends OncePerRequestFilter {
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) {}
}`,
			},
			{
				Name: "Spring HandlerInterceptor 实现",
				Src: `public class LoginInterceptor implements HandlerInterceptor {
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) { return false; }
}`,
			},
			{
				Name: "WebMvcConfigurer 注册拦截器",
				Src: `public class WebConfig implements WebMvcConfigurer {
    public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(new LoginInterceptor()); }
}`,
			},
			{
				Name: "Spring Security 配置",
				Src:  `@EnableWebSecurity public class SecurityConfig { SecurityFilterChain chain(HttpSecurity http) { return null; } }`,
			},
			// —— 2026-08-27 M1：短/歧义分支 \b 锚定的正 fixture（须命中，spec §3.1/§7.1.4）——
			// 正（须命中）：\b 不得漏真拦截器形态的标识符变体（漏认 → 假 none 精度风险）。
			{
				Name: "SecurityConfiguration 配置类名（SecurityConfig 长形）",
				Src:  `public class SecurityConfiguration { }`,
				Note: "SecurityConfiguration 是真 config 常用名；SecurityConfig(uration)?\\b 须命中（短形 Config + 长形 uration）。裸 SecurityConfig\\b 会漏它（Config 后 uration 无 \\b）→ 假 none 精度风险。",
			},
			{
				Name: "WebMvcConfigurer addInterceptors 重写（复数方法名，空体）",
				Src:  `public class WebConfig implements WebMvcConfigurer { public void addInterceptors(InterceptorRegistry registry) {} }`,
				Note: "addInterceptors（复数，WebMvcConfigurer 钩子）是拦截器注册信号；addInterceptors?\\b 须命中复数。裸 addInterceptor\\b 会漏它（s 后无 \\b）。",
			},
			{
				Name: "Spring Security permitAll 放行链",
				Src:  `chain.anyRequest().permitAll();`,
				Note: "permitAll( 是放行链调用；permitAll\\b 须命中（后接 ( 非 \\w）。",
			},
			{
				Name: "Spring Security requestMatchers 路由",
				Src:  `http.requestMatchers("/api/**");`,
				Note: "requestMatchers( 是 SecurityFilterChain 路由；requestMatchers\\b 须命中（后接 (）。",
			},
			{
				Name: "Spring Security antMatchers 路由（deprecated pre-5.8）",
				Src:  `http.antMatchers("/api/**");`,
				Note: "antMatchers( 是 deprecated（pre-5.8）路由匹配；antMatchers\\b 须命中（后接 ( 非 \\w）。GR-7 与 requestMatchers\\b 同形。",
			},
			{
				Name: "servlet Filter 实现类（无 @WebFilter，靠 implements Filter）",
				Src:  `public class AuthFilter implements Filter { public void doFilter(ServletRequest req, ServletResponse res, FilterChain c) {} }`,
				Note: "implements Filter { 是 javax.servlet.Filter 实现；implements\\s+Filter\\b 须命中（Filter 后空格 → \\b）。@WebFilter 之外的 Filter 实现靠这条。",
			},
		},
		MustNotRecognize: []Sample{
			{
				Name: "普通 controller（真的什么守卫都没有）",
				Src: `@RestController
public class PlainController {
    @RequestMapping("/x") public String x(@PathVariable Integer n) { return "ok" + n; }
}`,
				Note: "probe-core 与 relation-trade 经独立核实确实零鉴权设施，必须仍能报 none —— 否则这条判据退化为永不出现",
			},
			{
				Name: "业务过滤类（名字含 filter 但与鉴权无关）",
				Src:  `public class DataFilterUtil { public List<Task> filterByOrg(List<Task> in) { return in; } }`,
				Note: "不能靠「名字里有 filter」判定，那会把任何数据处理类当成鉴权设施",
			},
			// —— 2026-08-27 M1：短/歧义分支 \b 锚定的反 fixture（须不命中，spec §3.1/§7.1.4）——
			// 反（须不命中）：业务标识符含 security 子串不得当拦截器 → 消假开脱（preHandle 活体同类）。
			{
				Name: "业务 holder 类名含 SecurityConfig（非 config）",
				Src:  `public class SecurityConfigHolder { private Object ctx; }`,
				Note: "SecurityConfigHolder 是业务 holder；SecurityConfig(uration)?\\b 须不命中（Config 后 H 均词字符无 \\b）—— 否则假开脱。",
			},
			{
				Name: "业务工具类名含 SecurityConfig",
				Src:  `public class SecurityConfigUtil { public static String mask(String s) { return s; } }`,
				Note: "SecurityConfigUtil 是业务 util；同上须不命中（Config 后 U 无 \\b）。",
			},
			{
				Name: "业务方法名 addInterceptorForXxx（非拦截器注册）",
				Src:  `public void addInterceptorForAudit(Log l) { }`,
				Note: "addInterceptorForAudit 是业务方法名；addInterceptors?\\b 须不命中（Interceptor 后 F 无 \\b）—— 否则假开脱。",
			},
			{
				Name: "业务方法名 permitAllCheck（非放行链）",
				Src:  `public boolean permitAllCheck(Object req) { return true; }`,
				Note: "permitAllCheck 是业务方法名；permitAll\\b 须不命中（All 后 C 无 \\b）—— 否则假开脱。",
			},
			{
				Name: "业务方法名 requestMatchersFor（非路由匹配）",
				Src:  `public List<String> requestMatchersFor(String path) { return null; }`,
				Note: "requestMatchersFor 是业务方法名；requestMatchers\\b 须不命中（Matchers 后 F 无 \\b）—— 否则假开脱。",
			},
			{
				Name: "业务方法名 antMatchersFor（非路由匹配）",
				Src:  `public List<String> antMatchersFor(String path) { return null; }`,
				Note: "antMatchersFor 是业务方法名；antMatchers\\b 须不命中（Matchers 后 F 无 \\b）—— 否则假开脱。GR-7 与 requestMatchersFor 同形。",
			},
			{
				Name: "implements Filterable（非 servlet Filter）",
				Src:  `public class JobFilter implements Filterable { public boolean filter(Object x) { return false; } }`,
				Note: "Filterable 是业务接口非 javax.servlet.Filter；implements\\s+Filter\\b 须不命中（Filter 后 a 无 \\b）—— 否则假开脱。",
			},
		},
	},
	{
		Fact:        "upload_file_write_sink",
		Exculpatory: "no", // 确定性否定 —— 开脱的最常见形态
		Why:         "FileWriteSink=\"none\" 直接推出「b1 webshell 与 b3 穿越写两支不可达」;漏认某个落盘 API 族 = 对那类项目产假否定,把真的 webshell 面藏掉",
		MustRecognize: []Sample{
			{Name: "Spring MultipartFile.transferTo", Src: `file.transferTo(new File(dir, name));`},
			{Name: "Files.write", Src: `Files.write(Paths.get(p), bytes);`},
			{Name: "Files.copy", Src: `Files.copy(in, Paths.get(p));`},
			{Name: "Files.newOutputStream", Src: `try (OutputStream o = Files.newOutputStream(Paths.get(p))) {}`},
			{Name: "new FileOutputStream", Src: `FileOutputStream fos = new FileOutputStream(savePath);`},
			{
				Name: "commons-io copyInputStreamToFile（活体：ceshi uploadLocal 一族）",
				Src:  `FileUtils.copyInputStreamToFile(mf.getInputStream(), new File(savePath));`,
				Note: "jshERP 的本地上传走 commons-io,不认它就会对整个 jshERP 系写出零落盘的假否定",
			},
			{Name: "commons-io writeByteArrayToFile", Src: `FileUtils.writeByteArrayToFile(new File(p), bytes);`},
			{Name: "RandomAccessFile 写", Src: `RandomAccessFile raf = new RandomAccessFile(p, "rw");`},
			{Name: "Spring FileCopyUtils", Src: `FileCopyUtils.copy(mf.getBytes(), new File(p));`},
			{Name: "createNewFile", Src: `new File(p).createNewFile();`},
		},
		MustNotRecognize: []Sample{
			{
				Name: "纯内存 Excel 解析（活体：ceshi SupplierController importMember）",
				Src: `Workbook wb = Workbook.getWorkbook(file.getInputStream());
Sheet sheet = wb.getSheet(0);
supplierMapper.insertSelective(convert(sheet));`,
				Note: "人工核实为真 FP：文件字节只进内存解析器再入库,从不落盘。若把它当落盘,零落盘这个确定性否定就永远出不来",
			},
			{
				Name: "只读文件",
				Src:  `try (FileInputStream in = new FileInputStream(p)) { in.read(buf); }`,
				Note: "读不是写;把读当写会让 b1 判据虚高",
			},
			{
				Name: "OSS 上传（对象存储不是本地磁盘）",
				Src:  `OssUtils.uploadFile(file, bucket, key, endpoint, id, secret);`,
				Note: "对象存储的 b1 取决于 bucket 是否可执行/可内联,不能等同本地落盘 —— 那是模型该判的,不是本事实该断的",
			},
		},
	},
	{
		Fact:        "upload_nosniff_header",
		Exculpatory: "no", // 确定性否定 —— 开脱的最常见形态
		Why:         "nosniff 缺席是 b2(存储型 XSS)的必要条件之一;漏认某种设置方式会对那类项目谎报「没有 nosniff」,把已被防住的 b2 说成可达",
		MustRecognize: []Sample{
			{Name: "setHeader 直写", Src: `response.setHeader("X-Content-Type-Options", "nosniff");`},
			{Name: "addHeader", Src: `resp.addHeader("X-Content-Type-Options", "nosniff");`},
			{Name: "Spring Security contentTypeOptions", Src: `http.headers().contentTypeOptions();`},
			{Name: "小写写法", Src: `res.setHeader("x-content-type-options", "nosniff");`},
		},
		MustNotRecognize: []Sample{
			{
				Name: "只设了 Content-Disposition attachment（三仓的真实形态）",
				Src:  `response.setHeader("content-disposition", "attachment;filename=" + name);`,
				Note: "三仓实测 nosniff 全为 0 —— 必须仍能报 none，否则这条确定性否定退化为永不出现",
			},
			{
				Name: "普通 Content-Type 设置",
				Src:  `response.setContentType("application/vnd.ms-excel");`,
				Note: "设类型不等于禁嗅探",
			},
		},
	},
	{
		Fact:        "engine_sanitizer_catalog",
		Exculpatory: "no", // 确定性否定 —— 开脱的最常见形态
		Why:         "HasSanitizer 答 false 是确定性否定,下游据此认为「没净化」。原目录只覆盖 XSS/编码一族,零条路径与文件名净化器 —— 对上传/路径穿越族一律答 false(实测 ceshi uploadLocal 里明明有 FileUtils.getFileName,精确询问仍答 false)",
		MustRecognize: []Sample{
			{Name: "commons-io FilenameUtils.getName（CWE-22 registry 明列）", Src: `FilenameUtils.getName`},
			{Name: "FilenameUtils.normalize", Src: `FilenameUtils.normalize`},
			{
				Name: "FileUtils.getFileName（约定级命名，各家 util 的常见写法）",
				Src:  `FileUtils.getFileName`,
				Note: "活体 ceshi uploadLocal 就是这个写法；commons-io 叫 FilenameUtils.getName，两者同义。receiver 门控保证只认工具类上的调用",
			},
			{Name: "File.getCanonicalPath（canonical 校验的前半）", Src: `File.getCanonicalPath`},
			{Name: "UUID.randomUUID（服务端生成名=丢弃客户端名，CWE-434 registry 明列）", Src: `UUID.randomUUID`},
			{Name: "原有 XSS 族不得被回归掉：URLEncoder.encode", Src: `URLEncoder.encode`},
			{Name: "原有 XSS 族：StringEscapeUtils.escapeHtml", Src: `StringEscapeUtils.escapeHtml`},
		},
		MustNotRecognize: []Sample{
			{
				Name: "裸 getFileName（无 receiver 收窄）",
				Src:  `getFileName`,
				Note: "任意 DTO 上的 getFileName 是普通 getter，不是净化；不收窄 receiver 会把它们全当净化",
			},
			{
				Name: "裸 getName（无 receiver 收窄）",
				Src:  `getName`,
				Note: "getName 是极高频方法名，不收窄 receiver 会把任意调用当净化，那会让「没净化」这个结论永不出现",
			},
			{
				Name: "普通业务方法",
				Src:  `SupplierService.importMember`,
				Note: "防目录膨胀成「什么都算净化」",
			},
		},
	},
	{
		Fact:        "authz_method_annotation",
		Exculpatory: "no", // 确定性否定 —— 开脱的最常见形态
		Why:         "写出确定性的 method_guard=false 会让「该端点无鉴权」成为判决输入；对 Shiro/Sa-Token 这类非 Spring-Security 项目，这个否定是假的",
		MustRecognize: []Sample{
			{Name: "Spring Security @PreAuthorize", Src: `@PreAuthorize("hasRole('ADMIN')") public void a() {}`},
			{Name: "Spring Security @PostAuthorize", Src: `@PostAuthorize("returnObject.owner == authentication.name") public Task a() { return null; }`},
			{Name: "Spring @Secured", Src: `@Secured("ROLE_ADMIN") public void a() {}`},
			{Name: "JSR-250 @RolesAllowed", Src: `@RolesAllowed({"ADMIN"}) public void a() {}`},
			{Name: "JSR-250 @DenyAll", Src: `@DenyAll public void a() {}`},
			{
				Name: "Shiro @RequiresPermissions",
				Src:  `@RequiresPermissions("task:create") public void a() {}`,
				Note: "Shiro 是国内 Java 项目的常见选型，原 pattern 集完全不认",
			},
			{Name: "Shiro @RequiresRoles", Src: `@RequiresRoles("admin") public void a() {}`},
			{Name: "Shiro @RequiresAuthentication", Src: `@RequiresAuthentication public void a() {}`},
			{Name: "Sa-Token @SaCheckLogin", Src: `@SaCheckLogin public void a() {}`},
			{Name: "Sa-Token @SaCheckPermission", Src: `@SaCheckPermission("task.add") public void a() {}`},
			{Name: "Sa-Token @SaCheckRole", Src: `@SaCheckRole("admin") public void a() {}`},
		},
		MustNotRecognize: []Sample{
			{
				Name: "无任何鉴权注解的端点",
				Src:  `@PostMapping("/task/create") public Response create(@RequestBody Req r) { return null; }`,
				Note: "这是 probe-core 全仓的形态，必须仍报 false —— 否则真的缺失鉴权全被藏掉",
			},
			{
				Name: "@Valid / @Validated（参数校验，不是鉴权）",
				Src:  `@PostMapping("/x") public Response x(@RequestBody @Valid Req r) { return null; }`,
				Note: "把入参校验当鉴权会把大批未授权端点判成已守卫",
			},
			{
				Name: "@PermitAll（显式放行，语义是「不需要鉴权」）",
				Src:  `@PermitAll public void a() {}`,
				Note: "已知偏差：现网实现把它算作守卫。它字面意思是「允许所有人」= 无鉴权，" +
					"算作守卫会把真的未授权端点藏掉。三仓零用量，故本条先记为契约、暂不改判决语义（改动需活体验证）",
			},
		},
	},
}
