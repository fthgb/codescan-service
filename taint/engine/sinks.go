package engine

import (
	"encoding/json"
	"os"
	"strings"
)

// ============================================================
//  Sink 字典与判定 —— 引擎本体能力（从 sim 收口而来）
//  原 sim/sink_catalog.go 仅作桥接，调用本文件。
// ============================================================

// SinkEntry 描述一个危险 sink 的元信息。
type SinkEntry struct {
	VulnType   string // 漏洞类型，如 command_injection / sql_injection / xss ...
	CWE        string // CWE 编号，如 CWE-78 / CWE-89
	Severity   int    // 严重度 1..5
	Benign     bool   // true=良性（日志/打印/类型转换等，不计入危险 sink）
	SourceSide bool   // true=出现在 source 侧（污点产生点），用于 Flow Summary 区分
}

// sinkDict 是引擎内置的危险 sink 字典。
// 设计原则：
//  1. 仅收录"已知且精确"的危险 API，避免宽泛关键词误判（修复 D1：ExecutorService.execute / CloseableHttpClient.execute 不再被误判为 sql_injection）。
//  2. 日志/打印/类型转换等归为 Benign，不污染危险 sink 判定（支撑 F1）。
//  3. SourceSide 标记 source 侧常见污点产生点。
var sinkDict = map[string]SinkEntry{
	// ── 命令执行 ──
	"getRuntime":         {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"Runtime.getRuntime": {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"exec":               {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"getRuntime().exec":  {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},

	// ── SQL 注入（仅保留已知 SQL 执行 API，不收录宽泛 execute） ──
	"java.sql.Statement.execute":               {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"java.sql.Statement.executeQuery":          {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"java.sql.Statement.executeUpdate":         {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"java.sql.Statement.executeLargeUpdate":    {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"java.sql.PreparedStatement.execute":       {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"java.sql.PreparedStatement.executeQuery":  {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"java.sql.PreparedStatement.executeUpdate": {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"executeQuery":                {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"executeUpdate":               {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"JdbcTemplate.query":          {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"JdbcTemplate.update":         {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"JdbcTemplate.queryForObject": {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"JdbcTemplate.queryForList":   {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"JdbcTemplate.execute":        {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},

	// ── JPA / Hibernate SQL 注入（R09：与 JDBC 同源 SQL 家族，载体是 EntityManager/Session API）──
	// 仅收录标准 SQL 执行 API，不收录宽泛 execute（避免 D1 误判）。
	// 危险判定经双闸：仅当 JPQL/SQL 字符串串入外部污点（如 "SELECT ... "+name）才 confirmed。
	"javax.persistence.EntityManager.createQuery":       {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"javax.persistence.EntityManager.createNativeQuery": {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"javax.persistence.TypedQuery.getResultList":        {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"org.hibernate.Session.createQuery":                 {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"org.hibernate.Session.createSQLQuery":              {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"org.hibernate.query.Query.getResultList":           {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	// R09 短名兜底：字段接收者调用边解析得到的是字段类型短名（如 EntityManager），
	// 字段类型未在全限定层面归一（JDK 标准类型不在 ClassExtends 中），故 sinkDict 同时收录短名，
	// 由双闸（source 链）把关防过宽。仅收录 JPA/Hibernate 标准 SQL 执行 API。
	"EntityManager.createQuery":       {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"EntityManager.createNativeQuery": {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"Session.createQuery":             {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"Session.createSQLQuery":          {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	// R09 增补：CriteriaBuilder.like/equal 等条件构造 API 第二个参数为 SQL 模式串，
	// 拼入污点即 SQL 注入（与 createQuery 同源 SQL 家族），补齐第七轮仅覆盖 createQuery 的子形态漏报。
	// 由双闸（参数级污点 + source 链）把关防过宽。
	"javax.persistence.criteria.CriteriaBuilder.like":  {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"javax.persistence.criteria.CriteriaBuilder.equal": {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"CriteriaBuilder.like":                             {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"CriteriaBuilder.equal":                            {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},

	// ── 命令/Runtime 的危险调用 ──
	"ProcessBuilder":       {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"ProcessBuilder.start": {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	// getInputStream 是 URL/HTTP 连接读取响应的一部分，归类 SSRF（CWE-918）而非命令注入，
	// 避免 URL.openConnection + getInputStream 的 SSRF 链路被主类型错归为 command_injection（B4 自洽）。
	"getInputStream": {VulnType: "ssrf", CWE: "CWE-918", Severity: 3},

	// ── XXE ──
	"newSAXParser":          {VulnType: "xxe", CWE: "CWE-611", Severity: 4},
	"SAXParser.parse":       {VulnType: "xxe", CWE: "CWE-611", Severity: 4},
	"DocumentBuilder.parse": {VulnType: "xxe", CWE: "CWE-611", Severity: 4},
	"newTransformer":        {VulnType: "xxe", CWE: "CWE-611", Severity: 4},
	"Transformer.transform": {VulnType: "xxe", CWE: "CWE-611", Severity: 4},

	// ── 路径遍历 ──
	"new FileInputStream":  {VulnType: "path_traversal", CWE: "CWE-22", Severity: 4},
	"new FileOutputStream": {VulnType: "path_traversal", CWE: "CWE-22", Severity: 4},
	"new File":             {VulnType: "path_traversal", CWE: "CWE-22", Severity: 3},
	"new RandomAccessFile": {VulnType: "path_traversal", CWE: "CWE-22", Severity: 3},

	// ── 反序列化 ──
	"readObject":            {VulnType: "deserialization", CWE: "CWE-502", Severity: 5},
	"XMLDecoder.readObject": {VulnType: "deserialization", CWE: "CWE-502", Severity: 5},
	"ObjectInputStream":     {VulnType: "deserialization", CWE: "CWE-502", Severity: 5},

	// ── SSRF ──
	"URL.openConnection": {VulnType: "ssrf", CWE: "CWE-918", Severity: 4},
	"openStream":         {VulnType: "ssrf", CWE: "CWE-918", Severity: 4},
	"HttpClient.send":    {VulnType: "ssrf", CWE: "CWE-918", Severity: 4},
	"HttpURLConnection":  {VulnType: "ssrf", CWE: "CWE-918", Severity: 4},

	// ── 表达式注入 / 命令 ──
	"Runtime.exec":                         {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"GroovyShell.evaluate":                 {VulnType: "expression_injection", CWE: "CWE-94", Severity: 5},
	"ScriptEngine.eval":                    {VulnType: "expression_injection", CWE: "CWE-94", Severity: 5},
	"SpelExpressionParser.parseExpression": {VulnType: "expression_injection", CWE: "CWE-94", Severity: 5},

	// ── SQL 短名精确匹配（救 import 短名场景；非通配 execute，避免 ExecutorService.execute / HttpStatement.execute 串类）──
	// 仅收录"类名.方法"精确短名，且类名是 JDBC 标准类型，撞名包（如 org.apache.http.Statement）不会命中。
	"Statement.execute":               {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"Statement.executeQuery":          {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"Statement.executeUpdate":         {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"PreparedStatement.execute":       {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"PreparedStatement.executeQuery":  {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},
	"PreparedStatement.executeUpdate": {VulnType: "sql_injection", CWE: "CWE-89", Severity: 4},

	// ── 业务自定义 RPC / 远程执行危险 sink（B2：精确预置，不做通配，避免 TransactionTemplate 等误标）──
	// 这些是高频且语义无歧义的 RPC 框架执行入口；业务方按自己项目约定用 RegisterSink 补充。
	"RpcCallTemplate.execute": {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"DubboInvoker.invoke":     {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"GrpcStub.call":           {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"FeignClient.invoke":      {VulnType: "ssrf", CWE: "CWE-918", Severity: 4},
	"RpcProxy.call":           {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"RpcProxy.invoke":         {VulnType: "command_injection", CWE: "CWE-78", Severity: 5},
	"log.info":                {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"logger.info":             {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},

	// ── 日志/打印（良性，不计入危险 sink） ──
	"printStackTrace": {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"printf":          {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"println":         {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"Logger.error":    {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"Logger.warn":     {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"Logger.info":     {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"Logger.debug":    {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},
	"System.out":      {VulnType: "logging", CWE: "CWE-532", Severity: 1, Benign: true},

	// ── 类型转换（源侧工具，非 sink；标 benign 使其不计入危险 sink，仅作 source-side 参考） ──
	"Long.parseLong":   {VulnType: "value_parse", CWE: "CWE-20", Severity: 1, Benign: true, SourceSide: true},
	"Integer.parseInt": {VulnType: "value_parse", CWE: "CWE-20", Severity: 1, Benign: true, SourceSide: true},
	"toString":         {VulnType: "value_convert", CWE: "CWE-20", Severity: 1, Benign: true, SourceSide: true},
	"valueOf":          {VulnType: "value_convert", CWE: "CWE-20", Severity: 1, Benign: true, SourceSide: true},
}

// DefaultSinkCatalog 返回引擎内置的危险 sink 字典（不可变副本）。
func DefaultSinkCatalog() map[string]SinkEntry {
	cp := make(map[string]SinkEntry, len(sinkDict))
	for k, v := range sinkDict {
		cp[k] = v
	}
	return cp
}

// RegisterSink 运行时注册/覆盖一个危险 sink 条目（业务方按自己项目的 RPC 约定补充，
// 而非引擎猜测）。key 支持全限定（Class.method）或精确短名（Class.method），
// 推荐使用全限定以避免撞名串类。重复 key 覆盖内置条目。
func RegisterSink(key string, e SinkEntry) {
	sinkDict[key] = e
}

// LoadSinkConfig 从 JSON 文件加载业务自定义 sink 字典并注册。
// JSON 格式：{ "Class.method": {"vuln_type":"...","cwe":"...","severity":N,"benign":false,"source_side":false}, ... }
// 加载失败返回 error（不中断主流程，由调用方决定是否 fatal）。
func LoadSinkConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw map[string]struct {
		VulnType   string `json:"vuln_type"`
		CWE        string `json:"cwe"`
		Severity   int    `json:"severity"`
		Benign     bool   `json:"benign"`
		SourceSide bool   `json:"source_side"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		sinkDict[k] = SinkEntry{
			VulnType:   v.VulnType,
			CWE:        v.CWE,
			Severity:   v.Severity,
			Benign:     v.Benign,
			SourceSide: v.SourceSide,
		}
	}
	return nil
}

// MatchSink 根据 class/method 全限定名匹配 sink 字典。
// 采用 word boundary 精确匹配：仅当 method 段（最后一个 '.' 之后）或
// 特定关键字命中时才算，避免 ExecutorService.execute 误判为 sql_injection。
func MatchSink(class, method string) (SinkEntry, bool) {
	// 1) 精确全限定 class.method
	fq := class + "." + method
	if e, ok := sinkDict[fq]; ok {
		return e, true
	}
	// 2) 关键字（method 段精确，word boundary）
	_, mm := methodClassMethod(method)
	if e, ok := sinkDict[mm]; ok {
		return e, true
	}
	// 3) 宽泛关键字（仅限非危险良性/已知窄义词，不匹配 execute 之类宽词）
	if e, ok := sinkDict[method]; ok {
		return e, true
	}
	return SinkEntry{}, false
}

// IsDangerousSink 报告该调用是否是"危险（非良性）sink"。
// 供引擎判定 hasDangerSinkEdge / role:sink 使用——仅直接调用危险 sink 才算。
func IsDangerousSink(class, method string) bool {
	e, ok := MatchSink(class, method)
	return ok && !e.Benign
}

// SinkVulnType 返回该 sink 的漏洞类型/CWE；非 sink 或良性 sink 返回 ("", "")。
// 良性（日志/打印/类型转换等 SourceSide 工具）不产生漏洞类型，避免误标。
func SinkVulnType(class, method string) (string, string) {
	e, ok := MatchSink(class, method)
	if !ok || e.Benign {
		return "", ""
	}
	return e.VulnType, e.CWE
}

// IsBenignSink 报告该调用是否为良性 sink（日志/打印）。
func IsBenignSink(class, method string) bool {
	e, ok := MatchSink(class, method)
	return ok && e.Benign
}

// nodeDirectlyCallsDangerSink 报告某方法是否"直接调用"了危险（非良性）sink。
// 用于 role:sink 标注（F1）：仅直接危险调用才算 sink 角色，传递性到达不算。
func nodeDirectlyCallsDangerSink(store *AnalysisStore, mk string) bool {
	for _, e := range store.Calls.Edges[mk] {
		if IsDangerousSink(e.CalleeClass, e.CalleeMethod) {
			return true
		}
	}
	return false
}

// nodeDirectlyCallsBenignSink 报告某方法是否"直接调用"了良性 sink（日志/打印）。
func nodeDirectlyCallsBenignSink(store *AnalysisStore, mk string) bool {
	for _, e := range store.Calls.Edges[mk] {
		if IsBenignSink(e.CalleeClass, e.CalleeMethod) {
			return true
		}
	}
	return false
}

// wordBoundaryHit 校验 keyword 是否以"词边界"方式命中 text。
// text 形如 Class.method，仅当最后的 method 段等于 keyword 或以 keyword 开头
// 且其后无字母数字（即 method 段本身就是该 keyword 或 keyword 是 method 前缀词），
// 才认为是命中。用于避免 execute 命中 ExecutorService.execute。
func wordBoundaryHit(keyword, text string) bool {
	if keyword == "" || text == "" {
		return false
	}
	// 取最后一个 '.' 之后的方法名段
	seg := text
	if idx := strings.LastIndex(text, "."); idx >= 0 {
		seg = text[idx+1:]
	}
	// method 段以 keyword 开头且其后紧跟非标识符字符（或结尾）
	if strings.HasPrefix(seg, keyword) {
		res := seg[len(keyword):]
		if res == "" {
			return true
		}
		c := res[0]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_' {
			return true
		}
	}
	return false
}
