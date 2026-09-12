package engine

import (
	"regexp"
	"strings"
	"time"
)

// ANALYSIS_VERSION — Go 版本从 1 起（JSON 格式，与 Python pickle 不互通）。
const ANALYSIS_VERSION = 1

// ============================================================
//  配置
// ============================================================

// AnalysisConfig 镜像 7.py AnalysisConfig。数值忠实 7.py 默认值。
type AnalysisConfig struct {
	MaxCallDepth         int `json:"max_call_depth"`
	MaxCallNodes         int `json:"max_call_nodes"`
	MaxTaintIterations   int `json:"max_taint_iterations"`
	MaxTaintRounds       int `json:"max_taint_rounds"`
	TypeResolveCacheSize int `json:"type_resolve_cache_size"`
}

func DefaultConfig() AnalysisConfig {
	return AnalysisConfig{
		MaxCallDepth:         20,
		MaxCallNodes:         200,
		MaxTaintIterations:   50,
		MaxTaintRounds:       3,
		TypeResolveCacheSize: 100000,
	}
}

// ============================================================
//  枚举（string 类型，忠实 7.py 枚举 .value 字符串）
// ============================================================

type AssignType string

const (
	AssignConstructor     AssignType = "constructor"
	AssignPostConstruct   AssignType = "post_construct"
	AssignSpringInjection AssignType = "spring_injection"
	AssignRuntime         AssignType = "runtime"
)

type TaintSourceType string

const (
	TaintSrcUserInput   TaintSourceType = "USER_INPUT"
	TaintSrcFieldProp   TaintSourceType = "FIELD_PROPAGATION"
	TaintSrcEntryMethod TaintSourceType = "ENTRY_METHOD"
	TaintSrcConfigValue TaintSourceType = "CONFIG_VALUE"
)

type EntryPointType string

const (
	EntryHTTP        EntryPointType = "http_endpoint"
	EntryContainer   EntryPointType = "container_entry"
	EntryScheduled   EntryPointType = "scheduled"
	EntryMsgListener EntryPointType = "message_listener"
	EntryEvtListener EntryPointType = "event_listener"
)

type CallConfidence string

const (
	ConfExact       CallConfidence = "exact"
	ConfHeuristic   CallConfidence = "heuristic"
	ConfPolymorphic CallConfidence = "polymorphic"
)

type CallCondition string

const (
	CondNone            CallCondition = "none"
	CondIfBranch        CallCondition = "if_branch"
	CondLambda          CallCondition = "lambda"
	CondAsync           CallCondition = "async"
	CondConditionalBean CallCondition = "conditional_bean"
	CondSelfCall        CallCondition = "self_call"
)

// LocationType — 忠实 7.py TaintFact.location_type 的字符串值。
// 7.py seed_from_store 用 'field' / 'method_param' / 'method_return' 三种。
type LocationType string

const (
	LocField        LocationType = "field"
	LocMethodParam  LocationType = "method_param"
	LocMethodReturn LocationType = "method_return"
)

// Phase 2 预定义类型（竞品增强，Phase 1 不激活但类型已预留）

type ContextLabel string

const (
	CtxLeftPar  ContextLabel = "left_par"  // 进入被调函数
	CtxRightPar ContextLabel = "right_par" // 返回调用者
)

type ReachabilityState string

const (
	ReachReachable   ReachabilityState = "reachable"
	ReachUnreachable ReachabilityState = "unreachable"
	ReachUnknown     ReachabilityState = "unknown"
)

// ============================================================
//  结构化数据类
// ============================================================

// FieldAssignment 镜像 7.py FieldAssignment。
type FieldAssignment struct {
	ClassName         string     `json:"class_name"`
	MethodKey         string     `json:"method_key"`
	MethodName        string     `json:"method_name"`
	Line              int        `json:"line"`
	FilePath          string     `json:"file_path"`
	AssignText        string     `json:"assign_text"`
	AssignType        AssignType `json:"assign_type"`
	TaintInfo         *TaintInfo `json:"taint_info"`
	IsValidated       bool       `json:"is_validated"`
	ValidationContext string     `json:"validation_context"`
}

// TaintInfo — FieldAssignment.taint_info 的 dict 结构。
type TaintInfo struct {
	SourceType          TaintSourceType `json:"source_type"`
	SourceMethod        string          `json:"source_method"`
	SourceField         string          `json:"source_field"`
	AssignMethod        string          `json:"assign_method"`
	AssignLine          int             `json:"assign_line"`
	AssignFile          string          `json:"assign_file"`
	AssignText          string          `json:"assign_text"`
	AssignType          AssignType      `json:"assign_type"`
	PropagationPath     []string        `json:"propagation_path"`
	AllPropagationPaths [][]string      `json:"all_propagation_paths"`
}

// CallSiteFieldAssign 镜像 7.py CallSiteFieldAssign。
type CallSiteFieldAssign struct {
	CallerKey    string `json:"caller_key"`
	CalleeKey    string `json:"callee_key"`
	CalleeClass  string `json:"callee_class"`
	CalleeMethod string `json:"callee_method"`
	CalleeArgCnt int    `json:"callee_arg_count"`
	FieldKey     string `json:"field_key"`
	AssignLine   int    `json:"assign_line"`
}

// FieldToFieldEdge 镜像 7.py FieldToFieldEdge。
type FieldToFieldEdge struct {
	SrcFieldKey string `json:"src_field_key"`
	DstFieldKey string `json:"dst_field_key"`
	MethodKey   string `json:"method_key"`
	Line        int    `json:"line"`
	FilePath    string `json:"file_path"`
	AssignText  string `json:"assign_text"`
	AssignType  string `json:"assign_type"`
}

// CallNode 镜像 7.py CallNode。
type CallNode struct {
	MethodKey  string `json:"method_key"`
	FilePath   string `json:"file_path"`
	Line       int    `json:"line"`
	IsEntry    bool   `json:"is_entry"`
	IsExternal bool   `json:"is_external"`
	IsCycle    bool   `json:"is_cycle"`
}

// CallPath 镜像 7.py CallPath。
type CallPath struct {
	Nodes []CallNode `json:"nodes"`
}

// FieldDefinition 镜像 7.py FieldDefinition。
type FieldDefinition struct {
	ClassName   string       `json:"class_name"`
	FieldName   string       `json:"field_name"`
	TypeName    string       `json:"type_name"`
	Line        int          `json:"line"`
	FilePath    string       `json:"file_path"`
	InitText    string       `json:"init_text"`
	Annotations []Annotation `json:"annotations"`
	IsStatic    bool         `json:"is_static"`
	IsTransient bool         `json:"is_transient"`
}

// CallEdge 镜像 7.py CallEdge。
type CallEdge struct {
	CalleeClass  string         `json:"callee_class"`
	CalleeMethod string         `json:"callee_method"`
	Line         int            `json:"line"`
	FilePath     string         `json:"file_path"`
	ArgCount     int            `json:"arg_count"`
	Confidence   CallConfidence `json:"confidence"`
	Rule         string         `json:"rule"`
	Condition    CallCondition  `json:"condition"`
	CallType     CallType       `json:"call_type,omitempty"`
}

// CallType 描述调用的解析类别，用于断点补齐（B2）时让 AI 区分
// 直接调用 / 接口多态 / 反射 / 动态代理 / 未解析。
type CallType string

const (
	CallDirect       CallType = "direct"
	CallInterface    CallType = "interface"
	CallReflection   CallType = "reflection"
	CallDynamicProxy CallType = "dynamic_proxy"
	CallUnresolved   CallType = "unresolved"
	// G4-2：JDK 标准库调用（java.*/javax.*/sun.*/android.* 等）。
	// 此类调用不是真断裂点——其定义由 JDK 提供而非业务仓，AI 应识别为
	// "标准库边界"而非"需要补齐的断链"，避免噪声误导（见 F05/F08）。
	CallStdlib CallType = "stdlib"
	// G4-1：RPC 跨服务接口调用类别。引擎单仓扫描时能看到 Feign/Dubbo/gRPC
	// 接口的仓内定义（注解、签名、源码位置），故单列以区分"普通未解析"。
	CallRPCFeign CallType = "rpc_feign"
	CallRPCDubbo CallType = "rpc_dubbo"
	CallRPCGrpc  CallType = "rpc_grpc"
	// R20：跨线程/异步调度边。当调用的方法实参是 Runnable/Callable 实现
	// （如 ExecutorService.submit(new Task(input))、new Thread(task)、
	// CompletableFuture.runAsync(task)），引擎将「提交点方法」连接到被调度任务
	// 的 run()/call() 实现，使跨线程调用图与污点链路连通（D-R20a 架构修复）。
	CallAsyncDispatch CallType = "async_dispatch"
	// R12：JNI/native 方法调用边。native 方法实现在 .so/.dll，静态不可见，
	// 属黑盒边界。污点流入 native 方法时引擎无法继续追踪，须标为「流入黑盒未确认」
	// 而非 VERIFIED_SAFE，否则 secret 流入 native sink 会被漏判（D-R12a）。
	CallNative CallType = "native"
)

// ============================================================
//  污点事实
// ============================================================

// TaintFact 镜像 7.py TaintFact（frozen dataclass）。
// identity() 的 6 字段用于去重——忠实 7.py，不含 Line/Provenance/Path。
type TaintFact struct {
	LocationType    LocationType
	LocationKey     string // 方法全限定名 或 字段全限定名
	ParamName       string // 参数名（location_type=method_param 时有效）
	SourceType      TaintSourceType
	SourceMethod    string
	SourceField     string
	Provenance      string
	PropagationPath []string
}

// TaintFactKey — 忠实 7.py identity() 的 6 字段 tuple，全 comparable 可做 map key。
type TaintFactKey struct {
	LocationType LocationType
	LocationKey  string
	ParamName    string
	SourceType   TaintSourceType
	SourceMethod string
	SourceField  string
}

// Key 返回 TaintFact 的去重 key（忠实 7.py identity()）。
func (f TaintFact) Key() TaintFactKey {
	return TaintFactKey{
		LocationType: f.LocationType,
		LocationKey:  f.LocationKey,
		ParamName:    f.ParamName,
		SourceType:   f.SourceType,
		SourceMethod: f.SourceMethod,
		SourceField:  f.SourceField,
	}
}

// ============================================================
//  缓存头
// ============================================================

// CacheHeader — JSON 缓存文件头，全量覆盖 + 版本/仓库校验。
type CacheHeader struct {
	Version   int       `json:"version"`
	RepoPath  string    `json:"repo_path"`
	ScanTime  time.Time `json:"scan_time"`
	FileCount int       `json:"file_count"`
}

// ============================================================
//  Phase 2 预定义类型（竞品增强，Phase 1 仅声明不激活）
// ============================================================

// ControlFlowCheck — 控制流可行性检查结果（RepoAudit B-54）。
type ControlFlowCheck struct {
	IsFeasible bool   `json:"is_feasible"`
	Reason     string `json:"reason"` // "mutual_exclusion" | "loop_back_edge" | "sequential" | "ok"
}

// CalleeRef — 结构化可达性契约中的 callee 引用（raptor）。
type CalleeRef struct {
	Name     string `json:"name,omitempty"`
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"` // §8: per-callee 行号（get_callees 工具锚点）
}

// ReachabilityResult — 结构化可达性契约（raptor CalleeResult）。
type ReachabilityResult struct {
	Definitive        []CalleeRef `json:"definitive,omitempty"`
	Uncertain         []CalleeRef `json:"uncertain,omitempty"`
	HasMethodDispatch bool        `json:"has_method_dispatch,omitempty"`
	Truncated         bool        `json:"truncated,omitempty"`
}

// ============================================================
//  R10: MyBatis XML mapper 语句（独立于 Java 注解式，解析 resources 下 *.xml）
// ============================================================

// XmlMapperStmt 表示 MyBatis XML mapper 中一个 <select|insert|update|delete id> 语句。
// 关键判定：SQL 含 ${...} 直接拼接（HasConcat=true）为危险 SQL 注入 sink；
// 仅含 #{...} 参数占位符（MyBatis 预编译绑定）为安全，不判 sink。
type XmlMapperStmt struct {
	Namespace  string `json:"namespace"`   // 全限定接口名，如 com.example.UserMapper
	ShortClass string `json:"short_class"` // namespace 末段，如 UserMapper
	Id         string `json:"id"`          // statement id（对应 Mapper 接口方法名）
	SQLText    string `json:"sql_text"`    // 原始 SQL 片段（已 trim）
	FilePath   string `json:"file_path"`
	Line       int    `json:"line"`
	HasConcat  bool   `json:"has_concat"` // 含 ${...} 直接拼接（危险）
	HasParam   bool   `json:"has_param"`  // 含 #{...} 参数占位（安全预编译）
}

// CallContext — CFL 上下文敏感括号栈（RepoAudit）。
type CallContext struct {
	Stack []ContextLabel
}

func (c *CallContext) PushEnter()  { c.Stack = append(c.Stack, CtxLeftPar) }
func (c *CallContext) PushReturn() { c.Stack = append(c.Stack, CtxRightPar) }

// IsBalanced 检查括号是否平衡（LEFT_PAR 与 RIGHT_PAR 数量相等）。
func (c *CallContext) IsBalanced() bool {
	if len(c.Stack) == 0 {
		return true
	}
	left, right := 0, 0
	for _, l := range c.Stack {
		if l == CtxLeftPar {
			left++
		} else {
			right++
		}
	}
	return left == right
}

// Clone 返回 CallContext 的深拷贝（DFS 路径分支用）。
func (c *CallContext) Clone() *CallContext {
	dup := make([]ContextLabel, len(c.Stack))
	copy(dup, c.Stack)
	return &CallContext{Stack: dup}
}

// ============================================================
//  MethodKeyHelper — 镜像 7.py MethodKeyHelper
// ============================================================

type MethodKeyHelper struct{}

func (MethodKeyHelper) ClassName(methodKey string) string {
	if methodKey == "" {
		return ""
	}
	dotPos := strings.Index(methodKey, ".")
	if dotPos <= 0 {
		return methodKey
	}
	parenPos := strings.Index(methodKey, "(")
	if parenPos > 0 && parenPos < dotPos {
		return methodKey[:parenPos]
	}
	return methodKey[:dotPos]
}

func (MethodKeyHelper) MethodName(methodKey string) string {
	if methodKey == "" {
		return ""
	}
	parenPos := strings.Index(methodKey, "(")
	searchEnd := len(methodKey)
	if parenPos > 0 {
		searchEnd = parenPos
	}
	dotPos := strings.LastIndex(methodKey[:searchEnd], ".")
	if dotPos < 0 {
		return methodKey[:searchEnd]
	}
	if parenPos > 0 {
		return methodKey[dotPos+1 : parenPos]
	}
	return methodKey[dotPos+1:]
}

func (MethodKeyHelper) SimpleClassName(methodKey string) string {
	cls := MethodKeyHelper{}.ClassName(methodKey)
	if idx := strings.Index(cls, "$"); idx >= 0 {
		return cls[idx+1:]
	}
	return cls
}

func (MethodKeyHelper) DisplayName(methodKey string) string {
	if idx := strings.Index(methodKey, "("); idx > 0 {
		return methodKey[:idx]
	}
	return methodKey
}

func (MethodKeyHelper) ParamCount(methodKey string) int {
	parenIdx := strings.Index(methodKey, "(")
	if parenIdx < 0 {
		return 0
	}
	sigPart := strings.TrimSuffix(methodKey[parenIdx+1:], ")")
	sigPart = strings.TrimSpace(sigPart)
	if sigPart == "" {
		return 0
	}
	count := 0
	for _, p := range strings.Split(sigPart, ",") {
		if strings.TrimSpace(p) != "" {
			count++
		}
	}
	return count
}

func (MethodKeyHelper) Build(className, methodName string, paramTypes []string) string {
	return className + "." + methodName + "(" + strings.Join(paramTypes, ",") + ")"
}

func (MethodKeyHelper) Pattern(className, methodName string) string {
	return className + "." + methodName
}

// ============================================================
//  常量定义（忠实 7.py L329-704）
// ============================================================

var httpMappingAnnotations = map[string]bool{
	"GetMapping": true, "PostMapping": true, "PutMapping": true,
	"DeleteMapping": true, "PatchMapping": true, "RequestMapping": true,
}

var nonHTTPEntryAnnotations = map[string]bool{
	"PostConstruct": true, "PreDestroy": true,
	"Scheduled":     true,
	"EventListener": true, "TransactionalEventListener": true,
	"RabbitListener": true, "KafkaListener": true, "JmsListener": true,
	"Bean":           true,
	"MessageMapping": true, "SubscribeMapping": true,
	"ServerEndpoint": true, "OnMessage": true,
	"GrpcService": true, "RsocketMessageMapping": true,
	"CommandLineRunner": true, "ApplicationRunner": true,
	"ExceptionHandler": true,
	"FeignClient":      true, "KafkaHandler": true, "RabbitHandler": true,
	"GraphQlQueryMapping": true, "GraphQlMutationMapping": true, "GraphQlSubscriptionMapping": true,
	"PrePersist": true, "PostPersist": true, "PreRemove": true, "PostRemove": true,
	"PostLoad": true, "PreUpdate": true, "PostUpdate": true,
}

var aopAspectAnnotations = map[string]bool{
	"Around": true, "Before": true, "After": true,
	"AfterReturning": true, "AfterThrowing": true,
}

func entryPointAnnotations() map[string]bool {
	out := make(map[string]bool, len(httpMappingAnnotations)+len(nonHTTPEntryAnnotations))
	for k := range httpMappingAnnotations {
		out[k] = true
	}
	for k := range nonHTTPEntryAnnotations {
		out[k] = true
	}
	return out
}

var controllerAnnotations = map[string]bool{"Controller": true, "RestController": true}
var controllerAdviceAnnotations = map[string]bool{"ControllerAdvice": true, "RestControllerAdvice": true}
var injectAnnotations = map[string]bool{
	"Autowired": true, "Resource": true, "Value": true, "Inject": true,
	"PersistenceContext": true, "PersistenceUnit": true, "Lookup": true,
}

var springComponentAnnotations = map[string]bool{
	"Component": true, "Service": true, "Repository": true,
	"Controller": true, "RestController": true,
	"Configuration": true, "ConfigurationProperties": true,
	"ManagedBean": true, "Named": true,
}

var ignoreDirs = map[string]bool{
	"target": true, "build": true, ".gradle": true, ".mvn": true,
	"node_modules": true, ".idea": true, ".git": true,
	"out": true, "bin": true, ".settings": true, "generated": true,
}

var taintSourceMethods = map[string]bool{
	"getParameter": true, "getHeader": true, "getQueryString": true,
	"getInputStream": true, "getReader": true,
	"getCookie": true, "getParameterValues": true,
	"readValue": true, "getBody": true,
	// R-A1（架构级，F41）：环境变量/系统属性 source——识别 JDK 标准 API 调用模式
	// (System.getenv / System.getProperty)，而非 hardcode 特定变量名。运维配置注入
	// 是典型的不可信输入入口（如 DB_PWD 经环境变量传入后被命令执行消费）。
	"getenv": true, "getProperty": true,
}

var taintParamAnnotations = map[string]bool{
	"RequestParam": true, "PathVariable": true, "RequestBody": true,
	"RequestHeader": true, "CookieValue": true, "ModelAttribute": true,
}

var lombokAnnotations = map[string]bool{
	"Data": true, "Getter": true, "Setter": true, "Value": true, "Builder": true,
}

// JDK_RETURN_TYPES — 忠实 7.py L386-581。key="Class.method" value=返回类型。
var jdkReturnTypes = map[string]string{
	// String
	"String.toUpperCase": "String", "String.toLowerCase": "String",
	"String.trim": "String", "String.substring": "String",
	"String.replace": "String", "String.replaceAll": "String",
	"String.format": "String", "String.valueOf": "String",
	"String.split": "String[]", "String.getBytes": "byte[]",
	"String.charAt": "char", "String.length": "int",
	"String.isEmpty": "boolean", "String.equals": "boolean",
	"String.contains": "boolean", "String.indexOf": "int",
	"String.startsWith": "boolean", "String.endsWith": "boolean",
	"String.toCharArray": "char[]", "String.concat": "String",
	"String.intern": "String", "String.strip": "String",
	"String.isBlank": "boolean", "String.repeat": "String",
	"String.indent": "String", "String.stripIndent": "String",
	"String.translateEscapes": "String",
	// StringBuilder / StringBuffer
	"StringBuilder.append": "StringBuilder", "StringBuilder.toString": "String",
	"StringBuilder.insert": "StringBuilder", "StringBuilder.delete": "StringBuilder",
	"StringBuilder.reverse": "StringBuilder", "StringBuilder.charAt": "char",
	"StringBuilder.length": "int", "StringBuilder.substring": "String",
	"StringBuffer.append": "StringBuffer", "StringBuffer.toString": "String",
	"StringBuffer.insert": "StringBuffer", "StringBuffer.delete": "StringBuffer",
	// List / ArrayList / LinkedList
	"List.size": "int", "List.get": "Object", "List.add": "boolean",
	"List.isEmpty": "boolean", "List.iterator": "Iterator",
	"List.stream": "Stream", "List.contains": "boolean",
	"List.remove": "Object", "List.clear": "void",
	"List.subList": "List", "List.toArray": "Object[]",
	"List.indexOf": "int", "List.lastIndexOf": "int",
	"List.of": "List", "List.copyOf": "List",
	"ArrayList.size": "int", "ArrayList.get": "Object", "ArrayList.add": "boolean",
	"ArrayList.isEmpty": "boolean", "ArrayList.stream": "Stream",
	"LinkedList.size": "int", "LinkedList.get": "Object", "LinkedList.add": "boolean",
	"LinkedList.isEmpty": "boolean", "LinkedList.stream": "Stream",
	// Map / HashMap / TreeMap
	"Map.get": "Object", "Map.put": "Object", "Map.keySet": "Set",
	"Map.values": "Collection", "Map.entrySet": "Set",
	"Map.containsKey": "boolean", "Map.containsValue": "boolean",
	"Map.size": "int", "Map.isEmpty": "boolean", "Map.remove": "Object",
	"Map.getOrDefault": "Object", "Map.putIfAbsent": "Object",
	"Map.of": "Map", "Map.copyOf": "Map",
	"HashMap.get": "Object", "HashMap.put": "Object", "HashMap.keySet": "Set",
	"HashMap.values": "Collection", "HashMap.entrySet": "Set",
	"TreeMap.get": "Object", "TreeMap.put": "Object", "TreeMap.keySet": "Set",
	// Set
	"Set.size": "int", "Set.isEmpty": "boolean", "Set.contains": "boolean",
	"Set.iterator": "Iterator", "Set.stream": "Stream",
	"Set.of": "Set", "Set.copyOf": "Set",
	// Optional
	"Optional.get": "Object", "Optional.orElse": "Object",
	"Optional.orElseGet": "Object", "Optional.isPresent": "boolean",
	"Optional.isEmpty": "boolean", "Optional.map": "Optional",
	"Optional.filter": "Optional", "Optional.flatMap": "Optional",
	"Optional.of": "Optional", "Optional.ofNullable": "Optional",
	"Optional.empty": "Optional", "Optional.or": "Optional",
	"Optional.orElseThrow": "Object", "Optional.ifPresent": "void",
	"Optional.ifPresentOrElse": "void",
	// Stream
	"Stream.map": "Stream", "Stream.filter": "Stream",
	"Stream.collect": "Object", "Stream.findFirst": "Optional",
	"Stream.findAny": "Optional", "Stream.count": "long",
	"Stream.forEach": "void", "Stream.toList": "List",
	"Stream.anyMatch": "boolean", "Stream.allMatch": "boolean",
	"Stream.noneMatch": "boolean", "Stream.flatMap": "Stream",
	"Stream.peek": "Stream", "Stream.skip": "Stream", "Stream.limit": "Stream",
	"Stream.distinct": "Stream", "Stream.sorted": "Stream",
	"Stream.min": "Optional", "Stream.max": "Optional",
	"Stream.reduce": "Object", "Stream.toArray": "Object[]",
	"Stream.of": "Stream", "Stream.builder": "Stream.Builder",
	"Stream.concat": "Stream", "Stream.generate": "Stream",
	"Stream.iterate":  "Stream",
	"IntStream.range": "IntStream", "IntStream.rangeClosed": "IntStream",
	"IntStream.of": "IntStream", "LongStream.range": "LongStream",
	// HttpServletRequest / Response
	"HttpServletRequest.getParameter":       "String",
	"HttpServletRequest.getParameterValues": "String[]",
	"HttpServletRequest.getHeader":          "String",
	"HttpServletRequest.getInputStream":     "ServletInputStream",
	"HttpServletRequest.getReader":          "BufferedReader",
	"HttpServletRequest.getCookies":         "Cookie[]",
	"HttpServletRequest.getQueryString":     "String",
	"HttpServletRequest.getMethod":          "String",
	"HttpServletRequest.getRequestURI":      "String",
	"HttpServletRequest.getRemoteAddr":      "String",
	"HttpServletRequest.getAttribute":       "Object",
	"HttpServletRequest.getSession":         "HttpSession",
	"HttpServletResponse.getWriter":         "PrintWriter",
	"HttpServletResponse.getOutputStream":   "ServletOutputStream",
	"HttpServletResponse.getStatus":         "int",
	// Object / Class
	"Object.toString": "String", "Object.getClass": "Class",
	"Object.hashCode": "int", "Object.equals": "boolean", "Object.clone": "Object",
	"Class.getName": "String", "Class.getSimpleName": "String",
	"Class.getCanonicalName": "String",
	// Integer / Long / Double
	"Integer.parseInt": "int", "Integer.valueOf": "Integer",
	"Integer.toString": "String", "Integer.intValue": "int",
	"Long.parseLong": "long", "Long.valueOf": "Long",
	"Double.parseDouble": "double", "Double.valueOf": "Double",
	// Jackson
	"ObjectMapper.readValue": "Object", "ObjectMapper.writeValueAsString": "String",
	"ObjectMapper.readTree": "JsonNode",
	"JsonNode.get":          "JsonNode", "JsonNode.path": "JsonNode",
	"JsonNode.asText": "String", "JsonNode.asInt": "int",
	"JsonNode.asLong": "long", "JsonNode.asBoolean": "boolean",
	"JsonNode.has": "boolean", "JsonNode.isArray": "boolean",
	"JsonNode.isObject": "boolean", "JsonNode.isMissingNode": "boolean",
	"JsonNode.size": "int", "JsonNode.fields": "Iterator",
	"JsonNode.elements": "Iterator", "JsonNode.findPath": "JsonNode",
	"JsonNode.findValue": "JsonNode", "JsonNode.findValues": "List",
	// RestTemplate / ResponseEntity
	"RestTemplate.getForObject": "Object", "RestTemplate.postForObject": "Object",
	"RestTemplate.exchange":  "ResponseEntity",
	"ResponseEntity.getBody": "Object", "ResponseEntity.getStatusCode": "HttpStatus",
	"ResponseEntity.getHeaders": "HttpHeaders",
	// Collection / Iterator
	"Collection.size": "int", "Collection.isEmpty": "boolean",
	"Collection.iterator": "Iterator", "Collection.stream": "Stream",
	"Collection.contains": "boolean", "Collection.toArray": "Object[]",
	"Iterator.hasNext": "boolean", "Iterator.next": "Object",
	// Scanner / BufferedReader / Files / Path
	"Scanner.nextLine": "String", "Scanner.nextInt": "int",
	"Scanner.hasNext": "boolean", "Scanner.hasNextLine": "boolean",
	"BufferedReader.readLine": "String",
	"Files.readAllLines":      "List", "Files.readAllBytes": "byte[]",
	"Files.lines": "Stream", "Files.newBufferedReader": "BufferedReader",
	"Path.toString": "String", "Path.resolve": "Path",
	"Path.getParent": "Path", "Path.getFileName": "Path",
	// CompletableFuture
	"CompletableFuture.supplyAsync":   "CompletableFuture",
	"CompletableFuture.thenApply":     "CompletableFuture",
	"CompletableFuture.thenCompose":   "CompletableFuture",
	"CompletableFuture.thenAccept":    "CompletableFuture",
	"CompletableFuture.thenRun":       "CompletableFuture",
	"CompletableFuture.exceptionally": "CompletableFuture",
	"CompletableFuture.handle":        "CompletableFuture",
	"CompletableFuture.whenComplete":  "CompletableFuture",
	"CompletableFuture.get":           "Object", "CompletableFuture.join": "Object",
	"CompletableFuture.thenApplyAsync":   "CompletableFuture",
	"CompletableFuture.thenComposeAsync": "CompletableFuture",
	"CompletableFuture.thenAcceptAsync":  "CompletableFuture",
	"CompletableFuture.allOf":            "CompletableFuture",
	"CompletableFuture.anyOf":            "CompletableFuture",
	"CompletableFuture.completedFuture":  "CompletableFuture",
	"CompletableFuture.failedFuture":     "CompletableFuture",
	"CompletableFuture.obtrudeValue":     "void",
	"CompletableFuture.cancel":           "boolean",
	"CompletableFuture.isDone":           "boolean", "CompletableFuture.isCancelled": "boolean",
	"CompletableFuture.isCompletedExceptionally": "boolean",
	// Collections / Arrays / Objects
	"Collections.emptyList": "List", "Collections.emptyMap": "Map",
	"Collections.emptySet": "Set", "Collections.singleton": "Set",
	"Collections.singletonList": "List", "Collections.singletonMap": "Map",
	"Collections.unmodifiableList": "List", "Collections.unmodifiableMap": "Map",
	"Collections.unmodifiableSet": "Set", "Collections.synchronizedList": "List",
	"Collections.synchronizedMap": "Map", "Collections.synchronizedSet": "Set",
	"Collections.sort": "void", "Collections.reverse": "void",
	"Collections.shuffle": "void", "Collections.max": "Object",
	"Collections.min": "Object", "Collections.frequency": "int",
	"Arrays.stream": "Stream", "Arrays.asList": "List",
	"Arrays.sort": "void", "Arrays.copyOf": "Object[]",
	"Arrays.copyOfRange": "Object[]", "Arrays.fill": "void",
	"Arrays.equals": "boolean", "Arrays.toString": "String",
	"Arrays.deepToString": "String", "Arrays.deepEquals": "boolean",
	"Objects.requireNonNull": "Object", "Objects.equals": "boolean",
	"Objects.hash": "int", "Objects.toString": "String",
	"Objects.isNull": "Object", "Objects.nonNull": "Object",
	// JPA / Hibernate
	"EntityManager.find": "Object", "EntityManager.getReference": "Object",
	"EntityManager.persist": "void", "EntityManager.merge": "Object",
	"EntityManager.remove": "void", "EntityManager.flush": "void",
	"EntityManager.createQuery": "Query", "EntityManager.createNativeQuery": "Query",
	"JpaRepository.findById": "Optional", "JpaRepository.findAll": "List",
	"JpaRepository.save": "Object", "JpaRepository.saveAll": "List",
	"JpaRepository.delete": "void", "JpaRepository.deleteById": "void",
	"JpaRepository.deleteByIdIn": "void", "JpaRepository.count": "long",
	"JpaRepository.existsById": "boolean", "JpaRepository.findAllById": "List",
	"CrudRepository.findById": "Optional", "CrudRepository.findAll": "List",
	"CrudRepository.save": "Object", "CrudRepository.saveAll": "List",
	"CrudRepository.delete": "void", "CrudRepository.deleteById": "void",
	"CrudRepository.count": "long", "CrudRepository.existsById": "boolean",
	"PagingAndSortingRepository.findAll": "Iterable",
	"Page.map":                           "Page", "Page.getContent": "List",
	"Page.getTotalElements": "long", "Page.getTotalPages": "int",
	"Page.getNumber": "int", "Page.getSize": "int",
	"Page.getNumberOfElements": "int", "Page.hasNext": "boolean",
	"Page.hasPrevious": "boolean", "Page.isFirst": "boolean",
	"Page.isLast":      "boolean",
	"Sort.getOrderFor": "Optional", "Sort.isEmpty": "boolean",
	"Sort.isSorted": "boolean", "Sort.isUnsorted": "boolean",
	"PageRequest.of": "PageRequest", "PageRequest.ofSize": "PageRequest",
	"Pageable.getPageNumber": "int", "Pageable.getPageSize": "int",
	"Pageable.getOffset": "long", "Pageable.getSort": "Sort",
	"Pageable.isPaged": "boolean", "Pageable.isUnpaged": "boolean",
	"Specification.toPredicate": "Predicate",
	"CriteriaBuilder.equal":     "Predicate", "CriteriaBuilder.and": "Predicate",
	"CriteriaBuilder.or": "Predicate", "CriteriaBuilder.not": "Predicate",
	"CriteriaBuilder.like": "Predicate", "CriteriaBuilder.between": "Predicate",
	"CriteriaBuilder.greaterThan": "Predicate", "CriteriaBuilder.lessThan": "Predicate",
	"CriteriaQuery.where": "CriteriaQuery", "CriteriaQuery.from": "Root",
	"CriteriaQuery.select": "CriteriaQuery", "CriteriaQuery.groupBy": "CriteriaQuery",
	"CriteriaQuery.having": "CriteriaQuery", "CriteriaQuery.orderBy": "CriteriaQuery",
	"Root.get": "Path", "Root.join": "Join", "Root.fetch": "Fetch",
	"Path.get":            "Path",
	"Query.getResultList": "List", "Query.getSingleResult": "Object",
	"Query.setParameter": "Query", "Query.setMaxResults": "Query",
	"Query.setFirstResult":     "Query",
	"TypedQuery.getResultList": "List", "TypedQuery.getSingleResult": "Object",
	"TypedQuery.setParameter": "TypedQuery", "TypedQuery.setMaxResults": "TypedQuery",
	"TypedQuery.setFirstResult": "TypedQuery",
}

// Sanitizer 三表 — 忠实 7.py L583-605。

var sanitizerMethodsFull = map[string]bool{
	"URLEncoder.encode": true, "URLDecoder.decode": true,
	"StringEscapeUtils.escapeHtml": true, "StringEscapeUtils.escapeJavaScript": true,
	"StringEscapeUtils.escapeXml": true, "StringEscapeUtils.escapeCsv": true,
	"EscapeUtils.escapeHtml": true, "EscapeUtils.escapeJavaScript": true,
	"Encode.forHtml": true, "Encode.forJavaScript": true, "Encode.forUriComponent": true,
	"HtmlUtils.htmlEscape": true, "JavaScriptUtils.javaScriptEscape": true,
}

// contextSensitiveSanitizers — key=方法名, value=允许的 receiver 类名集合。
var contextSensitiveSanitizers = map[string]map[string]bool{
	"encode":   {"URLEncoder": true, "URLCodec": true, "Base64": true},
	"decode":   {"URLDecoder": true, "URLCodec": true, "Base64": true},
	"escape":   {"StringEscapeUtils": true, "EscapeUtils": true, "HtmlUtils": true, "JavaScriptUtils": true, "Encoder": true},
	"sanitize": {"Sanitizer": true, "Validator": true, "InputSanitizer": true},
	"validate": {"Validator": true, "InputValidator": true},
}

var universalSanitizerNames = map[string]bool{
	"encodeForHTML": true, "encodeForJavaScript": true, "encodeForURL": true,
	"encodeForSQL": true, "encodeForXML": true, "encodeForCSS": true,
	"encodeForJava": true, "htmlEscape": true, "javaScriptEscape": true,
}

var safeObjectTypes = map[string]bool{
	"String": true, "Integer": true, "Long": true, "Double": true,
	"Float": true, "Boolean": true, "BigDecimal": true, "BigInteger": true,
	"AtomicInteger": true, "AtomicLong": true,
	"StringBuilder": true, "StringBuffer": true,
	"List": true, "ArrayList": true, "LinkedList": true,
	"Map": true, "HashMap": true, "TreeMap": true,
	"Set": true, "HashSet": true, "TreeSet": true,
	"Optional": true, "Stream": true, "IntStream": true, "LongStream": true,
	"Path": true, "File": true, "URL": true, "URI": true,
	"Class": true, "Object": true, "Throwable": true, "Exception": true,
	"JsonNode": true, "ObjectNode": true, "ArrayNode": true,
	"Properties": true, "ResourceBundle": true,
	"Configuration": true, "Environment": true,
}

var skipParentTypes = map[string]bool{
	"field_access": true, "method_invocation": true, "object_creation_expression": true,
	"variable_declarator": true, "formal_parameter": true, "type_identifier": true,
	"import_declaration": true, "class_declaration": true, "interface_declaration": true,
	"method_declaration": true, "marker_annotation": true, "annotation": true, "modifier": true,
	"catch_formal_parameter": true, "inferred_parameters": true, "formal_parameters": true,
	"assignment_expression": true, "augmented_assignment_expression": true,
}

var skipRecurseTypes = map[string]bool{
	"comment": true, "string_literal": true, "character_literal": true,
	"number_literal": true, "boolean_literal": true, "null_literal": true,
	"void_type": true, "primitive_type": true,
	"float_literal": true, "integer_literal": true, "text_block": true,
}

var skipArgTypes = map[string]bool{
	"(": true, ")": true, ",": true, "{": true, "}": true, ";": true,
	"comment": true, "line_comment": true, "block_comment": true,
}

var argumentNodeTypes = map[string]bool{
	"identifier": true, "field_access": true, "method_invocation": true,
	"object_creation_expression": true, "string_literal": true, "number_literal": true,
	"boolean_literal": true, "null_literal": true, "this": true, "super": true,
	"cast_expression": true, "ternary_expression": true, "binary_expression": true,
	"lambda_expression": true, "method_reference": true, "array_access": true,
	"array_creation_expression": true, "parenthesized_expression": true,
	"class_literal": true, "type_cast": true, "generic_type": true,
	"unary_expression": true, "update_expression": true, "assignment_expression": true,
	"character_literal": true, "float_literal": true, "integer_literal": true,
	"hex_integer_literal": true, "octal_integer_literal": true,
	"true": true, "false": true,
	"switch_expression": true, "instanceof_expression": true,
	"text_block": true, "underscore_pattern": true,
}

var eventPublishMethods = map[string]bool{
	"publishEvent": true, "publish": true, "sendEvent": true,
}

var collectionMethods = map[string]bool{
	"add": true, "addAll": true, "put": true, "putAll": true,
	"set": true, "setAll": true, "offer": true, "push": true,
	"addFirst": true, "addLast": true, "replace": true,
}

var callbackChainMethods = map[string]bool{
	"ifPresent": true, "ifPresentOrElse": true,
	"forEach": true, "peek": true,
	"thenAccept": true, "thenAcceptAsync": true, "thenRun": true,
	"whenComplete": true,
}

// streamChainMethods：Stream/Lambda 链式中间/终端操作（R6-2）。
// 这些方法以 lambda 为实参，且 lambda 的参数代表「流中的元素」——
// 元素污点来自链首构造（Stream.of / Arrays.stream / *.stream()）。
// 注：forEach/peek 已在 callbackChainMethods 中（语义相近），此处集合用于
// 「回溯链首取 source」分支；map/filter/flatMap 是典型「元素变换」场景。
var streamChainMethods = map[string]bool{
	"map": true, "filter": true, "flatMap": true, "peek": true, "forEach": true,
	"distinct": false, // 占位：distinct 无 lambda，不参与
	"sorted":   false, "collect": false,
}

var springLifecycleCallbacks = map[string]string{
	"CommandLineRunner":       "run",
	"ApplicationRunner":       "run",
	"InitializingBean":        "afterPropertiesSet",
	"DisposableBean":          "destroy",
	"BeanFactoryAware":        "setBeanFactory",
	"ApplicationContextAware": "setApplicationContext",
	"EnvironmentAware":        "setEnvironment",
}

var repositoryInterfaces = map[string]bool{
	"JpaRepository": true, "CrudRepository": true, "PagingAndSortingRepository": true,
	"MongoRepository": true, "ElasticsearchRepository": true, "RedisRepository": true,
	"CassandraRepository": true, "CouchbaseRepository": true,
}

var heuristicRequestVars = map[string]bool{
	"request": true, "req": true, "httprequest": true, "servletrequest": true,
	"response": true, "resp": true, "httpresponse": true,
}

var collectionAccessMethods = map[string]bool{
	"get": true, "poll": true, "remove": true, "peek": true, "element": true,
	"next": true, "iterator": true, "stream": true,
	"keySet": true, "values": true, "entrySet": true,
}

var comparisonOperators = map[string]bool{
	"==": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true,
	"instanceof": true,
}

var nonTaintPropagatingOps = map[string]bool{
	"==": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true,
	"instanceof": true, "&&": true, "||": true,
}

var javaPrimitiveDefaults = map[string]string{
	"int": "0", "long": "0L", "double": "0.0", "float": "0.0f",
	"boolean": "false", "char": "'\\u0000'",
	"byte": "0", "short": "0",
}

var validationMethods = map[string]bool{
	"isValid": true, "validate": true, "check": true, "verify": true,
	"isAuthorized": true, "isAuthenticated": true, "hasRole": true,
	"hasAuthority": true, "hasPermission": true,
	"isSafe": true, "isAllowed": true, "isPermitted": true, "isTrusted": true,
	"sanitize": true, "escape": true, "encode": true, "filter": true, "clean": true,
}

var aopPointcutPattern = regexp.MustCompile(
	`execution\(\s*\*\s+([\w.*]+)\.([\w.*]+)\s*\([^)]*\)\s*\)`,
)

var validationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`if\s*\(\s*!?\s*\w+\.(isValid|validate|check|verify)\s*\(`),
	regexp.MustCompile(`if\s*\(\s*\w+\s*!=\s*null\s*\)`),
	regexp.MustCompile(`if\s*\(\s*Objects\.requireNonNull`),
	regexp.MustCompile(`StringUtils\.(isNotBlank|isNotEmpty)\s*\(`),
}
