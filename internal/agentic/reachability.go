package agentic

import (
	"regexp"
	"strings"
	"unicode"

	"appsecgo/internal/contract"
)

// reachability.go — Layer A sink 可达性预判（spec §Layer A）。loop 前对候选 callee
// 做非-LLM 可达性判定，把不可达集合作为软注记注入 messages，避免模型对不在源码树内
// 的 sink 反复搜索打转（ceshi 2 个 likely_tp 实证根因：pluginOperator.uploadConfigFile
// 实现在外部模块/接口代理，grep 全仓只命中调用点）。
//
// 三态：reachable / unreachable / unknown。仅 unreachable 触发注入；unknown（grep 截断）
// 不下结论，避免截断假象误判。AND 闸（search:false + grep 无新文件 + not-truncated）
// 保证真阳性深挖（每轮 grep 命中新文件 → reachable → 零注入）不受影响。
//
// 输入用 map[string]any（SlicedContext 的 model_dump 形式，全 judge 管线一致）：
// hop["function_body"] / hop["file_path"]（contract.HopSlice 的 json tag）。

const (
	reachReachable   = "reachable"
	reachUnreachable = "unreachable"
	reachUnknown     = "unknown"
	reachUncertain   = "uncertain" // in-repo-not-in-slice: grep 命中仓内新文件（callerFiles 外），非 in-slice Definitive（spec §4(a0)）
)

// candidateCallRe 匹配 Java 方法调用 recv.method(。捕获 receiver(组1)+method(组2)。
// 字符串/注释内的误匹配无害（软标注 + AND 闸过滤）。
var candidateCallRe = regexp.MustCompile(`\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(`)

// accessorRe 匹配 JavaBean accessor 命名（getXxx/setXxx/isXxx）。与 internal/slice/enrich.go
// 的 accessorNameRe 共用 contract.AccessorNamePattern（2026-09-08 消除重复防漂移）。
// accessor 非 sink-flow callee：实现是字段读写，无 sanitize 逻辑可漏判 → flag 它 uncertain
// 只造噪音（getter grep 全仓命中非切片文件 → 假 fire，T4 §7.1 实证 99% fire 主因之一）。
// 滤除安全：accessor 调用仍在切片 function_body 内，LLM 仍可见，不丢 taint 信号；guard 不
// pre-降级 accessor ≠ 漏判（accessor impl 无可 sanitize，乐观 TP 根因是 sink-flow callee 不可达，
// 非 getter）。spec §4(a0) 抽取范围（2026-08-24 补：原 silent，T4 §7.1 暴露抽取过广）。
var accessorRe = regexp.MustCompile(contract.AccessorNamePattern)

// jdkReceiverWhitelist 接收器白名单：JDK/常见库 + this/super，非业务 callee。
var jdkReceiverWhitelist = map[string]bool{
	"System": true, "String": true, "Arrays": true, "List": true, "Map": true,
	"Optional": true, "Objects": true, "Math": true, "Collections": true,
	"Integer": true, "Boolean": true, "Path": true, "Paths": true, "Files": true,
	"this": true, "super": true,
}

// jdkMethodStoplist 方法名白名单（v1.6, spec §3）：JDK/common 库方法名, 业务代码几乎
// 不 override（substring/println/entrySet/hasNext/lastIndexOf/indexOf — String/PrintStream/
// Map/Iterator 契约, 业务不实现这些类）。不收业务常 override 的通用名（put/get/add/remove/
// size/clear/contains/equals — §3.2 判据）；边界 putAll 保守不收（fail-safe 宁 fire, §3.4）。
// 与 jdkReceiverWhitelist 正交: 后者 recv 级（大写类名 System/String）, 本者 method 级
// （小写 var recv 的 JDK 契约方法, jdkReceiverWhitelist 漏的 — §3.1）。初始 = spike §10.6
// fire-case 实际出现的无歧义名, 增量维护。drop 在 ExtractCandidateCallees line 68（同
// jdkReceiverWhitelist 位置, alert unc + --debug-callees 两路径一致, §3.5 GR-8 核证）。
var jdkMethodStoplist = map[string]bool{
	"substring": true, "println": true, "entrySet": true, "hasNext": true,
	"lastIndexOf": true, "indexOf": true,
}

// calleeRef 保留 receiver + method 名。ExtractCandidateCallees 返回 []calleeRef 供
// PrejudgeCalleeReachability 的 D1.2 receiver-type 过滤（recv∈vtm ∧ ClassDeclared=false
// → 仓外实例方法 drop）。calleeRef 不导出：外部包（cmd/derive_fire）用
// ExtractCandidateCalleeNames 包装取 method 名，v2 tree-sitter 升级不破坏外部契约。
type calleeRef struct {
	Recv, Method string
}

// ExtractCandidateCallees 扫 hops 的 function_body 提取候选 callee（recv+method）。
// 过滤 this./super./JDK 白名单 + JavaBean accessor（get/set/is，非 sink-flow）；去重键
// recv\x00method（同 method 不同 recv 分立——D1.2 §6 精度：svc.addHeader keep vs
// resp.addHeader drop 由 recv 区分，见 _addHeaderPrecision 测试）。保序。
// hops 是 SlicedContext["hops"] 的元素（map[string]any，键 function_body）。
func ExtractCandidateCallees(hops []map[string]any) []calleeRef {
	seen := map[string]bool{}
	out := []calleeRef{}
	for _, h := range hops {
		body, _ := h["function_body"].(string)
		for _, m := range candidateCallRe.FindAllStringSubmatch(body, -1) {
			recv, method := m[1], m[2]
			if jdkReceiverWhitelist[recv] || jdkMethodStoplist[method] {
				continue
			}
			if accessorRe.MatchString(method) {
				continue
			}
			key := recv + "\x00" + method
			if !seen[key] {
				seen[key] = true
				out = append(out, calleeRef{Recv: recv, Method: method})
			}
		}
	}
	return out
}

// ExtractCandidateCalleeNames 投影 []calleeRef → []string（method 名），供外部包
// （cmd/derive_fire）消费——不暴露 unexported calleeRef。保持旧 []string 契约。
func ExtractCandidateCalleeNames(hops []map[string]any) []string {
	refs := ExtractCandidateCallees(hops)
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Method)
	}
	return out
}

// varTypeRe 匹配 Java 局部变量/参数声明 `[Type] name [=...]`。捕获 type(组1)+name(组2)。
// 终止符 [=;,)] 覆盖：`File dir = new File();`（=）、`void f(MyService svc)`（, 或 )）、
// `File f;`（;）。增强-for `for (File f : list)` 的 `:` 不在字符类 → 不匹配 → fail-safe keep。
// scope 上限声明（非 bug，spec §3(b)）：多声明/泛型/钻石/数组/链式/字段/enhanced-for
// 一律不解析 → keep，走原三态（保守，宁 fire 不漏 sink-flow 业务 callee）。
var varTypeRe = regexp.MustCompile(`\b([A-Z]\w*)\s+([A-Za-z_]\w*)\s*[=;,\)]`)

// buildVarTypeMap 扫 hops 的 function_body（含方法签名 → 参数可见）建 var→type 映射。
// 后写覆盖先写（同一 var 多次声明取最后一次，保守——实际罕见）。仅解析 varTypeRe 命中。
func buildVarTypeMap(hops []map[string]any) map[string]string {
	vtm := map[string]string{}
	for _, h := range hops {
		body, _ := h["function_body"].(string)
		for _, m := range varTypeRe.FindAllStringSubmatch(body, -1) {
			vtm[m[2]] = m[1]
		}
	}
	return vtm
}

// resolveReceiverType 查 vtm 得 recv 的声明类型；空 recv 或未命中 → ok=false（fail-safe keep）。
func resolveReceiverType(recv string, vtm map[string]string) (typ string, ok bool) {
	if recv == "" {
		return "", false
	}
	typ, ok = vtm[recv]
	return typ, ok
}

// isUpper 判 Java 类名 PascalCase 首字母大写（D8 v1.5, 2026-08-25: 静态调用 recv=类名
// 大写, 字段/var recv camelCase 小写; 区分二者定向 drop 静态框架调用 Collectors.toMap,
// 小写字段 helper 不进 v1.5 → fail-safe keep）。非 ASCII 大写亦 true（罕见不影响）。
func isUpper(r rune) bool { return unicode.IsUpper(r) }

// judgeReachability 纯决策逻辑（无 exec 依赖，可单测）。三态见文件头注释。
// callerFiles: 已入切片的 hop 文件集合（grep 命中若全在此 → 无独立定义文件 → 不可达）。
func judgeReachability(defsFound bool, grepMatches []map[string]any,
	grepTruncated bool, grepReason string, callerFiles map[string]bool) (state, evidence string) {
	if defsFound {
		return reachReachable, "def indexed in tree"
	}
	if grepTruncated || grepReason == "file cap reached" {
		return reachUnknown, "grep capped; cannot judge"
	}
	if len(grepMatches) == 0 {
		return reachUnreachable, "no grep matches at all"
	}
	for _, mt := range grepMatches {
		file, _ := mt["file"].(string)
		if !callerFiles[file] {
			// grep 命中仓内新文件（callerFiles 外）= in-repo-not-in-slice：
			// callee 在仓内被引用但切片未证明可达（可能是另一处 call-site 非 def，
			// 也可能 search_definitions 漏索引的真 def）→ uncertain，rejudge 核证（spec §4(a0)）。
			// v1 误分类为 reachReachable → 塞 Definitive + reachableNote → 乐观 TP（R2/R3 假阳根因）。
			return reachUncertain, "grep hit new file (in-repo not in-slice): " + file
		}
	}
	return reachUnreachable, "only call-site in-slice; impl not in tree"
}

// JudgeCalleeReachability 包装：调 executor 的 search_definitions + grep_repo，喂纯决策。
// exec==nil 或 callee 空 → unknown（不下结论）。Delegates to judgeCalleeReachabilityWithDef
// (keeps the exported symbol + signature; the def-file_path variant is the single source).
func JudgeCalleeReachability(exec *ToolExecutor, callee string, callerFiles map[string]bool) (state, evidence string) {
	st, ev, _ := judgeCalleeReachabilityWithDef(exec, callee, callerFiles)
	return st, ev
}

// judgeCalleeReachabilityWithDef wraps search_definitions + grep_repo + pure
// judgeReachability, also returning the first definition's file_path (for CalleeRef).
// Unlike JudgeCalleeReachability it does not discard the definition results.
func judgeCalleeReachabilityWithDef(exec *ToolExecutor, callee string,
	callerFiles map[string]bool) (state, evidence, filePath string) {
	if exec == nil || callee == "" {
		return reachUnknown, "no executor or callee", ""
	}
	defs := exec.searchDefinitions(map[string]any{"name": callee})
	defsFound, _ := defs["found"].(bool)
	if results, ok := defs["results"].([]map[string]any); ok && len(results) > 0 {
		if fp, ok := results[0]["file_path"].(string); ok {
			filePath = fp
		}
	}
	// ③ grepRepo pattern 收紧（\bcallee\s*\(）2026-08-25 GR-1 实测回退: 收紧减少 grep 命中数,
	// 对 common-token（next/info/values/iterator）从 v1.5 裸词 file-cap→reachUnknown→drop
	// 变 hit→uncertain→fire; 对业务名（sendDing）从 v1.5 命中集⊆callerFiles→unreachable 变
	// 命中 callerFiles 外→uncertain→fire（业务名不可 stoplist, 不可治）。净效果: 消除
	// codeup analyze→MY_COMMA_ANALYZER 常量 false hit（1, 但 3a27a06016de putAll 主 fire,
	// analyze 附加不降 fire）+ 引入大量新 fire（codeup ~16 next/sendDing, ceshi info, underwrite
	// ApplicantDTO）。③ 回退裸词, analyze false hit 留（已知 trade-off, codeup [21] putAll 主
	// fire 不受影响）。详见 spec §4 回退说明 + LESSONS。pattern 保持 callee 裸词:
	grAny := exec.grepRepo(map[string]any{"pattern": callee, "file_glob": "*.java"})
	gr, ok := grAny.(grepRepoResult)
	if !ok {
		return reachUnknown, "grep returned non-struct", filePath
	}
	st, ev := judgeReachability(defsFound, gr.Matches, gr.Truncated, gr.Reason, callerFiles)
	return st, ev, filePath
}

// unreachableNotePrefix/Suffix 软注记（spec §Layer A）。独立 user 消息注入（role=user）。
const unreachableNotePrefix = "以下 callee 的实现疑似不在本仓源码树内（外部模块/接口代理）："
const unreachableNoteSuffix = "。若 search_definitions 无果，请基于调用点可见契约（参数类型/注解/调用上下文）给出结论，不必反复搜索其实现。"

const reachableNotePrefix = "以下 callee 已确认在扫描仓库内有定义（切片已证明可达）："
const reachableNoteSuffix = `。不得以"断裂/不可达"为由降级。`

// uncertainNotePrefix/Suffix 软验证注记（spec §4(a0) reachableNote 位移：信任→验证）。
// in-repo-not-in-slice callee：仓内有引用但切片未证明可达 → 不假声称可达，改请 LLM 核证。
const uncertainNotePrefix = "以下 callee 在仓内有引用但切片未证明可达（in-repo not in-slice）："
const uncertainNoteSuffix = "。用 get_callees/search_definitions 核证其可达性，无法核证按 uncertain 提交。"

// PrejudgeCalleeReachability extends Layer A: loop 前对候选 callee 做三态可达性判定，
// reachable 写入 sliced["forward_reachable"].Definitive（guard 读），unreachable 仍发
// 软注记（现状保留）。exec/sliced nil → 空注记，不改 sliced。返合并软注记串
// （reachable 前缀 + unreachable 注记；空串=不注入）。注入点在 BuildMessages 之后
// （judge.go:158）→ prompt_golden/messages 不动；loopMessages 是 copy。
//
// v1 不填 ForwardReachable.Uncertain（见 plan 设计决策 2：unreachable 非 in-repo，
// 与字段文档语义冲突；无 v1 消费者读 Uncertain）。
func PrejudgeCalleeReachability(sliced map[string]any, exec *ToolExecutor) string {
	if sliced == nil || exec == nil {
		return ""
	}
	hopsAny, _ := sliced["hops"].([]any)
	hops := make([]map[string]any, 0, len(hopsAny))
	for _, h := range hopsAny {
		if hm, ok := h.(map[string]any); ok {
			hops = append(hops, hm)
		}
	}
	callerFiles := map[string]bool{}
	for _, h := range hops {
		if fp, ok := h["file_path"].(string); ok {
			callerFiles[fp] = true
		}
	}
	// definitive/uncertain 用 []any（map 形切片的 canonical 类型：JSON round-trip 后 []CalleeRef
	// 落到 []any of map[string]any；guard 的 definitiveCallees 也读 []any，类型对齐）。
	// truncated 是 bool（ForwardReachable.Truncated，spec §4(a0)）。
	definitive := []any{}
	uncertain := []any{}
	var unreachable []string
	var truncated bool
	vtm := buildVarTypeMap(hops)
	// v1.7 (spec 2026-08-25-v1-7, b1, Path B1): class-field type-res. buildVarTypeMap
	// 只扫 function_body（方法体, 不含类字段声明）→ 类字段 recv（如 reentrantLockServiceImpl,
	// 类体声明 `private LockService reentrantLockServiceImpl;`）vtm 无 → resolveReceiverType
	// ok=false → v1.5 keep → fire（② fire-noise, ca15851d REAL TP 准确度损失）。此处 lazy 调
	// exec.idx.ClassFieldsFor(file, name) 取该 hop 方法所在 class/interface/enum/record body
	// 的 field_declaration direct children 文本, varTypeRe 扫入 vtm（b1: 只 field_declaration,
	// 不扫其他方法局部 local_variable_declaration → 零跨方法污染, b2 flawed 的反证, spec §3.1/§4）。
	// buildVarTypeMap 不动（保纯 + 单测, §3.3）。fail-safe: exec.idx==nil 或 ClassFieldsFor
	// ok=false/空 → vtm 不扩 → v1.5 keep 不变。class_fields 不入 hop JSON（走 FunctionExtractor
	// seam 非 HopSlice contract 改）→ judge 永不见, §3.3 非破坏（比 spike 原述 HopSlice-threading 更强）。
	if exec.idx != nil {
		for _, h := range hops {
			file, _ := h["file_path"].(string)
			name, _ := h["function_name"].(string)
			if file == "" || name == "" {
				continue
			}
			if cf, ok := exec.idx.ClassFieldsFor(file, name); ok && cf != "" {
				for _, m := range varTypeRe.FindAllStringSubmatch(cf, -1) {
					vtm[m[2]] = m[1] // 字段 name → type, 后写覆盖先写（同 buildVarTypeMap 语义）
				}
			}
		}
	}
	for _, c := range ExtractCandidateCallees(hops) {
		// D1.2 receiver-type 过滤（spec §3 + D8 v1.5）：recv∈vtm 声明类型 ∧ 该类型仓外
		// （!ClassDeclared）→ 仓外实例方法（JDK/框架，如 dir→File.exists），rejudge 永不可解
		// → drop（v1）。recv∉vtm ∧ PascalCase 大写 ∧ 仓外类（!ClassDeclared(recv)）→ 框架
		// 静态方法（Collectors.toMap/ListUtils.partition），rejudge 永不可解（无 repo def）
		// → drop（v1.5, D8, c5f2e 实证否则永久 uncertain 致 REAL TP 准确度损失）。余
		// recv∉vtm ∧ 小写（字段/链式/enhanced-for/多声明/泛型/钻石/数组）→ fail-safe keep。
		// 仓内 static 类（RepoUtil.foo → ClassDeclared=true）不 drop；nil-guard 镜 :361。
		if exec.idx != nil {
			if typ, ok := resolveReceiverType(c.Recv, vtm); ok {
				if !exec.idx.ClassDeclared(typ) {
					continue
				}
			} else if len(c.Recv) > 0 && isUpper(rune(c.Recv[0])) && !exec.idx.ClassDeclared(c.Recv) {
				continue
			}
		}
		st, _, fp := judgeCalleeReachabilityWithDef(exec, c.Method, callerFiles)
		switch st {
		case reachReachable:
			ref := map[string]any{"name": c.Method}
			if fp != "" {
				ref["file_path"] = fp
			}
			definitive = append(definitive, ref) // map[string]any auto-boxed to any
		case reachUncertain:
			// in-repo-not-in-slice（spec §4(a0)）：加 uncertain；rejudge RefreshForwardReachable
			// 解析后从 uncertain 移除、加 definitive（§4(d)）。
			ref := map[string]any{"name": c.Method}
			if fp != "" {
				ref["file_path"] = fp
			}
			uncertain = append(uncertain, ref)
		case reachUnknown:
			// grep file-cap = 常见 token 的 perf 限（length/mock/printStackTrace/toJSONString/error…），
			// 非「闭包不完整」——grepRepo 是 flat token-grep 不做闭包 BFS，file-cap = token 太常见。
			// spec §4(a0) item3 误把 grepRepo file-cap 当闭包 cap → 置 truncated → 假 fire；
			// T4 §7.1 实证 10/11 fire 在此。drop（not-applicable，不置 truncated）：
			// P0-a 只管 in-repo-not-in-slice（uncertain）；common-token/out-of-repo callee
			// （JDK/框架/外部 lib）按 spec §3 D1 note 属 P1+，不属 P0-a。
			// drop 安全：common-token grep-cap 的 callee 实现在仓外/框架（非 sink-flow 业务 callee，
			// 无 sanitize 可漏判），LLM 仍见调用点；真 sink-flow 业务 callee 名罕（uploadConfigFile）
			// → grep 不 cap → 走 uncertain → fire（preserve）。truncated 字段留 P1+ 真 闭包 cap。
		case reachUnreachable:
			unreachable = append(unreachable, c.Method)
		}
	}
	// 写三键：任一非空才写（definitive 空 + uncertain 非空 也须写，否则 MapForwardReachable 读不到 fire 态）。
	if len(definitive) > 0 || len(uncertain) > 0 || truncated {
		sliced["forward_reachable"] = map[string]any{
			"definitive": definitive,
			"uncertain":  uncertain,
			"truncated":  truncated,
		}
	}
	var note string
	if len(definitive) > 0 {
		names := make([]string, 0, len(definitive))
		for _, d := range definitive {
			if dm, ok := d.(map[string]any); ok {
				if n, ok := dm["name"].(string); ok {
					names = append(names, n)
				}
			}
		}
		note = reachableNotePrefix + strings.Join(names, ", ") + reachableNoteSuffix
	}
	// uncertainNote（spec §4(a0)：reachableNote 位移的"验证"半）。
	// in-repo-not-in-slice callee 不假声称可达，改请 LLM 用 get_callees 核证。
	if len(uncertain) > 0 {
		names := make([]string, 0, len(uncertain))
		for _, u := range uncertain {
			if um, ok := u.(map[string]any); ok {
				if n, ok := um["name"].(string); ok {
					names = append(names, n)
				}
			}
		}
		note += uncertainNotePrefix + strings.Join(names, ", ") + uncertainNoteSuffix
	}
	if len(unreachable) > 0 {
		note += unreachableNotePrefix + strings.Join(unreachable, ", ") + unreachableNoteSuffix
	}
	return note
}

// PrejudgeUnreachableCallees 薄封装（保留旧名供 reachability_test.go:70 既有引用）。
// Prefer PrejudgeCalleeReachability（新调用方用新名）。
func PrejudgeUnreachableCallees(sliced map[string]any, exec *ToolExecutor) string {
	return PrejudgeCalleeReachability(sliced, exec)
}
