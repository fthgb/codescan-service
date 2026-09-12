package agentic

// 截断/上限常量，逐字移植 agentic_enrich.py:30-32 + :246-253。raw read 结果由 agentic loop
// 截断（cap = _READ_TRUNC_CAPS.get(name, RAW_TRUNC_CHARS)），cap 错则 char_total/char_budget drift。
const (
	MaxReadLines          = 400  // agentic_enrich.py:30
	MaxGrepMatches        = 30   // :31
	MaxGrepFiles          = 2000 // :32
	RawTruncChars         = 800  // 默认 read 结果截断（对齐 RAW_TRUNC_CHARS, agentic_enrich.py:247）
	RawTruncCharsReadFile = 8000 // read_file 抬到更大 cap（对齐 RAW_TRUNC_CHARS_READFILE, agentic_enrich.py:252）
	FindingToolName       = "record_finding"
)

// ReadToolNames 对齐 _READ_TOOL_NAMES (agentic_enrich.py:244)：计 explore_rounds 的 read 工具集。
var ReadToolNames = map[string]bool{
	"read_file": true, "grep_repo": true,
	"search_definitions": true, "read_function": true,
}

// ReadTools 移植 _READ_TOOLS (agentic_enrich.py:34-54)：read_file + grep_repo。
var ReadTools = []map[string]any{
	{"type": "function", "function": map[string]any{
		"name":        "read_file",
		"description": "按相对路径读取仓库内任意文件（含 MyBatis mapper XML、yml 配置、properties），用于核实切片未展示的决定性事实（如 mapper 用 ${} 拼接还是 #{} 参数化）。路径必须相对仓库根、不得含 .. 或绝对路径。默认返回前 400 行。",
		"parameters": map[string]any{"type": "object", "properties": map[string]any{
			"file_path":  map[string]any{"type": "string", "description": "相对仓库根的路径，如 mapper_xml/UserMapper.xml"},
			"start_line": map[string]any{"type": "integer", "description": "起始行（默认 1）"},
			"end_line":   map[string]any{"type": "integer", "description": "结束行（默认 400）"}},
			"required": []string{"file_path"}}}},
	{"type": "function", "function": map[string]any{
		"name":        "grep_repo",
		"description": "在仓库内按正则搜索文件内容，返回匹配的 文件:行:文本。用于定位某个 id/方法名在哪个文件定义、或 ${} 拼接出现在哪些 mapper。file_glob 限定文件类型，默认 *.java；查 mapper 用 *.xml。",
		"parameters": map[string]any{"type": "object", "properties": map[string]any{
			"pattern":   map[string]any{"type": "string", "description": "正则表达式"},
			"file_glob": map[string]any{"type": "string", "description": "文件名通配，默认 *.java"}},
			"required": []string{"pattern"}}}},
}

// FindingTool 移植 _FINDING_TOOL (agentic_enrich.py:58-74)：结论锁定工具。
var FindingTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "record_finding",
	"description": "把刚读取的代码蒸成结构化结论写进判定上下文。调用后，本轮 raw 读取内容会从上下文移除，只剩这条结论——所以必须包含后续判定所需的关键特征（正则模式/拼接形式/调用参数/分支条件），不要只写一句话摘要。decisive_features 的 key 用本 CWE 模板列出的项。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"target":            map[string]any{"type": "string", "description": "验的是谁，如 StringUtil.safeSqlParse"},
		"file_lines":        map[string]any{"type": "string", "description": "如 StringUtil.java:1123-1150"},
		"decisive_features": map[string]any{"type": "object", "description": "per-CWE 决定性特征，key 由模板决定，value 自由文本", "additionalProperties": map[string]any{"type": "string"}},
		"verdict_on_fact":   map[string]any{"type": "string", "description": "此事实上的判定：是有效净化/是危险 sink/无关/... 不是整体 verdict"},
		"remaining_gap":     map[string]any{"type": "string", "description": "仍缺什么（喂下一轮 plan + 最终 missing_info"}},
		"required": []string{"target", "decisive_features", "verdict_on_fact"}}}}

// VerdictTool 移植 _VERDICT_TOOL (prompts.py:195-199): submit_verdict 终止工具。
// parameters 逐字对齐 _VERDICT_TOOL_INPUT_SCHEMA (prompts.py:163-193)。Go map 序
// (marshal 排序键) 对 tool schema 无影响——anthropic_kwargs_golden.json 由
// json.dump(sort_keys=True) 录制，键序亦为字典序，故 byte-match；数组 (required/
// type 列表) 保序与 Python 一致。
var VerdictTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "submit_verdict",
	"description": "提交最终安全判定（结构化）。调用此工具提交你的 verdict，不要输出自由文本 JSON。",
	"parameters": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"disposition": map[string]any{"type": "string",
				"description": "true_positive|likely_tp|likely_fp|false_positive|out_of_scope"},
			"confidence": map[string]any{"type": "integer", "description": "1-10"},
			"actual_vulnerability_types": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "枚举这条数据流里你看到的所有漏洞类型 slug；无则空数组 []"},
	"exploit_payload": map[string]any{"type": []string{"string", "null"},
		"description": "用来证明可利用的载荷（如注入串/恶意文件名/路径）。判 true_positive 时：若为注入/上传/路径穿越类，必须提供本字段（具体可验证攻击输入，不得编造）；若为缺失鉴权/IDOR/访问控制类，此处填 null（改走 decisive_checks）。判 false_positive 时填你认为会被拦下的输入。exploit_payload 与 decisive_checks 两者皆空时，必须将 verdict 降为 likely_tp 且 confidence≤6。"},
	"decisive_checks": map[string]any{"type": "array", "items": map[string]any{
		"type": "object", "properties": map[string]any{
			"kind":     map[string]any{"type": "string"},
			"code":     map[string]any{"type": "string"},
			"asserts":  map[string]any{"type": "string"},
			"location": map[string]any{"type": "string"}}},
		"description": "判定所依赖的守卫/缺失控制清单（列表，可空）：每项 kind=regex|string_replace|prefix_startswith|mybatis_param|mybatis_concat|preparedstatement_bind|strong_type_param|other，code=该校验的表达式/正则/方法原样，asserts=blocks(它拦住了)|allows(它拦不住，如缺失鉴权时的'无 @PreAuthorize'这类在场证据)，location=file:line。判 true_positive 时：若为缺失鉴权/IDOR/访问控制类漏洞，必须提供本字段（指出缺失的注解/鉴权函数/守卫，可核实事实，不得编造）；若为注入类，此处可空数组 []。exploit_payload 与 decisive_checks 两者皆空时，必须将 verdict 降为 likely_tp 且 confidence≤6。"},
	"exploit_path": map[string]any{"type": "object", "properties": map[string]any{
		"entry_point": map[string]any{"type": "string", "description": "file:line（调用链入口）"},
		"taint_source": map[string]any{"type": []string{"object", "null"}, "properties": map[string]any{
			"code":     map[string]any{"type": "string", "description": "污点源真实代码——攻击者可控数据的出生点（如 entry.getName()、@RequestParam String name），切片/工具回执真读到的原样"},
			"location": map[string]any{"type": "string", "description": "file:line"}},
			"description": "判 true_positive/likely_tp 且为 taint-flow 类（注入/路径穿越/XSS 等污点流漏洞）时必填，缺失鉴权/配置类填 null。污点源是【可控数据出生点】不是调用入口；代码非你真读到则整字段 null，不因缺它降判"},
		"data_flow":                map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "每步末尾 cite [跳N] 或 [工具:...@file]；第 0 步从污点源写起，不是入口调用链"},
		"sink_reached":             map[string]any{"type": "boolean"},
		"attacker_control_at_sink": map[string]any{"type": "string", "description": "full|partial|none"},
		"path_broken_at":           map[string]any{"type": []string{"string", "null"}},
		"sink_evidence": map[string]any{"type": []string{"object", "null"}, "properties": map[string]any{
			"sink_code":     map[string]any{"type": "string", "description": "sink 真实代码/SQL 原貌(MyBatis ${}/#{ 与 <if> 原样)，来自工具回执/切片真读，不得编造"},
			"sink_location": map[string]any{"type": "string", "description": "file:line"},
			"method_key":    map[string]any{"type": []string{"string", "null"}, "description": "Class.method 或 null"},
			"source_tool":   map[string]any{"type": []string{"string", "null"}, "description": "reachable_sinks|read_file|null"},
			"param_style":   map[string]any{"type": []string{"string", "null"}, "description": "concat|mixed|parameterized|null"}},
			"description": "判 TP 且 sink_reached=true 时必填，否则 null；无真值留 null 并改判 uncertain(conf≤6)"}}},
			"reasoning":          map[string]any{"type": "string", "description": "≤3 句"},
			"sanitization_found": map[string]any{"type": []string{"string", "null"}},
			"suggested_fix":      map[string]any{"type": []string{"string", "null"}, "description": "[file:line] 修改前→修改后\\n说明：一句话"},
			"severity":           map[string]any{"type": []string{"string", "null"}, "description": "critical|high|medium|low"},
			"severity_rationale": map[string]any{"type": []string{"string", "null"}},
			"dev_summary": map[string]any{"type": []string{"string", "null"},
				"description": "给不懂安全的后端开发的一句话：谁（未登录的人/任意登录用户）能通过哪个接口做成什么事；术语首次出现须括号解释。判 true_positive/likely_tp 时必填"},
			"design_note": map[string]any{"type": []string{"string", "null"},
				"description": "先承认原设计里合理的部分、再指出缺的那一步，句式「……本身没问题，问题是……」。判 true_positive/likely_tp 时必填"},
			"remaining_gap": map[string]any{"type": []string{"string", "null"},
				"description": "探索后仍缺的证据/未验证点；verdict=uncertain 时填具体缺口（喂 JudgeResult.missing_info）"},
		},
		"required": []string{"disposition", "confidence", "exploit_path", "reasoning"},
	},
}}

// searchDefinitionsTool / readFunctionTool 移植 _ENRICH_TOOLS[0]/[1] (agentic_enrich.py:99+)。
var searchDefinitionsTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "search_definitions",
	"description": "按名称查找仓库内某函数的定义。返回引用（文件、类、行号）。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"name": map[string]any{"type": "string", "description": "函数名"}},
		"required": []string{"name"}}}}

var readFunctionTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "read_function",
	"description": "读取某函数的完整源码（按 file_path + function_name 定位）。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"file_path":     map[string]any{"type": "string"},
		"function_name": map[string]any{"type": "string"}},
		"required": []string{"function_name"}}}}

// AgenticJudgeTools 移植 _AGENTIC_JUDGE_TOOLS (judge.py:534)。
var AgenticJudgeTools = []map[string]any{
	searchDefinitionsTool, readFunctionTool, ReadTools[0], ReadTools[1], VerdictTool,
}

// finishTool 移植 _TOOLS[4] (agentic_enrich.py:116-123)：enrich 终止工具，
// 列出要纳入判定上下文的仓库内函数。对应 Python _run_agentic_loop 的 finish_tool_name。
var finishTool = map[string]any{"type": "function", "function": map[string]any{
	"name":        "finish",
	"description": "结束：列出要纳入判定上下文的仓库内函数（例如你已核实的净化器/守卫）。",
	"parameters": map[string]any{"type": "object", "properties": map[string]any{
		"include": map[string]any{"type": "array", "items": map[string]any{
			"type": "object", "properties": map[string]any{
				"file_path":     map[string]any{"type": "string"},
				"function_name": map[string]any{"type": "string"}},
			"required": []string{"file_path", "function_name"}}}},
		"required": []string{"include"}},
}}

// enrichTools 移植 _TOOLS (agentic_enrich.py:99-124)：enrich 专用工具集。
// = [search_definitions, read_function, read_file, grep_repo, finish]。
// 与 AgenticJudgeTools（含 submit_verdict）的区别：enrich 用 finish 列 callee，不判 verdict。
var enrichTools = []map[string]any{
	searchDefinitionsTool, readFunctionTool, ReadTools[0], ReadTools[1], finishTool,
}
