package judge

import (
	"fmt"
	"regexp"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/verifier"
)

// dynamic.go — 移植 appsec/dynamic_executor.py 的 IRExecutor + dynamic_verify 包装。
// 第0.5层动态执行验证（VerifyVerdict + BuildAttackRequest 后、falsify 前，对齐 judge.py:867-872）。
// IR executor 纯评估复用 verifier sink 语义（EscapesBase/ExtractBaseLiteralFromSlice/ExecutorVisible），
// 无 java/docker 依赖。junit 档 deferral（依赖 tree-sitter method_invocations + JDK 工具链，推 B 阶段）。
//
// 契约边界（铁律 A/D）：IRExecutor.Verify 纯评估（产 DynamicResult，不改 verdict/confidence）；
// 降级由 DynamicVerify 包装按 §2 动作矩阵应用（只降不升，永不翻对岸）。CONFIRMED 的更高有效置信
// 只进 verification.dynamic.confirmed_confidence 注解，不碰 confidence 字段（保 provenance）。
//
// 核心不变量（§2）：IR 永不翻 verdict 到对岸（TP→FP 或 FP→TP）；confidence 只降不升。
// 切片 hops 本就是 SAST 抽出的 source→sink 路径（代码 ground truth），IR 不重导路径，只验 sink 语义；
// 守卫中和已由第0层 VerifyVerdict 判过，IR 不重复。
//
// fail-open：任何 panic → 记 dynamic_error，不重抛，保持原判（对齐 Python try/except Exception）。

// fsSinkRe 匹配 path_traversal 的文件系统 sink（Python dynamic_executor._path_sink_outcome:53）。
var fsSinkRe = regexp.MustCompile(`\bnew\s+File\b|Files\.(write|copy|newOutputStream)|FileOutputStream|Paths\.get\(`)

// inconclusiveDynResult 构造 INCONCLUSIVE DynamicResult（Python _inconclusive:42-44）。
func inconclusiveDynResult(reason string, path []string) map[string]any {
	return map[string]any{
		"outcome":              "INCONCLUSIVE",
		"evidence":             reason,
		"reason":               reason,
		"path":                 path,
		"confirmed_confidence": nil,
	}
}

// hopsOfDyn 是 verifier.hopsOf 的本地副本（避免 export 扩散；judge 包无 hopsOf）。
// 容错 []map[string]any（Go 构造）与 []any（JSON unmarshal parity 路径）。
func hopsOfDyn(sliced map[string]any) []map[string]any {
	switch v := sliced["hops"].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, h := range v {
			if m, ok := h.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// hopBodiesDyn joins all hop function_body with "\n"（verifier.hopBodies 本地副本）。
func hopBodiesDyn(sliced map[string]any) string {
	parts := []string{}
	for _, h := range hopsOfDyn(sliced) {
		if b, ok := h["function_body"].(string); ok {
			parts = append(parts, b)
		}
	}
	return strings.Join(parts, "\n")
}

// dynPath 构造取证 path（Python IRExecutor.verify:85-86）。
// line_range 容错 []any（JSON）与 []int（Go 构造），取 [0]。
func dynPath(sliced map[string]any) []string {
	path := []string{}
	for _, h := range hopsOfDyn(sliced) {
		fn, _ := h["function_name"].(string)
		fp, _ := h["file_path"].(string)
		if fn == "" {
			fn = "?"
		}
		if fp == "" {
			fp = "?"
		}
		ln := 0
		switch lr := h["line_range"].(type) {
		case []any:
			if len(lr) > 0 {
				ln = intFromAny(lr[0])
			}
		case []int:
			if len(lr) > 0 {
				ln = lr[0]
			}
		}
		path = append(path, fmt.Sprintf("%s@%s:%d", fn, fp, ln))
	}
	return path
}

// pathSinkOutcome 移植 _path_sink_outcome: path_traversal sink 语义。
// CONFIRMED = 切片有 FS sink 且 EscapesBase True；NOT_REPRODUCED = 有 sink 但未逃；
// INCONCLUSIVE = 切片内无 FS sink 或无 BASE 字面量（守 inc27 never-fabricate + RC-A 反漏报）。
func pathSinkOutcome(sliced map[string]any, payload string) (string, string) {
	bodies := hopBodiesDyn(sliced)
	if !fsSinkRe.MatchString(bodies) {
		return "INCONCLUSIVE", "切片内无文件系统 sink，IR 无法确认 payload 是否到达 sink"
	}
	base := verifier.ExtractBaseLiteralFromSlice(sliced)
	if base == "" {
		return "INCONCLUSIVE", "切片内有 FS sink 但无 BASE 字面量，IR 不伪造 base、不判穿越（守 inc27 never-fabricate + RC-A 反漏报）"
	}
	if verifier.EscapesBase(base, payload) {
		return "CONFIRMED", fmt.Sprintf("payload %s 到达 FS sink，Paths.get(base+payload).normalize() 逃出 base=%s，sink 语义确认危险生效", payload, base)
	}
	return "NOT_REPRODUCED", fmt.Sprintf("payload %s 到达 FS sink 但 normalize() 未逃出 base=%s，sink 语义不构成穿越", payload, base)
}

// sqlSinkOutcome 移植 _sql_sink_outcome: sql_injection sink 语义（复用 verifier.ExecutorVisible）。
// raw_concat=CONFIRMED（payload 拼入 SQL 文本），prepared=NOT_REPRODUCED（参数化绑定），none=INCONCLUSIVE。
func sqlSinkOutcome(sliced map[string]any) (string, string) {
	switch verifier.ExecutorVisible(sliced) {
	case "raw_concat":
		return "CONFIRMED", "切片内可见原生 Statement.execute/createNativeQuery 字符串拼接，payload 拼入 SQL 文本，可注入"
	case "prepared":
		return "NOT_REPRODUCED", "切片内可见 PreparedStatement/setString 参数化绑定，payload 不入 SQL 文本，不可注入"
	default:
		return "INCONCLUSIVE", "SQL 执行器不在切片（MyBatis mapper DAO 等），无法确认是否真拼接"
	}
}

// irExecutor 移植 IRExecutor（Python dynamic_executor:77-99）。
// name="ir"，复用 inc27 verify.py 的 sink 语义模拟；不重导路径（切片即路径）；不重复守卫中和。
type irExecutor struct{}

func (irExecutor) Name() string { return "ir" }

// Verify 移植 IRExecutor.verify: 纯评估，产 DynamicResult，不改 verdict/confidence。
func (irExecutor) Verify(result contract.JudgeResult, sliced map[string]any) map[string]any {
	payload := ptrStr(result.ExploitPayload)
	vtype := strings.ToLower(strings.TrimSpace(strOr(sliced, "vulnerability_type", "")))
	path := dynPath(sliced)
	if payload == "" {
		return inconclusiveDynResult("无 exploit_payload，IR 无从追踪", path)
	}
	var outcome, reason string
	switch vtype {
	case "path_traversal":
		outcome, reason = pathSinkOutcome(sliced, payload)
	case "sql_injection":
		outcome, reason = sqlSinkOutcome(sliced)
	default:
		return inconclusiveDynResult(fmt.Sprintf("IR 首档未覆盖类型 %s", vtype), path)
	}
	dr := map[string]any{
		"outcome":              outcome,
		"evidence":             reason,
		"path":                 path,
		"reason":               reason,
		"confirmed_confidence": nil,
	}
	if outcome == "CONFIRMED" {
		conf := result.Confidence
		if conf < 9 {
			conf = 9
		}
		dr["confirmed_confidence"] = conf
	}
	return dr
}

// dynamicDowngrade 移植 _ir_downgrade: 应用 §2 矩阵降级（只降不升）。
// verdict→uncertain, conf≤4, reasoning 前缀。不动 verification（由 DynamicVerify 统一写）。
func dynamicDowngrade(result *contract.JudgeResult, prefix string) {
	result.Verdict = "uncertain"
	if result.Confidence > 4 {
		result.Confidence = 4
	}
	result.Reasoning = prefix + result.Reasoning
}

// DynamicVerify 移植 dynamic_verify 包装（Python dynamic_executor:120-157）。
// 跑 IRExecutor，写 verification.dynamic，按 §2 动作矩阵应用降级。
// 永不抛（fail-open: panic → 不重抛，记 dynamic_error，保持原判）。返回 (result, info)。
//
// gate（对齐 Python judge.py:867-868）：mode=="ir" && verdict in (TP, FP)。
// mode=="junit" 等同 off skip（junit deferral，依赖 tree-sitter method_invocations + JDK）。
//
// 动作矩阵（§2）：
//
//	TP + CONFIRMED      → 保持 TP + 注解 confirmed_confidence（confidence 不动）
//	TP + NOT_REPRODUCED → 降 uncertain（TP 被执行证据证伪）
//	FP + CONFIRMED      → 降 uncertain（FP 被证伪，反漏报）
//	FP + NOT_REPRODUCED → 保持 FP + 注解（执行证据支撑 FP）
//	任一 + INCONCLUSIVE → 不干预（落第1层 falsify_tp）
//	uncertain + 任一     → 不干预（已 uncertain，不翻回）
//
// 命名返回值 r/info 确保 panic 时 defer recover 返回原 result + 带 dynamic_error 的 info。
func DynamicVerify(result contract.JudgeResult, sliced map[string]any, mode string) (r contract.JudgeResult, info map[string]any) {
	r = result
	info = map[string]any{"dynamic_run": false, "dynamic_outcome": nil, "dynamic_error": nil}
	// gate: mode=="ir"（junit/off/unknown → skip，junit deferral）+ verdict in (TP, FP)。
	if mode != "ir" || (result.Verdict != "true_positive" && result.Verdict != "false_positive") {
		return
	}
	// fail-open: panic → 记 dynamic_error，保持原 result（r 未被 verify 改）
	defer func() {
		if rec := recover(); rec != nil {
			info["dynamic_error"] = fmt.Sprintf("%v", rec)
			info["dynamic_run"] = false
			info["dynamic_outcome"] = nil
		}
	}()
	dr := irExecutor{}.Verify(r, sliced)
	outcome, _ := dr["outcome"].(string)
	info["dynamic_outcome"] = outcome
	info["dynamic_run"] = true
	// method 兜底: executor 若未在返回 dict 里带 method，包装从 executor.name 回填
	if _, ok := dr["method"]; !ok {
		dr["method"] = "ir"
	}
	// §2 矩阵降级
	if outcome == "CONFIRMED" && r.Verdict == "false_positive" {
		dynamicDowngrade(&r, "[动态执行: payload 达 sink 生效，原 FP 不成立] ")
	} else if outcome == "NOT_REPRODUCED" && r.Verdict == "true_positive" {
		dynamicDowngrade(&r, "[动态执行: payload 经 sink 语义不构成危险，原 TP 被执行证据证伪] ")
	}
	// 写 verification.dynamic（MERGE，不替换现有 verification 子键——保 falsify 等其他层 provenance）
	v := map[string]any{}
	if r.Verification != nil {
		v = r.Verification
	}
	v["dynamic"] = dr
	r.Verification = v
	return
}
