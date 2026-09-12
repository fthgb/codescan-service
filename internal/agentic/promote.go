package agentic

import (
	"encoding/json"
	"os"
	"strings"
)

// xmlPromoteGate mirrors config.AGENTIC_XML_PROMOTE. P7 re-enabled (2026-08-08):
// the潜伏 []int/[]any line_range bug is fixed (promote now emits []any{float64,...}
// shape — verified by TestPromote_LineRangeShapeForGuardExtraction). EAGER_MAPPER_XML
// still deterministically pulls mapper XML pre-LLM, but post-agentic promote is kept
// as a fail-open fallback to catch deeper mapper paths eager misses. Default "on"
// (config-overridable via APPSEC_AGENTIC_XML_PROMOTE). SetXmlPromoteGate exported so
// pipeline.Run can drive it from config and tests can lock "off" for golden parity.
// A var (not const) so config/tests can flip it.
var xmlPromoteGate = "on"

// SetXmlPromoteGate drives the promote gate from config (pipeline.Run reads
// RunOpts.AgenticXmlPromote) or tests (parity replay locks "off" to match golden
// recorded with production off config). Production default "on" (config.Load).
func SetXmlPromoteGate(v string) { xmlPromoteGate = v }

// PromoteAgenticXmlToSlice 移植 _promote_agentic_xml_to_slice (judge.py:217-275)。
//
// 扫 toolLog 里 read_file 命中 .xml 的，按 args（非 result_excerpt）重读盘，取
// readlines-忠实切片；body 含 ${} 拼接（危险 concat）则 append 一个 agentic_xml
// hop 进 sliced["hops"]。纯 #{} 不提升。fail-open recover（绝不因提升失败致 uncertain）。
//
// 签名只取 repoRoot string（controller 决策：promote 只需 repoRoot，不需整个 index），
// 对齐 Python getattr(repo_index, "repo_root", None)。
//
// 双形状 hops 读：sliced["hops"] 可能是 []map[string]any（Go 构造）或
// []any（json.Unmarshal 形状，每元素 map[string]any）。promoteHops 统一抽取。
// 若 added，写回 sliced["hops"] = hops（[]map[string]any 形状）——形状可能从 []any
// 变为 []map[string]any，这是内部 + parity 安全的：JudgeResult 不携带 hops，
// 下游 verifier/judge 的 hops 访问器均为双形状。
func PromoteAgenticXmlToSlice(sliced map[string]any, toolLog []map[string]any, repoRoot string) {
	defer func() { recover() }() // fail-open：对齐 Python `except Exception: return`
	if xmlPromoteGate != "on" || repoRoot == "" || len(toolLog) == 0 {
		return
	}
	exec := &ToolExecutor{repoRoot: repoRoot} // 复用 safeResolve（same-package）
	hops := promoteHops(sliced)               // 双形状抽取，可能 nil/空
	present := map[string]bool{}
	maxIdx := -1
	for _, h := range hops {
		if fp, ok := h["file_path"].(string); ok {
			present[fp] = true
		}
		// hop_index 可能 int 或 float64（JSON）
		if idx := toIntOr(h["hop_index"], 0); idx > maxIdx {
			maxIdx = idx
		}
	}
	nextIdx := maxIdx + 1
	added := false
	for _, e := range toolLog {
		tool, _ := e["tool"].(string)
		if tool != "read_file" {
			continue
		}
		args, _ := e["args"].(map[string]any)
		rel, _ := args["file_path"].(string)
		if !strings.HasSuffix(rel, ".xml") || present[rel] {
			continue
		}
		target, ok := exec.safeResolve(rel)
		if !ok {
			continue
		}
		st, err := os.Stat(target) // isfile parity：拒目录/不存在
		if err != nil || st.IsDir() {
			continue
		}
		data, err := os.ReadFile(target)
		if err != nil { // 对齐 Python except OSError: continue
			continue
		}
		// universal-newline 归一化 + readlines（保留 \n 终止符，去单一尾随空元素）
		normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
		normalized = strings.ReplaceAll(normalized, "\r", "\n")
		lines := strings.SplitAfter(normalized, "\n")
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = lines[:n-1]
		}
		total := len(lines)
		// start = max(1, int(args.get("start_line",1) or 1))：缺省/0/负 → 1
		start := toIntOr(args["start_line"], 1)
		if start < 1 {
			start = 1
		}
		// end = int(args.get("end_line", start+30) or start+30)：缺省/0 → start+30；
		// 非零（含负）保留原值；无 MaxReadLines 上夹（Python 无）。
		endDefault := start + 30
		end := toIntOr(args["end_line"], endDefault)
		// OOB-clamp（拟合 Python list[start-1:end] 越界不报错，永不 panic）
		lo := start - 1
		if lo < 0 {
			lo = 0
		}
		if lo > total {
			lo = total
		}
		hi := end
		if hi < 0 {
			hi = 0
		}
		if hi > total {
			hi = total
		}
		var sel []string
		if lo < hi {
			sel = lines[lo:hi]
		} else {
			sel = lines[:0]
		}
		body := strings.Join(sel, "")      // 空分隔，拟合 Python "".join(sel)
		if !strings.Contains(body, "${") { // 只提升含 ${} 拼接的；纯 #{} 不提升
			continue
		}
		hops = append(hops, map[string]any{
			"hop_index":      nextIdx,
			"file_path":      rel,
			"function_name":  "",
			"function_body":  body,
			"taint_variable": "",
			"line_range":     []any{float64(start), float64(start + len(sel) - 1)},
			"expanded_from":  "agentic_xml",
		})
		present[rel] = true
		nextIdx++
		added = true
	}
	if added { // Python 仅在 added 时写回
		sliced["hops"] = hops
		// token_count 触碰但不重算（Python sliced.get("token_count", 0)）
		tc, ok := sliced["token_count"]
		if !ok {
			tc = 0
		}
		sliced["token_count"] = tc
	}
}

// promoteHops 双形状抽取 sliced["hops"]：支持 []map[string]any（Go 构造）与
// []any（json.Unmarshal 形状）。对齐 internal/verifier/helpers.go 的 hopsOf，
// 但因 铁律 A（agentic 不依赖 verifier）而本地实现。返回的 []map 可能 nil/空。
// 注：对 []any 形状返回新 slice（追加不污染原 []any；写回后形状变为 []map）。
func promoteHops(sliced map[string]any) []map[string]any {
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

// toIntOr 拟合 Python `int(args.get(k, def) or def)` 的真值语义：
// nil/缺省 → def；int/float64/json.Number 非零 → 数值（负值保留）；零 → def。
// 调用方对 start 再 max(1, ...)，对 end 不上夹（Python 无上夹）。
func toIntOr(v any, def int) int {
	switch n := v.(type) {
	case int:
		if n != 0 {
			return n
		}
	case float64:
		if n != 0 {
			return int(n)
		}
	case json.Number:
		if i, err := n.Int64(); err == nil && i != 0 {
			return int(i)
		}
	}
	return def
}
