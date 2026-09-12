// CodeSafeAdapter — parses a CodeSafe REST bug-detail dump into []contract.SASTResult.
// Faithful port of appsec/adapters/codesafe.py.
//
// CodeSafe is an internal SAST platform queried via fetch_bugflow.py. Its per-defect
// detail carries bugTraces[], each node tagged with kind (2=SOURCE, 1=SINK, 0=propagation)
// and linked by fatherTraceid -> traceId into a DAG (not a single chain — nodes may
// fork/merge). That DAG is the dataflow; we flatten it into a topo-ordered taint_path.
//
// Architecture (铁律 D / ADR-0005): this adapter is the ONLY place that knows CodeSafe's
// field names (bugTraces/kind/fatherTraceid/bugFile/level/...). Downstream nodes eat only
// the contract.SASTResult contract. Swapping CodeSafe for another SAST = write another adapter.
//
// Input shape: raw["bugs"] is the all_bugs.json produced by fetch_bugflow.py MODE=fetch_all.
// (Python also accepts a bare list[bug]; Go Parse signature takes map, and run_scan/webhook
// always wrap into {"bugs":[...]} — bare-list case doesn't apply.)
//
// Path consistency (CRITICAL): normPath here MUST match the on-disk path that
// fetch_bugflow.py writes under code_dump/, so the slicer (repo_root = code_dump) can open
// the same files. The transform is one line, duplicated in the fetch script (separate repo,
// can't import); keep them in sync.
package adapter

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"appsecgo/internal/bughash"
	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
)

// codesafeCWERE mirrors _CWE_RE = re.compile(r"cwe-?(\d+)", re.IGNORECASE).
var codesafeCWERE = regexp.MustCompile(`(?i)cwe-?(\d+)`)

// codesafeSlugRE mirrors the slugify fallback: re.sub(r"[^a-z0-9]+", "_", rc.lower()).
var codesafeSlugRE = regexp.MustCompile(`[^a-z0-9]+`)

// codesafeLevelMap mirrors _LEVEL_MAP (CodeSafe bugLevel: 1=低危 3=中危 5=高危).
// 2026-09-08 修正：原映射写反了（1→high/5→low），导致 SQL 注入（bugLevel=5）
// 被判为 low、被 severity 过滤丢弃。代码卫士 bugLevel 是数字越大越严重。
// Keys normalized to string (bugLevel may arrive as JSON number or string); both 1 and
// "1" collapse to "1". ruleVO.level uses the same 1/3/5 scale.
var codesafeLevelMap = map[string]string{
	"1": "low",
	"3": "medium",
	"5": "high",
}

// normPath mirrors _norm_path: backslash→forward slash, lstrip "/".
// MUST stay identical to fetch_bugflow.py's path transform (see module docstring).
func normPath(p string) string {
	if p == "" {
		return ""
	}
	return strings.TrimLeft(strings.ReplaceAll(p, "\\", "/"), "/")
}

// traceKey normalizes a traceId/fatherTraceid value (int|float|string|nil) to a string
// key for the DAG map. nil→""; numeric→strconv; string→as-is; else fmt.Sprint.
//
// Parity note: Python's _flatten_dag uses the raw traceId (int or str) as dict key, so
// int 1 and string "1" are DISTINCT keys in Python. Go normalizes both to "1" (unified).
// Real CodeSafe data uses a consistent type per field (traceId always int OR always str),
// so this divergence is unreachable in practice — recorded as a known parity deviation.
func traceKey(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.Itoa(int(x))
	default:
		return fmt.Sprint(x)
	}
}

// extractCWEBug mirrors _extract_cwe: ruleVO.refs[] CWE ref (referenceType=="CWE",
// referenceTypeId=<cwe#>) → scan ruleCode/ruleName text → "CWE-UNKNOWN" (truthy).
func extractCWEBug(bug map[string]any) string {
	rv := asMap(bug["ruleVO"])
	for _, rAny := range asSlice(rv["refs"]) {
		r := asMap(rAny)
		if asString(r["referenceType"]) != "CWE" {
			continue
		}
		tid := r["referenceTypeId"]
		if tid == nil {
			continue
		}
		// Python: try int(tid); except (ValueError,TypeError): regex search str(tid).
		switch x := tid.(type) {
		case float64:
			return "CWE-" + strconv.Itoa(int(x))
		case int:
			return "CWE-" + strconv.Itoa(x)
		case string:
			if n, err := strconv.Atoi(x); err == nil {
				return "CWE-" + strconv.Itoa(n)
			}
			if m := codesafeCWERE.FindStringSubmatch(x); m != nil {
				return "CWE-" + m[1]
			}
		default:
			if m := codesafeCWERE.FindStringSubmatch(fmt.Sprint(tid)); m != nil {
				return "CWE-" + m[1]
			}
		}
	}
	for _, k := range []string{"ruleCode", "ruleName"} {
		v, ok := bug[k].(string)
		if !ok {
			continue
		}
		if m := codesafeCWERE.FindStringSubmatch(v); m != nil {
			return "CWE-" + m[1]
		}
	}
	return "CWE-UNKNOWN"
}

// inferVulnTypeBug mirrors _infer_vuln_type: prefer reg.SlugForCwe(cweID) (SAST-agnostic
// registry); no CWE/ unmapped → slugify ruleCode/ruleName; never empty (conformance).
// reg may be nil (degrades to slugify, mirroring Python slug_for_cwe→None fallback).
func inferVulnTypeBug(reg *cwereg.Registry, ruleCode, ruleName, cweID string) string {
	if reg != nil {
		if slug := reg.SlugForCwe(cweID); slug != "" {
			return slug
		}
	}
	rc := ruleCode
	if rc == "" {
		rc = ruleName
	}
	if rc == "" {
		rc = "unknown"
	}
	slug := codesafeSlugRE.ReplaceAllString(strings.ToLower(rc), "_")
	slug = strings.Trim(slug, "_")
	if slug == "" {
		return "unknown"
	}
	return slug
}

// severityBug mirrors _severity: bugLevel (1/3/5) → high/medium/low;
// fallback ruleVO.level (same scale); default "medium". `level` (bug-level) is
// empirically None — not read (parity with Python docstring).
func severityBug(bug map[string]any) string {
	if bl, ok := codesafeLevelMap[traceKey(bug["bugLevel"])]; ok {
		return bl
	}
	rv := asMap(bug["ruleVO"])
	if bl, ok := codesafeLevelMap[traceKey(rv["level"])]; ok {
		return bl
	}
	return "medium"
}

// flattenDAG mirrors _flatten_dag: topo-order trace nodes by fatherTraceid → traceId.
// CodeSafe dataflow is a DAG (forks/merges), not a single chain; DFS from roots preserves
// a sane source→sink order. Orphans (cycles / detached) appended so no node is dropped.
//
// roots: fatherTraceid is nil/""/0/"0" OR father not present in by (detached).
func flattenDAG(traces []any) []map[string]any {
	by := map[string]map[string]any{}
	for _, tAny := range traces {
		t := asMap(tAny)
		k := traceKey(t["traceId"])
		// Python: if isinstance(t, dict) and t.get("traceId") is not None
		if k == "" {
			continue
		}
		// last-wins — mirrors Python by[t["traceId"]] = t (plain dict assign overwrites).
		// CodeSafe emits DUPLICATE traceIds (same id, different father/kind); the last
		// occurrence is often the sink (kind==1). First-wins would keep the earlier node,
		// mark the id seen via it, and silently drop the sink from the taint path → wrong
		// path_sig → wrong bughash + path_complete collapses. See TestCodeSafeFlattenDAGDupTraceIdLastWins.
		by[k] = t
	}
	children := map[string][]string{}
	var roots []string
	for _, tAny := range traces {
		t := asMap(tAny)
		tid := traceKey(t["traceId"])
		if tid == "" {
			continue
		}
		fid := traceKey(t["fatherTraceid"])
		if fid == "" || fid == "0" {
			roots = append(roots, tid)
		} else if _, ok := by[fid]; !ok {
			// father not in by → detached → treat as root (parity: Python `fid not in by`)
			roots = append(roots, tid)
		} else {
			children[fid] = append(children[fid], tid)
		}
	}

	order := []map[string]any{}
	seen := map[string]bool{}
	var walk func(tid string)
	walk = func(tid string) {
		if tid == "" || seen[tid] {
			return
		}
		t, ok := by[tid]
		if !ok {
			return
		}
		seen[tid] = true
		order = append(order, t)
		for _, c := range children[tid] {
			walk(c)
		}
	}
	for _, r := range roots {
		walk(r)
	}
	// Orphans: cycles / detached nodes not reached by DFS — append so none dropped.
	for _, tAny := range traces {
		t := asMap(tAny)
		tid := traceKey(t["traceId"])
		if tid == "" || seen[tid] {
			continue
		}
		order = append(order, t)
		seen[tid] = true
	}
	return order
}

// hop mirrors _hop: file/function/line/message. function is always "" (CodeSafe gives no
// per-trace method; honest, not bugFunc).
func hop(t map[string]any) map[string]any {
	return map[string]any{
		"file":     normPath(asString(t["bugFile"])),
		"function": "",
		"line":     intFromAny(t["codeBeginline"]),
		"message":  asString(t["codePart"]),
	}
}

// firstKind returns the first trace node in order with kind==k, else nil.
func firstKind(order []map[string]any, k int) map[string]any {
	for _, t := range order {
		if intFromAny(t["kind"]) == k {
			return t
		}
	}
	return nil
}

// anyKind reports whether any trace node in order has kind==k.
func anyKind(order []map[string]any, k int) bool {
	for _, t := range order {
		if intFromAny(t["kind"]) == k {
			return true
		}
	}
	return false
}

// CodeSafeAdapter parses a CodeSafe all_bugs.json dump (raw["bugs"]) into
// []contract.SASTResult. Reg is optional (*cwereg.Registry for CWE→slug resolution);
// nil degrades inferVulnType to slugify (mirrors Python slug_for_cwe→None fallback).
type CodeSafeAdapter struct {
	Reg *cwereg.Registry
}

func (CodeSafeAdapter) Capabilities() map[string]bool {
	// bugFunc gives the sink function; bugTraces give a real taint path; lines are exact.
	return map[string]bool{
		"guarantees_function_name": true,
		"guarantees_taint_path":    true,
		"guarantees_line_number":   true,
	}
}

func (a CodeSafeAdapter) Parse(raw map[string]any) ([]contract.SASTResult, error) {
	out := []contract.SASTResult{}
	if raw == nil {
		return out, nil
	}
	bugs := asSlice(raw["bugs"])
	for _, bugAny := range bugs {
		bug := asMap(bugAny)

		// traces: bugTraces || traces || []
		var traces []any
		if v := asSlice(bug["bugTraces"]); len(v) > 0 {
			traces = v
		} else {
			traces = asSlice(bug["traces"])
		}
		order := flattenDAG(traces)

		// source: kind==2 node; else order[0]; else bug-level (bugFile/bugBeginline/bugFunc).
		var source map[string]any
		if srcNode := firstKind(order, 2); srcNode != nil {
			source = map[string]any{
				"file":     normPath(asString(srcNode["bugFile"])),
				"line":     intFromAny(srcNode["codeBeginline"]),
				"function": "", // CodeSafe gives no per-trace method; honest, not bugFunc
				"variable": asString(srcNode["codePart"]),
			}
		} else if len(order) > 0 {
			source = hop(order[0])
		} else {
			source = map[string]any{
				"file":     normPath(asString(bug["bugFile"])),
				"line":     intFromAny(bug["bugBeginline"]),
				"function": asString(bug["bugFunc"]),
				"variable": "",
			}
		}

		// sink: bug-level bugFile/bugBeginline/bugFunc is the authoritative sink location.
		sink := map[string]any{
			"file":     normPath(asString(bug["bugFile"])),
			"line":     intFromAny(bug["bugBeginline"]),
			"function": asString(bug["bugFunc"]),
			"variable": "",
		}

		taintPath := make([]map[string]any, 0, len(order))
		for _, t := range order {
			taintPath = append(taintPath, hop(t))
		}
		pathComplete := anyKind(order, 2) && anyKind(order, 1)

		cweID := extractCWEBug(bug)
		vulnType := inferVulnTypeBug(a.Reg, asString(bug["ruleCode"]), asString(bug["ruleName"]), cweID)
		severity := severityBug(bug)

		// No function name for the source → src_id degrades to file#line; the full
		// taint-path shape (path_sig) disambiguates two flows into the same sink line
		// (same defense as CodeQL's no-function-name case, 铁律 D #6 collision class).
		bh := bughash.ComputeBughash(
			vulnType, cweID,
			asString(source["file"]), asString(source["function"]),
			asString(sink["file"]), asString(sink["function"]),
			"", "",
			intFromAny(source["line"]), intFromAny(sink["line"]),
			bughash.PathSignature(taintPath),
		)

		alertID := "codesafe-" + asString(bug["bugId"]) + "-" + asString(bug["bugFile"]) + ":" + strconv.Itoa(intFromAny(bug["bugBeginline"]))
		rawOut, _ := json.Marshal(bug)
		out = append(out, contract.SASTResult{
			AlertID:           alertID,
			Bughash:           bh,
			VulnerabilityType: vulnType,
			CweID:             cweID,
			Severity:          severity,
			Source:            source,
			Sink:              sink,
			TaintPath:         taintPath,
			TaintPathComplete: pathComplete,
			IsGenerated:       false,
			RawOutput:         json.RawMessage(rawOut),
		})
	}
	return out, nil
}
