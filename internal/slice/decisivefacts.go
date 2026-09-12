package slice

import (
	"regexp"
	"strings"

	"appsecgo/internal/contract"
)

// decisivefacts.go ports appsec/decisive_facts.py + the two appsec/verify.py
// helpers it reuses (single source, 铁律 D): classify_sink_param_style +
// _executor_visible + _is_mybatis_mapper_context. P3 verify will reuse the
// regexes/helpers here rather than re-porting them, so the probe layer and
// the contract-decisive-fact layer never drift apart.
//
// Parity: the regexes and the if-chain order are copied verbatim from the
// Python source. RE2 \w/\b are ASCII-only; Python re is Unicode-aware by
// default — placeholder names, Java API names, and MyBatis tags are all
// ASCII identifiers, so the two match on every reachable input. CJK
// placeholder names are not a real case (documented asymmetry, same as 2a).
//
// ③ (2026-08-31): the #{}-only branch deviates from Python — Go returns
// "parameterized" for #{} in a MyBatis mapper context (framework contract),
// Python returned "unknown". Python is deprecated/non-authoritative (CLAUDE.md);
// this is a Go-自主 semantic correction (GR-5: verdict accuracy > parity).
// spec 2026-08-31-sink-param-style-mybatis-semantic-fix-design.md §1/§7.

var (
	// ConcatPlaceholderRe / ParamPlaceholderRe — MyBatis ${} raw string
	// substitution vs #{} parameterized placeholder. Exported so internal/verifier
	// (inc27 probe) reuses the single source (铁律 D: slicer 与 probe 不漂移).
	ConcatPlaceholderRe = regexp.MustCompile(`\$\{(\w+)\}`)
	ParamPlaceholderRe  = regexp.MustCompile(`#\{(\w+)\}`)
	// _executor_visible: prepared is checked BEFORE raw_concat (Python if-order).
	preparedExecutorRe  = regexp.MustCompile(`\bprepareStatement\b|\.setString\s*\(`)
	rawConcatExecutorRe = regexp.MustCompile(`\bcreateStatement\b|\.execute\s*\(|createNativeQuery`)
	// _is_mybatis_mapper_context: file ends .xml OR body has a MyBatis tag.
	mybatisTagRe = regexp.MustCompile(`<(?:select|insert|update|delete|foreach|if|bind|where|set)\b`)
)

// hopBodies ports decisive_facts._hop_bodies: join all hop function bodies
// with "\n". classify scans the joined bodies for placeholder/executor signals.
func hopBodies(s *contract.SlicedContext) string {
	parts := make([]string, len(s.Hops))
	for i, h := range s.Hops {
		parts[i] = h.FunctionBody
	}
	return strings.Join(parts, "\n")
}

// executorVisible ports verify._executor_visible. Order-sensitive: prepared is
// checked before raw_concat (matches Python's if-chain). Returns one of
// "prepared" / "raw_concat" / "none".
func executorVisible(s *contract.SlicedContext) string {
	bodies := hopBodies(s)
	if preparedExecutorRe.MatchString(bodies) {
		return "prepared"
	}
	if rawConcatExecutorRe.MatchString(bodies) {
		return "raw_concat"
	}
	return "none"
}

// isMybatisMapperContext ports verify._is_mybatis_mapper_context: true if any
// hop's file_path ends in .xml OR its body contains a MyBatis tag. In such a
// context ${} is by definition raw string substitution (raw concat), not
// "unverifiable" — the old not_verifiable was over-conservative and starved
// correct TPs (2026-07-28 jshERP ORDER BY case).
func isMybatisMapperContext(s *contract.SlicedContext) bool {
	for _, h := range s.Hops {
		if strings.HasSuffix(h.FilePath, ".xml") || mybatisTagRe.MatchString(h.FunctionBody) {
			return true
		}
	}
	return false
}

// classifySinkParamStyle ports decisive_facts.classify_sink_param_style.
// Returns "" for not-applicable (Python None) — "" is never a valid style, so
// it is a safe sentinel. The caller fills decisive_facts only on non-empty:
//   - "concat"        — ${} in a MyBatis mapper XML, OR ${} with a visible
//     raw-concat executor (Statement.execute / createNativeQuery).
//   - "parameterized" — #{} in a MyBatis mapper context (framework
//     PreparedStatement; executor in org.apache.ibatis not slice-reachable
//     but contract-guaranteed), OR #{} with a visible prepared executor
//     (PreparedStatement / setString). ③ (2026-08-31) added the mapper-context
//     early-return — was "unknown" before (Python parity, now superseded).
//   - "unknown"       — applicable but unresolved: ${} without mapper context
//     and without raw-concat executor, OR #{} without mapper context AND
//     without a visible prepared executor. The contract guard rejects a
//     non-uncertain verdict here.
//   - ""              — not applicable: no MyBatis placeholder signal at all
//     (Java-native SQLi etc.). Not filled → guard no-op → AI explores free.
func classifySinkParamStyle(s *contract.SlicedContext) string {
	bodies := hopBodies(s)
	hasConcat := ConcatPlaceholderRe.MatchString(bodies)
	hasParam := ParamPlaceholderRe.MatchString(bodies)
	if !hasConcat && !hasParam {
		return "" // not applicable (None) — guard no-op, AI explores free
	}
	if hasConcat {
		if isMybatisMapperContext(s) || executorVisible(s) == "raw_concat" {
			return "concat"
		}
		return "unknown"
	}
	// only hasParam (#{}). MyBatis #{} is framework PreparedStatement binding
	// (org.apache.ibatis generates PreparedStatement); the executor is never
	// slice-reachable, but the framework contract guarantees parameterization.
	// Go 自主语义修正 (③, 2026-08-31): Python 返 "unknown"(executor 不可见即
	// not_verifiable),但 Python 已废弃非权威(CLAUDE.md);Go 据 MyBatis 契约判
	// parameterized(语义正确性,GR-5)。spec 2026-08-31-sink-param-style-mybatis-semantic-fix-design.md §1。
	if isMybatisMapperContext(s) {
		return "parameterized"
	}
	if executorVisible(s) == "prepared" {
		return "parameterized"
	}
	return "unknown"
}
