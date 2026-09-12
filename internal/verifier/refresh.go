package verifier

import (
	"appsecgo/internal/slice"
)

// sinkParamStyleGate mirrors config.SLICE_SINK_PARAM_STYLE (spec §0, default "on").
const sinkParamStyleGate = "on"

// classifySinkParamStyleMap mirrors slice.classifySinkParamStyle (decisivefacts.go:85)
// but in map form, reusing this package's map-based hopBodies/ExecutorVisible/
// isMybatisMapperContext (P3 helpers.go, parity green). "" = not applicable
// (Python None); "concat"/"parameterized"/"unknown".
func classifySinkParamStyleMap(sliced map[string]any) string {
	bodies := hopBodies(sliced)
	hasConcat := slice.ConcatPlaceholderRe.MatchString(bodies)
	hasParam := slice.ParamPlaceholderRe.MatchString(bodies)
	if !hasConcat && !hasParam {
		return ""
	}
	if hasConcat {
		if isMybatisMapperContext(sliced) || ExecutorVisible(sliced) == "raw_concat" {
			return "concat"
		}
		return "unknown"
	}
	// only hasParam (#{}). MyBatis #{} = framework PreparedStatement(同 decisivefacts.go
	// classifySinkParamStyle #{}-only 分支)。③ (2026-08-31): mapper context 内 #{} ->
	// parameterized(契约绑定,执行器非切片可见);was "unknown" before ③。spec §2。
	if isMybatisMapperContext(sliced) {
		return "parameterized"
	}
	if ExecutorVisible(sliced) == "prepared" {
		return "parameterized"
	}
	return "unknown"
}

// RefreshSinkParamStyle ports _refresh_sink_param_style (judge.py:278-296).
// After promotion, re-runs classify to refresh decisive_facts["sink_param_style"].
// Python None (Go "") -> remove key. Fail-open: any panic silently skipped.
// Python setdefault semantics: decisive_facts key always present after refresh
// (missing/non-map -> set to {}, else reuse existing; always written back).
func RefreshSinkParamStyle(sliced map[string]any) {
	defer func() { recover() }() // fail-open (铁律 D)
	if sinkParamStyleGate != "on" {
		return
	}
	style := classifySinkParamStyleMap(sliced)
	df, _ := sliced["decisive_facts"].(map[string]any)
	if df == nil {
		df = map[string]any{}
	}
	if style == "" {
		delete(df, "sink_param_style")
	} else {
		df["sink_param_style"] = style
	}
	sliced["decisive_facts"] = df
}
