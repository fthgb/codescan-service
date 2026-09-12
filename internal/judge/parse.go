package judge

import (
	"appsecgo/internal/contract"
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"appsecgo/internal/llm"
	"appsecgo/internal/prompts"
)

// ErrParse mirrors prompts.ParseError (raised when no valid JSON found).
var ErrParse = errors.New("ParseError")

var fenceRe = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// ParseJudgeOutput mirrors prompts.py:parse_judge_output: 3-layer (direct / markdown
// fenced / brace scan). Raises ErrParse when no valid JSON.
func ParseJudgeOutput(text string) (map[string]any, error) {
	// Layer 1: direct
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err == nil {
		return obj, nil
	}
	// Layer 2: markdown fenced
	if m := fenceRe.FindStringSubmatch(text); m != nil {
		if err := json.Unmarshal([]byte(m[1]), &obj); err == nil {
			return obj, nil
		}
	}
	// Layer 3: brace scan (balanced first top-level object)
	depth, start := 0, -1
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 && start >= 0 {
				if err := json.Unmarshal([]byte(text[start:i+1]), &obj); err == nil {
					return obj, nil
				}
				start = -1
			}
		}
	}
	return nil, ErrParse
}

// RepairJSON mirrors prompts.py:repair_json: lenient salvage of truncated/malformed
// JSON. Bounded iteration: tail key no value -> ""/null; trailing comma deleted;
// unbalanced string/braces closed. Never raises. Returns nil if unrepairable.
//
// RE2 note: prompts.py used Python regex lookahead (?=...) for the
// key-no-value and trailing-comma rules. Go's regexp (RE2) rejects lookahead,
// so the same behavior is reproduced by CAPTURING the trailing delimiter and
// reinserting it in the replacement. Verified by TestRepairJSON.
func RepairJSON(s string) map[string]any {
	if s == "" {
		return nil
	}
	if obj, ok := tryParse(s); ok {
		return obj
	}
	repaired := s
	// keyNoValBracket: quoted key + ":" immediately before a close bracket -> insert "".
	// (RE2 rewrite of `("[^"]*")\s*:\s*(?=\s*[\}\]]|\z)` — capture the bracket, reinsert.)
	keyNoValBracket := regexp.MustCompile(`("[^"]*"\s*:\s*)([\}\]])`)
	// keyNoValEnd: quoted key + ":" at end-of-string -> insert "".
	// (RE2 rewrite of the `\z` branch of the same lookahead.)
	keyNoValEnd := regexp.MustCompile(`("[^"]*"\s*:\s*)$`)
	// trailComma: comma + whitespace before a close bracket -> delete the comma.
	// (RE2 rewrite of `,\s*(?=\s*[\}\]])` — capture the bracket, reinsert.)
	trailComma := regexp.MustCompile(`,\s*([\}\]])`)
	for i := 0; i < 8; i++ {
		next := keyNoValBracket.ReplaceAllString(repaired, `${1}""${2}`)
		next = keyNoValEnd.ReplaceAllString(next, `${1}""`)
		next = trailComma.ReplaceAllString(next, `${1}`)
		if next == repaired {
			break
		}
		repaired = next
		if obj, ok := tryParse(repaired); ok {
			return obj
		}
	}
	// last try: close unbalanced string + braces
	cand := repaired
	// count unescaped quotes
	quotes := 0
	for i := 0; i < len(cand); i++ {
		if cand[i] == '"' && (i == 0 || cand[i-1] != '\\') {
			quotes++
		}
	}
	if quotes%2 == 1 {
		cand += `"`
	}
	opens := countByte(cand, '{') - countByte(cand, '}')
	bracks := countByte(cand, '[') - countByte(cand, ']')
	if opens > 0 || bracks > 0 {
		for i := 0; i < opens; i++ {
			cand += "}"
		}
		for i := 0; i < bracks; i++ {
			cand += "]"
		}
		if obj, ok := tryParse(cand); ok {
			return obj
		}
	}
	return nil
}

func tryParse(s string) (map[string]any, bool) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(s), &obj); err == nil {
		return obj, true
	}
	return nil, false
}
func countByte(s string, b byte) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			n++
		}
	}
	return n
}

// NormalizeVerdictData mirrors judge.py:_normalize_verdict_data: unwrap the qwen
// {"raw_arguments":"<json str>"} deform + Layer1 RepairJSON. Normal shape passthrough.
// harness may be nil when no Layer2 needed.
func NormalizeVerdictData(data map[string]any, harness llm.Provider, model string) map[string]any {
	if data == nil {
		return data
	}
	if len(data) == 1 {
		if raw, ok := data["raw_arguments"].(string); ok {
			var obj map[string]any
			if err := json.Unmarshal([]byte(raw), &obj); err == nil {
				RecoverArgFramingInto(obj)
				return obj
			}
			if fixed := RepairJSON(raw); fixed != nil {
				RecoverArgFramingInto(fixed)
				return fixed
			}
			// Layer1 failed -> leave for Layer2 (RepairRetryRawArguments)
		}
	}
	RecoverArgFramingInto(data)
	return data
}

// RecoverArgFramingInto —— 微语法契约 I6 在 judge 侧的落地(解析器在 contract 层,单一权威)。
//
// 导出是因为 discovery(internal/discover)直接用 ParseJudgeOutput、不经 NormalizeVerdictData,
// 同样会被 I6 打到(它也读 suggested_fix/severity_rationale)。同一函数两处调用,不复制第二份。
//
// 为什么挂在 NormalizeVerdictData 而不是 ParseJudgeOutput:这里本就是「provider 异形归一」
// 那一处(已治 qwen 的 raw_arguments 变形),I6 是同一类损伤 —— provider 把自己的传输框架
// 漏进了载荷。放这里同时覆盖工具路径与文本路径(judge.go:445 是唯一调用点),且不会把
// judge 的字段名白名单误加到 falsify/discover 那两套不同 schema 上。
//
// 三条不覆盖原则:
//   - 拆出的 nullish 值直接丢弃 —— 不把字面 "null" 当真值补进字段(GR-8)。
//   - 已有真值的键绝不覆盖:只填「不存在」或「值本身是 nullish」的坑。
//   - 宿主字段一律写回剥净的值,即使一个字段都没拆出来 —— 否则框架标记会印进报告正文
//     (2026-08-22 实证:用户在 probe-core 报告里看到的 `<arg_value:6124c78e>` 正是此漏)。
func RecoverArgFramingInto(data map[string]any) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	for _, k := range keys {
		s, ok := data[k].(string)
		if !ok {
			continue
		}
		clean, rec := contract.RecoverArgFraming(s)
		if clean == s && rec == nil {
			continue
		}
		data[k] = clean
		for rk, rv := range rec {
			if contract.IsNullish(rv) {
				continue
			}
			// exists && cur != nil 才谈得上「已有值」—— JSON null 解出来是 nil interface,
			// 断言成 string 会失败,若把断言失败当「已有真值」就会把该填的坑全跳过
			// (2026-08-22 全量回放实测:19 条污染里 0 条被填,正是踩这里)。
			if cur, exists := data[rk]; exists && cur != nil {
				cs, isStr := cur.(string)
				if !isStr || !contract.IsNullish(cs) {
					continue // 已有真值,不动
				}
			}
			data[rk] = rv
		}
	}
}

// RepairRetryRawArguments mirrors judge.py:_repair_retry_raw_arguments (Layer 2):
// when raw_arguments JSON is too broken for Layer1 -> extra harness.Complete call
// (build_repair_messages; P5 threads the repair prompt — judge.py:812) -> parse+
// normalize. Still unparseable -> return original data (let BuildJudgeResult raise
// ErrParse -> fail-open).
func RepairRetryRawArguments(data map[string]any, harness llm.Provider, model string) map[string]any {
	raw, ok := data["raw_arguments"].(string)
	if !ok || raw == "" {
		if b, _ := json.Marshal(data); b != nil {
			raw = string(b)
		}
	}
	if harness == nil {
		return data
	}
	resp, err := harness.Complete(context.Background(), llm.Request{
		Messages: prompts.BuildRepairMessages(raw), MaxTokens: 8192,
	})
	if err != nil {
		return data // fail-open: leave original, BuildJudgeResult raises ErrParse
	}
	repaired2, perr := ParseJudgeOutput(resp.Text)
	if perr != nil {
		return data
	}
	norm := NormalizeVerdictData(repaired2, harness, model)
	if _, hasRaw := norm["raw_arguments"]; !hasRaw {
		return norm
	}
	return data
}
