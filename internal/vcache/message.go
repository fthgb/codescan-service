package vcache

import (
	"bytes"
	"encoding/json"
)

// Message is the minimal judge-prompt message struct. Field order = Python
// dict insertion order (Role → Content); json.Marshal emits fields in declared
// order, matching Python json.dumps dict-insertion order (key-ordering parity
// trap: Go map[string]any would sort keys alphabetically and break the SHA256).
// P5 extends with ToolCalls/ToolCallID as Python build_messages grows them.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// jsonMarshal ports Python json.dumps(v, ensure_ascii=False) with default
// separators (', ', ': '). Three parity traps handled:
//  1. Encoder.Encode appends '\n' → TrimRight.
//  2. SetEscapeHTML(false) → no <>& / U+2028 escaping (stdlib's only off-switch).
//  3. Go compact has no spaces → injectPythonSpaces adds ', '/': ' outside strings.
func jsonMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	b = injectPythonSpaces(b)
	return b, nil
}

// injectPythonSpaces adds a space after ':' and ',' OUTSIDE string literals,
// matching Python json.dumps default separators (', ', ': '). State machine
// tracking in-string + \" escapes. '{}' / empty unchanged.
func injectPythonSpaces(b []byte) []byte {
	var out bytes.Buffer
	inStr := false
	backslashes := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		out.WriteByte(c)
		if c == '\\' {
			backslashes++
			continue
		}
		if c == '"' {
			if backslashes%2 == 0 {
				inStr = !inStr
			}
			backslashes = 0
			continue
		}
		backslashes = 0
		if inStr {
			continue
		}
		if (c == ':' || c == ',') && i+1 < len(b) {
			out.WriteByte(' ')
		}
	}
	return out.Bytes()
}
