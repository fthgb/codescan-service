package vcache

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Key ports judge.py:784-789: sha256(jsonMarshal(messages) + "\x00" + model +
// "\x00" + logicVersion). Callers pass []Message (ordered) — never []map[string]any
// (Go map iteration is non-deterministic + Marshal sorts keys → parity breaks).
func Key(messages []Message, model, logicVersion string) string {
	rawBytes, _ := jsonMarshal(messages)
	raw := string(rawBytes) + "\x00" + model + "\x00" + logicVersion
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Cacheable ports judge.py:927-930. Only caches reproducible verdicts
// (success / contract-guard rejection); NOT flaky ParseError / empty_slice
// (prevents "first accidental error → permanent wrong cache" deadlock).
func Cacheable(failReason *string) bool {
	fr := ptrStr(failReason)
	return fr == "" ||
		strings.HasPrefix(fr, "decisive_fact_unknown:") ||
		strings.HasPrefix(fr, "bare_fp_buries_actual:")
}

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
