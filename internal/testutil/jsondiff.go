// Package testutil holds test helpers shared across packages (judge, pipeline,
// gots) to avoid drifted duplicate JSON-diff implementations.
package testutil

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// AssertJSONEqual parses two JSON files and DeepEquals them, optionally
// dropping a set of non-deterministic keys (TOP-LEVEL ONLY — not recursive).
// Extracted VERBATIM from internal/pipeline/e2e_parity_test.go:231
// (assertJSONEqual + its mustJSON helper) — behavior is byte-identical so the
// existing e2e parity tests are unaffected. Uses t.Errorf (continues the test,
// does not abort), matching the original.
func AssertJSONEqual(t *testing.T, label, gotPath, wantPath string, exclude map[string]bool) {
	t.Helper()
	gotB, err := os.ReadFile(gotPath)
	if err != nil {
		t.Errorf("%s: read got %s: %v", label, gotPath, err)
		return
	}
	wantB, err := os.ReadFile(wantPath)
	if err != nil {
		t.Errorf("%s: read want %s: %v", label, wantPath, err)
		return
	}
	var got, want any
	if err := json.Unmarshal(gotB, &got); err != nil {
		t.Errorf("%s: parse got: %v", label, err)
		return
	}
	if err := json.Unmarshal(wantB, &want); err != nil {
		t.Errorf("%s: parse want: %v", label, err)
		return
	}
	// exclude (non-deterministic top-level keys) only applies to map values
	// (meta.json); alerts_input.json is an array → exclude is nil there.
	if exclude != nil {
		if gm, ok := got.(map[string]any); ok {
			for k := range exclude {
				delete(gm, k)
			}
		}
		if wm, ok := want.(map[string]any); ok {
			for k := range exclude {
				delete(wm, k)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s parity mismatch:\ngot =%s\nwant=%s", label, mustJSON(got), mustJSON(want))
	}
}

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
