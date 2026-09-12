package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

type CweConfig struct {
	CweID                 string           `json:"cwe_id"`
	VulnerabilityType     string           `json:"vulnerability_type"`
	LongDesc              string           `json:"long_desc"`
	TaintModel            json.RawMessage  `json:"taint_model"`
	FilterHints           string           `json:"filter_hints"`
	Calibrated            bool             `json:"calibrated"`
	ConclusionTemplate    []string         `json:"conclusion_template"`
	RequiredDecisiveFacts []string         `json:"required_decisive_facts"`
	CweAliases            []string         `json:"cwe_aliases"`
	Signals               []map[string]any `json:"signals"`
	Adjacency             []string         `json:"adjacency"`
	AdjacentCheck         string           `json:"adjacent_check"`
}

// NormalizeFilterHints replicates appsec/state.py:_normalize_hint_lines.
// list -> ordered, NOT deduped, "\n".join("- "+item). string -> as-is.
func NormalizeFilterHints(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		parts := make([]string, 0, len(x))
		for _, it := range x {
			parts = append(parts, "- "+fmt.Sprint(it))
		}
		return strings.Join(parts, "\n")
	case []string:
		parts := make([]string, 0, len(x))
		for _, it := range x {
			parts = append(parts, "- "+it)
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

// UnmarshalCweConfig enforces extra="forbid" via DisallowUnknownFields, and runs the
// filter_hints before-validator (list|string -> string) by pre-parsing that one field.
func UnmarshalCweConfig(data []byte) (CweConfig, error) {
	// Pull filter_hints out first (it may be a list; the strict decode into `string` would fail).
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return CweConfig{}, err
	}
	var hints string
	if raw, ok := probe["filter_hints"]; ok {
		var anyv any
		if err := json.Unmarshal(raw, &anyv); err != nil {
			return CweConfig{}, err
		}
		// STRICT contract (state.py:7-9): accept ONLY a JSON string or JSON array.
		// Any other type is a loud error, not a silent coercion to "".
		switch anyv.(type) {
		case string, []any:
			hints = NormalizeFilterHints(anyv)
		default:
			return CweConfig{}, fmt.Errorf("cwe_config filter_hints must be string or list, got %T", anyv)
		}
		delete(probe, "filter_hints")
	}
	rest, _ := json.Marshal(probe)
	dec := json.NewDecoder(bytes.NewReader(rest))
	dec.DisallowUnknownFields()
	var c CweConfig
	if err := dec.Decode(&c); err != nil {
		return CweConfig{}, fmt.Errorf("cwe_config extra=forbid: %w", err)
	}
	c.FilterHints = hints
	// Python default cwe_id="UNKNOWN" (state.py:12): absent key -> "UNKNOWN", not zero-value "".
	if _, ok := probe["cwe_id"]; !ok {
		c.CweID = "UNKNOWN"
	}
	return c, nil
}

type AppContext struct {
	Exposure              *string        `json:"exposure"`
	SecurityModel         *string        `json:"security_model"`
	RequiresRemoteTrigger *bool          `json:"requires_remote_trigger"`
	IntendedBehaviors     []string       `json:"intended_behaviors"`
	NotAVulnerability     []string       `json:"not_a_vulnerability"`
	TrustBoundaries       map[string]any `json:"trust_boundaries"`
	Extra                 map[string]any `json:"-"`
}

// UnmarshalAppContext implements extra="allow" with EXACT-CASE key matching (parity with
// pydantic). Go's default struct unmarshal matches keys case-insensitively, which would both
// populate a named field AND leak the original-cased key into Extra. Routing keys manually
// keeps a case-mismatched key (e.g. "Exposure") ONLY in Extra, leaving the named field nil.
func UnmarshalAppContext(data []byte) (AppContext, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return AppContext{}, err
	}
	var out AppContext
	named := map[string]any{
		"exposure":                &out.Exposure,
		"security_model":          &out.SecurityModel,
		"requires_remote_trigger": &out.RequiresRemoteTrigger,
		"intended_behaviors":      &out.IntendedBehaviors,
		"not_a_vulnerability":     &out.NotAVulnerability,
		"trust_boundaries":        &out.TrustBoundaries,
	}
	extra := map[string]any{}
	for k, raw := range all {
		if ptr, ok := named[k]; ok { // exact-case only
			if err := json.Unmarshal(raw, ptr); err != nil {
				return AppContext{}, err
			}
		} else {
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				return AppContext{}, err
			}
			extra[k] = v
		}
	}
	out.Extra = extra
	return out, nil
}
