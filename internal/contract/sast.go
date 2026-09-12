package contract

import "encoding/json"

type SASTResult struct {
	AlertID           string           `json:"alert_id"`
	Bughash           string           `json:"bughash"`
	VulnerabilityType string           `json:"vulnerability_type"`
	CweID             string           `json:"cwe_id"`
	Severity          string           `json:"severity"`
	Source            map[string]any   `json:"source"`
	Sink              map[string]any   `json:"sink"`
	TaintPath         []map[string]any `json:"taint_path"`
	TaintPathComplete bool             `json:"taint_path_complete"`
	IsGenerated       bool             `json:"is_generated"`
	RawOutput         json.RawMessage  `json:"raw_output"`
}

type ExploitPath struct {
	EntryPoint            string   `json:"entry_point"`
	DataFlow              []string `json:"data_flow"`
	SinkReached           bool     `json:"sink_reached"`
	AttackerControlAtSink string   `json:"attacker_control_at_sink"`
	PathBrokenAt          *string  `json:"path_broken_at"`
	// TaintSource is the LLM-emitted structured taint source truth
	// (code/location): the birth point of the attacker-controlled data
	// (e.g. entry.getName(), an @RequestParam), NOT the call-chain entry
	// (that's EntryPoint). nil = absent / not applicable (missing-auth
	// class) / LLM couldn't ground it. Mirrors SinkEvidence
	// (map[string]any, not a typed struct) so prompt/tool-schema/parse
	// move as one JSON blob. Rendered by the report as the head of the
	// Source→flow→Sink chain (2026-09-07 根因报告 §8).
	TaintSource *map[string]any `json:"taint_source,omitempty"`
	// SinkEvidence is the LLM-emitted structured sink truth (sink_code/sink_location/
	// method_key/source_tool/param_style). nil = absent. The render layer consumes
	// this first-class before reverse-looking-up tool_log reachable_sinks (arc ②).
	// Mirrors DecisiveCheck (map[string]any, not a typed struct) so prompt/tool-schema/
	// parse move as one JSON blob. NOT read by the grounding gate (that's a separate arc).
	SinkEvidence *map[string]any `json:"sink_evidence"`
}

func GetStr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func GetInt(m map[string]any, k string) int {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
