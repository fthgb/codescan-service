package poc

import "strings"

// BuildBypassPayload ports poc.py:146. Renders the bypass witness as a
// reproducible HTTP request (reuses BuildAttackRequest route-inference).
// nil when witness is empty, narrative (contains a space), or no route.
// Only fills attack_request; caller never upgrades verdict (只降级不升 TP).
func BuildBypassPayload(sliced map[string]any, witness string) *string {
	if witness == "" || strings.Contains(witness, " ") {
		return nil
	}
	return BuildAttackRequest(sliced, witness)
}
