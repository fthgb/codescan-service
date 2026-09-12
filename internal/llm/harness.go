package llm

import (
	"context"
	"time"
)

// backoff mirrors anthropic_native._backoff (0.5/1/2s). Overridable in tests.
var backoffFn = func(attempt int) time.Duration {
	switch attempt {
	case 0:
		return 500 * time.Millisecond
	case 1:
		return time.Second
	default:
		return 2 * time.Second
	}
}

// SetBackoffForTest zeroes/overrides backoff so retry tests don't sleep. Test-only.
func SetBackoffForTest(f func(int) time.Duration) { backoffFn = f }

// Harness wraps a Provider with Layer A: empty-response retry (3 attempts, backoff)
// + thinking-budget-exhausted detection (raise, no retry). Runs on BOTH live and replay
// (recording is at SDK boundary = pre-harness, so the recorded Response is what Harness
// classifies). Mirrors anthropic_native.complete()/complete_with_tools() Layer A.
type Harness struct{ p Provider }

func NewHarness(p Provider) *Harness { return &Harness{p: p} }

func (h *Harness) SupportsTools() bool { return h.p.SupportsTools() }
func (h *Harness) Model() string      { return h.p.Model() }

// Complete runs the Layer A retry loop. Success/empty/exhausted classification is
// per-call-type (driven by req.Tools), faithful to Python's complete() (text path:
// tool_use-no-text retries) vs complete_with_tools (tool path: tool_use = success).
func (h *Harness) Complete(ctx context.Context, req Request) (Response, error) {
	toolPath := len(req.Tools) > 0
	for attempt := 0; attempt < 3; attempt++ { // _MAX_ATTEMPTS=3
		resp, err := h.p.Complete(ctx, req)
		if err != nil {
			return resp, err
		}
		// thinking exhausted (verbatim anthropic_native.py:216): HasThinking &&
		// stop_reason=="max_tokens" && no text && no tool_calls -> raise, NO retry.
		if resp.HasThinking && resp.StopReason == "max_tokens" && resp.Text == "" && len(resp.ToolCalls) == 0 {
			return resp, ErrThinkingBudgetExhausted
		}
		// success: text path has text; tool path has text OR tool_calls.
		if resp.Text != "" || (toolPath && len(resp.ToolCalls) > 0) {
			return resp, nil
		}
		// flaky empty (incl. text-path tool_use-no-text per 2026-07-18 fix) -> retry.
		if attempt < 2 {
			time.Sleep(backoffFn(attempt))
		}
	}
	return Response{}, ErrEmptyAfter3Attempts
}
