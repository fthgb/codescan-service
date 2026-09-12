package llm

import "errors"

// ErrThinkingBudgetExhausted mirrors anthropic_native.ThinkingBudgetExhausted:
// raised (NOT retried) when a thinking model spent all max_tokens on ThinkingBlock(s)
// and emitted no text/tool answer. Deterministic config error, not flaky.
var ErrThinkingBudgetExhausted = errors.New("thinking_budget_exhausted")

// ErrEmptyAfter3Attempts mirrors anthropic_native.complete() raising
// RuntimeError("empty LLM response after 3 attempts (model=...)") after _MAX_ATTEMPTS=3.
var ErrEmptyAfter3Attempts = errors.New("empty response after 3 attempts")
