package llm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// ErrReplayExhausted: ReplayProvider called more times than recorded (call-index drift).
var ErrReplayExhausted = errors.New("replay exhausted (more calls than recorded)")

type recordedCall struct {
	CallIndex   int              `json:"call_index"`
	Model       string           `json:"model"` // 录制的 model 名;Model() 返回它(replay 模式 cache/meta 一致)
	Tools       []map[string]any `json:"tools"`
	RawResponse struct {
		ContentBlocks []map[string]any `json:"content_blocks"`
		StopReason    string           `json:"stop_reason"`
		Usage         struct {
			In  int `json:"in"`
			Out int `json:"out"`
		} `json:"usage"`
	} `json:"raw_response"`
}

// ReplayProvider implements Provider by serving recorded SDK-boundary responses in
// call order. Ignores req content (messages were recorded; Go doesn't rebuild prompts
// in P2). Parses raw content_blocks via ExtractText/ExtractToolCalls/HasThinking so
// the response-side adapters are parity-covered.
type ReplayProvider struct {
	calls   []recordedCall
	idx     int
	support bool
}

func NewReplayProvider(jsonPath string) (*ReplayProvider, error) {
	f, err := os.Open(jsonPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rp := &ReplayProvider{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24) // large bodies
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rc recordedCall
		if err := json.Unmarshal(line, &rc); err != nil {
			return nil, fmt.Errorf("parse jsonl line: %w", err)
		}
		rp.calls = append(rp.calls, rc)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rp.calls) > 0 {
		rp.support = rp.calls[0].Tools != nil // SupportsTools = first call tools non-null
	}
	return rp, nil
}

func (r *ReplayProvider) SupportsTools() bool { return r.support }

// Model 返回首条录制调用的 model 名(replay 模式 cache key/meta 用;空录制返 "")。
func (r *ReplayProvider) Model() string {
	if len(r.calls) > 0 {
		return r.calls[0].Model
	}
	return ""
}

func (r *ReplayProvider) Complete(_ context.Context, _ Request) (Response, error) {
	if r.idx >= len(r.calls) {
		return Response{}, ErrReplayExhausted
	}
	rc := r.calls[r.idx]
	r.idx++
	blocks := rc.RawResponse.ContentBlocks
	return Response{
		Text:        ExtractText(blocks),
		ToolCalls:   ExtractToolCalls(blocks),
		StopReason:  rc.RawResponse.StopReason,
		Usage:       Usage{InputTokens: rc.RawResponse.Usage.In, OutputTokens: rc.RawResponse.Usage.Out},
		HasThinking: HasThinking(blocks),
	}, nil
}
