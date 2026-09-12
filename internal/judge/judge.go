package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"appsecgo/internal/agentic"
	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
	"appsecgo/internal/funcdistill"
	"appsecgo/internal/llm"
	"appsecgo/internal/poc"
	"appsecgo/internal/prompts"
	"appsecgo/internal/slice"
	"appsecgo/internal/stratreg"
	"appsecgo/internal/taintbridge"
	"appsecgo/internal/vcache"
	"appsecgo/internal/verifier"
)

// judgeViaToolOrText's tool path uses agentic.VerdictTool (the full
// submit_verdict schema, prompts.py:_VERDICT_TOOL). P5: schema is now complete;
// messages threading lands in Task 6 (replay ignores req.Tools, zero-regression).

const (
	maxConfidence = 10
	llmMaxTokens  = 8192 // config.LLM_MAX_TOKENS
	// logicVersion cross-language-isolates the Go verdict_cache key space from
	// Python's "v3" cache (design §4.4): same messages+model but different version
	// suffix → different sha256, constructive non-collision so a shared prod db
	// never serves a Python-cached verdict to Go (or vice-versa).
	logicVersion = "go-parity-v2"
)

// toVcacheMessages adapts build_messages output ([{role,content}]) to
// []vcache.Message for the cache key. build_messages produces only string-content
// system+user messages (no tool_calls/tool_call_id), so Role+Content capture the
// full key material. vcache.jsonMarshal(Message) byte-matches Python
// json.dumps({"role":...,"content":...}) (P3 injectPythonSpaces parity).
func toVcacheMessages(messages []map[string]any) []vcache.Message {
	out := make([]vcache.Message, 0, len(messages))
	for _, m := range messages {
		role, _ := m["role"].(string)
		content, _ := m["content"].(string)
		out = append(out, vcache.Message{Role: role, Content: content})
	}
	return out
}

// judgeViaToolOrText mirrors judge.py:judge_via_tool_or_text. P4 adds the agentic
// explore branch (judge.py:552-630) at the TOP, falling through to the existing
// single-turn tool/text path on any failure (loop nil→forced→forced-fail→single-turn;
// panic→tool_error→single-turn — never hard-fails). Returns (data, info, err).
//
// info carries ALL Python keys (judge.py:554-556): tool_used, tool_turns, llm_raw_response,
// json_repaired, judge_agentic, findings, budget_used, missing_info, tool_log. info→trace
// (not parity-compared) but kept faithful.
func judgeViaToolOrText(messages []map[string]any, harness llm.Provider, model string, temp *float64, repoIndex *slice.RepositoryIndex, vulnType string, sliced map[string]any, engine taintbridge.EngineQuerier) (map[string]any, map[string]any, error) {
	info := map[string]any{
		"tool_used": false, "tool_turns": 0, "llm_raw_response": nil,
		"json_repaired": false, "judge_agentic": false,
		"findings": []map[string]any{}, "budget_used": map[string]any{},
		"missing_info": nil, "tool_log": []map[string]any{},
	}
	if agenticExploreActive(harness, repoIndex) {
		// agenticJudge mutates info in place; non-nil verdictArgs = success (return),
		// nil = forced-convergence failed OR panic caught → fall through to single-turn.
		if verdictArgs := agenticJudge(messages, harness, model, vulnType, repoIndex, info, sliced, engine); verdictArgs != nil {
			return verdictArgs, info, nil
		}
		// nil → fall through to single-turn tool/text path (never hard-fail)
	}
	// —— single-turn tool/text path (P2, unchanged) ——
	tempCopy := temp // tool path: nil (thinking forces temp=1); text path: temp.
	if harness.SupportsTools() {
		resp, err := harness.Complete(context.Background(), llm.Request{
			Messages: messages, MaxTokens: llmMaxTokens,
			Tools: []map[string]any{agentic.VerdictTool}, ToolChoice: "auto",
		}) // Temperature nil on tool path (anthropic_native.py:635-638)
		if err == nil {
			// select the submit_verdict tool call (NOT [0] — name filter, judge.py:642)
			for _, c := range resp.ToolCalls {
				if c.Name == "submit_verdict" {
					info["tool_used"] = true
					info["llm_raw_response"] = jsonString(c.Arguments)
					return c.Arguments, info, nil
				}
			}
			// model skipped tool / no submit_verdict -> fall through to text
		}
		// (err != nil: tool path errored -> fall through to text, mirroring Python's
		// except+continue. tool_error trace not kept — YAGNI for P2 parity.)
	}
	// text fallback (complete DOES pass temperature)
	resp, err := harness.Complete(context.Background(), llm.Request{
		Messages: messages, MaxTokens: llmMaxTokens, Temperature: tempCopy,
	})
	if err != nil {
		return nil, info, err
	}
	info["llm_raw_response"] = resp.Text
	data, perr := ParseJudgeOutput(resp.Text)
	if perr == nil {
		return data, info, nil
	}
	// call B: repair unparseable text (judge.py:673). messages = build_repair_messages(rawA).
	resp2, err2 := harness.Complete(context.Background(), llm.Request{
		Messages:  prompts.BuildRepairMessages(resp.Text),
		MaxTokens: llmMaxTokens, Temperature: tempCopy,
	})
	if err2 != nil {
		return nil, info, err2
	}
	info["llm_raw_response"] = resp2.Text
	info["json_repaired"] = true
	data, perr2 := ParseJudgeOutput(resp2.Text)
	if perr2 != nil {
		return nil, info, fmt.Errorf("%w: no valid JSON in LLM output after repair", ErrParse)
	}
	return data, info, nil
}

// agenticExploreActive mirrors _agentic_explore_active (judge.py:537-557) on the
// default-on path: MODE=on is moot (P4 default-on), so the gate is just
// repoIndex != nil && SupportsTools. nil repoIndex MUST short-circuit false so the
// P2 callers passing nil never enter the agentic loop (zero-regression).
func agenticExploreActive(harness llm.Provider, repoIndex *slice.RepositoryIndex) bool {
	if repoIndex == nil {
		return false
	}
	return harness.SupportsTools()
}

// buildLoopMessages 装载 Layer A 软注记（PrejudgeCalleeReachability +
// RenderAuthzNote）注入 loopMessages。无注记 → 返原 messages（alias，
// parity：replay 不进 agenticJudge → 不跑 → 不注入 → prompt_golden 字节同 →
// cache key 不变）。有注记 → copy + append（不 mutate 原 messages）。
// 注入在 BuildMessages 之后 → prompt_golden/messages 不动。authz 事实由
// ComputeAuthzCoverage 在 JudgeOne sr.Select 之前写入 sliced（A1 §1.1），此处只读。
func buildLoopMessages(messages []map[string]any, sliced map[string]any, exec *agentic.ToolExecutor) []map[string]any {
	var extra []map[string]any
	if note := agentic.PrejudgeCalleeReachability(sliced, exec); note != "" {
		extra = append(extra, map[string]any{"role": "user", "content": note})
	}
	if note := agentic.RenderAuthzNote(sliced); note != "" {
		extra = append(extra, map[string]any{"role": "user", "content": note})
	}
	// upload 三分支事实固化(P1-1):占 uncertain 缺口 73%,三个问题固定却每次让模型自由重问。
	// 注记只陈述**已确认存在**的事实,未列出的分支表示未确定而非已排除(见 RenderUploadNote 红线)。
	if note := agentic.RenderUploadNote(sliced); note != "" {
		extra = append(extra, map[string]any{"role": "user", "content": note})
	}
	if len(extra) == 0 {
		return messages
	}
	return append(append([]map[string]any{}, messages...), extra...)
}

// agenticJudge runs the agentic explore loop + forced-convergence fallback
// (judge.py:560-630). Mutates info in place. Returns verdictArgs: non-nil = success
// (caller returns), nil = fall through to single-turn path. A panic anywhere inside
// (forced-convergence message-building, a type assertion, ...) is caught: info gets
// tool_error + judge_agentic=true, returns nil (never propagates — fall through).
// The loop itself + executor have their own defer-recover; harness.Complete returns
// errors not panics — this guard covers the surrounding glue (faithful to Python's
// try/except around the whole agentic block).
func agenticJudge(messages []map[string]any, harness llm.Provider, model, vulnType string, repoIndex *slice.RepositoryIndex, info map[string]any, sliced map[string]any, engine taintbridge.EngineQuerier) (verdictArgs map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			info["tool_error"] = fmt.Sprintf("%v", r)
			info["judge_agentic"] = true
			verdictArgs = nil
		}
	}()
	exec := agentic.NewToolExecutor(repoIndex, nil, "", nil) // judge explore 不蒸馏，走 off 路径
	exec.SetEngineQuery(engine)                              // NEW: nil → 引擎工具 off（零回归）
	// Phase 1 (root-2 裸名消歧, disambiguation spec §4): alert sink file (codesafe bugFile,
	// realJudgeAlert 从 a.Sink["file"] 注入 sliced["sink_file"]) → exec.alertSinkFile。LLM 不传
	// file_path 时 resolveMethodKey 兜底消歧 (component.submit 而非 controller.submit)。off 路径
	// (engine==nil) resolveMethodKey 早返不读 → 无效;on 路径仅 LLM 不传 file_path 时启用。
	if sf, ok := sliced["sink_file"].(string); ok && sf != "" {
		exec.SetAlertSinkFile(sf)
	}
	// Layer A: loop 前预判软注记。PrejudgeCalleeReachability（可达性）+
	// RenderAuthzNote（鉴权覆盖，读 ComputeAuthzCoverage 在 JudgeOne 写的 struct，
	// missing-auth 事实固化 §6.3 / A1 §1.2）注入 loopMessages（独立 user 消息，
	// role=user；BuildMessages 之后 → 不碰 prompt_golden → parity 不破）。
	loopMessages := buildLoopMessages(messages, sliced, exec)
	// P0-a §4(a): Prejudge（buildLoopMessages 内 :147 副作用）写 forward_reachable struct 后，
	// 映射三态 → decisive_facts["forward_reachable"]（guard :474 读 "unknown" fire，D2 复用既有触发）。
	// §4(b)+§4(f) 已落：cwe_registry required_decisive_facts 含 forward_reachable → guard 读 "unknown" fire 生效（非 dormant）；config DecisiveFactRejudgeMode="on" → fact-unknown 时 rejudge 调 RefreshForwardReachable drain Uncertain→Definitive。
	// BuildJudgeResult 不覆写 decisive_facts（build.go 无写），RefreshSinkParamStyle 只填
	// sink_param_style → forward_reachable 写入存活至 :474 guard 读。
	if fr, ok := sliced["forward_reachable"].(map[string]any); ok {
		if v := slice.MapForwardReachable(fr); v != "" {
			df, _ := sliced["decisive_facts"].(map[string]any)
			if df == nil {
				df = map[string]any{}
				sliced["decisive_facts"] = df
			}
			df["forward_reachable"] = v
		}
	}
	// P5: real build_messages prompt (replaces the P4 stub {"role":"user","content":"judge"}).
	// ReplayProvider ignores messages; live AnthropicProvider sends them. The loop returns
	// finalMessages (6th return) — forced-convergence MUST build on those, not the input
	// messages, for faithfulness (Python mutates messages in place across turns).
	finishArgs, finalMessages, turns, findings, budget, toolLog := agentic.RunPlanSolveReActLoop(
		loopMessages, harness, model, exec.JudgeTools(), exec, vulnType, "submit_verdict", llmMaxTokens)
	// P7 rejudge 需要第一次 explore loop 的完整对话历史（Python messages mutate 后等价物）。
	// copy 防 forced convergence 的 append mutate（line 173 append(finalMessages, ...)）。
	info["final_messages"] = append([]map[string]any{}, finalMessages...)
	info["judge_agentic"] = true
	info["tool_turns"] = turns
	info["findings"] = findings
	info["budget_used"] = budget
	info["tool_log"] = toolLog
	if finishArgs != nil {
		info["tool_used"] = true
		info["llm_raw_response"] = jsonString(finishArgs)
		disp := strOr(finishArgs, "disposition", strOr(finishArgs, "verdict", ""))
		if VerdictOf(disp) == "uncertain" {
			setRemainingGap(info, finishArgs) // Python verdict_args.get("remaining_gap")
		}
		return finishArgs
	}
	// nil → forced-convergence (judge.py:605-626): append ForcedConvergenceProse to the
	// loop's finalMessages (NOT the stub), one more Complete call offering ONLY
	// submit_verdict. 2026-09-07 机制化（spec 2026-09-07-prompt-noise-convergence-
	// taintsource-design §三.1）：ToolChoice 首选 "required" —— 唯一工具就是 submit_verdict，
	// tool_choice=required 时端点机制上必须回一个工具调用，"forced-verdict returned no
	// submit_verdict call"（133953/8ea8 uncertain 直接成因）在协议层不可能再发生。
	// required 被网关拒（400 等非 nil err）→ 退 "auto" 重试一次再放弃（不因机制升级丢判定；
	// anthropic provider thinking-on 已有 required→auto 的优雅降级，两 provider 均合法）。
	forcedMsgs := append(finalMessages, map[string]any{"role": "user", "content": agentic.ForcedConvergenceProse})
	forced := func(choice string) (llm.Response, error) {
		return harness.Complete(context.Background(), llm.Request{
			Messages: forcedMsgs, MaxTokens: llmMaxTokens,
			Tools: []map[string]any{agentic.VerdictTool}, ToolChoice: choice,
		})
	}
	resp, ferr := forced("required")
	if ferr != nil {
		resp, ferr = forced("auto")
	}
	if ferr != nil {
		info["tool_error"] = "forced-verdict: " + ferr.Error()
		return nil
	}
	for _, c := range resp.ToolCalls {
		if c.Name == "submit_verdict" {
			info["tool_used"] = true
			info["tool_turns"] = turns + 1
			info["llm_raw_response"] = jsonString(c.Arguments)
			disp := strOr(c.Arguments, "disposition", strOr(c.Arguments, "verdict", ""))
			if VerdictOf(disp) == "uncertain" {
				setRemainingGap(info, c.Arguments)
			}
			return c.Arguments
		}
	}
	info["tool_error"] = "forced-verdict returned no submit_verdict call"
	return nil
}

// jsonString marshals v to a compact JSON string. Faithful stand-in for Python
// json.dumps(verdict_args, ensure_ascii=False) (trace-only field, not parity-compared;
// json.Marshal is HTML-escaped but that is irrelevant for a trace string). Falls back
// to fmt.Sprintf on marshal error (should not happen for tool args).
func jsonString(v any) string {
	// Python json.dumps(args, ensure_ascii=False) 风格（judge.py:596/449）：
	// separators (", ", ": ") + 不转义 HTML + 不转义非 ASCII（中文保留原文）。
	// 注意：与 agentic/loop.go pythonJSON 不同——后者用于 prompt_sent arguments
	// （写 trace 时 Python json.dumps 默认 ensure_ascii=True 转义），而 llm_raw_response
	// Python 显式用 ensure_ascii=False（不转义）。Go json.Marshal 默认 SetEscapeHTML(true)
	// 转 \u003c/\u003e/\u0026；用 Encoder 关闭。非 ASCII 保留原文（不转义）。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprintf("%v", v)
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	// Go compact 用 (",", ":")；Python json.dumps 用 (", ", ": ")。stateful 遍历在
	// 字符串外结构字符 ,/: 后加空格，匹配 Python byte-shape（不破坏字符串内容）。
	// 字符串内非 ASCII 保留原文（ensure_ascii=False，匹配 Python judge.py:596）。
	out := make([]byte, 0, len(b)+16)
	inStr, escaped := false, false
	for _, c := range b {
		if escaped {
			out = append(out, c)
			escaped = false
			continue
		}
		if c == '\\' {
			out = append(out, c)
			escaped = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			out = append(out, c)
			continue
		}
		if !inStr && (c == ',' || c == ':') {
			out = append(out, c, ' ')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// setRemainingGap lifts args["remaining_gap"] (string) into info["missing_info"] when
// present. Python verdict_args.get("remaining_gap") -> None if absent; only called when
// VerdictOf(disp) == "uncertain" (judge.py:570, :623). Non-string/absent -> leave nil.
func setRemainingGap(info, args map[string]any) {
	if rg, ok := args["remaining_gap"].(string); ok {
		info["missing_info"] = rg
	}
}

// missingInfoFrom lifts info["missing_info"] to *string (Python result.missing_info =
// tool_info.get("missing_info"); None/"" -> nil). Set BEFORE the guards (judge.py:831);
// guards may OVERWRITE MissingInfo on downgrade (that's faithful — Python order).
func missingInfoFrom(info map[string]any) *string {
	if mi, ok := info["missing_info"].(string); ok && mi != "" {
		return &mi
	}
	return nil
}

// JudgeOne mirrors judge.py:judge_one single-round + pure guards + P4 agentic
// promotion/refresh. Order faithful to judge.py:828-887:
//
//	Build → MissingInfo → PromoteAgenticXmlToSlice → RefreshSinkParamStyle →
//	EnforceDecisiveFactKnown → EnforceNoBareFp → VerifyVerdict → BuildAttackRequest
//
// (rejudge_*/falsify/dynamic are gated-off default-on — P5). nil repoIndex →
// agenticExploreActive=false → single-turn path (P2 zero-regression).
// P5: resolve cfg/secondary/allCfgs via cwereg, build_messages prompt, thread
// messages through every harness.Complete (tool path / text A / text B repair /
// agentic loop / forced-convergence). store!=nil enables verdict_cache (Task 7);
// parity tests pass nil (cache bypass, zero-regression).
// Returns (result, trace, err): err != nil means a fail-open trigger was hit; callers
// use JudgeOneFailOpen for the fail-open uncertain result (parity compares against golden).
func JudgeOne(sliced, appCtx map[string]any, harness llm.Provider, reg *cwereg.Registry, model string, temp *float64, repoIndex *slice.RepositoryIndex, store *vcache.Store, rejudgeMode string, summaryStore *funcdistill.FunctionSummaryStore, verifyMode string, dynamicVerifyMode string, engine taintbridge.EngineQuerier, stratReg ...*stratreg.Registry) (contract.JudgeResult, map[string]any, error) {
	// P5: resolve cfg/secondary/allCfgs (judge.py:701-714) + build_messages（在 trace
	// 初始化前，对齐 Python judge.py:713→716 顺序——trace.prompt_sent = messages）。
	vulnType, _ := sliced["vulnerability_type"].(string)
	cfg, _ := resolveCfg(reg, vulnType, sliced) // A (915 arc): numeric vuln_type → cwe_id→slug fallback; see resolve_cfg.go
	secondary := filterSecondary(reg.ConfigsForSlugs(reg.ImplicatedSinkTypes(sliced, vulnType)))
	allCfgs := reg.AllConfigs()
	agenticOn := agenticExploreActive(harness, repoIndex)
	// A1: 事实驱动 strategy 视角。ComputeAuthzCoverage 前移到 Select 之前，写
	// sliced["authz_coverage"]（无渲染层 → messages/cache key 不含 → parity 稳；
	// repoIndex=nil → no-op）。Select 的 authz_none trigger 读此事实 fire missing_auth。
	agentic.ComputeAuthzCoverage(sliced, repoIndex)
	// upload 三分支事实固化(P1-1),同位置同口径:无渲染层耦合,repoIndex=nil / 非上传流 → no-op。
	agentic.ComputeUploadDisposition(sliced, repoIndex, engine)
	// ③-e 2b: strategy 评估视角（filed-CWE 错类补正）。stratReg variadic nil-safe：
	// nil（parity/trace 测试传 0 变参）→ Select 返 nil（Step 1 nil gate）→
	// strategyLayer 空串 → BuildMessages 字节不变（parity 第二道锁）。生产 main.go
	// 传真 registry → general 等 strategy 上桌，凭切片 token 驱动，非 filed CWE 绑死。
	var sr *stratreg.Registry
	if len(stratReg) > 0 {
		sr = stratReg[0]
	}
	strategies := sr.Select(sliced, vulnType)
	// engineOn：engine 接入则 BuildMessages 追加 EngineToolsSuffix（覆盖 AgenticSuffix
	// 的 read_file-MyBatis 指令，引导 LLM 用 reachable_sinks）。engine==nil → off，不追加。
	engineOn := engine != nil
	messages := prompts.BuildMessages(sliced, appCtx, cfg, secondary, allCfgs, strategies, agenticOn, engineOn)

	// trace 初始化对齐 Python judge.py:716-748（25 字段 + cached 主路径）。timing 用变量
	// 避免反复类型断言；tStart 计 total_ms（parity 排除——wall-clock 非确定性）。
	tStart := time.Now()
	hopsN := hopsLen(sliced)
	timing := map[string]any{"llm_ms": 0, "total_ms": 0}
	trace := map[string]any{
		"alert_id":           strOr(sliced, "alert_id", ""),
		"bughash":            strOr(sliced, "bughash", ""),
		"vulnerability_type": vulnType,
		"slicer_output": map[string]any{
			"hops_extracted": hopsN,
			"token_count":    intFromAny(sliced["token_count"]),
			"degraded":       boolOr(sliced["degraded"]),
			"source_class":   classCtxName(sliced["source_class_context"]),
			"sink_class":     classCtxName(sliced["sink_class_context"]),
		},
		"sliced":              sliced, // gap-fix A (judge.py:727): full SlicedContext for labelling
		"prompt_sent":         messages,
		"llm_raw_response":    nil,
		"tool_used":           false,
		"tool_turns":          0,
		"judge_agentic":       false,
		"findings":            []map[string]any{},
		"tool_log":            []map[string]any{},
		"budget_used":         map[string]any{},
		"dropped_hops":        []any{},
		"falsify_run":         false,
		"falsify_exploitable": nil,
		"falsify_raw":         nil,
		"falsify_error":       nil,
		"dynamic_run":         false,
		"dynamic_outcome":     nil,
		"dynamic_error":       nil,
		"json_repaired":       false,
		"parsed_result":       nil,
		"error":               nil,
		"cached":              false,
		"timing":              timing,
	}
	// empty slice short-circuit (judge.py:766) — pre-LLM fail-open. hopsLen tolerates
	// BOTH []any (json.Unmarshal parity path) AND []map[string]any (Go-constructed test
	// path); a single-shape assertion would falsely fire empty_slice for real fixtures.
	if hopsN == 0 {
		r := uncertainResult(sliced, model, "empty_slice: 0 hops extracted — repo_root may be wrong or source files missing")
		timing["total_ms"] = int(time.Since(tStart).Milliseconds())
		return r, trace, fmt.Errorf("empty_slice")
	}
	// verdict_cache Get (judge.py:793-797): store==nil -> bypass (parity zero-regression).
	// Fail-open: any Get error / bad row / TTL-expiry -> miss (vcache.Store.Get already
	// degrades to !ok). A hit short-circuits the LLM call entirely and returns the
	// cached JudgeResult. logic version "go-parity-v2" cross-language-isolates from
	// Python's "v3" cache (constructive non-collision, design §4.4).
	var cacheKey string
	if store != nil {
		cacheKey = vcache.Key(toVcacheMessages(messages), model, logicVersion)
		if row, ok := store.Get(cacheKey); ok {
			if rj, _ := row["result_json"].(string); rj != "" {
				var cached contract.JudgeResult
				if err := json.Unmarshal([]byte(rj), &cached); err == nil {
					// uncertain 不缓存/不继承（见下方 Upsert 门控）。历史库里修本 bug
					// 之前残留的 uncertain 行命中也当 miss 重判——防"第一次失败→缓存→
					// 永远失败"（LLM 非确定性 / agentic 非收敛退化成的 uncertain 不该冻结）。
					if cached.Verdict == "uncertain" {
						trace["cached_stale_uncertain"] = true
					} else {
						trace["cached"] = true
						timing["total_ms"] = 0    // judge.py:795
						return cached, trace, nil // hit short-circuit (fail-open: bad row already missed)
					}
				}
			}
		}
	}
	tLLMStart := time.Now()
	data, info, err := judgeViaToolOrText(messages, harness, model, temp, repoIndex, vulnType, sliced, engine)
	timing["llm_ms"] = int(time.Since(tLLMStart).Milliseconds()) // judge.py:813
	if err != nil {
		// fail-open audit (judge.py:889-907): preserve exploration audit trail from info
		// so "AI read_file explored but verdict failed" isn't lost (铁律 D audit)。
		fillTraceAudit(trace, info)
		trace["error"] = fmt.Sprintf("%T: %v", err, err)
		timing["total_ms"] = int(time.Since(tStart).Milliseconds())
		return uncertainResult(sliced, model, failReasonFor(err, model)), trace, err
	}
	trace["llm_raw_response"] = info["llm_raw_response"] // judge.py:814
	trace["tool_used"] = info["tool_used"]               // :815
	trace["tool_turns"] = info["tool_turns"]             // :816
	trace["judge_agentic"] = info["judge_agentic"]       // :817
	// agentic explore 跑了多轮，prompt_sent 应含完整对话历史（Python messages
	// mutate in-place across turns — finalMessages 是 mutate 后等价物）。非 agentic
	// 路径保持初始 messages（system+user），与 Python single-turn 一致。
	if agenticOn {
		if fm, ok := info["final_messages"].([]map[string]any); ok && len(fm) > 0 {
			trace["prompt_sent"] = fm
		}
	}
	trace["tool_error"] = info["tool_error"]                           // :818
	trace["findings"] = info["findings"]                               // :819
	trace["budget_used"] = info["budget_used"]                         // :820
	trace["tool_log"] = info["tool_log"]                               // :821
	trace["dropped_hops"] = skipReasonsOrEmpty(sliced["skip_reasons"]) // :822
	if jr, ok := info["json_repaired"].(bool); ok && jr {              // :823-824
		trace["json_repaired"] = true
	}
	trace["parsed_result"] = data // :825
	llmRaw, _ := info["llm_raw_response"].(string)
	data = NormalizeVerdictData(data, harness, model)
	if _, ok := data["raw_arguments"]; ok {
		data = RepairRetryRawArguments(data, harness, model) // call C
	}
	result, err := BuildJudgeResult(data, sliced, model, maxConfidence, llmRaw, reg) // :828
	if err != nil {
		return uncertainResult(sliced, model, failReasonFor(err, model)), trace, err
	}
	result.MissingInfo = missingInfoFrom(info) // :831 (set BEFORE guards; guards may overwrite on downgrade)
	// P7 rejudge 需要守卫之前的原始 LLM 判决（一致性校验用）
	origVerdict := result.Verdict
	origConf := float64(result.Confidence)
	origDisp := ptrStr(result.Disposition)
	// —— P4 promote → refresh (judge.py:835-838), BEFORE guards so they see promoted hops ——
	toolLog, _ := info["tool_log"].([]map[string]any)
	repoRoot := ""
	if repoIndex != nil {
		repoRoot = repoIndex.RepoRoot()
	}
	agentic.PromoteAgenticXmlToSlice(sliced, toolLog, repoRoot)
	verifier.RefreshSinkParamStyle(sliced)
	// —— guards (judge.py:844-847) on the post-promote/refresh decisive_facts ——
	result = EnforceDecisiveFactKnown(result, sliced, reg)
	result = EnforceNoBareFp(result, sliced, reg)
	// ③ (2026-08-31): mapper-context #{} 现判 parameterized(SQLi-safe)后,EnforceDecisiveFactKnown
	// 不再 fire 这些 alert;本守卫兜底单面 SQLi-TP 与 parameterized(值不入 SQL 文本)矛盾 ->
	// 降 likely_tp(折 uncertain) conf6。多面含非 SQLi 不降(防 multiface-wobble FN,spec §0/§5)。
	// fail_reason=parameterized_contradicts_sqli_tp 不在 contractRejected -> 不触 rejudge;
	// uncertain 经 cache 门排除无粘性(judge.go:544 写 / :408 读跳过)。
	result = EnforceParameterizedSqliTpContradiction(result, sliced)
	// 根因1 代码兜底(见 guard.go EnforceEvidenceOnTp):TP 高置信 + exploit_payload 与
	// decisive_checks 双空 -> likely_tp(折 uncertain) conf6。3-run 实证 8a6fddf7 稳定
	// hollow-TP×3,纯 prompt 挡不住稳态偷懒,故代码强制。hollow_tp_no_evidence 不触
	// rejudge(前缀不在 contractRejected);uncertain 经 cache 门排除无粘性。
	result = EnforceEvidenceOnTp(result)
	// 报告去「未证实」arc Part D：EnforceGroundedDataFlow（监控先行 flag-OFF）。
	// 报告不再显「未证实」标记后，data_flow 步 grounding 判定移到 judge 层本门：
	// verdict==TP 且 conf>6 时，遍历 data_flow 步判 Case A（无 hop 锚点 + 无 tool_log
	// 读过的代码 = 真幻觉）→ 降 uncertain；Case B（工具读过但没落 hop = 词法匹到 tool_log）
	// 不降。APPSEC_GROUNDING_GATE=off(默认零回归)/monitor(只 log)/on(降)。toolLog 已在
	// :459 提取。监控期跑数据验零误降真 TP 后翻 on（Crack-D 教训）。不触 rejudge
	// （ungrounded_data_flow_step 前缀不在 contractRejected）；uncertain 经 cache 门排除。
	result = EnforceGroundedDataFlow(result, sliced, toolLog)
	// EnforceReachableSinkClaim (Crack D guard) reverted 2026-08-12 实证后；
	// forward_reachable contract (PrejudgeCalleeReachability, judge.go:158) retained.
	// See memory crack-d-reachable-callee-empirical.
	// —— P7 rejudge（DECISIVE_FACT_REJUDGE_MODE=on）——
	// 守卫拒判（decisive_fact_unknown / bare_fp_buries_actual）后 LLM 重判自修复。
	// gate：rejudgeMode=="on" && contractRejected && repoIndex!=nil && SupportsTools。
	// fail-open：rejudge 内部任何失败 → 保留守卫 uncertain。rejudge 结果不再触发 rejudge（防无限循环）。
	if rejudgeMode == "on" && contractRejected(result) && repoIndex != nil && harness.SupportsTools() {
		finalMsgs, _ := info["final_messages"].([]map[string]any)
		result = RejudgeContractRejection(result, origVerdict, origConf, origDisp,
			finalMsgs, sliced, model, harness, repoIndex, summaryStore, trace, reg, engine)
	}
	result = verifier.VerifyVerdict(result, sliced) // inc27, judge.py:862
	// judge.py:887 `or` semantics: build_attack_request nil → keep verifier's bypass PoC.
	if req := poc.BuildAttackRequest(sliced, ptrStr(result.ExploitPayload)); req != nil {
		result.AttackRequest = req
	}
	// —— P7 dynamic_verify（DYNAMIC_VERIFY_MODE=ir）——
	// VerifyVerdict + BuildAttackRequest 后、falsify 前（judge.py:867-872）。IR executor 纯评估
	// 复用 verifier sink 语义，§2 矩阵降级（只降不升）。gate mode=="ir" && verdict in (TP,FP)。
	// fail-open：panic → 记 dynamic_error 保持原判。junit deferral（mode=="junit" 等同 off）。
	result, dynInfo := DynamicVerify(result, sliced, dynamicVerifyMode)
	trace["dynamic_run"] = dynInfo["dynamic_run"]
	trace["dynamic_outcome"] = dynInfo["dynamic_outcome"]
	trace["dynamic_error"] = dynInfo["dynamic_error"]
	// —— P7 falsify（VERIFY_MODE=adversarial）——
	// VerifyVerdict 后 LLM 扮攻击者证利用，证不出降 uncertain，证得出保持/降级按矩阵。永不升 TP。
	// gate verifyMode=="adversarial"。fail-open：provider error/parse fail/exploitable=false → 降 uncertain（conf≤4）。
	if verifyMode == "adversarial" {
		result = Falsify(result, sliced, model, harness, reg, verifyMode)
	}
	// —— B1 补问缺失的展示字段(2026-08-23,用户拍板)——
	// 放在**所有守卫/verify/falsify 之后、缓存之前**:
	//   之后 —— 判决此时已定型,补问拿到的是最终 verdict,不会与守卫降级后的结论矛盾;
	//   之前 —— 补齐的字段一并入缓存,命中缓存时不必再补问一次。
	// 只要字段不重判(见 backfill.go 红线);gate off 或任何失败 → 原样返回。
	if r2, bi := BackfillDevFields(result, sliced, harness, model, backfillMode); len(bi) > 0 {
		result = r2
		for k, v := range bi {
			trace[k] = v
		}
	}

	// verdict_cache Upsert (judge.py:927-930): only cache reproducible verdicts
	// (Cacheable = success / contract-guard rejection; NOT flaky ParseError/empty_slice —
	// prevents "first accidental error → permanent wrong cache"). Fail-open: Upsert
	// error silently skipped (vcache.Store.Upsert already no-ops on error).
	//
	// uncertain 额外排除（含干净 uncertain FailReason="" 与守卫拒判 uncertain
	// decisive_fact_unknown:/bare_fp_buries_actual:）：uncertain 是唯一"重判有正 EV"的
	// 判决（可能收敛为 TP/FP），缓存会把 LLM 非确定性 / agentic 非收敛退化冻结成
	// "永远 uncertain"——用户担忧的"第一次失败→缓存→永远失败"。rejudge 失败后的守卫
	// 拒判 uncertain 也不冻结，下次跑再给一次 rejudge 机会。Python judge.py:927 会缓存
	// 干净 uncertain；本案故意分叉（准确度 > Python parity，见 memory
	// go-migration-verdict-divergence）。读取侧亦跳过历史残留 uncertain 行（见上方 Get）。
	if store != nil && cacheKey != "" && result.Verdict != "uncertain" && vcache.Cacheable(result.FailReason) {
		if rj, err := json.Marshal(result); err == nil {
			store.Upsert(cacheKey, string(rj), model)
		}
	}
	timing["total_ms"] = int(time.Since(tStart).Milliseconds()) // judge.py:936
	return result, trace, nil
}

// JudgeOneFailOpen is the parity entry: same as JudgeOne but ALWAYS returns the
// post-fail-open uncertain result (or the success result). ErrReplayExhausted is NOT
// fail-opened (propagated as a hard test error — call-count mismatch means a malformed
// fixture / Go bug, not a prod fail-open).
func JudgeOneFailOpen(sliced, appCtx map[string]any, harness llm.Provider, reg *cwereg.Registry, model string, temp *float64, repoIndex *slice.RepositoryIndex, store *vcache.Store, rejudgeMode string, summaryStore *funcdistill.FunctionSummaryStore, verifyMode string, dynamicVerifyMode string, stratReg ...*stratreg.Registry) contract.JudgeResult {
	r, _, err := JudgeOne(sliced, appCtx, harness, reg, model, temp, repoIndex, store, rejudgeMode, summaryStore, verifyMode, dynamicVerifyMode, nil, stratReg...)
	if err == nil {
		return r
	}
	// ErrReplayExhausted: hard error, NOT fail-open (parity test must fail loudly).
	if isReplayExhausted(err) {
		panic(err) // let parity test t.Fatalf via recover
	}
	return r // r already holds the uncertain + fail_reason
}

func isReplayExhausted(err error) bool {
	return err != nil && strings.Contains(err.Error(), "replay exhausted")
}

// hopsLen returns the number of slice hops, tolerating both JSON-unmarshal and
// Go-constructed shapes ([]any and []map[string]any). Mirrors the T2 hopsOf approach
// without importing its unexported symbol. 0 when absent or a non-list shape.
func hopsLen(sliced map[string]any) int {
	switch v := sliced["hops"].(type) {
	case []map[string]any:
		return len(v)
	case []any:
		return len(v)
	}
	return 0
}

// filterSecondary mirrors judge.py:706-708: drop configs with cwe_id=="UNKNOWN"/
// missing (a sink's implicated classes without a loaded expert layer). Keeps the
// reg.ConfigsForSlugs order (implicated first-seen).
func filterSecondary(cfgs []contract.CweConfig) []contract.CweConfig {
	out := make([]contract.CweConfig, 0, len(cfgs))
	for _, c := range cfgs {
		if c.CweID != "" && c.CweID != "UNKNOWN" {
			out = append(out, c)
		}
	}
	return out
}

// failReasonFor builds the逐字 Python fail_reason = "ai_judge: <PyType>: <msg>".
// Maps Go typed errors back to the Python exception type name + exact message format.
// Uses llmMaxTokens const (config.LLM_MAX_TOKENS=8192); stop_reason is always max_tokens
// in the exhausted case.
func failReasonFor(err error, model string) string {
	if isThinkingExhausted(err) {
		return fmt.Sprintf("ai_judge: ThinkingBudgetExhausted: model=%s emitted ThinkingBlock(s) but no text answer (stop_reason=max_tokens): thinking exhausted max_tokens=%d. Raise config.LLM_MAX_TOKENS and/or set config.LLM_THINKING_BUDGET so reasoning leaves room for the JSON answer. (Config error, not a flaky gateway — not retried.)", model, llmMaxTokens)
	}
	if isEmptyAfter3(err) {
		return fmt.Sprintf("ai_judge: RuntimeError: empty LLM response after 3 attempts (model=%s)", model)
	}
	// ErrParse and others: "ai_judge: <GoErrType-ish>: <msg>" — Python uses type(e).__name__.
	msg := err.Error()
	if strings.Contains(msg, "ParseError") || strings.Contains(msg, "no valid JSON") || strings.Contains(msg, "raw_arguments") {
		return "ai_judge: ParseError: " + parsePyMsg(msg)
	}
	return "ai_judge: RuntimeError: " + msg
}

func parsePyMsg(msg string) string {
	if strings.Contains(msg, "raw_arguments") {
		return "unparseable submit_verdict raw_arguments (model 返回残缺 JSON 包成 raw_arguments)"
	}
	return "no valid JSON in LLM output"
}

// ---- trace helpers (parity with Python judge.py:716-748 / 889-907) ----

// intFromAny coerces any to int (nil → 0). JSON unmarshal yields float64;
// Go-constructed sliced maps yield int. Mirrors Python int(x) consumption side.
func intFromAny(v any) int {
	switch x := v.(type) {
	case nil:
		return 0
	case int:
		return x
	case float64:
		return int(x)
	case string:
		if n, err := strconvAtoi(x); err == nil {
			return n
		}
		return 0
	}
	return 0
}

// boolOr coerces any to bool (nil → false). Mirrors Python sliced.get("degraded", False).
func boolOr(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// classCtxName extracts class_name from a source/sink ClassContext map (nil if absent).
// Mirrors Python (sliced.get("source_class_context") or {}).get("class_name") → str|None.
func classCtxName(v any) any {
	if m, ok := v.(map[string]any); ok {
		if cn, ok := m["class_name"].(string); ok {
			return cn
		}
	}
	return nil
}

// skipReasonsOrEmpty returns sliced["skip_reasons"] or []any{} if absent (parity:
// Python sliced.get("skip_reasons", []) always yields a list, never None).
func skipReasonsOrEmpty(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

// fillTraceAudit copies audit-trail fields from judgeViaToolOrText's info into trace
// on the fail-open path (judge.py:889-907): preserves llm_raw_response/tool_used/
// tool_turns/judge_agentic/findings/tool_log/tool_error/budget_used/json_repaired
// so "AI explored but verdict failed" isn't lost (铁律 D audit trail).
func fillTraceAudit(trace, info map[string]any) {
	// 对齐 Python judge.py:896-905 fail-open audit：无条件设（map 不存在的 key → nil，
	// 与 Python _info.get("tool_error") → None 一致），保审计字段存在不丢。
	trace["llm_raw_response"] = info["llm_raw_response"]
	trace["tool_used"] = info["tool_used"]
	trace["tool_turns"] = info["tool_turns"]
	trace["judge_agentic"] = info["judge_agentic"]
	trace["findings"] = info["findings"]
	trace["tool_log"] = info["tool_log"]
	trace["tool_error"] = info["tool_error"]
	trace["budget_used"] = info["budget_used"]
	if jr, ok := info["json_repaired"].(bool); ok && jr {
		trace["json_repaired"] = true
	}
}

// strconvAtoi is a thin wrapper to keep intFromAny self-contained (avoids adding a
// strconv import just for one call site; judge.go otherwise doesn't need strconv).
func strconvAtoi(s string) (int, error) {
	var n int
	var neg bool
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	if i == len(s) {
		return 0, fmt.Errorf("empty")
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("bad")
		}
		n = n*10 + int(s[i]-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

// uncertainResult builds the fail-open JudgeResult (judge.py:913-921):
// uncertain + confidence=0 + ExploitPath(entry_point) + reasoning="local fail-open" + fail_reason.
func uncertainResult(sliced map[string]any, model, failReason string) contract.JudgeResult {
	return contract.JudgeResult{
		AlertID:    strOr(sliced, "alert_id", ""),
		Bughash:    strOr(sliced, "bughash", ""),
		Verdict:    "uncertain",
		Confidence: 0,
		ExploitPath: contract.ExploitPath{
			EntryPoint: strOr(sliced, "entry_point_signature", "?"),
			DataFlow:   []string{},
		},
		Reasoning:  "local fail-open",
		ModelUsed:  model,
		FailReason: &failReason,
	}
}

// isThinkingExhausted / isEmptyAfter3 mirror errors.Is against llm sentinels.
func isThinkingExhausted(err error) bool { return errorsIs(err, llm.ErrThinkingBudgetExhausted) }
func isEmptyAfter3(err error) bool       { return errorsIs(err, llm.ErrEmptyAfter3Attempts) }

func errorsIs(err, target error) bool { return errors.Is(err, target) }
