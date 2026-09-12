package slice

// forward_reachable.go — decisive-fact 映射：ForwardReachable 三态 →
// decisive_facts["forward_reachable"] 值（spec P0-a §4(a)，纯函数）。
//
// guard EnforceDecisiveFactKnown（internal/judge/guard.go:51-57）读 decisive_facts[f]=="unknown"
// fire（D2 复用既有触发，不改 guard）。故 fire 态写 "unknown"；anchored 写 "anchored"；
// not-applicable 写 ""（调用方不回写 map → key 缺席 → guard no-op）。
// rejudge 的 recoverable/terminal 区分读 ForwardReachable struct 字段（D5），不靠此 token——
// 任何需区分 fire 子态的消费者必须读 struct，禁止从 map token 反推语义。

// MapForwardReachable 把 PrejudgeCalleeReachability 产的三态（map 形：keys
// "definitive"/"uncertain"/"truncated"，reachability.go 写）映射成
// decisive_facts["forward_reachable"] 的值。调用方（judge.go pre-loop / rejudge.go
// post-extract）决定是否回写 map。
//   - Uncertain 非空 || Truncated → "unknown"（fire：in-source-uncollected / 截断，guard 降 uncertain）
//   - Definitive 非空 && Uncertain 空 && !Truncated → "anchored"（路径已解析，guard 不 fire）
//   - 都空 && !Truncated → ""（not-applicable，调用方不写 map → guard no-op，D2）
//   - fr nil → ""（Prejudge 未写 struct，同 not-applicable）
func MapForwardReachable(fr map[string]any) string {
	if fr == nil {
		return ""
	}
	truncated, _ := fr["truncated"].(bool)
	if unc, _ := fr["uncertain"].([]any); len(unc) > 0 || truncated {
		return "unknown"
	}
	if defs, _ := fr["definitive"].([]any); len(defs) > 0 {
		return "anchored"
	}
	return ""
}
