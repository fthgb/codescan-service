package contract

// naming.go — 跨包共享的命名约定常量。slice / agentic / prompts 三包均依赖 contract，
// 故此处定义消除重复（2026-09-08 spec 优化项 §五.2-3）。

// AccessorNamePattern 匹配 JavaBean accessor 命名（getXxx/setXxx/isXxx）。
// 消费方：internal/slice/enrich.go（未解析 callee 清单过滤）、
// internal/agentic/reachability.go（ExtractCandidateCallees 过滤）。
// 两处原各自 regexp.MustCompile 同一 pattern，现共用本常量防漂移。
// 过滤依据（T4 §7.1 实证）：accessor 实现是字段读写，无 sanitize 逻辑可漏判；
// 进未解析清单只会引导 judge 逐个 getter 探索（纯噪声），还会假 fire guard。
const AccessorNamePattern = `^(get|set|is)[A-Z]`

// MaxUnresolvedNoteNames 是未解析 callee 名单（enrichment_note 散文 + prompts 渲染层）的
// 名字数上限；超出部分聚合计数，不逐个罗列。70+ 名单（2026-09-06 实证：getId/
// getNumber/getUnitName…）会被 judge 读成「70 个待验证项」，是探索轮次翻倍的三驱动之一
// （2026-09-06 根因报告 §1.4）。结构化 ForwardReachable.Uncertain 保持完整——守卫
// （MapForwardReachable）/rejudge（RefreshForwardReachable）消费全量，只截散文。
// 消费方：internal/slice/enrich.go（EnrichSlice 截断）、internal/prompts/messages.go
// （forwardReachableLayer 渲染截断）。两处原各自硬编码 20，现共用本常量防漂移。
const MaxUnresolvedNoteNames = 20
