package adapter

import (
	"appsecgo/internal/contract"
	"appsecgo/internal/cwereg"
)

type Adapter interface {
	Parse(raw map[string]any) ([]contract.SASTResult, error)
	Capabilities() map[string]bool
}

// ByName 按名字选适配器 —— **选择逻辑的单一入口**(铁律 D)。
//
// 此前该 switch 只活在 `cmd/server`,而 `cmd/audit` 的 `--adapter` flag 存在却被忽略、
// 硬写 CodeQLAdapter:喂 CodeSafe 导出(`{"bugs":[...]}`)时 CodeQL 只认 SARIF 的
// `runs[].results[]` → 解析出 0 条,整跑空转还落一个空 run 目录(2026-08-22 实际踩到)。
//
// 未知/空名字兜底 CodeQL,对齐 server 既有口径(Python `_ADAPTERS` 会 KeyError,Go 不);
// reg 仅 codesafe 需要(CWE→slug),其余忽略,传 nil 安全。
func ByName(name string, reg *cwereg.Registry) Adapter {
	switch name {
	case "codesafe":
		return CodeSafeAdapter{Reg: reg}
	default:
		return CodeQLAdapter{}
	}
}
