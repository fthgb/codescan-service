package verifier

import (
	"appsecgo/internal/slice"
)

// bypass.go — detect_guard_variable_bypass delegate (RC-A 反漏报红线).
// 实现已下沉到 slice 包（sanitizers.go）为单一源，避免 slice↔verifier 循环依赖。

// detectGuardVariableBypass delegates to slice.DetectGuardVariableBypass
// (下沉到 slice 包为 RC-A bypass 检测单一源，避免 slice↔verifier 循环依赖，铁律 D)。
func detectGuardVariableBypass(sliced map[string]any) map[string]any {
	return slice.DetectGuardVariableBypass(sliced)
}
