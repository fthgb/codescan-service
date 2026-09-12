package llm

import (
	"strings"

	"appsecgo/internal/config"
)

// NewProviderFromConfig 按 cfg.LLMProvider 选 live provider(铁律 D 单边界:加第 N 个
// provider = 加一个 case + 一个 NewXxxProvider,不改调用方)。
//
//	默认 "" / "anthropic" → AnthropicProvider(qwen via corp Anthropic-shape 网关)。
//	"hunyuan" / "openai"  → OpenAIProvider(OpenAI 兼容 /chat/completions;hy3 via
//	                       copilot.tencent.com,强制 forceStream——copilot 拒绝非流式)。
//
// 默认分支零回归:cfg.LLMProvider 默认 "anthropic" → 走原 AnthropicProvider,
// 与改动前 byte-for-byte 一致(不设 APPSEC_LLM_PROVIDER 即 qwen 链路不变)。
// 环形 import 检查:config 不 import llm,本文件单向依赖 config,无环。
func NewProviderFromConfig(cfg config.Config) Provider {
	switch strings.ToLower(cfg.LLMProvider) {
	case "hunyuan", "openai":
		// copilot.tencent 端点必 forceStream(参考 main.go:70 口径);其它 OpenAI 兼容
		// 端点按 cfg.HunyuanForceStream。
		fs := cfg.HunyuanForceStream || strings.Contains(cfg.HunyuanBaseURL, "copilot.tencent")
		// 温度未配置 → 不传该 option → provider 一个 temperature 键都不发(零回归)。
		var opts []func(*OpenAIProvider)
		if cfg.HunyuanTemperature != nil {
			opts = append(opts, WithOpenAITemperature(*cfg.HunyuanTemperature))
		}
		return NewOpenAIProvider(cfg.HunyuanBaseURL, cfg.HunyuanAPIKey, cfg.HunyuanModel, fs, opts...)
	default: // "", "anthropic"
		return NewAnthropicProvider(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.LLMModel, cfg.LLMThinkingBudget)
	}
}
