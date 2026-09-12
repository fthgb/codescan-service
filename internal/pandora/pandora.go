// Package pandora reads infrastructure config (OSS + DB) from a Pandora
// config file shared with sec-service. The pandorago SDK dependency is
// encapsulated here; callers receive plain Go structs and never see Viper.
package pandora

import (
	"fmt"

	pandorago "tb.devops.aliyun.com/codeup/cathay/cathay_ops/pandorago.git.git"
)

// OSSConfig holds OSS storage bucket configuration read from Pandora.
type OSSConfig struct {
	BucketName     string // oss.bucketName
	ObjectName     string // oss.objectName (object path prefix, e.g. "sec")
	Region         string // oss.region
	Endpoint       string // oss.endpoint (internal, with -internal)
	PublicEndpoint string // oss.publicEndpoint (optional; empty → derived by storage)
	AccessKey      string // sec_ali_jkey
	SecretKey      string // sec_ali_secret
}

// DBConfig holds database configuration.
type DBConfig struct {
	DatabaseLink string // database.link (MySQL connection string)
	Driver       string // database.driver (e.g. "mysql")
	Charset      string // database.charset (e.g. "utf8mb4")
}

// LLMConfig holds LLM provider configuration read from Pandora.
// Two provider sets: anthropic (qwen) and openai (generic OpenAI-compatible).
type LLMConfig struct {
	Provider string  // llm.provider: "anthropic" | "openai"
	APIKey   string  // llm.api_key (anthropic provider key)
	BaseURL  string  // llm.base_url (anthropic provider endpoint)
	Model    string  // llm.model (anthropic provider model)
	// OpenAI-compatible provider (env: HUNYUAN_*, used when Provider=openai/hunyuan)
	OpenAIBaseURL    string  // llm.openai_base_url
	OpenAIAPIKey     string  // llm.openai_api_key
	OpenAIModel      string  // llm.openai_model
	OpenAIForceStreamStr   string // llm.openai_force_stream (raw string; empty = use default)
	OpenAITemperatureStr string // llm.openai_temperature (raw string; empty = don't send key)
}

// CodescanConfig holds codescan REST client config read from Pandora.
type CodescanConfig struct {
	BaseURL          string // codescan.base_url
	AuthToken        string // codescan.auth_token
	AuthCookie       string // codescan.auth_cookie
	GitAdminUser     string // codescan.git_admin_user
	GitAdminPassword string // codescan.git_admin_password
}

// CMDBConfig holds CMDB push configuration read from Pandora.
type CMDBConfig struct {
	PushURL         string // cmdb.push_url
	Key             string // cmdb.key
	Gate            string // cmdb.gate
	ExternalBaseURL string // cmdb.external_base_url
	LabelerName     string // cmdb.labeler_name
	APIToken        string // cmdb.api_token
}

// FeatureConfig holds feature switch config read from Pandora.
type FeatureConfig struct {
	TaintEngineMode     string // feature.taint_engine_mode
	VerdictContentCache string // feature.verdict_content_cache
	MinSeverity         string // feature.min_severity
}

// Config bundles infrastructure config extracted from a Pandora config file.
type Config struct {
	OSS      OSSConfig
	DB       DBConfig
	LLM      LLMConfig
	Codescan CodescanConfig
	CMDB     CMDBConfig
	Feature  FeatureConfig
}

// Load reads a Pandora config file (key=value format) and extracts OSS + DB config.
// configPath points to the same config file sec-service uses.
// Tries full Init() first (includes Pandora config center); falls back to
// InitFromConfigFile() (local file only) when Pandora config center is unavailable.
// Returns error if both fail.
func Load(configPath string) (*Config, error) {
	c := pandorago.NewWithOption(pandorago.WithPandora())
	c.V.SetConfigFile(configPath)

	// Try full Init (file + Pandora config center); fall back to file-only.
	// This allows the same code to work in production (with Pandora access)
	// and dev/CI (without Pandora config center network access).
	if err := c.Init(); err != nil {
		if ferr := c.InitFromConfigFile(); ferr != nil {
			return nil, fmt.Errorf("pandora init failed: %w (file-only also failed: %v)", err, ferr)
		}
	}

	return &Config{
		OSS: OSSConfig{
			BucketName:     c.V.GetString("oss.bucketName"),
			ObjectName:     c.V.GetString("oss.objectName"),
			Region:         c.V.GetString("oss.region"),
			Endpoint:       c.V.GetString("oss.endpoint"),
			PublicEndpoint: c.V.GetString("oss.publicEndpoint"),
			AccessKey:      c.V.GetString("sec_ali_jkey"),
			SecretKey:      c.V.GetString("sec_ali_secret"),
		},
		DB: DBConfig{
			DatabaseLink: c.V.GetString("database.link"),
			Driver:       c.V.GetString("database.driver"),
			Charset:      c.V.GetString("database.charset"),
		},
		LLM: LLMConfig{
			Provider:          c.V.GetString("llm.provider"),
			APIKey:            c.V.GetString("llm.api_key"),
			BaseURL:           c.V.GetString("llm.base_url"),
			Model:             c.V.GetString("llm.model"),
			OpenAIBaseURL:     c.V.GetString("llm.openai_base_url"),
			OpenAIAPIKey:      c.V.GetString("llm.openai_api_key"),
			OpenAIModel:       c.V.GetString("llm.openai_model"),
			OpenAIForceStreamStr:   c.V.GetString("llm.openai_force_stream"),
			OpenAITemperatureStr: c.V.GetString("llm.openai_temperature"),
		},
		Codescan: CodescanConfig{
			BaseURL:          c.V.GetString("codescan.base_url"),
			AuthToken:        c.V.GetString("codescan.auth_token"),
			AuthCookie:       c.V.GetString("codescan.auth_cookie"),
			GitAdminUser:     c.V.GetString("codescan.git_admin_user"),
			GitAdminPassword: c.V.GetString("codescan.git_admin_password"),
		},
		CMDB: CMDBConfig{
			PushURL:         c.V.GetString("cmdb.push_url"),
			Key:             c.V.GetString("cmdb.key"),
			Gate:            c.V.GetString("cmdb.gate"),
			ExternalBaseURL: c.V.GetString("cmdb.external_base_url"),
			LabelerName:     c.V.GetString("cmdb.labeler_name"),
			APIToken:        c.V.GetString("cmdb.api_token"),
		},
		Feature: FeatureConfig{
			TaintEngineMode:     c.V.GetString("feature.taint_engine_mode"),
			VerdictContentCache: c.V.GetString("feature.verdict_content_cache"),
			MinSeverity:         c.V.GetString("feature.min_severity"),
		},
	}, nil
}
