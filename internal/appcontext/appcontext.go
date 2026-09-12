package appcontext

// appContextRegistry 逐字移植 appsec/nodes/trigger.py:APP_CONTEXT_REGISTRY。
// list 用 []any、dict 用 map[string]any(JSON-native,prompt builder 的 .([]any) 断言生效)。
var appContextRegistry = map[string]map[string]any{
	"repo-ecommerce-web": {
		"type":           "web_app",
		"framework":      "spring-boot",
		"auth_model":     "spring-security",
		"rpc_frameworks": []any{"dubbo"},
		"exposure":       "public_internet",
	},
	"repo-internal-admin": {
		"type":                "web_app",
		"framework":           "spring-boot",
		"auth_model":          "spring-security",
		"exposure":            "internal_network",
		"intended_behaviors":  []any{"Authenticated admins read/export files by name from the console"},
		"not_a_vulnerability": []any{"Local filesystem access by an authenticated admin operator"},
		"trust_boundaries": map[string]any{
			"http_request_body": "untrusted",
			"admin_session":     "semi_trusted",
		},
	},
}

// Resolve 等价 Python resolve_app_context(repo_key) =
// AppContext(**raw).model_dump(exclude_none=True)。
//
// AppContext(state.py:51-64) 的 named 字段:exposure/security_model/requires_remote_trigger
// 默认 None(exclude_none 丢);intended_behaviors/not_a_vulnerability/trust_boundaries
// 默认 []/[]/{}(非 None → exclude_none 保留,即使空)。extra="allow" 保留 type/framework/...
// 缺省 raw = {"type":"web_app","exposure":"public_internet"}。
//
// 故:out 先放三个非-None 默认([]/[]/{}),再 overlay raw(去 nil),保留 extras。
// 一切值 JSON-native,prompt builder 的 comma-ok .([]any)/.(map[string]any) 断言生效。
func Resolve(repoKey string) map[string]any {
	raw, ok := appContextRegistry[repoKey]
	if !ok {
		raw = map[string]any{"type": "web_app", "exposure": "public_internet"}
	}
	out := map[string]any{
		"intended_behaviors":  []any{},
		"not_a_vulnerability": []any{},
		"trust_boundaries":    map[string]any{},
	}
	for k, v := range raw {
		if v == nil { // exclude_none
			continue
		}
		out[k] = v
	}
	return out
}
