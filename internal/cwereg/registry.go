package cwereg

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"appsecgo/internal/contract"
)

// vulnSynonyms mirrors appsec/nodes/judge.py:_VULN_SYNONYMS (port verbatim). Used by
// DetectBuriedTypes: a slug mentioned (via synonyms) in reasoning but NOT in
// actual_vulnerability_types is "buried" (prevent a bare FP burying a real bug).
var vulnSynonyms = map[string][]string{
	"sql_injection":            {"sql注入", "sql injection", "sqli"},
	"xss":                      {"xss", "跨站脚本", "存储型xss", "stored xss", "反射型xss", "reflected xss"},
	"path_traversal":           {"路径穿越", "路径遍历", "path traversal", "目录穿越", "目录遍历", "directory traversal"},
	"ssrf":                     {"ssrf", "服务端请求伪造", "server-side request forgery"},
	"command_injection":        {"命令注入", "command injection"},
	"insecure_deserialization": {"反序列化", "deserialization", "反序列"},
	"arbitrary_file_upload":    {"任意文件上传", "arbitrary file upload"},
	"xxe":                      {"xxe", "xml外部实体"},
	"ssti":                     {"ssti", "模板注入", "server-side template injection"},
	"open_redirect":            {"开放重定向", "open redirect"},
	"insecure_randomness":      {"弱随机", "弱随机数", "不安全随机", "可预测随机", "weak random", "weak prng", "insecure random", "predictable random"},
	"weak_crypto":              {"弱加密", "弱哈希", "弱加密算法", "弱哈希算法", "弱密码学", "密码哈希计算量不足", "weak crypto", "weak hash", "weak hashing", "weak algorithm", "insufficient computational effort"},
	"hardcoded_credentials":    {"硬编码凭证", "硬编码密码", "硬编码密钥", "硬编码凭据", "硬编码口令", "hardcoded credentials", "hardcoded password", "hardcoded secret", "hardcoded credential", "hard-coded password"},
}

// vulnSynonymOrder holds the slugs of vulnSynonyms in Python _VULN_SYNONYMS
// insertion order. DetectBuriedTypes iterates THIS (not the map) so that the
// "preserve order" dedup is deterministic and matches Python 3.7+ dict order
// (Go map iteration is non-deterministic). Keep in sync with vulnSynonyms.
var vulnSynonymOrder = []string{
	"sql_injection",
	"xss",
	"path_traversal",
	"ssrf",
	"command_injection",
	"insecure_deserialization",
	"arbitrary_file_upload",
	"xxe",
	"ssti",
	"open_redirect",
	"insecure_randomness",
	"weak_crypto",
	"hardcoded_credentials",
}

// cweNum mirrors registry.py:_CWE_NUM = re.compile(r"(\d+)").
var cweNum = regexp.MustCompile(`(\d+)`)

// cweIDRe mirrors judge.py:_CWE_ID_RE = re.compile(r"^cwe[-_\s]?(\d+)$"). CASE-SENSITIVE
// (lowercase cwe only), anchored. Python only normalizes lowercase "cwe-89"/"cwe89"/"cwe 89"
// forms; uppercase "CWE-89" does NOT match -> passes through un-normalized (then flagged
// by type_mismatch). Faithful: do not make Go more aggressive than Python.
var cweIDRe = regexp.MustCompile(`^cwe[-_\s]?(\d+)$`)

// compiledSignal precompiles a signal pattern (RE2). Bad patterns skipped (fail-open,
// mirrors type_coverage._signals_registry). P2 first-cut Java sink patterns are simple
// enough for RE2 (risk #10 — verify during impl, adjust yaml + re-dump if not).
type compiledSignal struct {
	lang string
	re   *regexp.Regexp
	vt   string
}

// Registry is the in-memory cwe config set, loaded from a recorded JSON dump of
// Python type_coverage._all_configs() (CweConfig.model_dump). NO yaml in P2 (yaml.v3
// is P5 live). Helpers mirror type_coverage.py + registry.py verbatim.
type Registry struct {
	configs   []contract.CweConfig
	cweToSlug map[string]string // "CWE-<n>" -> slug (first claimant wins, mirrors _cwe_to_slug setdefault)
	signals   []compiledSignal
}

func NewRegistry(jsonPath string) (*Registry, error) {
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var cfgs []contract.CweConfig
	if err := json.Unmarshal(raw, &cfgs); err != nil {
		return nil, err
	}
	r := &Registry{configs: cfgs, cweToSlug: map[string]string{}}
	for _, c := range cfgs {
		slug := c.VulnerabilityType
		if slug == "" {
			continue
		}
		if c.CweID != "" && c.CweID != "UNKNOWN" {
			if _, ok := r.cweToSlug[c.CweID]; !ok { // setdefault: first claimant wins
				r.cweToSlug[c.CweID] = slug
			}
		}
		for _, alias := range c.CweAliases {
			alias = strings.TrimSpace(alias)
			if alias == "" {
				continue
			}
			if _, ok := r.cweToSlug[alias]; !ok {
				r.cweToSlug[alias] = slug
			}
		}
		for _, sig := range c.Signals {
			lang := "java"
			if v, ok := sig["lang"].(string); ok && v != "" {
				lang = v
			}
			pat, _ := sig["pattern"].(string)
			if pat == "" {
				continue
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				continue // fail-open: skip unparseable pattern
			}
			r.signals = append(r.signals, compiledSignal{lang: lang, re: re, vt: slug})
		}
	}
	return r, nil
}

func (r *Registry) AllConfigs() []contract.CweConfig { return r.configs }

// ConfigForSlug returns the cfg whose vulnerability_type matches slug
// (case-insensitive, EqualFold — mirrors the .lower() lookups Python does).
// (!ok) when absent (Python load_cwe_config returns a zero cfg with cwe_id
// "UNKNOWN"; callers filter UNKNOWN downstream). P5 build_messages resolve.
func (r *Registry) ConfigForSlug(slug string) (contract.CweConfig, bool) {
	for _, c := range r.configs {
		if strings.EqualFold(c.VulnerabilityType, slug) {
			return c, true
		}
	}
	return contract.CweConfig{}, false
}

// ConfigsForSlugs batch-resolves slugs in order, skipping absent ones. Used by
// JudgeOne to resolve the secondary (implicated) configs list (judge.py:701-714).
func (r *Registry) ConfigsForSlugs(slugs []string) []contract.CweConfig {
	out := []contract.CweConfig{}
	for _, s := range slugs {
		if c, ok := r.ConfigForSlug(s); ok {
			out = append(out, c)
		}
	}
	return out
}

// IsCalibrated ports report._is_calibrated: a CWE is calibrated only if its
// config explicitly says so. Unknown/missing → false (anti false-negative).
func (r *Registry) IsCalibrated(vt string) bool {
	if vt == "" {
		return false
	}
	for _, c := range r.configs {
		if strings.EqualFold(c.VulnerabilityType, vt) {
			return c.Calibrated
		}
	}
	return false
}

// SlugForCwe mirrors registry.py:slug_for_cwe: extract digits -> "CWE-<n>" -> lookup.
// Returns "" when unmapped (Python None -> caller degrades).
func (r *Registry) SlugForCwe(cweID string) string {
	if cweID == "" {
		return ""
	}
	m := cweNum.FindStringSubmatch(cweID)
	if m == nil {
		return ""
	}
	return r.cweToSlug["CWE-"+m[1]]
}

// NormalizeVulnType mirrors judge.py:_normalize_vuln_type: lowercase "cwe[-_ ]<n>" ->
// slug (via SlugForCwe); slugs + uppercase CWE + unmapped pass through (let
// type_mismatch flag it, never silently drop). Uses cweIDRe (case-sensitive, anchored).
func (r *Registry) NormalizeVulnType(t string) string {
	if cweIDRe.MatchString(t) {
		if s := r.SlugForCwe(t); s != "" {
			return s
		}
	}
	return t
}

// hopsOf extracts hop maps from sliced["hops"], tolerating BOTH []any (JSON-unmarshaled,
// the parity path) and []map[string]any (Go-constructed, focused tests). Returns nil
// if absent. Centralizes the shape tolerance so langOf/ImplicatedSinkTypes don't
// assert a single type.
func hopsOf(sliced map[string]any) []map[string]any {
	raw, ok := sliced["hops"]
	if !ok || raw == nil {
		return nil
	}
	if hs, ok := raw.([]map[string]any); ok {
		return hs
	}
	if ais, ok := raw.([]any); ok {
		out := make([]map[string]any, 0, len(ais))
		for _, h := range ais {
			if m, ok := h.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// langOf mirrors type_coverage._lang_of: entry hop file ext (.php->php, else java).
func langOf(sliced map[string]any) string {
	hops := hopsOf(sliced)
	path := ""
	if len(hops) > 0 {
		path, _ = hops[0]["file_path"].(string)
	}
	if strings.HasSuffix(path, ".php") {
		return "php"
	}
	return "java"
}

// ImplicatedSinkTypes mirrors type_coverage.implicated_sink_types: scan hop bodies
// against the signals registry. Excludes declared, dedups, first-seen order.
func (r *Registry) ImplicatedSinkTypes(sliced map[string]any, declared string) []string {
	declared = strings.ToLower(declared)
	hops := hopsOf(sliced)
	parts := make([]string, 0, len(hops))
	for _, h := range hops {
		if b, ok := h["function_body"].(string); ok {
			parts = append(parts, b)
		}
	}
	bodies := strings.Join(parts, "\n")
	lang := langOf(sliced)
	out := []string{}
	seen := map[string]bool{}
	for _, sig := range r.signals {
		if sig.lang != lang || !sig.re.MatchString(bodies) {
			continue
		}
		if sig.vt == declared || seen[sig.vt] {
			continue
		}
		seen[sig.vt] = true
		out = append(out, sig.vt)
	}
	return out
}

// LoadedKnowledgeTypes mirrors type_coverage.loaded_knowledge_types:
// {declared} ∪ implicated_sink_types ∪ declared-config.adjacency.
func (r *Registry) LoadedKnowledgeTypes(sliced map[string]any, declared string) map[string]bool {
	declared = strings.ToLower(declared)
	loaded := map[string]bool{declared: true}
	for _, t := range r.ImplicatedSinkTypes(sliced, declared) {
		loaded[strings.ToLower(t)] = true
	}
	for _, c := range r.configs {
		if strings.ToLower(c.VulnerabilityType) == declared {
			for _, a := range c.Adjacency {
				loaded[strings.ToLower(a)] = true
			}
		}
	}
	delete(loaded, "")
	return loaded
}

// DetectBuriedTypes mirrors judge.py:_detect_buried_types: scan reasoning (whitespace
// stripped, lowercased) for vuln slugs via synonyms; return those NOT in actual. Dedup,
// preserve order. Empty -> nil (Python None).
func (r *Registry) DetectBuriedTypes(reasoning string, actual []string) []string {
	text := strings.ToLower(strings.Join(strings.Fields(reasoning), ""))
	if text == "" {
		return nil
	}
	actualSet := map[string]bool{}
	for _, t := range actual {
		actualSet[strings.ToLower(t)] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, slug := range vulnSynonymOrder {
		syns := vulnSynonyms[slug]
		if actualSet[slug] {
			continue
		}
		for _, s := range syns {
			if strings.Contains(text, strings.ToLower(strings.Join(strings.Fields(s), ""))) {
				if !seen[slug] {
					seen[slug] = true
					out = append(out, slug)
				}
				break
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
