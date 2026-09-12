package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ============================================================
//  Spring 配置解析（镜像 7.py ConfigFileParser 系列）
//  .properties + 环境变量 + YAML 正则提取（无 YAML 库依赖）
// ============================================================

var envConfigPrefixes = []string{
	"SPRING_", "SERVER_", "MANAGEMENT_", "LOGGING_",
	"SPRING_APPLICATION_", "SPRING_DATASOURCE_",
	"SPRING_JPA_", "SPRING_REDIS_", "SPRING_KAFKA_",
	"SPRING_RABBITMQ_", "SPRING_MAIL_", "SPRING_SECURITY_",
}

var placeholderRe = regexp.MustCompile(`\$\{([^}:]+)(?::([^}]*))?\}`)

// ConfigFileParser — 组合各配置数据源（镜像 7.py ConfigFileParser）。
type ConfigFileParser struct {
	RepoRoot       string
	Properties     map[string]string
	ActiveProfiles map[string]bool
}

func NewConfigFileParser(repoRoot string) *ConfigFileParser {
	cfp := &ConfigFileParser{
		RepoRoot:       repoRoot,
		Properties:     make(map[string]string),
		ActiveProfiles: make(map[string]bool),
	}
	cfp.load()
	return cfp
}

func (c *ConfigFileParser) load() {
	// .properties
	c.loadProperties()
	// YAML（正则提取）
	c.loadYAML()
	// 环境变量
	c.loadEnvVars()
	// Profile 覆盖
	c.applyProfileOverrides()
}

func (c *ConfigFileParser) loadProperties() {
	var configFiles []string
	filepath.Walk(c.RepoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if ignoreDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if strings.HasSuffix(name, ".properties") && strings.Contains(name, "application") {
			configFiles = append(configFiles, path)
		}
		return nil
	})
	// 排序：application.* 优先
	sortConfigFiles(configFiles)
	for _, path := range configFiles {
		profile := getProfile(path, ".properties")
		c.parsePropertiesFile(path, profile)
	}
}

func (c *ConfigFileParser) parsePropertiesFile(path, profile string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	var pendingKey, pendingValue string
	for _, line := range lines {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if pendingKey != "" {
			if strings.HasSuffix(stripped, "\\") {
				pendingValue += stripped[:len(stripped)-1]
			} else {
				pendingValue += stripped
				key := pendingKey
				if _, exists := c.Properties[key]; !exists {
					c.Properties[key] = strings.TrimSpace(pendingValue)
				}
				pendingKey = ""
				pendingValue = ""
			}
			continue
		}
		if idx := strings.Index(stripped, "="); idx > 0 {
			key := strings.TrimSpace(stripped[:idx])
			value := strings.TrimSpace(stripped[idx+1:])
			if strings.HasSuffix(value, "\\") {
				pendingKey = key
				pendingValue = value[:len(value)-1]
			} else {
				if _, exists := c.Properties[key]; !exists {
					c.Properties[key] = value
				}
			}
		}
	}
}

func (c *ConfigFileParser) loadYAML() {
	var configFiles []string
	filepath.Walk(c.RepoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if ignoreDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) &&
			strings.Contains(name, "application") {
			configFiles = append(configFiles, path)
		}
		return nil
	})
	sortConfigFiles(configFiles)
	for _, path := range configFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		keys := extractYAMLKeys(data)
		for k, v := range keys {
			if _, exists := c.Properties[k]; !exists {
				c.Properties[k] = v
			}
		}
	}
}

// extractYAMLKeys 用正则提取 YAML key（不依赖 YAML 解析器，覆盖 80% 场景）。
// 仅处理顶层 key + 缩进嵌套（dot 分隔路径），不处理锚点/多文档。
var yamlLineRe = regexp.MustCompile(`^(\s*)([\w.\-]+)\s*:\s*(.*)$`)

func extractYAMLKeys(content []byte) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(string(content), "\n")
	var pathStack []string
	var indentStack []int
	for _, line := range lines {
		// 跳过注释/空行
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := yamlLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := len(m[1])
		key := m[2]
		value := strings.TrimSpace(m[3])
		// 去除引号
		value = strings.Trim(value, "\"'")
		// 弹出比当前缩进深或等的项
		for len(indentStack) > 0 && indent <= indentStack[len(indentStack)-1] {
			pathStack = pathStack[:len(pathStack)-1]
			indentStack = indentStack[:len(indentStack)-1]
		}
		pathStack = append(pathStack, key)
		indentStack = append(indentStack, indent)
		if value != "" {
			fullKey := strings.Join(pathStack, ".")
			if _, exists := result[fullKey]; !exists {
				result[fullKey] = value
			}
		}
	}
	return result
}

func (c *ConfigFileParser) loadEnvVars() {
	for _, env := range os.Environ() {
		idx := strings.Index(env, "=")
		if idx <= 0 {
			continue
		}
		envKey := env[:idx]
		envValue := env[idx+1:]
		matched := false
		for _, prefix := range envConfigPrefixes {
			if strings.HasPrefix(envKey, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		configKey := strings.ToLower(strings.ReplaceAll(envKey, "_", "."))
		for strings.Contains(configKey, "..") {
			configKey = strings.ReplaceAll(configKey, "..", ".")
		}
		if _, exists := c.Properties[configKey]; !exists {
			c.Properties[configKey] = envValue
		}
	}
}

func (c *ConfigFileParser) applyProfileOverrides() {
	// spring.profiles.active
	if val, ok := c.Properties["spring.profiles.active"]; ok {
		for _, p := range strings.Split(val, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				c.ActiveProfiles[p] = true
			}
		}
	}
	if val, ok := c.Properties["spring.profiles.include"]; ok {
		for _, p := range strings.Split(val, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				c.ActiveProfiles[p] = true
			}
		}
	}
	// spring.profiles.group.* 分组展开（BFS，镜像 7.py:1040-1058）
	groupPrefix := "spring.profiles.group."
	queue := []string{}
	for k, v := range c.Properties {
		if strings.HasPrefix(k, groupPrefix) {
			groupName := strings.TrimPrefix(k, groupPrefix)
			if c.ActiveProfiles[groupName] {
				for _, sub := range strings.Split(v, ",") {
					sub = strings.TrimSpace(sub)
					if sub != "" && !c.ActiveProfiles[sub] {
						c.ActiveProfiles[sub] = true
						queue = append(queue, sub)
					}
				}
			}
		}
	}
	// BFS 展开嵌套分组
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		gk := groupPrefix + curr
		if v, ok := c.Properties[gk]; ok {
			for _, sub := range strings.Split(v, ",") {
				sub = strings.TrimSpace(sub)
				if sub != "" && !c.ActiveProfiles[sub] {
					c.ActiveProfiles[sub] = true
					queue = append(queue, sub)
				}
			}
		}
	}
	// 按 active profile 覆盖 key.profile → key
	for profile := range c.ActiveProfiles {
		suffix := "." + profile
		for k, v := range c.Properties {
			if strings.HasSuffix(k, suffix) {
				baseKey := strings.TrimSuffix(k, suffix)
				if _, exists := c.Properties[baseKey]; !exists {
					c.Properties[baseKey] = v
				}
			}
		}
	}
}

// ResolveWithPlaceholders 解析 ${key:default} 占位符。
func (c *ConfigFileParser) ResolveWithPlaceholders(value string, visited map[string]bool) string {
	if value == "" || !strings.Contains(value, "${") {
		return value
	}
	if visited == nil {
		visited = make(map[string]bool)
	}
	return placeholderRe.ReplaceAllStringFunc(value, func(match string) string {
		sub := placeholderRe.FindStringSubmatch(match)
		key := sub[1]
		defaultVal := sub[2]
		if visited[key] {
			return match
		}
		visited[key] = true
		if val, ok := c.Properties[key]; ok {
			return c.ResolveWithPlaceholders(val, visited)
		}
		if defaultVal != "" {
			return defaultVal
		}
		return match
	})
}

// Lookup 查找配置表达式（镜像 7.py ConfigFileParser.lookup）。
func (c *ConfigFileParser) Lookup(expression string) string {
	key, defaultVal := parseConfigExpression(expression)
	if key == "" {
		return defaultVal
	}
	if val, ok := c.Properties[key]; ok {
		return c.ResolveWithPlaceholders(val, nil)
	}
	return defaultVal
}

// ExtractSpringDefault 提取 @Value 表达式中的默认值。
func ExtractSpringDefault(expr string) string {
	_, defaultVal := parseConfigExpression(expr)
	return defaultVal
}

func parseConfigExpression(expression string) (key, defaultVal string) {
	if expression == "" {
		return "", ""
	}
	// #{...} SpEL — 非贪婪匹配最外层（镜像 7.py:1122-1167）
	if strings.HasPrefix(expression, "#{") {
		// 找到最外层闭合 }（括号计数）
		depth := 0
		endIdx := -1
		for i, ch := range expression {
			if ch == '{' {
				depth++
			} else if ch == '}' {
				depth--
				if depth == 0 {
					endIdx = i
					break
				}
			}
		}
		if endIdx > 0 {
			inner := strings.TrimSpace(expression[2:endIdx])
			return parseSpELInner(inner)
		}
	}
	// ${key:default}
	m := placeholderRe.FindStringSubmatch(expression)
	if m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// parseSpELInner 解析 SpEL 表达式内部内容（镜像 7.py:1126-1167）。
// 不递归解析嵌套三元运算符，只做子模式匹配。
var (
	spELSystemPropsRe = regexp.MustCompile(`systemProperties\[\s*['"]([^'"]+)['"]\s*\]`)
	spELEnvironmentRe = regexp.MustCompile(`environment\[\s*['"]([^'"]+)['"]\s*\]`)
	spELBeanRe        = regexp.MustCompile(`^@(\w+)`)
	spELTypeRe        = regexp.MustCompile(`^T\(([^)]+)\)\.(\w+)`)
	spELNewRe         = regexp.MustCompile(`^new\s+(\w+)`)
)

func parseSpELInner(inner string) (key, defaultVal string) {
	// (a) 含 ${ → 递归调用统一入口处理嵌套占位符
	if idx := strings.Index(inner, "${"); idx >= 0 {
		// 提取 ${...} 部分
		subExpr := inner[idx:]
		// 找到闭合 }
		depth := 0
		endIdx := -1
		for i, ch := range subExpr {
			if ch == '{' {
				depth++
			} else if ch == '}' {
				depth--
				if depth == 0 {
					endIdx = i
					break
				}
			}
		}
		if endIdx > 0 {
			return parseConfigExpression(subExpr[:endIdx+1])
		}
		return parseConfigExpression(subExpr)
	}
	// (b) @beanName
	if m := spELBeanRe.FindStringSubmatch(inner); m != nil {
		return m[1], ""
	}
	// (c) systemProperties['key']
	if m := spELSystemPropsRe.FindStringSubmatch(inner); m != nil {
		return "systemProperties." + m[1], ""
	}
	// (d) environment['key']
	if m := spELEnvironmentRe.FindStringSubmatch(inner); m != nil {
		return m[1], ""
	}
	// (e) T(Class).method
	if m := spELTypeRe.FindStringSubmatch(inner); m != nil {
		return m[1] + "." + m[2], ""
	}
	// (f) new Class()
	if m := spELNewRe.FindStringSubmatch(inner); m != nil {
		return m[1] + ".<init>", ""
	}
	// (g) 纯字面量
	trimmed := strings.TrimSpace(inner)
	if trimmed == "true" || trimmed == "false" {
		return "", trimmed
	}
	if _, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return "", trimmed
	}
	if (strings.HasPrefix(trimmed, "'") && strings.HasSuffix(trimmed, "'")) ||
		(strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"")) {
		return "", trimmed[1 : len(trimmed)-1]
	}
	// 无法识别的 SpEL，返回空
	return "", ""
}

func getProfile(path, ext string) string {
	base := filepath.Base(path)
	namePart := strings.TrimSuffix(base, ext)
	if strings.HasPrefix(namePart, "application-") {
		return strings.TrimPrefix(namePart, "application-")
	}
	return ""
}

func sortConfigFiles(files []string) {
	// 简单排序：application.* 优先
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			iBase := filepath.Base(files[i])
			jBase := filepath.Base(files[j])
			iPrio := 0
			jPrio := 0
			if !strings.Contains(iBase, "application.") {
				iPrio = 1
			}
			if !strings.Contains(jBase, "application.") {
				jPrio = 1
			}
			if iPrio > jPrio {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
}
