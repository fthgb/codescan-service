package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// ============================================================
//  FieldValueResolver — 8 种字段值解析器（镜像 7.py L2096-2445）
//  显式优先级链：Config → ConfigDefault → SpringInjection →
//  ConfigProperties → PostConstruct → Constructor → Declaration → JavaDefault
// ============================================================

// FieldValueContribution — 字段值解析结果。
type FieldValueContribution struct {
	Priority int                    `json:"priority"`
	Source   string                 `json:"source"`
	Value    string                 `json:"value"`
	FilePath string                 `json:"file_path,omitempty"`
	Line     int                    `json:"line,omitempty"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// FieldValueResolverBase — 解析器基类（Go 用接口 + 结构体组合）。
type FieldValueResolverBase interface {
	Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution
}

// ─── 1. ConfigValueResolver（优先级1: @Value 配置值） ───
type ConfigValueResolver struct{}

func (r ConfigValueResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	key := className + "." + fieldName
	fdef, ok := store.Fields.Defs[key]
	if !ok {
		return nil
	}
	for _, ann := range fdef.Annotations {
		if ann.Name == "Value" {
			expr := ann.Params["_value"]
			if store.ConfigParser != nil {
				configVal := store.ConfigParser.Lookup(expr)
				if configVal != "" {
					return &FieldValueContribution{
						Priority: 1, Source: "@Value配置", Value: configVal,
						Extra: map[string]interface{}{
							"config_key":       expr,
							"config_value":     configVal,
							"spring_injection": "@Value(" + expr + ")",
						},
					}
				}
			}
		}
	}
	return nil
}

// ─── 2. ConfigDefaultValueResolver（优先级2: @Value 默认值） ───
type ConfigDefaultValueResolver struct{}

func (r ConfigDefaultValueResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	key := className + "." + fieldName
	fdef, ok := store.Fields.Defs[key]
	if !ok {
		return nil
	}
	for _, ann := range fdef.Annotations {
		if ann.Name == "Value" {
			expr := ann.Params["_value"]
			if store.ConfigParser != nil {
				configVal := store.ConfigParser.Lookup(expr)
				if configVal == "" {
					configDefault := ExtractSpringDefault(expr)
					if configDefault != "" {
						return &FieldValueContribution{
							Priority: 2, Source: "@Value默认值", Value: configDefault,
							Extra: map[string]interface{}{
								"config_key":       expr,
								"config_default":   configDefault,
								"spring_injection": "@Value(" + expr + ")",
							},
						}
					}
				}
			}
		}
	}
	return nil
}

// ─── 3. SpringInjectionResolver（优先级3: Spring 注入） ───
type SpringInjectionResolver struct{}

func (r SpringInjectionResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	key := className + "." + fieldName
	fdef, ok := store.Fields.Defs[key]
	if !ok {
		return nil
	}
	injection := ""
	qualifierName := ""
	for _, ann := range fdef.Annotations {
		switch ann.Name {
		case "Autowired":
			injection = "@Autowired"
		case "Resource":
			injection = "@Resource"
		case "Inject":
			injection = "@Inject"
		case "Qualifier":
			qualifierName = ann.Params["_value"]
		case "Value":
			expr := ann.Params["_value"]
			injection = "@Value(" + expr + ")"
		}
	}
	if injection == "" {
		return nil
	}
	var beanInfo []map[string]interface{}
	if injection == "@Autowired" || injection == "@Resource" || injection == "@Inject" {
		if fieldType, ok := store.Types.GlobalFieldTypes[key]; ok {
			baseType := tr.StripGenerics(fieldType)
			if dotIdx := strings.LastIndex(baseType, "."); dotIdx >= 0 {
				baseType = baseType[dotIdx+1:]
			}
			if producerMethods, ok := store.Types.BeanProducers[baseType]; ok && len(producerMethods) > 0 {
				if qualifierName != "" {
					var qualified []string
					for _, m := range producerMethods {
						if strings.Contains(m, qualifierName) {
							qualified = append(qualified, m)
						}
					}
					if len(qualified) > 0 {
						producerMethods = qualified
					}
				}
				injection = injection + " → [" + strings.Join(producerMethods, ", ") + "]"
				for _, pmk := range producerMethods {
					if fn, ok := store.Methods.Functions[pmk]; ok {
						beanInfo = append(beanInfo, map[string]interface{}{
							"method_key":    pmk,
							"file_path":     fn.FilePath,
							"line":          fn.Line,
							"return_taints": store.Methods.ReturnTaints[pmk],
						})
					}
				}
			}
		}
	}
	return &FieldValueContribution{
		Priority: 3, Source: "Spring注入", Value: injection,
		Extra: map[string]interface{}{
			"spring_injection":   injection,
			"bean_producer_info": beanInfo,
		},
	}
}

// ─── 4. ConfigPropertiesResolver（优先级4: @ConfigurationProperties） ───
type ConfigPropertiesResolver struct{}

var camelToKebabRe1 = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
var camelToKebabRe2 = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func (r ConfigPropertiesResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	if _, ok := store.Fields.ConfigPropsClasses[className]; !ok {
		return nil
	}
	key := className + "." + fieldName
	fdef, ok := store.Fields.Defs[key]
	_ = fdef
	if !ok {
		return nil
	}
	if store.Fields.IsStatic[key] || store.Fields.IsTransient[key] {
		return nil
	}
	prefix := store.Fields.ConfigPropsClasses[className]
	if store.ConfigParser == nil {
		return nil
	}
	normalizedTarget := normalizeConfigKey(prefix) + "." + normalizeConfigKey(fieldName)
	for ckey, val := range store.ConfigParser.Properties {
		if normalizeConfigKey(ckey) == normalizedTarget {
			return &FieldValueContribution{
				Priority: 4, Source: "@ConfigurationProperties", Value: val,
				Extra: map[string]interface{}{
					"config_key":       ckey,
					"config_value":     val,
					"spring_injection": "@ConfigurationProperties(prefix=" + prefix + ")",
				},
			}
		}
	}
	camelToKebab := camelToKebabRe1.ReplaceAllString(fieldName, "$1-$2")
	camelToKebab = camelToKebabRe2.ReplaceAllString(camelToKebab, "$1-$2")
	camelToKebab = strings.ReplaceAll(camelToKebab, "_", "-")
	camelToKebab = strings.ToLower(camelToKebab)
	candidates := []string{
		prefix + "." + camelToKebab,
		prefix + "." + fieldName,
		prefix + "." + strings.ReplaceAll(fieldName, "_", "."),
	}
	for _, candidate := range candidates {
		if val, ok := store.ConfigParser.Properties[candidate]; ok {
			return &FieldValueContribution{
				Priority: 4, Source: "@ConfigurationProperties", Value: val,
				Extra: map[string]interface{}{
					"config_key":       candidate,
					"config_value":     val,
					"spring_injection": "@ConfigurationProperties(prefix=" + prefix + ")",
				},
			}
		}
	}
	return nil
}

// ─── 5. PostConstructResolver（优先级5: @PostConstruct） ───
type PostConstructResolver struct{}

func (r PostConstructResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	key := className + "." + fieldName
	if store.Fields.IsStatic[key] {
		return nil
	}
	for _, assignment := range store.Fields.Assignments[key] {
		if assignment.AssignType == AssignPostConstruct {
			return &FieldValueContribution{
				Priority: 5, Source: "@PostConstruct", Value: assignment.AssignText,
				FilePath: assignment.FilePath, Line: assignment.Line,
				Extra: map[string]interface{}{"method_name": assignment.MethodName},
			}
		}
	}
	return nil
}

// ─── 6. ConstructorResolver（优先级6: 构造函数） ───
type ConstructorResolver struct{}

func (r ConstructorResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	key := className + "." + fieldName
	isStatic := store.Fields.IsStatic[key]
	for _, assignment := range store.Fields.Assignments[key] {
		if assignment.AssignType == AssignConstructor {
			if isStatic && assignment.MethodName != "<static_init>" && assignment.MethodName != "<clinit>" {
				continue
			}
			if !isStatic && assignment.MethodName == "<static_init>" {
				continue
			}
			return &FieldValueContribution{
				Priority: 6, Source: "构造函数", Value: assignment.AssignText,
				FilePath: assignment.FilePath, Line: assignment.Line,
				Extra: map[string]interface{}{"method_name": assignment.MethodName},
			}
		}
	}
	return nil
}

// ─── 7. DeclarationResolver（优先级7: 声明处初始化） ───
type DeclarationResolver struct{}

func (r DeclarationResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	key := className + "." + fieldName
	fdef, ok := store.Fields.Defs[key]
	if ok && fdef.InitText != "" {
		return &FieldValueContribution{
			Priority: 7, Source: "声明处初始化", Value: fdef.InitText,
			FilePath: fdef.FilePath, Line: fdef.Line,
		}
	}
	return nil
}

// ─── 8. JavaDefaultResolver（优先级8: Java 语言默认值） ───
type JavaDefaultResolver struct{}

func (r JavaDefaultResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	key := className + "." + fieldName
	typeName := store.Types.GlobalFieldTypes[key]
	baseType := tr.StripGenerics(typeName)
	if bracketIdx := strings.Index(baseType, "["); bracketIdx > 0 {
		baseType = strings.TrimSpace(baseType[:bracketIdx])
	}
	if defVal, ok := javaPrimitiveDefaults[baseType]; ok {
		return &FieldValueContribution{
			Priority: 8, Source: "Java默认值", Value: defVal + " (Java 默认值)",
		}
	}
	return &FieldValueContribution{
		Priority: 8, Source: "Java默认值", Value: "null (Java 默认值)",
	}
}

// ============================================================
//  FieldValueResolver — 优先级链组合器
// ============================================================

type FieldValueResolver struct {
	chain []FieldValueResolverBase
}

func NewFieldValueResolver() *FieldValueResolver {
	return &FieldValueResolver{
		chain: []FieldValueResolverBase{
			ConfigValueResolver{},
			ConfigDefaultValueResolver{},
			SpringInjectionResolver{},
			ConfigPropertiesResolver{},
			PostConstructResolver{},
			ConstructorResolver{},
			DeclarationResolver{},
			JavaDefaultResolver{},
		},
	}
}

// Resolve 按优先级链解析字段值，返回第一个命中结果。
func (fvr *FieldValueResolver) Resolve(store *AnalysisStore, tr *TypeResolver, className, fieldName string) *FieldValueContribution {
	for _, resolver := range fvr.chain {
		if result := resolver.Resolve(store, tr, className, fieldName); result != nil {
			return result
		}
	}
	return nil
}

// GetEffectiveValueSummary 返回字段有效值的中文摘要（镜像 7.py:2421-2440）。
func (fvr *FieldValueResolver) GetEffectiveValueSummary(store *AnalysisStore, tr *TypeResolver, className, fieldName string) string {
	contrib := fvr.Resolve(store, tr, className, fieldName)
	if contrib == nil {
		return "无可用值"
	}
	summary := contrib.Value
	if summary == "" {
		summary = "(空)"
	}
	location := ""
	if contrib.FilePath != "" {
		location = fmt.Sprintf(" [%s:%d]", contrib.FilePath, contrib.Line)
	}
	return fmt.Sprintf("值=%s 来源=%s%s", summary, contrib.Source, location)
}

// ─── 辅助函数 ───

func normalizeConfigKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", "."))
}
