package engine

import (
	"strings"

	"github.com/odvcencio/gotreesitter"
)

// ============================================================
//  MethodScope — 变量作用域跟踪（镜像 7.py MethodScope）
// ============================================================

type MethodScope struct {
	className string
	parent    *MethodScope
	vars      map[string]*scopeVar
}

type scopeVar struct {
	varType      string
	taintSources map[string]bool
	// fieldTaint（R5-2）：对象字段污点。当变量指向某方法调用的返回值且该方法的返回值
	// 携带字段污点（如深拷贝 cloneOf 返回的 .data 字段污点来自实参）时记录，
	// 供 checkFieldAccess 对 `var.field` 读取时回溯。
	fieldTaint map[string]string
}

func NewMethodScope(className string, parent *MethodScope) *MethodScope {
	return &MethodScope{
		className: className,
		parent:    parent,
		vars:      make(map[string]*scopeVar),
	}
}

func (s *MethodScope) Define(name, varType string, taintSources map[string]bool) {
	s.vars[name] = &scopeVar{varType: varType, taintSources: taintSources}
}

// Reassign 合并已有变量的 taintSources 而非覆盖（镜像 7.py MethodScope.reassign）。
// 若变量不存在则等价于 Define（varType 留空）。
func (s *MethodScope) Reassign(name string, taintSources map[string]bool) {
	if v, ok := s.vars[name]; ok {
		if taintSources != nil {
			if v.taintSources == nil {
				v.taintSources = make(map[string]bool)
			}
			for src := range taintSources {
				v.taintSources[src] = true
			}
		}
	} else {
		s.vars[name] = &scopeVar{taintSources: taintSources}
	}
}

func (s *MethodScope) Resolve(name string) string {
	if v, ok := s.vars[name]; ok {
		return v.varType
	}
	if s.parent != nil {
		return s.parent.Resolve(name)
	}
	return ""
}

func (s *MethodScope) ResolveTaint(name string) map[string]bool {
	if v, ok := s.vars[name]; ok {
		return v.taintSources
	}
	if s.parent != nil {
		return s.parent.ResolveTaint(name)
	}
	return nil
}

func (s *MethodScope) ClassName() string {
	return s.className
}

// SetFieldTaint（R5-2）：记录变量（对象）的字段污点。
func (s *MethodScope) SetFieldTaint(name, field, source string) {
	v, ok := s.vars[name]
	if !ok {
		v = &scopeVar{}
		s.vars[name] = v
	}
	if v.fieldTaint == nil {
		v.fieldTaint = make(map[string]string)
	}
	v.fieldTaint[field] = source
}

// GetFieldTaint（R5-2）：读取变量的字段污点（沿继承链）。
func (s *MethodScope) GetFieldTaint(name, field string) (string, bool) {
	if v, ok := s.vars[name]; ok && v.fieldTaint != nil {
		if src, ok := v.fieldTaint[field]; ok {
			return src, true
		}
	}
	if s.parent != nil {
		return s.parent.GetFieldTaint(name, field)
	}
	return "", false
}

// ============================================================
//  TypeResolver — 类型推断/方法解析/类继承层次（镜像 7.py TypeResolver）
// ============================================================

type TypeResolver struct {
	store              *AnalysisStore
	typeResolveCache   map[typeCacheKey]string
	methodResolveCache map[methodCacheKey]methodResolveResult
}

type typeCacheKey struct {
	startByte, endByte int
	currentClass       string
	filePath           string
}

type methodCacheKey struct {
	className, methodName string
	argCount              int
}

type methodResolveResult struct {
	class string
	key   string
}

func NewTypeResolver(store *AnalysisStore) *TypeResolver {
	return &TypeResolver{
		store:              store,
		typeResolveCache:   make(map[typeCacheKey]string),
		methodResolveCache: make(map[methodCacheKey]methodResolveResult),
	}
}

// StripGenerics 去除泛型参数：List<String> → List。
func (tr *TypeResolver) StripGenerics(typeStr string) string {
	var result strings.Builder
	depth := 0
	for _, ch := range typeStr {
		if ch == '<' {
			depth++
		} else if ch == '>' {
			depth--
		} else if depth == 0 {
			result.WriteRune(ch)
		}
	}
	return strings.TrimSpace(result.String())
}

// GetFirstGenericParam 提取第一个泛型参数：List<String> → String。
func (tr *TypeResolver) GetFirstGenericParam(typeStr string) string {
	start := strings.Index(typeStr, "<")
	if start < 0 {
		return ""
	}
	depth := 0
	end := -1
	for i := start; i < len(typeStr); i++ {
		if typeStr[i] == '<' {
			depth++
		} else if typeStr[i] == '>' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return ""
	}
	inner := strings.TrimSpace(typeStr[start+1 : end])
	innerDepth := 0
	for i, ch := range inner {
		if ch == '<' {
			innerDepth++
		} else if ch == '>' {
			innerDepth--
		} else if ch == ',' && innerDepth == 0 {
			inner = inner[:i]
			break
		}
	}
	return tr.StripGenerics(strings.TrimSpace(inner))
}

// ResolveMethodClass 在类继承层次中解析方法定义所在类。
// 返回 (定义类名, 方法全限定Key)，未找到返回 ("", "")。
func (tr *TypeResolver) ResolveMethodClass(className, methodName string, argCount int) (string, string) {
	cacheKey := methodCacheKey{className, methodName, argCount}
	if cached, ok := tr.methodResolveCache[cacheKey]; ok {
		return cached.class, cached.key
	}
	cls, key := tr.resolveMethodClassImpl(className, methodName, argCount)
	tr.methodResolveCache[cacheKey] = methodResolveResult{cls, key}
	return cls, key
}

func (tr *TypeResolver) resolveMethodClassImpl(className, methodName string, argCount int) (string, string) {
	visited := make(map[string]bool)
	queue := []string{className}
	for len(queue) > 0 {
		cls := queue[0]
		queue = queue[1:]
		if visited[cls] {
			continue
		}
		visited[cls] = true
		pattern := cls + "." + methodName
		if matched, ok := tr.store.Indices.MethodNameIndex[pattern]; ok && len(matched) > 0 {
			for _, m := range matched {
				if pc, exists := tr.store.Methods.ParamCounts[m]; exists && pc == argCount {
					return cls, m
				}
			}
			return cls, matched[0]
		}
		if parent, ok := tr.store.Types.ClassExtends[cls]; ok {
			queue = append(queue, parent)
		}
		for _, iface := range tr.store.Types.ClassInterfaces[cls] {
			queue = append(queue, iface)
		}
	}
	return "", ""
}

// ResolveFieldTypeInHierarchy 在类层次中解析字段类型。
func (tr *TypeResolver) ResolveFieldTypeInHierarchy(className, fieldName string) string {
	visited := make(map[string]bool)
	queue := []string{className}
	for len(queue) > 0 {
		cls := queue[0]
		queue = queue[1:]
		if visited[cls] {
			continue
		}
		visited[cls] = true
		fieldKey := cls + "." + fieldName
		if ft, ok := tr.store.Types.GlobalFieldTypes[fieldKey]; ok {
			return ft
		}
		if parent, ok := tr.store.Types.ClassExtends[cls]; ok {
			queue = append(queue, parent)
		}
		for _, iface := range tr.store.Types.ClassInterfaces[cls] {
			queue = append(queue, iface)
		}
	}
	return ""
}

// ResolveType 推断 AST 表达式节点的类型。
func (tr *TypeResolver) ResolveType(exprNode *gotreesitter.Node, currentClass string, src []byte, filePath string, scope *MethodScope) string {
	if exprNode == nil {
		return ""
	}
	if nodeType(exprNode) == "identifier" {
		return tr.resolveTypeImpl(exprNode, currentClass, src, filePath, scope)
	}
	cacheKey := typeCacheKey{
		startByte:    int(exprNode.StartByte()),
		endByte:      int(exprNode.EndByte()),
		currentClass: currentClass,
		filePath:     filePath,
	}
	if cached, ok := tr.typeResolveCache[cacheKey]; ok {
		return cached
	}
	result := tr.resolveTypeImpl(exprNode, currentClass, src, filePath, scope)
	if len(tr.typeResolveCache) < tr.store.Config.TypeResolveCacheSize {
		tr.typeResolveCache[cacheKey] = result
	}
	return result
}

func (tr *TypeResolver) resolveTypeImpl(exprNode *gotreesitter.Node, currentClass string, src []byte, filePath string, scope *MethodScope) string {
	nodeT := nodeType(exprNode)
	switch nodeT {
	case "identifier":
		name := nodeText(src, exprNode)
		if name == "this" {
			return currentClass
		}
		if name == "super" {
			if parent, ok := tr.store.Types.ClassExtends[currentClass]; ok {
				return parent
			}
			return currentClass
		}
		imports := tr.store.Types.ImportsMap[filePath]
		if fqn, ok := imports[name]; ok {
			if tr.store.Types.AmbiguousNames[name] {
				return tr.resolveClassForFile(name, filePath)
			}
			parts := strings.Split(fqn, ".")
			return parts[len(parts)-1]
		}
		if scope != nil {
			localType := scope.Resolve(name)
			if localType != "" {
				stripped := tr.StripGenerics(localType)
				parts := strings.Split(stripped, ".")
				return parts[len(parts)-1]
			}
		}
		fieldKey := currentClass + "." + name
		if ft, ok := tr.store.Types.GlobalFieldTypes[fieldKey]; ok {
			stripped := tr.StripGenerics(ft)
			parts := strings.Split(stripped, ".")
			return parts[len(parts)-1]
		}
		if tr.store.Types.ClassNameSet[name] {
			return name
		}
		return name

	case "object_creation_expression":
		typeNode := fieldChild(exprNode, "type")
		if typeNode != nil {
			stripped := tr.StripGenerics(nodeText(src, typeNode))
			parts := strings.Split(stripped, ".")
			return parts[len(parts)-1]
		}

	case "cast_expression":
		typeNode := fieldChild(exprNode, "type")
		if typeNode != nil {
			stripped := tr.StripGenerics(nodeText(src, typeNode))
			parts := strings.Split(stripped, ".")
			return parts[len(parts)-1]
		}

	case "field_access":
		objNode := fieldChild(exprNode, "object")
		fieldNode := fieldChild(exprNode, "field")
		if objNode != nil && fieldNode != nil {
			objText := nodeText(src, objNode)
			fieldName := nodeText(src, fieldNode)
			if objText == "this" || objText == currentClass {
				ft := tr.ResolveFieldTypeInHierarchy(currentClass, fieldName)
				if ft != "" {
					stripped := tr.StripGenerics(ft)
					parts := strings.Split(stripped, ".")
					return parts[len(parts)-1]
				}
				return ""
			}
			if strings.HasSuffix(objText, ".this") {
				outerClass := objText[:len(objText)-5]
				if currentClass != "" && strings.Contains(currentClass, "$") {
					parts := strings.Split(currentClass, "$")
					for i := range parts {
						candidate := strings.Join(parts[:i+1], "$")
						if strings.HasSuffix(candidate, outerClass) || outerClass == parts[i] {
							ft := tr.ResolveFieldTypeInHierarchy(candidate, fieldName)
							if ft != "" {
								stripped := tr.StripGenerics(ft)
								parts2 := strings.Split(stripped, ".")
								return parts2[len(parts2)-1]
							}
						}
					}
				}
				ft := tr.ResolveFieldTypeInHierarchy(outerClass, fieldName)
				if ft != "" {
					stripped := tr.StripGenerics(ft)
					parts := strings.Split(stripped, ".")
					return parts[len(parts)-1]
				}
				return ""
			}
			objClass := tr.ResolveType(objNode, currentClass, src, filePath, scope)
			if objClass != "" {
				fieldKey := objClass + "." + fieldName
				if ft, ok := tr.store.Types.GlobalFieldTypes[fieldKey]; ok {
					stripped := tr.StripGenerics(ft)
					parts := strings.Split(stripped, ".")
					return parts[len(parts)-1]
				}
				ft := tr.ResolveFieldTypeInHierarchy(objClass, fieldName)
				if ft != "" {
					stripped := tr.StripGenerics(ft)
					parts := strings.Split(stripped, ".")
					return parts[len(parts)-1]
				}
			}
		}
		return ""

	case "method_invocation":
		objNode := fieldChild(exprNode, "object")
		nameNode := fieldChild(exprNode, "name")
		if nameNode != nil {
			calledMethod := nodeText(src, nameNode)
			var objClass string
			if objNode != nil {
				objText := nodeText(src, objNode)
				if objText == "super" {
					if parent, ok := tr.store.Types.ClassExtends[currentClass]; ok {
						objClass = parent
					} else {
						objClass = currentClass
					}
				} else {
					objClass = tr.ResolveType(objNode, currentClass, src, filePath, scope)
				}
			} else {
				objClass = currentClass
			}
			if objClass != "" {
				sigPattern := objClass + "." + calledMethod
				if matched, ok := tr.store.Indices.MethodNameIndex[sigPattern]; ok && len(matched) > 0 {
					argCount := tr.CountArguments(exprNode)
					bestMatch := ""
					for _, mk := range matched {
						if pc, exists := tr.store.Methods.ParamCounts[mk]; exists && pc == argCount {
							bestMatch = mk
							break
						}
					}
					if bestMatch == "" {
						bestMatch = matched[0]
					}
					if sig, exists := tr.store.Types.MethodSigs[bestMatch]; exists && len(sig) > 0 {
						returnType := sig[0]
						baseReturn := tr.StripGenerics(returnType)
						parts := strings.Split(baseReturn, ".")
						baseReturn = parts[len(parts)-1]
						if baseReturn == "Object" || baseReturn == "T" {
							if objNode != nil && nodeText(src, objNode) != "super" {
								objFieldName := nodeText(src, objNode)
								objFieldKey := currentClass + "." + objFieldName
								if rawType, ok := tr.store.Types.GlobalFieldTypes[objFieldKey]; ok {
									firstParam := tr.GetFirstGenericParam(rawType)
									if firstParam != "" {
										parts := strings.Split(firstParam, ".")
										return parts[len(parts)-1]
									}
								}
							}
						}
						return baseReturn
					}
				}
				lookup := objClass + "." + calledMethod
				if ret, ok := jdkReturnTypes[lookup]; ok {
					if ret == "Object" && objNode != nil && nodeText(src, objNode) != "super" {
						objFieldName := nodeText(src, objNode)
						objFieldKey := currentClass + "." + objFieldName
						if rawType, ok := tr.store.Types.GlobalFieldTypes[objFieldKey]; ok {
							firstParam := tr.GetFirstGenericParam(rawType)
							if firstParam != "" {
								parts := strings.Split(firstParam, ".")
								return parts[len(parts)-1]
							}
						}
					}
					return ret
				}
			}
		}
		return ""

	case "parenthesized_expression":
		for _, child := range nodeChildren(exprNode) {
			ct := nodeType(child)
			if ct != "(" && ct != ")" {
				return tr.ResolveType(child, currentClass, src, filePath, scope)
			}
		}

	case "ternary_expression":
		consequence := fieldChild(exprNode, "consequence")
		if consequence != nil {
			return tr.ResolveType(consequence, currentClass, src, filePath, scope)
		}
		alternative := fieldChild(exprNode, "alternative")
		if alternative != nil {
			return tr.ResolveType(alternative, currentClass, src, filePath, scope)
		}

	case "array_creation_expression":
		typeNode := fieldChild(exprNode, "type")
		if typeNode != nil {
			baseType := tr.StripGenerics(nodeText(src, typeNode))
			parts := strings.Split(baseType, ".")
			return parts[len(parts)-1] + "[]"
		}

	case "array_access":
		arrayNode := fieldChild(exprNode, "array")
		if arrayNode != nil {
			arrType := tr.ResolveType(arrayNode, currentClass, src, filePath, scope)
			if strings.HasSuffix(arrType, "[]") {
				return arrType[:len(arrType)-2]
			}
			return arrType
		}
	}
	return ""
}

func (tr *TypeResolver) resolveClassForFile(simpleName, filePath string) string {
	if !tr.store.Types.AmbiguousNames[simpleName] {
		return simpleName
	}
	key := simpleName + "::" + filePath
	if fqn, ok := tr.store.Types.FqnResolution[key]; ok {
		parts := strings.Split(fqn, ".")
		return parts[len(parts)-1]
	}
	return simpleName
}

// CountArguments 计算方法调用的参数个数。
func (tr *TypeResolver) CountArguments(invocationNode *gotreesitter.Node) int {
	argList := fieldChild(invocationNode, "arguments")
	if argList == nil {
		for _, child := range nodeChildren(invocationNode) {
			if nodeType(child) == "argument_list" {
				argList = child
				break
			}
		}
	}
	if argList == nil {
		return 0
	}
	count := 0
	for _, c := range nodeChildren(argList) {
		if argumentNodeTypes[nodeType(c)] {
			count++
		}
	}
	return count
}

func (tr *TypeResolver) ClearCaches() {
	tr.typeResolveCache = make(map[typeCacheKey]string)
	tr.methodResolveCache = make(map[methodCacheKey]methodResolveResult)
}
