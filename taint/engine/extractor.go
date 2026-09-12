package engine

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/odvcencio/gotreesitter"
)

// ============================================================
//  collectAnnotationInfo — 提取节点注解信息（镜像 7.py L281-327）
// ============================================================

func collectAnnotationInfo(node *gotreesitter.Node, src []byte) []Annotation {
	var annotations []Annotation

	processAnnotation := func(annNode *gotreesitter.Node) {
		nt := nodeType(annNode)
		if nt == "marker_annotation" {
			nameNode := fieldChild(annNode, "name")
			if nameNode != nil {
				annotations = append(annotations, Annotation{
					Name:   nodeText(src, nameNode),
					Params: make(map[string]string),
				})
			}
		} else if nt == "annotation" {
			nameNode := fieldChild(annNode, "name")
			name := ""
			if nameNode != nil {
				name = nodeText(src, nameNode)
			}
			params := make(map[string]string)
			for _, child := range nodeChildren(annNode) {
				if nodeType(child) == "annotation_argument_list" {
					for _, arg := range nodeChildren(child) {
						at := nodeType(arg)
						switch at {
						case "string_literal":
							val := strings.Trim(nodeText(src, arg), `"`)
							params["_value"] = strings.TrimSpace(val)
						case "number_literal":
							params["_value"] = strings.TrimSpace(nodeText(src, arg))
						case "true", "false":
							params["_value"] = strings.TrimSpace(nodeText(src, arg))
						case "element_value_pair":
							keyNode := fieldChild(arg, "key")
							valNode := fieldChild(arg, "value")
							if keyNode != nil && valNode != nil {
								k := nodeText(src, keyNode)
								v := strings.Trim(nodeText(src, valNode), `"`)
								params[k] = strings.TrimSpace(v)
							}
						}
					}
				}
			}
			if name != "" {
				annotations = append(annotations, Annotation{Name: name, Params: params})
			}
		}
	}

	for _, child := range nodeChildren(node) {
		if nodeType(child) == "modifiers" {
			for _, modChild := range nodeChildren(child) {
				processAnnotation(modChild)
			}
		} else {
			processAnnotation(child)
		}
	}
	return annotations
}

// ============================================================
//  Extractor — 第一遍 AST 抽取（镜像 7.py _first_pass/_walk_first_pass）
// ============================================================

type Extractor struct {
	store        *AnalysisStore
	typeResolver *TypeResolver
	anonClassMap map[[2]int]string
}

func NewExtractor(store *AnalysisStore, tr *TypeResolver) *Extractor {
	return &Extractor{
		store:        store,
		typeResolver: tr,
		anonClassMap: make(map[[2]int]string),
	}
}

// GetJavaFiles 遍历仓库收集 .java 文件（跳过 ignoreDirs）。
func (e *Extractor) GetJavaFiles(repoRoot string) []string {
	var files []string
	filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if ignoreDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(info.Name(), ".java") {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// FirstPass 第一遍扫描：抽取 imports/package/class/method/field/annotation。
func (e *Extractor) FirstPass(repoRoot string) {
	for _, filePath := range e.GetJavaFiles(repoRoot) {
		pf, err := parseJavaFile(filePath)
		if err != nil {
			continue
		}
		e.extractImports(pf.Root, pf.Src, filePath)
		pkgName := e.extractPackage(pf.Root, pf.Src)
		e.walkFirstPass(pf.Root, pf.Src, filePath, pkgName)
	}
	e.resolveWildcardImports()
	e.store.Types.ClassNameSet = make(map[string]bool)
	for cls := range e.store.Types.ClassAnnotations {
		e.store.Types.ClassNameSet[cls] = true
	}
}

func (e *Extractor) extractPackage(root *gotreesitter.Node, src []byte) string {
	for _, node := range nodeChildren(root) {
		if nodeType(node) == "package_declaration" {
			for _, child := range nodeChildren(node) {
				ct := nodeType(child)
				if ct == "scoped_identifier" || ct == "identifier" {
					return nodeText(src, child)
				}
			}
		}
	}
	return ""
}

func (e *Extractor) extractImports(root *gotreesitter.Node, src []byte, filePath string) {
	imports := make(map[string]string)
	var wildcards []string
	for _, node := range nodeChildren(root) {
		if nodeType(node) == "import_declaration" {
			text := nodeText(src, node)
			isStatic := strings.Contains(text, "static ")
			cleanText := strings.ReplaceAll(text, "import ", "")
			cleanText = strings.ReplaceAll(cleanText, "static ", "")
			cleanText = strings.ReplaceAll(cleanText, ";", "")
			cleanText = strings.TrimSpace(cleanText)
			parts := strings.Split(cleanText, ".")
			if strings.Contains(cleanText, "*") {
				pkg := strings.ReplaceAll(cleanText, "*", "")
				pkg = strings.TrimSuffix(pkg, ".")
				if pkg != "" {
					wildcards = append(wildcards, pkg)
				}
			} else if len(parts) >= 2 {
				if isStatic {
					clsName := parts[len(parts)-2]
					fullClass := strings.Join(parts[:len(parts)-1], ".")
					imports[clsName] = fullClass
					imports[parts[len(parts)-1]] = fullClass
				} else {
					simple := parts[len(parts)-1]
					full := strings.Join(parts, ".")
					imports[simple] = full
				}
			}
		}
	}
	// 存储通配符导入供后续解析
	for _, pkg := range wildcards {
		imports["_wildcard_"+pkg] = pkg
	}
	e.store.Types.ImportsMap[filePath] = imports
}

func (e *Extractor) resolveWildcardImports() {
	for _, imps := range e.store.Types.ImportsMap {
		var wildcards []string
		for k, v := range imps {
			if strings.HasPrefix(k, "_wildcard_") {
				wildcards = append(wildcards, v)
				delete(imps, k)
			}
		}
		for _, pkg := range wildcards {
			if classes, ok := e.store.Types.PackageClassMap[pkg]; ok {
				for clsName := range classes {
					if _, exists := imps[clsName]; !exists {
						imps[clsName] = pkg + "." + clsName
					}
				}
			}
		}
	}
}

func (e *Extractor) getMethodKey(node *gotreesitter.Node, currentClass string, src []byte) string {
	nameNode := fieldChild(node, "name")
	methodName := ""
	if nameNode != nil {
		methodName = nodeText(src, nameNode)
	} else if nodeType(node) == "constructor_declaration" {
		methodName = "<init>"
	} else {
		return ""
	}
	paramsNode := fieldChild(node, "parameters")
	var paramTypes []string
	if paramsNode != nil {
		for _, param := range nodeChildren(paramsNode) {
			if nodeType(param) == "formal_parameter" {
				typeNode := fieldChild(param, "type")
				if typeNode != nil {
					paramTypes = append(paramTypes, e.typeResolver.StripGenerics(nodeText(src, typeNode)))
				}
			}
		}
	}
	return MethodKeyHelper{}.Build(currentClass, methodName, paramTypes)
}

func (e *Extractor) walkFirstPass(root *gotreesitter.Node, src []byte, filePath, currentPkg string) {
	var walk func(node *gotreesitter.Node, classStack []string, isIfaceStack []bool)
	walk = func(node *gotreesitter.Node, classStack []string, isIfaceStack []bool) {
		enteredClass := false
		nt := nodeType(node)
		if nt == "class_declaration" || nt == "interface_declaration" ||
			nt == "enum_declaration" || nt == "record_declaration" {
			nameNode := fieldChild(node, "name")
			if nameNode != nil {
				clsName := nodeText(src, nameNode)
				if len(classStack) > 0 {
					clsName = classStack[len(classStack)-1] + "$" + clsName
				}
				classStack = append(classStack, clsName)
				isIfaceStack = append(isIfaceStack, nt == "interface_declaration")
				enteredClass = true
				if currentPkg != "" {
					if e.store.Types.PackageClassMap[currentPkg] == nil {
						e.store.Types.PackageClassMap[currentPkg] = make(map[string]bool)
					}
					e.store.Types.PackageClassMap[currentPkg][clsName] = true
				}
				e.store.Types.ClassAnnotations[clsName] = collectAnnotationInfo(node, src)
				for _, ann := range e.store.Types.ClassAnnotations[clsName] {
					if ann.Name == "ConfigurationProperties" {
						prefix := ann.Params["prefix"]
						if prefix == "" {
							prefix = ann.Params["_value"]
						}
						e.store.Fields.ConfigPropsClasses[clsName] = prefix
					} else if ann.Name == "ConstructorBinding" {
						e.store.Types.ConstructorBindingClasses[clsName] = true
					}
				}
				// superclass
				superclassNode := fieldChild(node, "superclass")
				if superclassNode != nil {
					for _, child := range nodeChildren(superclassNode) {
						if nodeType(child) == "type_identifier" {
							e.store.Types.ClassExtends[clsName] = nodeText(src, child)
							break
						}
					}
				}
				// interfaces
				var ifaces []string
				for _, child := range nodeChildren(node) {
					ct := nodeType(child)
					if ct == "super_interfaces" || ct == "interface_list" || ct == "extends_interfaces" {
						for _, ifaceChild := range nodeChildren(child) {
							if nodeType(ifaceChild) == "type_identifier" {
								ifaces = append(ifaces, nodeText(src, ifaceChild))
							} else if nodeType(ifaceChild) == "type_list" {
								for _, t := range nodeChildren(ifaceChild) {
									if nodeType(t) == "type_identifier" {
										ifaces = append(ifaces, nodeText(src, t))
									}
								}
							}
						}
					}
				}
				e.store.Types.ClassInterfaces[clsName] = ifaces
				// record formal parameters as fields
				if nt == "record_declaration" {
					for _, child := range nodeChildren(node) {
						if nodeType(child) == "formal_parameters" {
							for _, param := range nodeChildren(child) {
								if nodeType(param) == "formal_parameter" {
									ptype := fieldChild(param, "type")
									pname := fieldChild(param, "name")
									if ptype != nil && pname != nil {
										ftype := strings.TrimSpace(nodeText(src, ptype))
										fname := nodeText(src, pname)
										fkey := clsName + "." + fname
										e.store.Types.GlobalFieldTypes[fkey] = ftype
										getterKey := clsName + "." + fname + "()"
										e.store.Types.MethodSigs[getterKey] = []string{ftype}
										e.store.Types.ClassAllMethods[clsName] = append(
											e.store.Types.ClassAllMethods[clsName], getterKey)
										e.store.RegisterMethodIndex(getterKey)
										e.store.Methods.ParamCounts[getterKey] = 0
									}
								}
							}
						}
					}
				}
			}
		}
		// 匿名类
		if nt == "object_creation_expression" {
			for _, child := range nodeChildren(node) {
				if nodeType(child) == "class_body" {
					anonKey := [2]int{filePath2int(filePath), int(node.StartByte())}
					anonClsName, exists := e.anonClassMap[anonKey]
					if !exists {
						anonIdx := len(e.anonClassMap) + 1
						if len(classStack) > 0 {
							anonClsName = classStack[len(classStack)-1] + "$Anonymous$" + itoa(anonIdx)
						} else {
							anonClsName = "Anonymous$" + itoa(anonIdx)
						}
						e.anonClassMap[anonKey] = anonClsName
					}
					classStack = append(classStack, anonClsName)
					isIfaceStack = append(isIfaceStack, false)
					for _, bodyChild := range nodeChildren(child) {
						walk(bodyChild, classStack, isIfaceStack)
					}
					classStack = classStack[:len(classStack)-1]
					isIfaceStack = isIfaceStack[:len(isIfaceStack)-1]
				}
			}
		}
		currentClass := ""
		if len(classStack) > 0 {
			currentClass = classStack[len(classStack)-1]
		}
		currentIsIface := false
		if len(isIfaceStack) > 0 {
			currentIsIface = isIfaceStack[len(isIfaceStack)-1]
		}
		// method/constructor declaration
		if (nt == "method_declaration" || nt == "constructor_declaration") && currentClass != "" {
			methodKey := e.getMethodKey(node, currentClass, src)
			if methodKey != "" {
				retNode := fieldChild(node, "type")
				returnType := "void"
				if retNode != nil {
					returnType = strings.TrimSpace(nodeText(src, retNode))
				}
				if nt == "constructor_declaration" {
					returnType = currentClass
				}
				// native 修饰符检测（R12 JNI 黑盒识别）
				isNative := false
				for _, child := range nodeChildren(node) {
					if nodeType(child) == "modifiers" {
						for _, mod := range nodeChildren(child) {
							if nodeText(src, mod) == "native" {
								isNative = true
								break
							}
						}
					}
					if isNative {
						break
					}
				}
				if isNative {
					e.store.Methods.NativeMethods[methodKey] = true
				}
				e.store.Types.MethodSigs[methodKey] = []string{returnType}
				e.store.Types.ClassAllMethods[currentClass] = append(
					e.store.Types.ClassAllMethods[currentClass], methodKey)
				e.store.RegisterMethodIndex(methodKey)
				if nt == "constructor_declaration" {
					e.store.Types.ConstructorMethodKeys[methodKey] = true
				}
				e.store.Methods.ParamCounts[methodKey] = MethodKeyHelper{}.ParamCount(methodKey)
				// default method check
				isDefaultMethod := false
				if currentIsIface {
					for _, child := range nodeChildren(node) {
						if nodeType(child) == "modifiers" {
							for _, mod := range nodeChildren(child) {
								if nodeText(src, mod) == "default" {
									isDefaultMethod = true
								}
							}
						}
					}
				}
				if currentIsIface && !isDefaultMethod {
					e.store.Types.InterfaceMethods[methodKey] = true
				}
				annsDetail := collectAnnotationInfo(node, src)
				e.store.Methods.Annotations[methodKey] = annsDetail
				for _, ann := range annsDetail {
					if ann.Name == "Bean" {
						baseReturn := e.typeResolver.StripGenerics(returnType)
						if dotIdx := strings.LastIndex(baseReturn, "."); dotIdx >= 0 {
							baseReturn = baseReturn[dotIdx+1:]
						}
						e.store.Types.BeanProducers[baseReturn] = append(
							e.store.Types.BeanProducers[baseReturn], methodKey)
					}
				}
				if nt == "constructor_declaration" {
					annNames := make(map[string]bool)
					for _, a := range annsDetail {
						annNames[a.Name] = true
					}
					if annNames["Autowired"] {
						if _, ok := e.store.Fields.ConfigPropsClasses[currentClass]; ok {
							e.store.Fields.ConfigPropsCtorClasses[currentClass] =
								e.store.Fields.ConfigPropsClasses[currentClass]
						}
					}
					if e.store.Types.ConstructorBindingClasses[currentClass] {
						e.store.Fields.ConfigPropsCtorClasses[currentClass] =
							e.store.Fields.ConfigPropsClasses[currentClass]
					}
				}
			}
		} else if nt == "field_declaration" && currentClass != "" {
			typeNode := fieldChild(node, "type")
			typeName := ""
			if typeNode != nil {
				typeName = strings.TrimSpace(nodeText(src, typeNode))
			}
			isStatic := false
			isTransient := false
			for _, child := range nodeChildren(node) {
				if nodeType(child) == "modifiers" {
					for _, mod := range nodeChildren(child) {
						modText := nodeText(src, mod)
						if modText == "static" {
							isStatic = true
						} else if modText == "transient" {
							isTransient = true
						}
					}
				}
			}
			for _, decl := range nodeChildren(node) {
				if nodeType(decl) == "variable_declarator" {
					nameNode := fieldChild(decl, "name")
					if nameNode != nil {
						fieldName := nodeText(src, nameNode)
						fkey := currentClass + "." + fieldName
						e.store.Types.GlobalFieldTypes[fkey] = typeName
						if isStatic {
							e.store.Fields.IsStatic[fkey] = true
						}
						if isTransient {
							e.store.Fields.IsTransient[fkey] = true
						}
						// Lombok getter/setter 合成
						clsAnns := e.store.Types.ClassAnnotations[currentClass]
						isLombok := false
						for _, a := range clsAnns {
							if lombokAnnotations[a.Name] {
								isLombok = true
								break
							}
						}
						if isLombok && !isStatic {
							baseType := e.typeResolver.StripGenerics(typeName)
							var getterName string
							if typeName == "boolean" {
								getterName = "is" + strings.ToUpper(fieldName[:1]) + fieldName[1:]
							} else {
								getterName = "get" + strings.ToUpper(fieldName[:1]) + fieldName[1:]
							}
							getterKey := currentClass + "." + getterName + "()"
							e.store.Types.MethodSigs[getterKey] = []string{typeName}
							e.store.Types.ClassAllMethods[currentClass] = append(
								e.store.Types.ClassAllMethods[currentClass], getterKey)
							e.store.RegisterMethodIndex(getterKey)
							e.store.Methods.ParamCounts[getterKey] = 0
							hasValue := false
							for _, a := range clsAnns {
								if a.Name == "Value" {
									hasValue = true
								}
							}
							if !hasValue {
								setterName := "set" + strings.ToUpper(fieldName[:1]) + fieldName[1:]
								setterKey := currentClass + "." + setterName + "(" + baseType + ")"
								e.store.Types.MethodSigs[setterKey] = []string{"void"}
								e.store.Types.ClassAllMethods[currentClass] = append(
									e.store.Types.ClassAllMethods[currentClass], setterKey)
								e.store.RegisterMethodIndex(setterKey)
								e.store.Methods.ParamCounts[setterKey] = 1
							}
						}
					}
				}
			}
		}
		for _, child := range nodeChildren(node) {
			walk(child, classStack, isIfaceStack)
		}
		if enteredClass {
			classStack = classStack[:len(classStack)-1]
			isIfaceStack = isIfaceStack[:len(isIfaceStack)-1]
		}
	}
	walk(root, nil, nil)
}

// filePath2int 将文件路径转为唯一 int（用于 anonClassMap key）。
// 简化实现：用文件路径的 hash。
func filePath2int(path string) int {
	h := 0
	for _, c := range path {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

// ============================================================
//  IfaceImplMap 构建 — 在第一遍后构建接口→实现类映射
// ============================================================

func (e *Extractor) BuildIfaceImplMap() {
	// 步骤1: 直接接口实现 — ClassInterfaces[cls] = [iface1, iface2, ...]
	for cls, ifaces := range e.store.Types.ClassInterfaces {
		for _, iface := range ifaces {
			if !sliceContains(e.store.Types.IfaceImplMap[iface], cls) {
				e.store.Types.IfaceImplMap[iface] = append(e.store.Types.IfaceImplMap[iface], cls)
			}
		}
	}
	// 步骤2: 类继承闭包 — C implements I, D extends C → D also implements I (BFS)
	parentChildMap := make(map[string][]string)
	for child, parent := range e.store.Types.ClassExtends {
		parentChildMap[parent] = append(parentChildMap[parent], child)
	}
	for iface := range e.store.Types.IfaceImplMap {
		allImpls := make(map[string]bool)
		var queue []string
		for _, impl := range e.store.Types.IfaceImplMap[iface] {
			allImpls[impl] = true
			queue = append(queue, impl)
		}
		for len(queue) > 0 {
			cls := queue[0]
			queue = queue[1:]
			for _, child := range parentChildMap[cls] {
				if !allImpls[child] {
					allImpls[child] = true
					queue = append(queue, child)
					e.store.Types.IfaceImplMap[iface] = append(e.store.Types.IfaceImplMap[iface], child)
				}
			}
		}
	}
	// 步骤3: 接口继承闭包 — InterfaceA extends InterfaceB → A's impls are also B's impls
	// ClassInterfaces[接口A] = [父接口B]（接口声明的 super_interfaces 也记录到 ClassInterfaces）
	changed := true
	for changed {
		changed = false
		for cls, ifaces := range e.store.Types.ClassInterfaces {
			impls, exists := e.store.Types.IfaceImplMap[cls]
			if !exists || len(impls) == 0 {
				continue // cls 不是接口或没有实现类
			}
			for _, parentIface := range ifaces {
				for _, implCls := range impls {
					if !sliceContains(e.store.Types.IfaceImplMap[parentIface], implCls) {
						e.store.Types.IfaceImplMap[parentIface] = append(e.store.Types.IfaceImplMap[parentIface], implCls)
						changed = true
					}
				}
			}
		}
	}
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ============================================================
//  SimpleToFqns 构建 — 简单类名→FQN 映射
// ============================================================

func (e *Extractor) BuildSimpleToFqns() {
	for _, imports := range e.store.Types.ImportsMap {
		for simple, fqn := range imports {
			if !strings.HasPrefix(simple, "_wildcard_") {
				e.store.Types.SimpleToFqns[simple] = append(e.store.Types.SimpleToFqns[simple], fqn)
			}
		}
	}
	// 标记歧义名
	for simple, fqns := range e.store.Types.SimpleToFqns {
		if len(fqns) > 1 {
			e.store.Types.AmbiguousNames[simple] = true
		}
	}
}
