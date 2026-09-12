package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/odvcencio/gotreesitter"
)

type JavaRepoAnalyzer struct {
	store         *AnalysisStore
	extractor     *Extractor
	typeResolver  *TypeResolver
	bodyCollector *MethodBodyCollector
	fieldResolver *FieldValueResolver
	configParser  *ConfigFileParser
	repoRoot      string
}

func NewJavaRepoAnalyzer(cfg AnalysisConfig) *JavaRepoAnalyzer {
	store := NewAnalysisStore(cfg)
	tr := NewTypeResolver(store)
	return &JavaRepoAnalyzer{store: store, extractor: NewExtractor(store, tr), typeResolver: tr, bodyCollector: NewMethodBodyCollector(store, tr), fieldResolver: NewFieldValueResolver()}
}

// Store 返回分析存储（供 CLI/测试层访问内部状态）。
func (a *JavaRepoAnalyzer) Store() *AnalysisStore { return a.store }

// TypeResolver 返回类型解析器（供 CLI/测试层访问内部状态）。
func (a *JavaRepoAnalyzer) TypeResolver() *TypeResolver { return a.typeResolver }

func (a *JavaRepoAnalyzer) Scan(repoRoot string) error {
	a.repoRoot = repoRoot
	t0 := time.Now()
	fmt.Fprintf(os.Stderr, "[SCAN] 开始: %s\n", repoRoot)
	a.configParser = NewConfigFileParser(repoRoot)
	a.store.ConfigParser = a.configParser
	fmt.Fprintf(os.Stderr, "[SCAN] 第一遍...\n")
	a.extractor.FirstPass(repoRoot)
	a.extractor.BuildIfaceImplMap()
	a.extractor.BuildSimpleToFqns()
	a.parseXmlMappers() // R10: MyBatis XML mapper 解析（独立于 Java 注解式）
	a.buildFqnMethodAliases()
	fmt.Fprintf(os.Stderr, "[SCAN] 第一遍完成: %d classes, %d methods\n", len(a.store.Types.ClassAnnotations), len(a.store.Methods.Functions))
	fmt.Fprintf(os.Stderr, "[SCAN] 第二遍...\n")
	a.secondPass()
	a.store.BuildFieldToFieldIndex()
	a.store.BuildCallSiteFieldAssignsIndex()
	a.store.BuildMethodReturnFieldsIndex()
	fmt.Fprintf(os.Stderr, "[SCAN] 继承方法传播...\n")
	a.buildInheritedMethods()
	fmt.Fprintf(os.Stderr, "[SCAN] 字段依赖图...\n")
	a.store.BuildFieldDependencyGraph()
	fmt.Fprintf(os.Stderr, "[SCAN] 调用解析...\n")
	for _, rule := range []CallResolutionRule{PolymorphicCallRule{}, EventPublishCallRule{}, AOPCallRule{}, SpringCallbackCallRule{}} {
		for _, p := range rule.Resolve(a.store) {
			a.store.Calls.Edges[p.CallerKey] = append(a.store.Calls.Edges[p.CallerKey], p.Edge)
		}
	}
	fmt.Fprintf(os.Stderr, "[SCAN] 污点传播...\n")
	engine := NewTaintEngine(a.store)
	engine.SeedFromStore()
	for r := 0; r < a.store.Config.MaxTaintRounds; r++ {
		n := engine.Propagate()
		if n == 0 {
			break
		}
	}
	engine.SyncToStore()
	fmt.Fprintf(os.Stderr, "[SCAN] 完成: %s\n", time.Since(t0))
	return nil
}

func (a *JavaRepoAnalyzer) secondPass() {
	ctorCounts := make(map[string]int)
	for mk := range a.store.Types.ConstructorMethodKeys {
		if !a.store.Methods.SyntheticMethods[mk] {
			cls := mk
			if i := strings.Index(mk, "."); i > 0 {
				cls = mk[:i]
			}
			ctorCounts[cls]++
		}
	}
	for _, fp := range a.extractor.GetJavaFiles(a.repoRoot) {
		pf, err := parseJavaFile(fp)
		if err != nil {
			continue
		}
		a.walkSecondPass(pf.Root, pf.Src, fp, ctorCounts)
	}
}

func (a *JavaRepoAnalyzer) walkSecondPass(root *gotreesitter.Node, src []byte, filePath string, ctorCounts map[string]int) {
	staticInitCounter := 0
	// R5-2：方法体收集分两个子遍——第一子遍填充各方法的返回值字段污点映射
	// （MethodReturnFieldTaint），第二子遍在映射就绪后再做字段透传继承（inheritReturnFieldTaint），
	// 使「深拷贝方法声明于调用方之后」的字段污点穿透也能闭合（解除 analyzer 遍历顺序依赖）。
	var walk func(n *gotreesitter.Node, cs []string, is []bool, mk string)
	walk = func(n *gotreesitter.Node, cs []string, is []bool, mk string) {
		entered := false
		nt := nodeType(n)
		if nt == "class_declaration" || nt == "interface_declaration" || nt == "enum_declaration" || nt == "record_declaration" {
			nn := fieldChild(n, "name")
			if nn != nil {
				cn := nodeText(src, nn)
				if len(cs) > 0 {
					cn = cs[len(cs)-1] + "$" + cn
				}
				cs = append(cs, cn)
				is = append(is, nt == "interface_declaration")
				entered = true
			}
		}
		cc := ""
		if len(cs) > 0 {
			cc = cs[len(cs)-1]
		}
		cIf := false
		if len(is) > 0 {
			cIf = is[len(is)-1]
		}
		if (nt == "method_declaration" || nt == "constructor_declaration") && cc != "" {
			methodKey := a.extractor.getMethodKey(n, cc, src)
			if methodKey != "" {
				mk = methodKey
				// R15 行号偏移修复：method_declaration 节点起点落在「注解/修饰符」行，
				// 而非方法签名行（当方法带 @Transactional/@Override 等多行注解时偏移 -1~N）。
				// 改用 identifier（方法名）子节点的行号作为方法签名真实行，保证 AI 定位不偏移。
				line := startLine1(n)
				if nameNode := fieldChild(n, "name"); nameNode != nil {
					if l := startLine1(nameNode); l > 0 {
						line = l
					}
				}
				a.store.Methods.Functions[methodKey] = MethodFunc{Class: cc, Method: MethodKeyHelper{}.DisplayName(methodKey), Line: line, FilePath: filePath}
				// R12（架构级，非 hardcode）：测试代码标记。基于文件路径启发式（测试目录或
				// *Test/*Tests/*IT/*TestCase 文件名）识别测试类/测试方法，供输出层降权/排除误报，
				// 避免 AI 脚手架被测试代码中的危险调用淹没。不破坏 sink 判定口径（真漏洞仍标记）。
				if isTestFilePath(filePath) {
					if a.store.Methods.TestCodeMethods == nil {
						a.store.Methods.TestCodeMethods = map[string]bool{}
					}
					a.store.Methods.TestCodeMethods[methodKey] = true
				}
				anns := collectAnnotationInfo(n, src)
				a.store.Methods.Annotations[methodKey] = anns
				if !cIf {
					et := a.isEntryPoint(anns, cc)
					if et != "" {
						a.store.Calls.EntryPoints[methodKey] = true
						a.store.Calls.EntryTypes[methodKey] = et
						p, hm := a.extractHTTPPath(anns, cc)
						if p != "" {
							a.store.Calls.HttpPaths[methodKey] = p
						}
						if hm != "" {
							a.store.Calls.HttpMethods[methodKey] = hm
						}
					}
					for _, ann := range anns {
						if ann.Name == "EventListener" || ann.Name == "TransactionalEventListener" {
							pn := fieldChild(n, "parameters")
							if pn != nil {
								for _, p := range nodeChildren(pn) {
									if nodeType(p) == "formal_parameter" {
										tn := fieldChild(p, "type")
										if tn != nil {
											et2 := a.typeResolver.StripGenerics(nodeText(src, tn))
											if i := strings.LastIndex(et2, "."); i >= 0 {
												et2 = et2[i+1:]
											}
											ex := toSet(a.store.Calls.EventListenerMethods[et2])
											if !ex[methodKey] {
												a.store.Calls.EventListenerMethods[et2] = append(a.store.Calls.EventListenerMethods[et2], methodKey)
											}
										}
									}
								}
							}
						}
					}
				}
				scope := NewMethodScope(cc, nil)
				pn := fieldChild(n, "parameters")
				if pn != nil {
					a.processParams(n, pn, src, cc, methodKey, scope, anns, ctorCounts, nt == "constructor_declaration")
				}
				// CRITICAL #3: 构造函数参数污点传播 (mirror 7.py:5095-5100)
				if nt == "constructor_declaration" {
					body := fieldChild(n, "body")
					if body != nil {
						for paramName, sources := range a.store.Methods.ParamTaints[methodKey] {
							a.bodyCollector.PropagateCtorParamTaint(body, src, cc, methodKey, filePath, paramName, sources)
						}
					}
				}
				body := fieldChild(n, "body")
				if body != nil {
					tc := make(map[[2]int]taintCheckResult)
					a.bodyCollector.Collect(body, src, cc, methodKey, filePath, scope, tc)
				}
			}
		} else if nt == "field_declaration" && cc != "" {
			a.handleFieldDecl(n, src, cc, filePath)
		} else if nt == "static_initializer" && cc != "" {
			staticInitCounter++
			methodKey := fmt.Sprintf("%s.<static_init$%d>()", cc, staticInitCounter)
			mk = methodKey
			startLine := startLine1(n)
			a.store.Methods.Functions[methodKey] = MethodFunc{Class: cc, Method: fmt.Sprintf("<static_init$%d>", staticInitCounter), Line: startLine, FilePath: filePath}
			a.store.Methods.Annotations[methodKey] = nil
			a.store.Methods.SyntheticMethods[methodKey] = true
			a.store.RegisterMethodIndex(methodKey)
			a.store.Methods.ParamCounts[methodKey] = 0
			a.store.Types.ConstructorMethodKeys[methodKey] = true
			scope := NewMethodScope(cc, nil)
			tc := make(map[[2]int]taintCheckResult)
			a.bodyCollector.Collect(n, src, cc, methodKey, filePath, scope, tc)
		} else if nt == "instance_initializer" && cc != "" {
			methodKey := cc + ".<instance_init>()"
			mk = methodKey
			startLine := startLine1(n)
			a.store.Methods.Functions[methodKey] = MethodFunc{Class: cc, Method: "<instance_init>", Line: startLine, FilePath: filePath}
			a.store.Methods.Annotations[methodKey] = nil
			a.store.Methods.SyntheticMethods[methodKey] = true
			a.store.RegisterMethodIndex(methodKey)
			a.store.Methods.ParamCounts[methodKey] = 0
			a.store.Types.ConstructorMethodKeys[methodKey] = true
			scope := NewMethodScope(cc, nil)
			tc := make(map[[2]int]taintCheckResult)
			a.bodyCollector.Collect(n, src, cc, methodKey, filePath, scope, tc)
		}
		for _, c := range nodeChildren(n) {
			walk(c, cs, is, mk)
		}
		if entered {
			cs = cs[:len(cs)-1]
			is = is[:len(is)-1]
		}
	}
	walk(root, nil, nil, "")

	// R5-2：第二子遍——第一子遍已填充所有方法的 MethodReturnFieldTaint，此处再 walk 一遍
	// 重建调用图（含 inheritReturnFieldTaint 字段透传继承），使「深拷贝方法声明于调用方之后」
	// 的字段污点穿透也能闭合（解除 analyzer 遍历顺序依赖）。
	walk(root, nil, nil, "")
}

func (a *JavaRepoAnalyzer) processParams(n, pn *gotreesitter.Node, src []byte, cc, mk string, scope *MethodScope, anns []Annotation, ctorCounts map[string]int, isCtor bool) {
	isAutoCtor := false
	annNames := make(map[string]bool)
	for _, ann := range anns {
		annNames[ann.Name] = true
	}
	if annNames["Autowired"] {
		isAutoCtor = true
	}
	if isCtor && ctorCounts[cc] == 1 {
		for _, ca := range a.store.Types.ClassAnnotations[cc] {
			if springComponentAnnotations[ca.Name] {
				isAutoCtor = true
				break
			}
		}
	}
	if a.store.Types.ConstructorBindingClasses[cc] && isCtor {
		isAutoCtor = true
	}
	idx := 0
	for _, p := range nodeChildren(pn) {
		if nodeType(p) != "formal_parameter" {
			continue
		}
		tn := fieldChild(p, "type")
		nn := fieldChild(p, "name")
		if tn == nil || nn == nil {
			continue
		}
		typeName := strings.TrimSpace(nodeText(src, tn))
		varName := nodeText(src, nn)
		pAnns := collectAnnotationInfo(p, src)
		var ts map[string]bool
		injected := false
		for _, pa := range pAnns {
			switch pa.Name {
			case "Value":
				if a.store.ConfigParser != nil {
					if v := a.store.ConfigParser.Lookup(pa.Params["_value"]); v != "" {
						ts = map[string]bool{string(TaintSrcConfigValue): true}
					}
				}
				injected = true
			case "RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue", "ModelAttribute":
				ts = map[string]bool{"@" + pa.Name: true}
				injected = true
			case "Autowired", "Resource", "Inject", "PersistenceContext", "PersistenceUnit", "Lookup":
				injected = true
			}
		}
		if isAutoCtor && !injected {
			injected = true
		}
		if a.store.Types.ConstructorBindingClasses[cc] && isCtor && ts == nil {
			ts = map[string]bool{string(TaintSrcConfigValue): true}
		}
		if _, ok := a.store.Fields.ConfigPropsCtorClasses[cc]; ok && isAutoCtor {
			ts = map[string]bool{string(TaintSrcConfigValue): true}
		}
		scope.Define(varName, typeName, ts)
		if a.store.Methods.ParamOrder[mk] == nil {
			a.store.Methods.ParamOrder[mk] = make(map[string]int)
		}
		a.store.Methods.ParamOrder[mk][varName] = idx
		idx++
		if ts != nil {
			if a.store.Methods.ParamTaints[mk] == nil {
				a.store.Methods.ParamTaints[mk] = make(map[string][]string)
			}
			for s := range ts {
				ex := toSet(a.store.Methods.ParamTaints[mk][varName])
				if !ex[s] {
					a.store.Methods.ParamTaints[mk][varName] = append(a.store.Methods.ParamTaints[mk][varName], s)
				}
			}
		}
	}
}

func (a *JavaRepoAnalyzer) handleFieldDecl(n *gotreesitter.Node, src []byte, cc, fp string) {
	tn := fieldChild(n, "type")
	typeName := ""
	if tn != nil {
		typeName = strings.TrimSpace(nodeText(src, tn))
	}
	fAnns := collectAnnotationInfo(n, src)
	isStatic, isTransient := false, false
	for _, c := range nodeChildren(n) {
		if nodeType(c) == "modifiers" {
			for _, m := range nodeChildren(c) {
				mt := nodeText(src, m)
				if mt == "static" {
					isStatic = true
				} else if mt == "transient" {
					isTransient = true
				}
			}
		}
	}
	for _, d := range nodeChildren(n) {
		if nodeType(d) != "variable_declarator" {
			continue
		}
		nn := fieldChild(d, "name")
		if nn == nil {
			continue
		}
		fn := nodeText(src, nn)
		key := cc + "." + fn
		iv := fieldChild(d, "value")
		it := ""
		if iv != nil {
			it = nodeText(src, iv)
		}
		ln := startLine1(nn)
		a.store.Fields.Defs[key] = FieldDefinition{ClassName: cc, FieldName: fn, TypeName: typeName, Line: ln, FilePath: fp, InitText: it, Annotations: fAnns, IsStatic: isStatic, IsTransient: isTransient}
		for _, ann := range fAnns {
			if ann.Name == "Value" {
				expr := ann.Params["_value"]
				if expr != "" {
					a.store.Fields.AddTaint(key, TaintInfo{SourceType: TaintSrcConfigValue, SourceMethod: "@Value(" + expr + ")", AssignMethod: "<field_init>", AssignLine: ln, AssignFile: fp, AssignText: "@Value(" + expr + ")", AssignType: AssignSpringInjection})
				}
			}
		}
		if iv != nil {
			imk := cc + ".<init_" + fn + ">()"
			a.store.Methods.Functions[imk] = MethodFunc{Class: cc, Method: "<init_" + fn + ">", Line: ln, FilePath: fp}
			a.store.Methods.SyntheticMethods[imk] = true
			a.store.RegisterMethodIndex(imk)
			a.store.Methods.ParamCounts[imk] = 0
			a.store.Methods.FieldInitMethodKeys[imk] = true
			a.bodyCollector.Collect(iv, src, cc, imk, fp, NewMethodScope(cc, nil), make(map[[2]int]taintCheckResult))
		}
	}
}

func (a *JavaRepoAnalyzer) isEntryPoint(anns []Annotation, cc string) EntryPointType {
	an := make(map[string]bool)
	for _, a2 := range anns {
		an[a2.Name] = true
	}
	for n := range an {
		if httpMappingAnnotations[n] {
			for _, ca := range a.store.Types.ClassAnnotations[cc] {
				if controllerAnnotations[ca.Name] {
					return EntryHTTP
				}
			}
			if an["ResponseBody"] {
				return EntryHTTP
			}
		}
	}
	if an["ExceptionHandler"] {
		for _, ca := range a.store.Types.ClassAnnotations[cc] {
			if controllerAnnotations[ca.Name] || controllerAdviceAnnotations[ca.Name] {
				return EntryHTTP
			}
		}
		return ""
	}
	if an["Bean"] {
		return EntryContainer
	}
	if an["Scheduled"] {
		return EntryScheduled
	}
	for n := range an {
		if n == "RabbitListener" || n == "KafkaListener" || n == "JmsListener" || n == "MessageMapping" || n == "SubscribeMapping" {
			return EntryMsgListener
		}
	}
	for n := range an {
		if n == "EventListener" || n == "TransactionalEventListener" {
			return EntryEvtListener
		}
	}
	for n := range an {
		if aopAspectAnnotations[n] {
			return ""
		}
	}
	for n := range an {
		if nonHTTPEntryAnnotations[n] {
			return EntryContainer
		}
	}
	return ""
}

func (a *JavaRepoAnalyzer) extractHTTPPath(anns []Annotation, cc string) (string, string) {
	mp, hm := "", ""
	for _, ann := range anns {
		if httpMappingAnnotations[ann.Name] {
			mp = ann.Params["_value"]
			if mp == "" {
				mp = ann.Params["path"]
			}
			if mp == "" {
				mp = ann.Params["value"]
			}
			switch ann.Name {
			case "GetMapping":
				hm = "GET"
			case "PostMapping":
				hm = "POST"
			case "PutMapping":
				hm = "PUT"
			case "DeleteMapping":
				hm = "DELETE"
			case "PatchMapping":
				hm = "PATCH"
			}
		}
	}
	cp := ""
	for _, ann := range a.store.Types.ClassAnnotations[cc] {
		if ann.Name == "RequestMapping" {
			cp = ann.Params["_value"]
			if cp == "" {
				cp = ann.Params["path"]
			}
			if cp == "" {
				cp = ann.Params["value"]
			}
		}
	}
	if mp != "" {
		fp := strings.TrimSuffix(cp, "/") + "/" + strings.TrimPrefix(mp, "/")
		for strings.Contains(fp, "//") {
			fp = strings.ReplaceAll(fp, "//", "/")
		}
		if !strings.HasPrefix(fp, "/") {
			fp = "/" + fp
		}
		return fp, hm
	}
	return "", hm
}

// buildFqnMethodAliases 为歧义类名构建 FQN 方法别名（镜像 7.py:5362-5378）。
func (a *JavaRepoAnalyzer) buildFqnMethodAliases() {
	for simpleName := range a.store.Types.AmbiguousNames {
		var methodKeys []string
		prefix := simpleName + "."
		for pattern, keys := range a.store.Indices.MethodNameIndex {
			if strings.HasPrefix(pattern, prefix) {
				methodKeys = append(methodKeys, keys...)
			}
		}
		for _, fqn := range a.store.Types.SimpleToFqns[simpleName] {
			fqnSimple := fqn
			if i := strings.LastIndex(fqn, "."); i >= 0 {
				fqnSimple = fqn[i+1:]
			}
			if fqnSimple != simpleName {
				continue
			}
			a.store.Types.FqnClassMap[fqn] = simpleName
			for _, mk := range methodKeys {
				fqnPattern := strings.Replace(mk, prefix, fqn+".", 1)
				existing := toSet(a.store.Indices.MethodNameIndex[fqnPattern])
				if !existing[mk] {
					a.store.Indices.MethodNameIndex[fqnPattern] = append(a.store.Indices.MethodNameIndex[fqnPattern], mk)
				}
			}
		}
	}
}

// buildInheritedMethods 拓扑排序类后，将父类/接口方法追加到子类 ClassAllMethods。
// 镜像 7.py _build_inherited_methods (L5452-5481) + _topological_sort_classes (L5483-5503)。
func (a *JavaRepoAnalyzer) buildInheritedMethods() {
	// 拓扑排序：visiting(grey)/visited(black) 双色标记检测回边
	visited := make(map[string]bool)
	visiting := make(map[string]bool)
	var order []string
	var visit func(cls string)
	visit = func(cls string) {
		if visited[cls] {
			return
		}
		if visiting[cls] {
			fmt.Fprintf(os.Stderr, "[WARN] 继承环检测: %s\n", cls)
			return
		}
		// 跳过不在 ClassAllMethods 中的外部类/接口
		if _, exists := a.store.Types.ClassAllMethods[cls]; !exists {
			return
		}
		visiting[cls] = true
		if parent, ok := a.store.Types.ClassExtends[cls]; ok && parent != "" {
			visit(parent)
		}
		for _, iface := range a.store.Types.ClassInterfaces[cls] {
			visit(iface)
		}
		visiting[cls] = false
		visited[cls] = true
		order = append(order, cls)
	}
	for cls := range a.store.Types.ClassAllMethods {
		visit(cls)
	}
	// 按拓扑序处理：父类/接口在前，子类在后
	for _, cls := range order {
		// 构建 declared_by_name: methodName → set of paramSigs
		declaredByName := make(map[string]map[string]bool)
		for _, m := range a.store.Types.ClassAllMethods[cls] {
			mName, mSig := extractMethodNameAndSig(m)
			if declaredByName[mName] == nil {
				declaredByName[mName] = make(map[string]bool)
			}
			declaredByName[mName][mSig] = true
		}
		// 收集继承方法
		var inherited []string
		if parent, ok := a.store.Types.ClassExtends[cls]; ok && parent != "" {
			if parentMethods, exists := a.store.Types.ClassAllMethods[parent]; exists {
				inherited = append(inherited, parentMethods...)
			}
		}
		for _, iface := range a.store.Types.ClassInterfaces[cls] {
			if ifaceMethods, exists := a.store.Types.ClassAllMethods[iface]; exists {
				inherited = append(inherited, ifaceMethods...)
			}
		}
		// 追加未被覆盖的继承方法
		for _, m := range inherited {
			mName, mSig := extractMethodNameAndSig(m)
			if sigs, ok := declaredByName[mName]; ok && sigs[mSig] {
				continue // 子类已声明同名同签名方法（覆盖）
			}
			a.store.Types.ClassAllMethods[cls] = append(a.store.Types.ClassAllMethods[cls], m)
			a.store.RegisterMethodIndex(m)
			if _, exists := a.store.Types.MethodSigs[m]; !exists {
				a.store.Types.MethodSigs[m] = []string{"Object"}
			}
			if _, exists := a.store.Methods.ParamCounts[m]; !exists {
				a.store.Methods.ParamCounts[m] = MethodKeyHelper{}.ParamCount(m)
			}
			if _, exists := a.store.Methods.Annotations[m]; !exists {
				a.store.Methods.Annotations[m] = []Annotation{}
			}
		}
	}
}

// extractMethodNameAndSig 从方法键中提取方法名和参数签名。
// methodKey 格式: Class.method(paramTypes) → mName=method, mSig=paramTypes
// isTestFilePath 识别测试代码文件路径（架构级启发式，非 hardcode 特定函数名）。
// 覆盖：路径含 /test/ 或 /tests/；文件名匹配 *Test.java / *Tests.java / *IT.java / *TestCase.java。
// 用于在扫描阶段标记测试类/测试方法，供输出层降权/排除误报。
func isTestFilePath(filePath string) bool {
	norm := strings.ReplaceAll(filePath, "\\", "/")
	lower := strings.ToLower(norm)
	if strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") {
		return true
	}
	base := norm
	if i := strings.LastIndex(norm, "/"); i >= 0 {
		base = norm[i+1:]
	}
	base = strings.ToLower(base)
	for _, suf := range []string{"test.java", "tests.java", "it.java", "testcase.java"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

func extractMethodNameAndSig(methodKey string) (string, string) {
	parenIdx := strings.Index(methodKey, "(")
	namePart := methodKey
	sigPart := ""
	if parenIdx > 0 {
		namePart = methodKey[:parenIdx]
		sigPart = strings.TrimSuffix(methodKey[parenIdx+1:], ")")
	}
	dotIdx := strings.LastIndex(namePart, ".")
	mName := namePart
	if dotIdx >= 0 {
		mName = namePart[dotIdx+1:]
	}
	return mName, sigPart
}

func (a *JavaRepoAnalyzer) SaveAnalysis(path string) error {
	hdr := CacheHeader{Version: ANALYSIS_VERSION, RepoPath: a.repoRoot, ScanTime: time.Now(), FileCount: len(a.store.Methods.Functions)}
	hdrData, _ := json.Marshal(hdr)
	storeData, err := json.Marshal(a.store)
	if err != nil {
		return err
	}
	combined := map[string]json.RawMessage{"header": hdrData, "store": storeData}
	data, err := json.MarshalIndent(combined, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (a *JavaRepoAnalyzer) LoadAnalysis(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var combined struct {
		Header CacheHeader
		Store  json.RawMessage
	}
	if err := json.Unmarshal(data, &combined); err != nil {
		return err
	}
	if combined.Header.Version != ANALYSIS_VERSION {
		return fmt.Errorf("缓存版本不匹配: %d vs %d", combined.Header.Version, ANALYSIS_VERSION)
	}
	a.repoRoot = combined.Header.RepoPath
	return json.Unmarshal(combined.Store, a.store)
}
