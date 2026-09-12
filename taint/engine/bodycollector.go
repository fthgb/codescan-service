package engine

import (
	"strconv"
	"strings"

	"github.com/odvcencio/gotreesitter"
)

// ============================================================
//  MethodBodyCollector — 第二遍 AST 遍历（镜像 7.py L3260-4060）
//  提取方法体中的调用点/字段读写/局部变量/返回值污点/参数污点
// ============================================================

type MethodBodyCollector struct {
	store             *AnalysisStore
	typeResolver      *TypeResolver
	taintChecker      *TaintChecker
	validationChecker *ValidationChecker
	lambdaMethodMap   map[[2]int]string
}

func NewMethodBodyCollector(store *AnalysisStore, tr *TypeResolver) *MethodBodyCollector {
	return &MethodBodyCollector{
		store:             store,
		typeResolver:      tr,
		taintChecker:      NewTaintChecker(store, tr),
		validationChecker: NewValidationChecker(store),
		lambdaMethodMap:   make(map[[2]int]string),
	}
}

func (bc *MethodBodyCollector) Collect(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	bc.visitIterative(node, src, currentClass, methodKey, filePath, scope, taintCache)
}

func (bc *MethodBodyCollector) visitIterative(rootNode *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	type stackItem struct {
		node  *gotreesitter.Node
		scope *MethodScope
	}
	stack := []stackItem{{rootNode, scope}}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node := item.node
		nodeScope := item.scope
		nt := nodeType(node)
		if skipRecurseTypes[nt] {
			continue
		}
		if nt == "identifier" {
			parent := node.Parent()
			if parent != nil && skipParentTypes[nodeType(parent)] {
				continue
			}
		}
		createsScope := nt == "for_statement" || nt == "block" || nt == "try_statement" || nt == "catch_clause"
		childScope := nodeScope
		if createsScope {
			childScope = NewMethodScope(currentClass, nodeScope)
		}
		switch nt {
		case "local_variable_declaration":
			bc.handleLocalVarDecl(node, src, currentClass, methodKey, filePath, childScope, taintCache)
		case "enhanced_for_statement":
			bc.handleEnhancedFor(node, src, currentClass, methodKey, filePath, childScope, taintCache)
		case "catch_clause":
			bc.handleCatch(node, src, currentClass, filePath, childScope)
		case "return_statement":
			bc.handleReturn(node, src, currentClass, methodKey, filePath, childScope, taintCache)
		case "method_invocation":
			bc.handleMethodInvocation(node, src, currentClass, methodKey, filePath, childScope, taintCache)
		case "assignment_expression", "augmented_assignment_expression":
			bc.handleAssignment(node, src, currentClass, methodKey, filePath, childScope, taintCache)
		case "field_access":
			bc.handleFieldAccess(node, src, currentClass, methodKey, filePath)
		case "lambda_expression":
			bc.handleLambda(node, src, currentClass, methodKey, filePath, childScope, taintCache)
		case "object_creation_expression":
			bc.handleObjectCreation(node, src, currentClass, methodKey, filePath)
		case "explicit_constructor_invocation":
			bc.handleExplicitConstructor(node, src, currentClass, methodKey, filePath)
		case "method_reference":
			bc.handleMethodReference(node, src, currentClass, methodKey, filePath, childScope)
		case "update_expression":
			bc.handleUpdateExpression(node, src, currentClass, methodKey, filePath, childScope)
		case "try_statement":
			bc.handleTry(node, src, currentClass, filePath, childScope)
		case "identifier":
			bc.handleIdentifierRead(node, src, currentClass, methodKey, filePath, childScope)
		}
		children := nodeChildren(node)
		// R6-2：lambda_expression 的 body 已由 handleLambda 用 lambdaScope 单独 visitIterative 处理，
		// 此处不再自动压栈其 children，避免以「外层 scope」重复处理 lambda body 内的调用
		// （会导致 taintCache 以错误 scope 缓存 false，使 lambda 参数污点注入失效）。
		if nt == "lambda_expression" {
			continue
		}
		for i := len(children) - 1; i >= 0; i-- {
			stack = append(stack, stackItem{children[i], childScope})
		}
	}
}

func (bc *MethodBodyCollector) handleLocalVarDecl(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	typeNode := fieldChild(node, "type")
	if typeNode == nil {
		return
	}
	typeName := strings.TrimSpace(nodeText(src, typeNode))
	for _, decl := range nodeChildren(node) {
		if nodeType(decl) != "variable_declarator" {
			continue
		}
		nameNode := fieldChild(decl, "name")
		if nameNode == nil {
			continue
		}
		varName := nodeText(src, nameNode)
		valueNode := fieldChild(decl, "value")
		initText := ""
		if valueNode != nil {
			initText = strings.TrimSpace(nodeText(src, valueNode))
		}
		actualType := typeName
		// var type inference (mirror 7.py:3358-3362)
		if bc.typeResolver.StripGenerics(typeName) == "var" && valueNode != nil {
			resolved := bc.typeResolver.ResolveType(valueNode, currentClass, src, filePath, scope)
			if resolved != "" {
				actualType = resolved
			}
		}
		var taintSources map[string]bool
		if valueNode != nil {
			isT, source := bc.taintChecker.Check(valueNode, src, scope, currentClass, filePath, 0, taintCache)
			if isT {
				taintSources = map[string]bool{source: true}
			}
		}
		scope.Define(varName, actualType, taintSources)
		if methodKey != "" {
			if bc.store.Methods.LocalVars[methodKey] == nil {
				bc.store.Methods.LocalVars[methodKey] = make(map[string]LocalVar)
			}
			var sources []string
			if taintSources != nil {
				for s := range taintSources {
					sources = append(sources, s)
				}
			}
			bc.store.Methods.LocalVars[methodKey][varName] = LocalVar{Type: actualType, Tainted: taintSources != nil, Sources: sources, InitText: initText, Line: startLine1(nameNode)}
		}
		if valueNode != nil && nodeType(valueNode) == "method_invocation" {
			rNameNode := fieldChild(valueNode, "name")
			rObjNode := fieldChild(valueNode, "object")
			if rNameNode != nil {
				rMethod := nodeText(src, rNameNode)
				var rObjClass string
				if rObjNode != nil {
					rObjText := nodeText(src, rObjNode)
					if rObjText == "super" {
						rObjClass = bc.store.Types.ClassExtends[currentClass]
						if rObjClass == "" {
							rObjClass = currentClass
						}
					} else {
						rObjClass = bc.typeResolver.ResolveType(rObjNode, currentClass, src, filePath, scope)
					}
				} else {
					rObjClass = currentClass
				}
				rArgCount := bc.typeResolver.CountArguments(valueNode)
				if rObjClass != "" {
					_, rCalleeKey := bc.typeResolver.ResolveMethodClass(rObjClass, rMethod, rArgCount)
					if rCalleeKey != "" {
						bc.store.Calls.CallReturnToLocalMap[rCalleeKey] = append(
							bc.store.Calls.CallReturnToLocalMap[rCalleeKey], [2]string{methodKey, varName})
					}
				}
				// R5-2：声明初始化 `T copy = cloneOf(p)` —— 若返回值字段透传自实参，
				// 把实参字段污点继承到 copy（与 handleAssignment 的赋值路径对称）。
				bc.inheritReturnFieldTaint(scope, varName, valueNode, src)
			}
		}
	}
}

// inheritReturnFieldTaint（R5-2）：当变量（声明或赋值左值）初始化为方法调用且该方法的
// 返回值字段透传自实参（如 cloneOf 的 `d.field = src.field`），按「retField→srcField」映射
// 把实参的字段污点继承到左值，使 `copy.data` 读取时穿透返回值闭合。
func (bc *MethodBodyCollector) inheritReturnFieldTaint(scope *MethodScope, varName string, valueNode *gotreesitter.Node, src []byte) {
	if valueNode == nil || nodeType(valueNode) != "method_invocation" {
		return
	}
	rcNode := fieldChild(valueNode, "name")
	if rcNode == nil {
		return
	}
	rcMethod := nodeText(src, rcNode)
	var argName string
	// 注意：treesitter Java grammar 中 method_invocation 的 argument_list 是匿名子节点，
	// fieldChild(valueNode, "argument_list") 取不到，需遍历子节点按类型匹配。
	var rcArgs *gotreesitter.Node
	for _, c := range nodeChildren(valueNode) {
		if nodeType(c) == "argument_list" {
			rcArgs = c
			break
		}
	}
	if rcArgs != nil {
		for _, ac := range nodeChildren(rcArgs) {
			var expr *gotreesitter.Node
			if nodeType(ac) == "argument" {
				expr = fieldChild(ac, "expression")
			}
			if expr == nil && nodeType(ac) == "identifier" {
				expr = ac
			}
			if expr != nil && nodeType(expr) == "identifier" {
				argName = nodeText(src, expr)
				break
			}
		}
	}
	if argName == "" {
		return
	}
	mkh := MethodKeyHelper{}
	for mk, fields := range bc.store.MethodReturnFieldTaint {
		if mkh.MethodName(mk) == rcMethod && len(fields) > 0 {
			for retField, srcField := range fields {
				if fs, ok := scope.GetFieldTaint(argName, srcField); ok && fs != "" {
					scope.SetFieldTaint(varName, retField, fs)
				}
			}
			break
		}
	}
}

func (bc *MethodBodyCollector) handleEnhancedFor(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	typeNode := fieldChild(node, "type")
	nameNode := fieldChild(node, "name")
	if typeNode == nil || nameNode == nil {
		return
	}
	varName := nodeText(src, nameNode)
	typeName := strings.TrimSpace(nodeText(src, typeNode))
	var taintSources map[string]bool
	children := nodeChildren(node)
	for i, child := range children {
		if nodeType(child) == ":" && i+1 < len(children) {
			isT, source := bc.taintChecker.Check(children[i+1], src, scope, currentClass, filePath, 0, taintCache)
			if isT {
				taintSources = map[string]bool{source: true}
			}
			break
		}
	}
	scope.Define(varName, typeName, taintSources)
}

func (bc *MethodBodyCollector) handleCatch(node *gotreesitter.Node, src []byte, currentClass, filePath string, scope *MethodScope) {
	param := fieldChild(node, "parameter")
	if param == nil {
		return
	}
	for _, child := range nodeChildren(param) {
		ct := nodeType(child)
		if ct == "catch_formal_parameter" || ct == "formal_parameter" {
			typeNode := fieldChild(child, "type")
			nameNode := fieldChild(child, "name")
			if typeNode != nil && nameNode != nil {
				scope.Define(nodeText(src, nameNode), strings.TrimSpace(nodeText(src, typeNode)), nil)
			}
		}
	}
}

func (bc *MethodBodyCollector) handleReturn(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	for _, child := range nodeChildren(node) {
		if nodeType(child) == ";" {
			continue
		}
		bc.checkReturnParamRefs(child, src, methodKey, scope, currentClass)
		bc.checkReturnFieldRefs(child, src, methodKey, currentClass, scope)
		if nodeType(child) == "identifier" {
			retName := nodeText(src, child)
			if scope.Resolve(retName) != "" {
				existingLRV := toSet(bc.store.Methods.LocalReturnVars[methodKey])
				if !existingLRV[retName] {
					bc.store.Methods.LocalReturnVars[methodKey] = append(bc.store.Methods.LocalReturnVars[methodKey], retName)
				}
				// R5-2：返回值对象字段污点提升。若返回变量 d 携带字段污点（来自方法内
				// `d.field = src.field` 赋值），记录到方法级 MethodReturnFieldTaint，供调用方
				// `copy.data` 读取时回溯穿透返回值。
				if ft := scope.vars[retName]; ft != nil && len(ft.fieldTaint) > 0 {
					if bc.store.MethodReturnFieldTaint[methodKey] == nil {
						bc.store.MethodReturnFieldTaint[methodKey] = make(map[string]string)
					}
					for f, s := range ft.fieldTaint {
						bc.store.MethodReturnFieldTaint[methodKey][f] = s
					}
				}
			}
		} else if nodeType(child) == "method_invocation" {
			objNode := fieldChild(child, "object")
			if objNode != nil && nodeType(objNode) == "identifier" {
				objName := nodeText(src, objNode)
				if scope.Resolve(objName) != "" {
					existingLRV := toSet(bc.store.Methods.LocalReturnVars[methodKey])
					if !existingLRV[objName] {
						bc.store.Methods.LocalReturnVars[methodKey] = append(bc.store.Methods.LocalReturnVars[methodKey], objName)
					}
				}
			}
		}
		isT, source := bc.taintChecker.Check(child, src, scope, currentClass, filePath, 0, taintCache)
		if isT {
			existing := toSet(bc.store.Methods.ReturnTaints[methodKey])
			if !existing[source] {
				bc.store.Methods.ReturnTaints[methodKey] = append(bc.store.Methods.ReturnTaints[methodKey], source)
			}
		}
	}
}

func (bc *MethodBodyCollector) handleMethodInvocation(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	nameNode := fieldChild(node, "name")
	if nameNode == nil {
		return
	}
	methodName := nodeText(src, nameNode)
	objNode := fieldChild(node, "object")
	if eventPublishMethods[methodName] {
		args := fieldChild(node, "arguments")
		if args != nil {
			for _, arg := range nodeChildren(args) {
				if nodeType(arg) == "object_creation_expression" {
					typeNode := fieldChild(arg, "type")
					if typeNode != nil {
						eventType := bc.typeResolver.StripGenerics(nodeText(src, typeNode))
						if dotIdx := strings.LastIndex(eventType, "."); dotIdx >= 0 {
							eventType = eventType[dotIdx+1:]
						}
						bc.store.Calls.EventPublishSites = append(bc.store.Calls.EventPublishSites, EventPublishSite{
							PublisherKey: methodKey, EventType: eventType, Line: startLine1(node), FilePath: filePath,
						})
					}
				}
			}
		}
	}
	// A3：识别 Spring 静态资源 handler 注册。WebMvcConfigurer.addResourceHandlers 内
	// registry.addResourceHandler("/static/**").addResourceLocations(...) 链式调用。
	// 此处识别 addResourceHandler(...) 调用，提取首个字符串参数作为 handler 路径并注册。
	// 这是通用提升（任何 receiver.addResourceHandler(path) 均登记），非 Spring 专属 hack。
	if methodName == "addResourceHandler" {
		if args := fieldChild(node, "arguments"); args != nil {
			for _, arg := range nodeChildren(args) {
				if nodeType(arg) == "string_literal" {
					path := strings.Trim(nodeText(src, arg), "\"`")
					if path != "" {
						// 去重：同 (ConfigClass, HandlerPath, Line) 只注册一次
						dup := false
						for _, hr := range bc.store.Calls.HandlerRegistrations {
							if hr.ConfigClass == currentClass && hr.HandlerPath == path && hr.Line == startLine1(node) {
								dup = true
								break
							}
						}
						if !dup {
							bc.store.Calls.HandlerRegistrations = append(bc.store.Calls.HandlerRegistrations, HandlerRegistration{
								ConfigClass: currentClass,
								HandlerPath: path,
								Line:        startLine1(node),
								FilePath:    filePath,
							})
						}
					}
					break
				}
			}
		}
	}
	var calleeClass string
	if objNode != nil {
		objText := nodeText(src, objNode)
		if objText == "super" {
			calleeClass = bc.store.Types.ClassExtends[currentClass]
			if calleeClass == "" {
				calleeClass = currentClass
			}
		} else {
			calleeClass = bc.typeResolver.ResolveType(objNode, currentClass, src, filePath, scope)
			// R09：字段接收者调用兜底——若 ResolveType 未解析且 receiver 是已知字段
			// （如 this.em 字段，类型 EntityManager），用字段声明类型作为 CalleeClass，
			// 避免 "em.createQuery(...)" 类调用边停在 unresolved 而漏掉 JPA/Hibernate sink。
			// 这是通用提升（所有 字段.method(...) 调用受益），非 JPA 专属 hack。
			if calleeClass == "" {
				if ft, ok := bc.store.Types.GlobalFieldTypes[currentClass+"."+objText]; ok && ft != "" {
					calleeClass = ft
				}
			}
		}
	} else {
		calleeClass = currentClass
	}
	// G-Out 参数绑定补全（R01-R07 修复）：当 receiver 类型解析失败（典型为 JDK 链式调用
	// 如 Runtime.getRuntime().exec(...)，其 object=Runtime.getRuntime() 返回类型不在项目索引中，
	// ResolveType 返回空），用 objNode 文本首标识符作 class 候选，反查 sinkDict 短名兜底
	// （sinkDict 已收录 "Runtime.exec" 等短名，与 JPA "EntityManager.createQuery" 同惯例）。
	// 命中则回填 calleeClass，使该 sink 调用的 CallParamTaints 得以记录，从而 SinkParamBindings
	// 能产出参数级绑定（否则 R01-R07 这类方法内直接 sink 调用全部丢失参数绑定）。
	if calleeClass == "" && objNode != nil {
		objText := strings.TrimSpace(nodeText(src, objNode))
		if dot := strings.Index(objText, "."); dot > 0 {
			rc := objText[:dot]
			if _, ok := MatchSink(rc, methodName); ok {
				calleeClass = rc
			}
		}
	}
	argCount := bc.typeResolver.CountArguments(node)
	line := startLine1(node)
	condition := bc.determineCallCondition(node, src)
	if calleeClass != "" {
		pattern := calleeClass + "." + methodName
		// Confidence based on param_counts matching (mirror 7.py:3506-3513)
		confidence := ConfHeuristic
		if matched, ok := bc.store.Indices.MethodNameIndex[pattern]; ok && len(matched) > 0 {
			for _, mk := range matched {
				if bc.store.Methods.ParamCounts[mk] == argCount {
					confidence = ConfExact
					break
				}
			}
		}
		edge := CallEdge{CalleeClass: calleeClass, CalleeMethod: methodName, Line: line, FilePath: filePath, ArgCount: argCount, Confidence: confidence, Rule: "DirectCall", Condition: condition}
		if matched, ok := bc.store.Indices.MethodNameIndex[pattern]; ok && len(matched) > 0 {
			// 已解析到定义，但反射/动态代理类调用即使解析到定义也应标为相应类别
			// （target 可控，AI 需警觉），否则标 direct。
			ct := bc.classifyResolvedCall(calleeClass, methodName)
			edge.CallType = ct
			bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], edge)
			for _, calleeKey := range matched {
				bc.store.Calls.ReverseEdges[calleeKey] = append(bc.store.Calls.ReverseEdges[calleeKey], ReverseEdge{CallerKey: methodKey, Line: line, FilePath: filePath, CallType: ct})
			}
		} else {
			ct := bc.classifyUnresolvedCall(calleeClass, methodName)
			edge.CallType = ct
			bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], edge)
			bc.store.Calls.UnresolvedReverseEdges[pattern] = append(bc.store.Calls.UnresolvedReverseEdges[pattern], ReverseEdge{CallerKey: methodKey, Line: line, FilePath: filePath, CallType: ct})
		}
	}
	args := fieldChild(node, "arguments")
	if args != nil {
		argIdx := 0
		for _, arg := range nodeChildren(args) {
			if skipArgTypes[nodeType(arg)] || !argumentNodeTypes[nodeType(arg)] {
				continue
			}
			isT, source := bc.taintChecker.Check(arg, src, scope, currentClass, filePath, 0, taintCache)
			if isT && calleeClass != "" {
				bc.store.Calls.CallParamTaints = append(bc.store.Calls.CallParamTaints, CallParamTaint{CallerKey: methodKey, CalleeClass: calleeClass, CalleeMethod: methodName, ParamIndex: argIdx, TaintSource: source})
				if bc.store.Methods.ParamToCallParam[methodKey] == nil {
					bc.store.Methods.ParamToCallParam[methodKey] = make(map[string][]CallParamT)
				}
				if nodeType(arg) == "identifier" {
					paramName := nodeText(src, arg)
					bc.store.Methods.ParamToCallParam[methodKey][paramName] = append(bc.store.Methods.ParamToCallParam[methodKey][paramName], CallParamT{CalleeClass: calleeClass, CalleeMethod: methodName, ArgIndex: argIdx})
				}
			}
			argIdx++
		}
	}
	// R20 架构修复（D-R20a）：跨线程/异步调度边。
	// 当调用的方法实参是 Runnable/Callable 实现（new MyTask(...) / lambda / new Thread(task) 等），
	// 将「提交点方法」连接到被调度任务的 run()/call() 实现，使跨线程调用图与污点链路连通。
	// 类型驱动（基于 ClassInterfaces 的 implements Runnable/Callable），不硬编码 API 白名单，
	// 覆盖 ExecutorService.submit/execute、Thread、CompletableFuture.runAsync/supplyAsync 等。
	if args != nil {
		for _, arg := range nodeChildren(args) {
			if skipArgTypes[nodeType(arg)] {
				continue
			}
			argCls := bc.typeResolver.ResolveType(arg, currentClass, src, filePath, scope)
			if argCls == "" {
				continue
			}
			ifaces := bc.store.Types.ClassInterfaces[argCls]
			isTask := false
			for _, iface := range ifaces {
				if iface == "Runnable" || iface == "Callable" || strings.HasSuffix(iface, ".Runnable") || strings.HasSuffix(iface, ".Callable") {
					isTask = true
					break
				}
			}
			if !isTask {
				continue
			}
			// 找该任务类的 run() / call() 实现（方法键可能无参形式 MyTask.run 或带签名 MyTask.run(...)）
			for _, m := range []string{"run", "call"} {
				exact := argCls + "." + m
				matchedKeys := []string{}
				for mk := range bc.store.Indices.MethodNameIndex {
					if mk == exact || strings.HasPrefix(mk, exact+"(") {
						matchedKeys = append(matchedKeys, mk)
					}
				}
				for _, mk := range matchedKeys {
					edge := CallEdge{CalleeClass: argCls, CalleeMethod: m, Line: line, FilePath: filePath, ArgCount: 0, Confidence: ConfExact, Rule: "AsyncDispatch", Condition: condition, CallType: CallAsyncDispatch}
					bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], edge)
					bc.store.Calls.ReverseEdges[mk] = append(bc.store.Calls.ReverseEdges[mk], ReverseEdge{CallerKey: methodKey, Line: line, FilePath: filePath, CallType: CallAsyncDispatch})
				}
			}
		}
	}
	// Collection add/put propagation (mirror 7.py:3549-3575)
	if collectionMethods[methodName] {
		if objNode != nil && args != nil {
			for _, arg := range nodeChildren(args) {
				if skipArgTypes[nodeType(arg)] {
					continue
				}
				isT2, argSource := bc.taintChecker.Check(arg, src, scope, currentClass, filePath, 0, taintCache)
				if isT2 {
					collFieldName := bc.extractThisField(objNode, src, currentClass)
					if collFieldName != "" {
						fkey := currentClass + "." + collFieldName
						line2 := startLine1(node)
						assignText2 := strings.TrimSpace(nodeText(src, node))
						bc.store.Fields.AddTaint(fkey, TaintInfo{
							SourceType:   TaintSrcUserInput,
							SourceMethod: argSource,
							AssignMethod: MethodKeyHelper{}.MethodName(methodKey),
							AssignLine:   line2,
							AssignFile:   filePath,
							AssignText:   assignText2,
							AssignType:   AssignRuntime,
						})
					}
					break
				}
			}
		}
	}
}

// classifyReflectOrProxy 识别反射 / 动态代理调用。由于 AST 解析出的 calleeClass
// 可能是简名/别名而非精确 FQN，采用「后缀匹配 + 方法名」降级识别，确保高风险
// 反射调用（target 可控，潜在 RCE）被准确分类，供 AI 警觉。
func (bc *MethodBodyCollector) classifyReflectOrProxy(calleeClass, methodName string) CallType {
	// calleeClass 可能是完整 FQN（java.lang.reflect.Method）或简名（Method），
	// 故同时匹配后缀与精确简名。
	if methodName == "invoke" &&
		(strings.HasSuffix(calleeClass, "reflect.Method") || calleeClass == "Method") {
		return CallReflection
	}
	if methodName == "newInstance" &&
		(strings.HasSuffix(calleeClass, "reflect.Constructor") || calleeClass == "Constructor") {
		return CallReflection
	}
	if methodName == "newProxyInstance" &&
		(strings.HasSuffix(calleeClass, "reflect.Proxy") || calleeClass == "Proxy") {
		return CallDynamicProxy
	}
	return ""
}

// classifyUnresolvedCall 为无法精确解析到方法定义的调用判定调用类别，
// 供断点补齐（B2）结构化输出 call_type。注意：bodycollector 运行于
// BuildIfaceImplMap 之后，故 IfaceImplMap 可用。
func (bc *MethodBodyCollector) classifyUnresolvedCall(calleeClass, methodName string) CallType {
	if ct := bc.classifyReflectOrProxy(calleeClass, methodName); ct != "" {
		return ct
	}
	// G4-1：RPC 跨服务接口识别。calleeClass 的仓内类注解可揭示其 RPC 性质，
	// 引擎单仓扫描时已解析这些接口定义，故单列 call_type 供 AI 基于契约推理。
	if ct := classifyRPC(bc.store, calleeClass, methodName); ct != "" {
		return ct
	}
	// G4-2：JDK 标准库调用。按包前缀通用规则判定（非硬编码特定方法），
	// 避免将 File.listFiles / String.substring 等标为 unresolved 噪声。
	if isStdlibClass(calleeClass) {
		return CallStdlib
	}
	// 接口多态：calleeClass 是已知接口（有实现类）但本仓库未含其实现
	if _, isIface := bc.store.Types.InterfaceMethods[calleeClass]; isIface {
		return CallInterface
	}
	if impls := bc.store.Types.IfaceImplMap[calleeClass]; len(impls) > 0 {
		return CallInterface
	}
	// 仓内嵌套类/内部接口：形如 Outer$Inner 的 calleeClass 若在仓内 Methods 中存在，
	// 说明定义就在本仓，应按 interface 处理而非 unresolved（消除 F08 自相矛盾）。
	if idx := strings.LastIndex(calleeClass, "$"); idx > 0 {
		outer := calleeClass[:idx]
		if _, isIface := bc.store.Types.InterfaceMethods[outer]; isIface {
			return CallInterface
		}
		if impls := bc.store.Types.IfaceImplMap[outer]; len(impls) > 0 {
			return CallInterface
		}
	}
	return CallUnresolved
}

// isStdlibClass 按包前缀通用判定 JDK 标准库类（G4-2）。
// 规则：以 java./javax./sun./jdk./android./kotlin./scala. 等标准库根包开头的 FQN，
// 或简名命中已知核心类（如 String/List/Map/File/Object/Math 等无包前缀的 JDK 简名）。
func isStdlibClass(calleeClass string) bool {
	switch {
	case strings.HasPrefix(calleeClass, "java."),
		strings.HasPrefix(calleeClass, "javax."),
		strings.HasPrefix(calleeClass, "sun."),
		strings.HasPrefix(calleeClass, "jdk."),
		strings.HasPrefix(calleeClass, "android."),
		strings.HasPrefix(calleeClass, "kotlin."),
		strings.HasPrefix(calleeClass, "scala."):
		return true
	}
	// 无包前缀的 JDK 核心简名（如 java.lang 下的类被解析为简名时）。
	stdlibShort := map[string]bool{
		"Object": true, "String": true, "Integer": true, "Long": true, "Double": true,
		"Boolean": true, "Float": true, "Short": true, "Byte": true, "Character": true,
		"Math": true, "System": true, "Runtime": true, "Process": true, "ProcessBuilder": true,
		"File": true, "List": true, "Map": true, "Set": true, "Collection": true,
		"HashMap": true, "ArrayList": true, "StringBuilder": true, "StringBuffer": true,
		"Thread": true, "Throwable": true, "Exception": true, "RuntimeException": true,
		"Arrays": true, "Collections": true, "Class": true, "ClassLoader": true,
		"URL": true, "URI": true, "InputStream": true, "OutputStream": true,
		"BufferedReader": true, "PrintWriter": true, "Logger": true,
	}
	return stdlibShort[calleeClass]
}

// classifyRPC 依据 calleeClass 的仓内类注解与方法注解判定是否为 RPC 跨服务调用。
// 仅依赖引擎已解析的数据（ClassAnnotations / Methods.Annotations），不跨仓。
func classifyRPC(store *AnalysisStore, calleeClass, methodName string) CallType {
	for _, ann := range store.Types.ClassAnnotations[calleeClass] {
		switch ann.Name {
		case "FeignClient":
			return CallRPCFeign
		case "DubboService", "DubboReference", "Reference":
			return CallRPCDubbo
		}
	}
	// gRPC 注解写入端使用 Build 风格 key（class.method(...) 带参数后缀，见
	// extractor.go:411 等 6 处），而调用点仅持有裸 class.method。先按裸 Pattern
	// 直接查，未命中再经 MethodNameIndex 归约表回查 Build-key 列表，逐一匹配
	// GrpcMethod/GrpcStub（C1 修复：修复前裸 key 与写入 key 格式不一致导致永不命中）。
	checkGrpc := func(mk string) bool {
		for _, ann := range store.Methods.Annotations[mk] {
			if ann.Name == "GrpcMethod" || ann.Name == "GrpcStub" {
				return true
			}
		}
		return false
	}
	if checkGrpc(MethodKeyHelper{}.Pattern(calleeClass, methodName)) {
		return CallRPCGrpc
	}
	if store.Indices != nil {
		for _, mk := range store.Indices.MethodNameIndex[calleeClass+"."+methodName] {
			if checkGrpc(mk) {
				return CallRPCGrpc
			}
		}
	}
	return ""
}

// classifyResolvedCall 用于已解析到定义的调用：默认 direct，但反射 / 动态代理
// 调用即使解析到定义也应标为相应类别（target 可控风险），让 AI 警觉。
func (bc *MethodBodyCollector) classifyResolvedCall(calleeClass, methodName string) CallType {
	if ct := bc.classifyReflectOrProxy(calleeClass, methodName); ct != "" {
		return ct
	}
	// R12：native 方法（JNI 黑盒）识别。实现在 .so/.dll 静态不可见，
	// 污点流入后无法继续追踪，调用边须标为 CallNative 供 AI/DFS 警觉。
	for _, mk := range bc.store.Indices.MethodNameIndex[calleeClass+"."+methodName] {
		if bc.store.Methods.NativeMethods[mk] {
			return CallNative
		}
	}
	return CallDirect
}

func (bc *MethodBodyCollector) handleAssignment(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	leftNode := fieldChild(node, "left")
	rightNode := fieldChild(node, "right")
	if leftNode == nil || rightNode == nil {
		return
	}
	fieldName := bc.extractThisField(leftNode, src, currentClass)
	if fieldName == "" {
		// Local variable reassignment (mirror 7.py:3761-3768)
		if nodeType(leftNode) == "identifier" {
			varName := nodeText(src, leftNode)
			if scope.Resolve(varName) != "" {
				var newTaint map[string]bool
				isT2, source2 := bc.taintChecker.Check(rightNode, src, scope, currentClass, filePath, 0, taintCache)
				if isT2 {
					newTaint = map[string]bool{source2: true}
				}
				// R01（架构级，非 hardcode）：control-dependency 隐式流。
				// 若本赋值位于 if 分支内，且该 if 的 condition 引用了已污点变量，
				// 则即使 rightNode 干净，target 仍被间接污染（干净变量因条件分支被间接污点）。
				if newTaint == nil {
					if condVars := bc.ifBranchTaintCondVars(node, src, scope, currentClass, filePath, methodKey, taintCache); len(condVars) > 0 {
						newTaint = make(map[string]bool)
						for _, cv := range condVars {
							newTaint["CONTROL_DEP:"+cv] = true
						}
					}
				}
				scope.Reassign(varName, newTaint)
				// R01 同步回写 LocalVars 存储（与 handleLocalVarDecl 对称），
				// 否则反向追踪(traceToSourcesCore 读 LocalVars)无法看到本赋值引入的污点（含 control-dep）。
				if methodKey != "" {
					if bc.store.Methods.LocalVars[methodKey] == nil {
						bc.store.Methods.LocalVars[methodKey] = make(map[string]LocalVar)
					}
					var sources []string
					if newTaint != nil {
						for s := range newTaint {
							sources = append(sources, s)
						}
					}
					// 保留声明时的 InitText/Line/Type，仅更新污点状态。
					existing := bc.store.Methods.LocalVars[methodKey][varName]
					existing.Tainted = newTaint != nil
					existing.Sources = sources
					bc.store.Methods.LocalVars[methodKey][varName] = existing
				}
				// R5-2：右值是方法调用且该方法返回值字段透传自实参（深拷贝/克隆）→
				// 把实参字段污点继承到左值（与声明初始化路径共用 inheritReturnFieldTaint）。
				bc.inheritReturnFieldTaint(scope, varName, rightNode, src)
			}
		} else if nodeType(leftNode) == "field_access" {
			// R5-2：局部对象字段赋值 `d.field = X` —— 记录变量 d 的字段污点。
			// 典型深拷贝：d.data = src.data（src 为污点实参）→ cloneOf 返回对象的 .data 字段携带污点，
			// 调用方 `copy.data` 读取时可穿透返回值闭合。
			objNode := fieldChild(leftNode, "object")
			fldNode := fieldChild(leftNode, "field")
			if objNode != nil && nodeType(objNode) == "identifier" && fldNode != nil {
				dName := nodeText(src, objNode)
				fld := nodeText(src, fldNode)
				if scope.Resolve(dName) != "" {
					if nodeType(rightNode) == "field_access" {
						// R5-2：retField 透传自实参字段（src.data）→ 记录字段名映射
						srcFldNode := fieldChild(rightNode, "field")
						if srcFldNode != nil {
							scope.SetFieldTaint(dName, fld, nodeText(src, srcFldNode))
						}
					} else {
						isT2, source2 := bc.taintChecker.Check(rightNode, src, scope, currentClass, filePath, 0, taintCache)
						if isT2 {
							scope.SetFieldTaint(dName, fld, source2)
						}
					}
				}
			}
			return
		}
		// 兜底：fieldName=="" 时（局部变量赋值，无论 identifier/field_access 是否命中）
		// 必须 return，否则会穿透到下方字段赋值逻辑导致 fieldName[:1] 越界 panic。
		return
	}
	fieldKey := currentClass + "." + fieldName
	isT, source := bc.taintChecker.Check(rightNode, src, scope, currentClass, filePath, 0, taintCache)
	line := startLine1(node)
	assignText := strings.TrimSpace(nodeText(src, node))
	isValidated, validationCtx := bc.validationChecker.Check(node, src, currentClass)
	assignType := AssignRuntime
	if bc.isPostConstructMethod(methodKey) {
		assignType = AssignPostConstruct
	} else if bc.isConstructorMethod(methodKey) {
		assignType = AssignConstructor
	}
	// Setter injection detection (mirror 7.py:3815-3818)
	methodCallerName := MethodKeyHelper{}.MethodName(methodKey)
	expectedSetter := "set" + strings.ToUpper(fieldName[:1]) + fieldName[1:]
	if methodCallerName == expectedSetter {
		for _, ann := range bc.store.Methods.Annotations[methodKey] {
			if injectAnnotations[ann.Name] {
				assignType = AssignSpringInjection
				break
			}
		}
	}
	var taintInfo *TaintInfo
	if isT {
		taintInfo = &TaintInfo{SourceType: TaintSrcUserInput, SourceMethod: source, AssignMethod: methodKey, AssignLine: line, AssignFile: filePath, AssignText: assignText, AssignType: assignType}
	}
	assignment := FieldAssignment{ClassName: currentClass, MethodKey: methodKey, MethodName: MethodKeyHelper{}.MethodName(methodKey), Line: line, FilePath: filePath, AssignText: assignText, AssignType: assignType, TaintInfo: taintInfo, IsValidated: isValidated, ValidationContext: validationCtx}
	bc.store.Fields.Assignments[fieldKey] = append(bc.store.Fields.Assignments[fieldKey], assignment)
	if isT && taintInfo != nil {
		bc.store.Fields.AddTaint(fieldKey, *taintInfo)
	}
	if nodeType(rightNode) == "identifier" {
		varName := nodeText(src, rightNode)
		if bc.store.Methods.LocalToField[methodKey] == nil {
			bc.store.Methods.LocalToField[methodKey] = make(map[string][]string)
		}
		existing := toSet(bc.store.Methods.LocalToField[methodKey][varName])
		if !existing[fieldKey] {
			bc.store.Methods.LocalToField[methodKey][varName] = append(bc.store.Methods.LocalToField[methodKey][varName], fieldKey)
		}
		if bc.store.Methods.ParamOrder[methodKey] != nil {
			if _, isParam := bc.store.Methods.ParamOrder[methodKey][varName]; isParam {
				if bc.store.Methods.ParamToField[methodKey] == nil {
					bc.store.Methods.ParamToField[methodKey] = make(map[string][]string)
				}
				existingPF := toSet(bc.store.Methods.ParamToField[methodKey][varName])
				if !existingPF[fieldKey] {
					bc.store.Methods.ParamToField[methodKey][varName] = append(bc.store.Methods.ParamToField[methodKey][varName], fieldKey)
				}
			}
		}
	}
	if nodeType(rightNode) == "field_access" {
		rObjNode := fieldChild(rightNode, "object")
		rFieldNode := fieldChild(rightNode, "field")
		if rObjNode != nil && rFieldNode != nil {
			rObjText := nodeText(src, rObjNode)
			rFieldName := nodeText(src, rFieldNode)
			if rObjText == "this" || rObjText == currentClass {
				srcFieldKey := currentClass + "." + rFieldName
				bc.store.Fields.FieldToFieldEdges = append(bc.store.Fields.FieldToFieldEdges, FieldToFieldEdge{SrcFieldKey: srcFieldKey, DstFieldKey: fieldKey, MethodKey: methodKey, Line: line, FilePath: filePath, AssignText: assignText, AssignType: "runtime"})
			} else if strings.HasSuffix(rObjText, ".this") {
				srcFieldKey := currentClass + "." + rFieldName
				bc.store.Fields.FieldToFieldEdges = append(bc.store.Fields.FieldToFieldEdges, FieldToFieldEdge{SrcFieldKey: srcFieldKey, DstFieldKey: fieldKey, MethodKey: methodKey, Line: line, FilePath: filePath, AssignText: assignText, AssignType: "runtime"})
			} else {
				// obj.field edge (mirror 7.py:3882-3888)
				rObjClass := bc.typeResolver.ResolveType(rObjNode, currentClass, src, filePath, scope)
				if rObjClass != "" {
					rFkey := rObjClass + "." + rFieldName
					if _, ok := bc.store.Types.GlobalFieldTypes[rFkey]; ok {
						bc.store.Fields.FieldToFieldEdges = append(bc.store.Fields.FieldToFieldEdges, FieldToFieldEdge{SrcFieldKey: rFkey, DstFieldKey: fieldKey, MethodKey: methodKey, Line: line, FilePath: filePath, AssignText: assignText, AssignType: "runtime"})
					}
				}
			}
		}
	}
	if nodeType(rightNode) == "method_invocation" {
		bc.recordCallSiteFieldAssign(rightNode, fieldKey, methodKey, line, src, currentClass, filePath, scope)
	}
}

func (bc *MethodBodyCollector) handleFieldAccess(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string) {
	objNode := fieldChild(node, "object")
	fieldNode := fieldChild(node, "field")
	if objNode == nil || fieldNode == nil {
		return
	}
	objText := nodeText(src, objNode)
	fieldName := nodeText(src, fieldNode)
	if objText == "this" || objText == currentClass {
		fieldKey := currentClass + "." + fieldName
		bc.store.Fields.Reads[fieldKey] = append(bc.store.Fields.Reads[fieldKey], FieldRead{MethodKey: methodKey, Line: startLine1(node), FilePath: filePath})
	}
}

func (bc *MethodBodyCollector) determineCallCondition(node *gotreesitter.Node, src []byte) CallCondition {
	parent := node.Parent()
	if parent != nil {
		if nodeType(parent) == "lambda_expression" {
			return CondLambda
		}
		gp := parent.Parent()
		if gp != nil && nodeType(gp) == "if_statement" {
			condition := fieldChild(gp, "condition")
			if condition != nil {
				return CondIfBranch
			}
		}
	}
	if nodeType(node) == "method_invocation" {
		objNode := fieldChild(node, "object")
		if objNode != nil && nodeText(src, objNode) == "this" {
			return CondSelfCall
		}
	}
	return CondNone
}

// ifBranchTaintCondVars 沿 AST 祖先链遍历所有 if_statement 祖先，
// 收集每个 if 的 condition 中已污点的变量名，累积到同一结果集（去重）。
// 用于 R01 control-dependency 隐式流：当赋值位于 if 分支内，且条件引用了污点变量，
// 则目标变量被间接污染。架构级：基于已有 taintChecker + AST 祖先遍历，非 hardcode。
// 注：必须累积所有 if 祖先（而非命中最近 if 即返回），否则嵌套 if 场景下外层
// 污点条件会丢失，导致内层分支赋值漏标 CONTROL_DEP（隐式流漏报退化路径）。
func (bc *MethodBodyCollector) ifBranchTaintCondVars(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath, methodKey string, taintCache map[[2]int]taintCheckResult) []string {
	seen := make(map[string]bool)
	var result []string
	var walk func(n *gotreesitter.Node)
	walk = func(n *gotreesitter.Node) {
		if n == nil {
			return
		}
		if nodeType(n) == "identifier" {
			name := nodeText(src, n)
			isT, _ := bc.taintChecker.Check(n, src, scope, currentClass, filePath, 0, taintCache)
			// 参数污点通过 ParamTaints 标记（entry param），checkIdentifier 仅查 scope，
			// 故补充检查该方法污点参数，确保 if 条件引用 entry 参数时能被识别。
			if !isT {
				if pts, ok := bc.store.Methods.ParamTaints[methodKey]; ok {
					if _, has := pts[name]; has {
						isT = true
					}
				}
			}
			if isT && !seen[name] {
				seen[name] = true
				result = append(result, name)
			}
			return
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	for cur := node.Parent(); cur != nil; cur = cur.Parent() {
		if nodeType(cur) == "if_statement" {
			if cond := fieldChild(cur, "condition"); cond != nil {
				walk(cond)
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (bc *MethodBodyCollector) extractThisField(node *gotreesitter.Node, src []byte, currentClass string) string {
	nt := nodeType(node)
	if nt == "field_access" {
		objNode := fieldChild(node, "object")
		fieldNode := fieldChild(node, "field")
		if objNode != nil && fieldNode != nil {
			objText := nodeText(src, objNode)
			if objText == "this" || objText == currentClass {
				return nodeText(src, fieldNode)
			}
		}
	} else if nt == "identifier" {
		parent := node.Parent()
		if parent != nil && nodeType(parent) == "assignment_expression" {
			leftNode := fieldChild(parent, "left")
			if leftNode != nil && sameNode(leftNode, node) {
				name := nodeText(src, node)
				fieldKey := currentClass + "." + name
				if _, ok := bc.store.Types.GlobalFieldTypes[fieldKey]; ok {
					return name
				}
			}
		}
	}
	return ""
}

func (bc *MethodBodyCollector) isPostConstructMethod(methodKey string) bool {
	for _, ann := range bc.store.Methods.Annotations[methodKey] {
		if ann.Name == "PostConstruct" {
			return true
		}
	}
	return false
}

func (bc *MethodBodyCollector) isConstructorMethod(methodKey string) bool {
	return bc.store.Types.ConstructorMethodKeys[methodKey]
}

// ============================================================
//  CRITICAL #1: ParamToReturn 填充 — checkReturnParamRefs
//  镜像 7.py:3999-4034
// ============================================================

func (bc *MethodBodyCollector) checkReturnParamRefs(node *gotreesitter.Node, src []byte, methodKey string, scope *MethodScope, currentClass string) {
	if node == nil || skipRecurseTypes[nodeType(node)] {
		return
	}
	nt := nodeType(node)
	if nt == "identifier" {
		name := nodeText(src, node)
		if paramOrder := bc.store.Methods.ParamOrder[methodKey]; paramOrder != nil {
			if _, ok := paramOrder[name]; ok {
				existing := toSet(bc.store.Methods.ParamToReturn[methodKey])
				if !existing[name] {
					bc.store.Methods.ParamToReturn[methodKey] = append(bc.store.Methods.ParamToReturn[methodKey], name)
				}
			}
		}
		return
	}
	if nt == "field_access" && currentClass != "" {
		objNode := fieldChild(node, "object")
		fieldNode := fieldChild(node, "field")
		if objNode != nil && fieldNode != nil {
			objText := nodeText(src, objNode)
			if objText == "this" || objText == currentClass || strings.HasSuffix(objText, ".this") {
				fieldName := nodeText(src, fieldNode)
				if paramOrder := bc.store.Methods.ParamOrder[methodKey]; paramOrder != nil {
					if _, ok := paramOrder[fieldName]; ok {
						existing := toSet(bc.store.Methods.ParamToReturn[methodKey])
						if !existing[fieldName] {
							bc.store.Methods.ParamToReturn[methodKey] = append(bc.store.Methods.ParamToReturn[methodKey], fieldName)
						}
					}
				}
			}
		}
		return
	}
	if nt == "method_invocation" {
		objNode := fieldChild(node, "object")
		if objNode != nil {
			bc.checkReturnParamRefs(objNode, src, methodKey, scope, currentClass)
		}
		args := fieldChild(node, "arguments")
		if args != nil {
			for _, arg := range nodeChildren(args) {
				if !skipArgTypes[nodeType(arg)] {
					bc.checkReturnParamRefs(arg, src, methodKey, scope, currentClass)
				}
			}
		}
		return
	}
	for _, child := range nodeChildren(node) {
		bc.checkReturnParamRefs(child, src, methodKey, scope, currentClass)
	}
}

// ============================================================
//  增强 #18: 递归 return 字段扫描 — checkReturnFieldRefs
//  镜像 7.py:3973-3997
// ============================================================

func (bc *MethodBodyCollector) checkReturnFieldRefs(node *gotreesitter.Node, src []byte, methodKey, currentClass string, scope *MethodScope) {
	if node == nil || skipRecurseTypes[nodeType(node)] {
		return
	}
	nt := nodeType(node)
	if nt == "field_access" {
		objNode := fieldChild(node, "object")
		fieldNode := fieldChild(node, "field")
		if objNode != nil && fieldNode != nil {
			objText := nodeText(src, objNode)
			if objText == "this" || objText == currentClass || strings.HasSuffix(objText, ".this") {
				fieldName := nodeText(src, fieldNode)
				fieldKey := currentClass + "." + fieldName
				existing := toSet(bc.store.Methods.ReturnFields[methodKey])
				if !existing[fieldKey] {
					bc.store.Methods.ReturnFields[methodKey] = append(bc.store.Methods.ReturnFields[methodKey], fieldKey)
				}
			}
		}
		return
	}
	if nt == "identifier" {
		name := nodeText(src, node)
		fkey := currentClass + "." + name
		if _, ok := bc.store.Types.GlobalFieldTypes[fkey]; ok {
			if scope == nil || scope.Resolve(name) == "" {
				existing := toSet(bc.store.Methods.ReturnFields[methodKey])
				if !existing[fkey] {
					bc.store.Methods.ReturnFields[methodKey] = append(bc.store.Methods.ReturnFields[methodKey], fkey)
				}
			}
		}
		return
	}
	if nt == "method_invocation" {
		return
	}
	for _, child := range nodeChildren(node) {
		bc.checkReturnFieldRefs(child, src, methodKey, currentClass, scope)
	}
}

// ============================================================
//  CRITICAL #2: CallSiteFieldAssigns 填充 — recordCallSiteFieldAssign
//  镜像 7.py:3902-3929
// ============================================================

func (bc *MethodBodyCollector) recordCallSiteFieldAssign(rightNode *gotreesitter.Node, fieldKey, methodKey string, line int, src []byte, currentClass, filePath string, scope *MethodScope) {
	rNameNode := fieldChild(rightNode, "name")
	if rNameNode == nil {
		return
	}
	rMethod := nodeText(src, rNameNode)
	rObjNode := fieldChild(rightNode, "object")
	var rObjClass string
	if rObjNode != nil {
		rObjText := nodeText(src, rObjNode)
		if rObjText == "super" {
			rObjClass = bc.store.Types.ClassExtends[currentClass]
			if rObjClass == "" {
				rObjClass = currentClass
			}
		} else {
			rObjClass = bc.typeResolver.ResolveType(rObjNode, currentClass, src, filePath, scope)
		}
	} else {
		rObjClass = currentClass
	}
	rArgCount := bc.typeResolver.CountArguments(rightNode)
	var rCalleeKey string
	if rObjClass != "" {
		_, rCalleeKey = bc.typeResolver.ResolveMethodClass(rObjClass, rMethod, rArgCount)
	}
	bc.store.Fields.CallSiteFieldAssigns = append(bc.store.Fields.CallSiteFieldAssigns, CallSiteFieldAssign{
		CallerKey:    methodKey,
		CalleeKey:    rCalleeKey,
		CalleeClass:  rObjClass,
		CalleeMethod: rMethod,
		CalleeArgCnt: rArgCount,
		FieldKey:     fieldKey,
		AssignLine:   line,
	})
}

// ============================================================
//  CRITICAL #3: 构造函数参数污点传播 — PropagateCtorParamTaint
//  镜像 7.py:5204-5258
// ============================================================

func (bc *MethodBodyCollector) PropagateCtorParamTaint(bodyNode *gotreesitter.Node, src []byte, currentClass, methodKey, filePath, paramName string, taintSources []string) {
	bc.scanCtorBody(bodyNode, src, currentClass, methodKey, filePath, paramName, taintSources)
}

func (bc *MethodBodyCollector) scanCtorBody(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath, paramName string, taintSources []string) {
	if node == nil || skipRecurseTypes[nodeType(node)] {
		return
	}
	nt := nodeType(node)
	if nt == "assignment_expression" {
		left := fieldChild(node, "left")
		right := fieldChild(node, "right")
		if left != nil && right != nil {
			if bc.exprReferencesNameOrTainted(right, src, paramName, currentClass, filePath) {
				fieldName := bc.extractThisField(left, src, currentClass)
				if fieldName != "" {
					fkey := currentClass + "." + fieldName
					line := startLine1(node)
					assignText := strings.TrimSpace(nodeText(src, node))
					isConfig := false
					for _, s := range taintSources {
						if strings.Contains(s, string(TaintSrcConfigValue)) {
							isConfig = true
							break
						}
					}
					sourceType := TaintSrcUserInput
					if isConfig {
						sourceType = TaintSrcConfigValue
					}
					sourceMethodName := paramName
					if len(taintSources) > 0 {
						sourceMethodName = taintSources[0]
					}
					assignMethod := currentClass
					if i := strings.LastIndex(currentClass, "$"); i >= 0 {
						assignMethod = currentClass[i+1:]
					}
					bc.store.Fields.AddTaint(fkey, TaintInfo{
						SourceType:   sourceType,
						SourceMethod: sourceMethodName,
						AssignMethod: assignMethod,
						AssignLine:   line,
						AssignFile:   filePath,
						AssignText:   assignText,
						AssignType:   AssignConstructor,
					})
				}
			}
		}
	}
	if nt == "method_invocation" {
		nameNode := fieldChild(node, "name")
		objNode := fieldChild(node, "object")
		args := fieldChild(node, "arguments")
		if nameNode != nil && args != nil {
			methodName := nodeText(src, nameNode)
			if collectionMethods[methodName] {
				for _, arg := range nodeChildren(args) {
					if !skipArgTypes[nodeType(arg)] {
						if bc.exprReferencesName(arg, src, paramName) {
							if objNode != nil {
								fieldName := bc.extractThisField(objNode, src, currentClass)
								if fieldName != "" {
									fkey := currentClass + "." + fieldName
									line := startLine1(node)
									assignText := strings.TrimSpace(nodeText(src, node))
									isConfig := false
									for _, s := range taintSources {
										if strings.Contains(s, string(TaintSrcConfigValue)) {
											isConfig = true
											break
										}
									}
									sourceType := TaintSrcUserInput
									if isConfig {
										sourceType = TaintSrcConfigValue
									}
									sourceMethodName := paramName
									if len(taintSources) > 0 {
										sourceMethodName = taintSources[0]
									}
									assignMethod := currentClass
									if i := strings.LastIndex(currentClass, "$"); i >= 0 {
										assignMethod = currentClass[i+1:]
									}
									bc.store.Fields.AddTaint(fkey, TaintInfo{
										SourceType:   sourceType,
										SourceMethod: sourceMethodName,
										AssignMethod: assignMethod,
										AssignLine:   line,
										AssignFile:   filePath,
										AssignText:   assignText,
										AssignType:   AssignConstructor,
									})
									break
								}
							}
						}
					}
				}
			}
		}
	}
	for _, child := range nodeChildren(node) {
		bc.scanCtorBody(child, src, currentClass, methodKey, filePath, paramName, taintSources)
	}
}

// exprReferencesName 检查节点是否引用了指定名称的变量（镜像 7.py:5310-5326）。
func (bc *MethodBodyCollector) exprReferencesName(node *gotreesitter.Node, src []byte, name string) bool {
	if node == nil {
		return false
	}
	nt := nodeType(node)
	if nt == "identifier" {
		return nodeText(src, node) == name
	}
	if nt == "method_invocation" {
		args := fieldChild(node, "arguments")
		if args != nil {
			for _, arg := range nodeChildren(args) {
				if !skipArgTypes[nodeType(arg)] {
					if bc.exprReferencesName(arg, src, name) {
						return true
					}
				}
			}
		}
		return false
	}
	for _, child := range nodeChildren(node) {
		if bc.exprReferencesName(child, src, name) {
			return true
		}
	}
	return false
}

// exprReferencesNameOrTainted 递归检查节点是否引用了指定名称的变量（镜像 7.py:5260-5308）。
func (bc *MethodBodyCollector) exprReferencesNameOrTainted(node *gotreesitter.Node, src []byte, name, currentClass, filePath string) bool {
	if node == nil {
		return false
	}
	nt := nodeType(node)
	if nt == "identifier" {
		return nodeText(src, node) == name
	}
	if nt == "method_invocation" {
		objNode := fieldChild(node, "object")
		if objNode != nil {
			if bc.exprReferencesNameOrTainted(objNode, src, name, currentClass, filePath) {
				return true
			}
		}
		args := fieldChild(node, "arguments")
		if args != nil {
			for _, arg := range nodeChildren(args) {
				if !skipArgTypes[nodeType(arg)] {
					if bc.exprReferencesNameOrTainted(arg, src, name, currentClass, filePath) {
						return true
					}
				}
			}
		}
		return false
	}
	if nt == "field_access" {
		objNode := fieldChild(node, "object")
		if objNode != nil {
			return bc.exprReferencesNameOrTainted(objNode, src, name, currentClass, filePath)
		}
		return false
	}
	if nt == "cast_expression" {
		valueNode := fieldChild(node, "value")
		if valueNode != nil {
			return bc.exprReferencesNameOrTainted(valueNode, src, name, currentClass, filePath)
		}
		return false
	}
	if nt == "ternary_expression" {
		consequence := fieldChild(node, "consequence")
		alternative := fieldChild(node, "alternative")
		if consequence != nil && bc.exprReferencesNameOrTainted(consequence, src, name, currentClass, filePath) {
			return true
		}
		if alternative != nil && bc.exprReferencesNameOrTainted(alternative, src, name, currentClass, filePath) {
			return true
		}
		return false
	}
	if nt == "parenthesized_expression" {
		for _, child := range nodeChildren(node) {
			ct := nodeType(child)
			if ct != "(" && ct != ")" {
				return bc.exprReferencesNameOrTainted(child, src, name, currentClass, filePath)
			}
		}
	}
	if nt == "binary_expression" {
		for _, child := range nodeChildren(node) {
			if !comparisonOperators[nodeType(child)] {
				if bc.exprReferencesNameOrTainted(child, src, name, currentClass, filePath) {
					return true
				}
			}
		}
		return false
	}
	for _, child := range nodeChildren(node) {
		if bc.exprReferencesNameOrTainted(child, src, name, currentClass, filePath) {
			return true
		}
	}
	return false
}

// ============================================================
//  AST Handler #6: lambda_expression (镜像 7.py:3617-3691)
// ============================================================

func (bc *MethodBodyCollector) handleLambda(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope, taintCache map[[2]int]taintCheckResult) {
	lambdaKey := [2]int{filePath2int(filePath), int(node.StartByte())}
	if _, ok := bc.lambdaMethodMap[lambdaKey]; !ok {
		bc.lambdaMethodMap[lambdaKey] = methodKey + "$lambda$" + strconv.Itoa(len(bc.lambdaMethodMap)+1)
	}
	lambdaMethodKey := bc.lambdaMethodMap[lambdaKey]
	lambdaLine := startLine1(node)
	bc.store.Methods.Functions[lambdaMethodKey] = MethodFunc{Class: currentClass, Method: "<lambda@" + strconv.Itoa(lambdaLine) + ">", Line: lambdaLine, FilePath: filePath}
	bc.store.Methods.Annotations[lambdaMethodKey] = nil
	bc.store.Methods.SyntheticMethods[lambdaMethodKey] = true
	bc.store.RegisterMethodIndex(lambdaMethodKey)
	bc.store.Methods.ParamCounts[lambdaMethodKey] = 0
	lambdaDisplayName := lambdaMethodKey
	if i := strings.Index(lambdaMethodKey, "("); i > 0 {
		lambdaDisplayName = lambdaMethodKey[:i]
	}
	if i := strings.LastIndex(lambdaDisplayName, "."); i >= 0 {
		lambdaDisplayName = lambdaDisplayName[i+1:]
	}
	bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], CallEdge{
		CalleeClass: currentClass, CalleeMethod: lambdaDisplayName, Line: lambdaLine, FilePath: filePath, ArgCount: 0, Confidence: ConfExact, Condition: CondLambda,
	})
	lambdaScope := NewMethodScope(currentClass, scope)
	lambdaParamIndex := 0
	lambdaParamOrder := make(map[string]int)
	// R6-2：在定义 lambda 参数时即注入「上游继承污点」，而非定义后再 Reassign。
	// 原因：taintCache 会缓存 lambda body 内 x 的首次 Check 结果；若先 Define(无污点) 后
	// Reassign，body 内 x 可能在 Reassign 前被 Check 并缓存 false，使注入失效。故在 Define 时
	// 就带上 source，保证首次 Check 即命中。
	inheritedSource := bc.lambdaInheritedSource(node, src, scope, currentClass, filePath, taintCache)
	defineParam := func(pname, varType string) {
		var srcMap map[string]bool
		if inheritedSource != "" {
			srcMap = map[string]bool{inheritedSource: true}
		}
		lambdaScope.Define(pname, varType, srcMap)
		lambdaParamOrder[pname] = lambdaParamIndex
		lambdaParamIndex++
	}
	for _, child := range nodeChildren(node) {
		ct := nodeType(child)
		if ct == "identifier" {
			defineParam(nodeText(src, child), "Object")
		} else if ct == "formal_parameters" {
			for _, param := range nodeChildren(child) {
				if nodeType(param) != "formal_parameter" {
					continue
				}
				tn := fieldChild(param, "type")
				nn := fieldChild(param, "name")
				if tn != nil && nn != nil {
					defineParam(nodeText(src, nn), strings.TrimSpace(nodeText(src, tn)))
				} else if nn != nil {
					defineParam(nodeText(src, nn), "Object")
				}
			}
		} else if ct == "inferred_parameters" {
			for _, param := range nodeChildren(child) {
				if nodeType(param) == "identifier" {
					defineParam(nodeText(src, param), "Object")
				}
			}
		}
	}
	if len(lambdaParamOrder) > 0 {
		bc.store.Methods.ParamOrder[lambdaMethodKey] = lambdaParamOrder
	}
	body := fieldChild(node, "body")
	if body != nil {
		bc.visitIterative(body, src, currentClass, lambdaMethodKey, filePath, lambdaScope, taintCache)
	}
}

// lambdaInheritedSource（R6-2）：计算 lambda 参数应继承的上游污点 source。
//   - Stream 链式（map/forEach/filter/...）：回溯 receiver 链首（Stream.of/Arrays.stream/*.stream()）
//     的首实参污点，注入 lambda 参数（元素即流源）。
//   - 回调链（thenAccept/ifPresent/...）：取 container method_invocation 的 receiver 污点注入。
//
// 仅当确为已知 sink/流方法时才注入，避免把普通 lambda 参数误标污点（过宽防护）。
func (bc *MethodBodyCollector) lambdaInheritedSource(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, taintCache map[[2]int]taintCheckResult) string {
	parentNode := node.Parent()
	// lambda 的直接 parent 是 argument（argument_list 的子节点），上跳一层到 argument_list
	if parentNode != nil && nodeType(parentNode) == "argument" {
		parentNode = parentNode.Parent()
	}
	if parentNode == nil || nodeType(parentNode) != "argument_list" {
		return ""
	}
	gp := parentNode.Parent()
	if gp == nil || nodeType(gp) != "method_invocation" {
		return ""
	}
	gpNameNode := fieldChild(gp, "name")
	if gpNameNode == nil {
		return ""
	}
	gpMethod := nodeText(src, gpNameNode)
	if streamChainMethods[gpMethod] {
		if srcNode := bc.streamChainSourceNode(gp, src); srcNode != nil {
			if isT, source := bc.taintChecker.Check(srcNode, src, scope, currentClass, filePath, 0, taintCache); isT && source != "" {
				return source
			}
		}
	} else if callbackChainMethods[gpMethod] {
		if gpObjNode := fieldChild(gp, "object"); gpObjNode != nil {
			if isT, source := bc.taintChecker.Check(gpObjNode, src, scope, currentClass, filePath, 0, taintCache); isT && source != "" {
				return source
			}
		}
	}
	return ""
}

// streamChainSourceNode（R6-2）：从 Stream 链式 lambda 的 container method_invocation 出发，
// 沿 receiver 链向上回溯，找到「链首构造调用」（Stream.of / Arrays.stream / *.stream()），
// 返回其第一个实参节点——该实参即流中的元素源，其污点应注入 lambda 参数。
// 例如 Stream.of(cmd).map(x->x).forEach(x->exec(x))：
//
//	node = forEach 的 lambda；gp = forEach(...); gp.object = Stream.of(cmd).map(x->x)
//	回溯：map(x->x) 的 object = Stream.of(cmd) → 命中链首 → 返回 cmd 节点。
//
// 仅当链首是 Stream 构造/stream() 时才返回（避免把普通方法链误判为流源，控制过宽）。
func (bc *MethodBodyCollector) streamChainSourceNode(start *gotreesitter.Node, src []byte) *gotreesitter.Node {
	cur := start
	depth := 0
	for cur != nil && depth < 16 {
		depth++
		obj := fieldChild(cur, "object")
		if obj == nil {
			return nil
		}
		// obj 可能是 method_invocation（继续回溯）或主表达式（链首元素）
		if nodeType(obj) == "method_invocation" {
			nm := fieldChild(obj, "name")
			if nm != nil {
				m := nodeText(src, nm)
				// 链首识别：Stream.of / Arrays.stream / *.stream()
				if m == "of" || m == "stream" || m == "Arrays.stream" || m == "Stream.of" {
					// 注：tree-sitter-java 把 Stream.of(cmd) 解析为 object=Stream / name=of /
					// argument_list 为直接子节点（非 named field），故 fieldChild 取不到，
					// 需遍历 children 按类型定位 argument_list。
					var al *gotreesitter.Node
					for _, ch := range nodeChildren(obj) {
						if nodeType(ch) == "argument_list" {
							al = ch
							break
						}
					}
					if al != nil {
						// tree-sitter-java 中 argument_list 的子节点为 ( expr ) 形态，
						// argument 为匿名节点（无 "argument" 类型名），故直接取首个非标点子节点。
						for _, c := range nodeChildren(al) {
							ct := nodeType(c)
							if ct == "(" || ct == ")" || ct == "," {
								continue
							}
							return c
						}
					}
					return nil
				}
			}
			cur = obj
			continue
		}
		// obj 非 method_invocation：说明 start 本身直接是 Stream.of(cmd) 的 receiver 形式？
		// 例如 start = map(x->x)，其 object 已是 Stream.of(cmd)（method_invocation，上面分支处理）。
		// 若 object 是普通表达式而非 method_invocation，则无上游链，不回溯。
		return nil
	}
	return nil
}

// ============================================================
//  AST Handler #7: object_creation_expression (镜像 7.py:3577-3586)
// ============================================================

func (bc *MethodBodyCollector) handleObjectCreation(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string) {
	typeNode := fieldChild(node, "type")
	if typeNode == nil {
		return
	}
	calledClass := bc.typeResolver.StripGenerics(nodeText(src, typeNode))
	if i := strings.LastIndex(calledClass, "."); i >= 0 {
		calledClass = calledClass[i+1:]
	}
	if calledClass == "" {
		return
	}
	line := startLine1(node)
	argCount := bc.typeResolver.CountArguments(node)
	bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], CallEdge{
		CalleeClass: calledClass, CalleeMethod: "<init>", Line: line, FilePath: filePath, ArgCount: argCount, Confidence: ConfHeuristic,
	})
}

// ============================================================
//  AST Handler #8: explicit_constructor_invocation (镜像 7.py:3588-3615)
// ============================================================

func (bc *MethodBodyCollector) handleExplicitConstructor(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string) {
	line := startLine1(node)
	argCount := bc.typeResolver.CountArguments(node)
	isThis := false
	isSuper := false
	for _, child := range nodeChildren(node) {
		childText := strings.TrimSpace(nodeText(src, child))
		if childText == "this" {
			isThis = true
			break
		} else if childText == "super" {
			isSuper = true
			break
		}
	}
	nameNode := fieldChild(node, "name")
	if nameNode != nil {
		calledName := strings.TrimSpace(nodeText(src, nameNode))
		if calledName == "this" {
			isThis = true
		} else if calledName == "super" {
			isSuper = true
		}
	}
	if isThis {
		bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], CallEdge{
			CalleeClass: currentClass, CalleeMethod: "<init>", Line: line, FilePath: filePath, ArgCount: argCount, Confidence: ConfExact,
		})
	} else if isSuper {
		parent := bc.store.Types.ClassExtends[currentClass]
		if parent == "" {
			parent = currentClass
		}
		bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], CallEdge{
			CalleeClass: parent, CalleeMethod: "<init>", Line: line, FilePath: filePath, ArgCount: argCount, Confidence: ConfHeuristic,
		})
	}
}

// ============================================================
//  AST Handler #9: method_reference (镜像 7.py:3693-3706)
// ============================================================

func (bc *MethodBodyCollector) handleMethodReference(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope) {
	nameNode := fieldChild(node, "name")
	if nameNode == nil {
		return
	}
	refMethod := nodeText(src, nameNode)
	refClass := currentClass
	classNode := fieldChild(node, "class")
	if classNode != nil {
		resolved := bc.typeResolver.ResolveType(classNode, currentClass, src, filePath, scope)
		if resolved != "" {
			refClass = resolved
		}
	}
	line := startLine1(node)
	bc.store.Calls.Edges[methodKey] = append(bc.store.Calls.Edges[methodKey], CallEdge{
		CalleeClass: refClass, CalleeMethod: refMethod, Line: line, FilePath: filePath, ArgCount: 0, Confidence: ConfHeuristic, Condition: CondLambda,
	})
}

// ============================================================
//  AST Handler #10: update_expression (镜像 7.py:3708-3749)
// ============================================================

func (bc *MethodBodyCollector) handleUpdateExpression(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope) {
	operand := (*gotreesitter.Node)(nil)
	for _, child := range nodeChildren(node) {
		ct := nodeType(child)
		if ct != "++" && ct != "--" {
			operand = child
			break
		}
	}
	if operand == nil {
		return
	}
	mkh := MethodKeyHelper{}
	methodName := mkh.MethodName(methodKey)
	if nodeType(operand) == "field_access" {
		objNode := fieldChild(operand, "object")
		fieldNode := fieldChild(operand, "field")
		if objNode != nil && fieldNode != nil {
			objText := nodeText(src, objNode)
			if objText == "this" || objText == currentClass || strings.HasSuffix(objText, ".this") {
				fieldName := nodeText(src, fieldNode)
				key := currentClass + "." + fieldName
				if _, ok := bc.store.Types.GlobalFieldTypes[key]; ok {
					line := startLine1(node)
					assignText := strings.TrimSpace(nodeText(src, node))
					bc.store.Fields.Assignments[key] = append(bc.store.Fields.Assignments[key], FieldAssignment{
						ClassName: currentClass, MethodKey: methodKey, MethodName: methodName, Line: line, FilePath: filePath, AssignText: assignText, AssignType: AssignRuntime,
					})
					bc.store.Fields.Reads[key] = append(bc.store.Fields.Reads[key], FieldRead{MethodKey: methodKey, Line: line, FilePath: filePath})
				}
			}
		}
	} else if nodeType(operand) == "identifier" {
		name := nodeText(src, operand)
		fkey := currentClass + "." + name
		if _, ok := bc.store.Types.GlobalFieldTypes[fkey]; ok {
			if scope == nil || scope.Resolve(name) == "" {
				line := startLine1(node)
				assignText := strings.TrimSpace(nodeText(src, node))
				bc.store.Fields.Assignments[fkey] = append(bc.store.Fields.Assignments[fkey], FieldAssignment{
					ClassName: currentClass, MethodKey: methodKey, MethodName: methodName, Line: line, FilePath: filePath, AssignText: assignText, AssignType: AssignRuntime,
				})
				bc.store.Fields.Reads[fkey] = append(bc.store.Fields.Reads[fkey], FieldRead{MethodKey: methodKey, Line: line, FilePath: filePath})
			}
		}
	}
}

// ============================================================
//  AST Handler #12: try_statement (镜像 7.py:3439-3454)
// ============================================================

func (bc *MethodBodyCollector) handleTry(node *gotreesitter.Node, src []byte, currentClass, filePath string, scope *MethodScope) {
	for _, child := range nodeChildren(node) {
		if nodeType(child) != "resource_specification" {
			continue
		}
		for _, resource := range nodeChildren(child) {
			if nodeType(resource) != "resource" {
				continue
			}
			for _, rchild := range nodeChildren(resource) {
				if nodeType(rchild) != "variable_declarator" {
					continue
				}
				vname := fieldChild(rchild, "name")
				vval := fieldChild(rchild, "value")
				if vname == nil {
					continue
				}
				rtype := "AutoCloseable"
				if vval != nil {
					resolved := bc.typeResolver.ResolveType(vval, currentClass, src, filePath, scope)
					if resolved != "" {
						rtype = resolved
					}
				}
				scope.Define(nodeText(src, vname), rtype, nil)
			}
		}
	}
}

// ============================================================
//  AST Handler #13: identifier 裸读 (镜像 7.py:3954-3971)
// ============================================================

func (bc *MethodBodyCollector) handleIdentifierRead(node *gotreesitter.Node, src []byte, currentClass, methodKey, filePath string, scope *MethodScope) {
	name := nodeText(src, node)
	fkey := currentClass + "." + name
	if scope != nil && scope.Resolve(name) != "" {
		return
	}
	if _, ok := bc.store.Types.GlobalFieldTypes[fkey]; !ok {
		return
	}
	parent := node.Parent()
	if parent == nil {
		return
	}
	pt := nodeType(parent)
	if pt == "assignment_expression" || pt == "augmented_assignment_expression" {
		leftNode := fieldChild(parent, "left")
		if leftNode != nil && sameNode(leftNode, node) {
			return
		}
	}
	if pt == "update_expression" {
		return
	}
	bc.store.Fields.Reads[fkey] = append(bc.store.Fields.Reads[fkey], FieldRead{MethodKey: methodKey, Line: startLine1(node), FilePath: filePath})
}
