package engine

import (
	"regexp"
	"strings"
)

// ============================================================
//  CallResolutionRule 接口 + 5 条规则（镜像 7.py L1882-2093）
// ============================================================

type CallResolutionRule interface {
	Resolve(store *AnalysisStore) []callerEdgePair
}

// callerEdgePair — (caller_key, CallEdge)
type callerEdgePair struct {
	CallerKey string
	Edge      CallEdge
}

// ─── 1. DirectCallRule（直接调用已在 edges 中，无需额外处理） ───
type DirectCallRule struct{}

func (r DirectCallRule) Resolve(store *AnalysisStore) []callerEdgePair { return nil }

// ─── 2. PolymorphicCallRule（多态调用解析） ───
type PolymorphicCallRule struct{}

func (r PolymorphicCallRule) Resolve(store *AnalysisStore) []callerEdgePair {
	var edges []callerEdgePair

	// 构建 parent→children 映射
	parentChildMap := make(map[string][]string)
	for cls, parent := range store.Types.ClassExtends {
		parentChildMap[parent] = append(parentChildMap[parent], cls)
	}

	// 构建 calls_set: caller_key → set of (calleeClass, calleeMethod, line, filePath)
	callsSet := make(map[string]map[string]bool)
	for callerKey, callees := range store.Calls.Edges {
		for _, edge := range callees {
			key := edge.CalleeClass + "|" + edge.CalleeMethod + "|" + itoa(edge.Line) + "|" + edge.FilePath
			if callsSet[callerKey] == nil {
				callsSet[callerKey] = make(map[string]bool)
			}
			callsSet[callerKey][key] = true
		}
	}

	// 构建 callee_to_caller_info
	type callerInfo struct {
		CallerKey, CalleeClass, CalleeMethod, FilePath string
		Line, ArgCount                                 int
	}
	calleeToCallerInfo := make(map[string][]callerInfo)
	for callerKey, callees := range store.Calls.Edges {
		for _, edge := range callees {
			lookup := edge.CalleeClass + "." + edge.CalleeMethod
			calleeToCallerInfo[lookup] = append(calleeToCallerInfo[lookup], callerInfo{
				CallerKey: callerKey, CalleeClass: edge.CalleeClass,
				CalleeMethod: edge.CalleeMethod, Line: edge.Line,
				FilePath: edge.FilePath, ArgCount: edge.ArgCount,
			})
		}
	}

	// reverse_calls_set: func_key → set of caller
	reverseCallsSet := make(map[string]map[string]bool)
	for funcKey, callers := range store.Calls.ReverseEdges {
		for _, re := range callers {
			if reverseCallsSet[funcKey] == nil {
				reverseCallsSet[funcKey] = make(map[string]bool)
			}
			reverseCallsSet[funcKey][re.CallerKey] = true
		}
	}

	// 接口方法 → 实现类方法
	for ifaceMethodKey := range store.Types.InterfaceMethods {
		ifaceName := ifaceMethodKey
		if dotIdx := strings.Index(ifaceMethodKey, "."); dotIdx > 0 {
			ifaceName = ifaceMethodKey[:dotIdx]
		}
		methodSig := ""
		if dotIdx := strings.Index(ifaceMethodKey, "."); dotIdx > 0 {
			methodSig = ifaceMethodKey[dotIdx+1:]
		}
		methodName := methodSig
		if parenIdx := strings.Index(methodSig, "("); parenIdx > 0 {
			methodName = methodSig[:parenIdx]
		}

		ifaceCallers := append([]ReverseEdge(nil), store.Calls.ReverseEdges[ifaceMethodKey]...)
		callLookupKey := ifaceName + "." + methodName
		ifaceDirectCallers := calleeToCallerInfo[callLookupKey]

		for _, implCls := range store.Types.IfaceImplMap[ifaceName] {
			implMethodKeys := store.Indices.ClassMethodNameIndex[implCls][methodName]
			for _, implMethodKey := range implMethodKeys {
				if store.Methods.ParamCounts[implMethodKey] != store.Methods.ParamCounts[ifaceMethodKey] {
					continue
				}
				for _, re := range ifaceCallers {
					if !reverseCallsSet[implMethodKey][re.CallerKey] {
						store.Calls.ReverseEdges[implMethodKey] = append(
							store.Calls.ReverseEdges[implMethodKey], re)
						if reverseCallsSet[implMethodKey] == nil {
							reverseCallsSet[implMethodKey] = make(map[string]bool)
						}
						reverseCallsSet[implMethodKey][re.CallerKey] = true
					}
				}
				for _, ci := range ifaceDirectCallers {
					edgeTuple := implCls + "|" + methodName + "|" + itoa(ci.Line) + "|" + ci.FilePath
					if !callsSet[ci.CallerKey][edgeTuple] {
						edges = append(edges, callerEdgePair{
							CallerKey: ci.CallerKey,
							Edge: CallEdge{
								CalleeClass: implCls, CalleeMethod: methodName,
								Line: ci.Line, FilePath: ci.FilePath, ArgCount: ci.ArgCount,
								Confidence: ConfPolymorphic, Rule: "PolymorphicCallRule",
							},
						})
						if callsSet[ci.CallerKey] == nil {
							callsSet[ci.CallerKey] = make(map[string]bool)
						}
						callsSet[ci.CallerKey][edgeTuple] = true
					}
				}
			}
		}
	}

	// 父类方法 → 子类方法
	for parentCls, children := range parentChildMap {
		for _, parentMethodKey := range store.Types.ClassAllMethods[parentCls] {
			methodName := parentMethodKey
			if parenIdx := strings.Index(parentMethodKey, "("); parenIdx > 0 {
				methodName = parentMethodKey[:parenIdx]
			}
			if dotIdx := strings.LastIndex(methodName, "."); dotIdx > 0 {
				methodName = methodName[dotIdx+1:]
			}
			parentCallers := append([]ReverseEdge(nil), store.Calls.ReverseEdges[parentMethodKey]...)
			callLookupKey := parentCls + "." + methodName
			parentDirectCallers := calleeToCallerInfo[callLookupKey]

			for _, childCls := range children {
				childMethodKeys := store.Indices.ClassMethodNameIndex[childCls][methodName]
				for _, childMethodKey := range childMethodKeys {
					if store.Methods.ParamCounts[childMethodKey] != store.Methods.ParamCounts[parentMethodKey] {
						continue
					}
					for _, re := range parentCallers {
						if !reverseCallsSet[childMethodKey][re.CallerKey] {
							store.Calls.ReverseEdges[childMethodKey] = append(
								store.Calls.ReverseEdges[childMethodKey], re)
							if reverseCallsSet[childMethodKey] == nil {
								reverseCallsSet[childMethodKey] = make(map[string]bool)
							}
							reverseCallsSet[childMethodKey][re.CallerKey] = true
						}
					}
					for _, ci := range parentDirectCallers {
						edgeTuple := childCls + "|" + methodName + "|" + itoa(ci.Line) + "|" + ci.FilePath
						if !callsSet[ci.CallerKey][edgeTuple] {
							edges = append(edges, callerEdgePair{
								CallerKey: ci.CallerKey,
								Edge: CallEdge{
									CalleeClass: childCls, CalleeMethod: methodName,
									Line: ci.Line, FilePath: ci.FilePath, ArgCount: ci.ArgCount,
									Confidence: ConfPolymorphic, Rule: "PolymorphicCallRule",
								},
							})
							if callsSet[ci.CallerKey] == nil {
								callsSet[ci.CallerKey] = make(map[string]bool)
							}
							callsSet[ci.CallerKey][edgeTuple] = true
						}
					}
				}
			}
		}
	}
	return edges
}

// ─── 3. EventPublishCallRule（事件发布→监听器） ───
type EventPublishCallRule struct{}

func (r EventPublishCallRule) Resolve(store *AnalysisStore) []callerEdgePair {
	var edges []callerEdgePair
	seenEdges := make(map[string]bool)

	for _, eps := range store.Calls.EventPublishSites {
		listenerMethods := append([]string(nil), store.Calls.EventListenerMethods[eps.EventType]...)
		// 事件类型祖先
		for childEventType, ancestors := range getEventTypeAncestors(store) {
			if ancestors[eps.EventType] {
				listenerMethods = append(listenerMethods, store.Calls.EventListenerMethods[childEventType]...)
			}
		}
		// 接口
		for _, iface := range store.Types.ClassInterfaces[eps.EventType] {
			listenerMethods = append(listenerMethods, store.Calls.EventListenerMethods[iface]...)
		}
		// 去重
		seen := make(map[string]bool)
		var unique []string
		for _, lm := range listenerMethods {
			if !seen[lm] {
				seen[lm] = true
				unique = append(unique, lm)
			}
		}
		for _, listenerKey := range unique {
			edgeKey := eps.PublisherKey + "|" + listenerKey
			if seenEdges[edgeKey] {
				continue
			}
			seenEdges[edgeKey] = true
			store.Calls.ReverseEdges[listenerKey] = append(
				store.Calls.ReverseEdges[listenerKey], ReverseEdge{
					CallerKey: eps.PublisherKey, Line: eps.Line, FilePath: eps.FilePath,
				})
			listenerClass := MethodKeyHelper{}.ClassName(listenerKey)
			listenerMethod := MethodKeyHelper{}.MethodName(listenerKey)
			edges = append(edges, callerEdgePair{
				CallerKey: eps.PublisherKey,
				Edge: CallEdge{
					CalleeClass: listenerClass, CalleeMethod: listenerMethod,
					Line: eps.Line, FilePath: eps.FilePath, ArgCount: 0,
					Confidence: ConfHeuristic, Rule: "EventPublishCallRule",
				},
			})
		}
	}
	return edges
}

func getEventTypeAncestors(store *AnalysisStore) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	for cls, parent := range store.Types.ClassExtends {
		_, clsIsListener := store.Calls.EventListenerMethods[cls]
		_, parentIsListener := store.Calls.EventListenerMethods[parent]
		if clsIsListener || parentIsListener {
			current := parent
			for current != "" {
				if result[cls] == nil {
					result[cls] = make(map[string]bool)
				}
				result[cls][current] = true
				current = store.Types.ClassExtends[current]
			}
		}
	}
	return result
}

// ─── 4. AOPCallRule（AOP 切面解析） ───
type AOPCallRule struct{}

func (r AOPCallRule) Resolve(store *AnalysisStore) []callerEdgePair {
	var edges []callerEdgePair
	type aspectAdvice struct {
		MethodKey, AdviceType, PointcutExpr string
	}
	var aspectAdvices []aspectAdvice

	for methodKey, anns := range store.Methods.Annotations {
		for _, ann := range anns {
			if aopAspectAnnotations[ann.Name] {
				pointcutExpr := ann.Params["_value"]
				if pointcutExpr != "" {
					aspectAdvices = append(aspectAdvices, aspectAdvice{
						MethodKey: methodKey, AdviceType: ann.Name, PointcutExpr: pointcutExpr,
					})
				}
			}
		}
	}
	if len(aspectAdvices) == 0 {
		return edges
	}

	for _, aa := range aspectAdvices {
		matchedMethods := matchPointcutExpression(store, aa.PointcutExpr)
		for _, targetMethodKey := range matchedMethods {
			if targetMethodKey == aa.MethodKey {
				continue
			}
			targetClass := MethodKeyHelper{}.ClassName(targetMethodKey)
			targetMethod := MethodKeyHelper{}.MethodName(targetMethodKey)
			if aa.AdviceType == "Before" || aa.AdviceType == "Around" {
				store.Calls.ReverseEdges[targetMethodKey] = append(
					store.Calls.ReverseEdges[targetMethodKey], ReverseEdge{
						CallerKey: aa.MethodKey, Line: 0, FilePath: "AOP",
					})
				edges = append(edges, callerEdgePair{
					CallerKey: aa.MethodKey,
					Edge: CallEdge{
						CalleeClass: targetClass, CalleeMethod: targetMethod,
						Line: 0, FilePath: "", ArgCount: 0,
						Confidence: ConfHeuristic, Rule: "AOPCallRule",
					},
				})
			} else if aa.AdviceType == "After" || aa.AdviceType == "AfterReturning" || aa.AdviceType == "AfterThrowing" {
				store.Calls.ReverseEdges[aa.MethodKey] = append(
					store.Calls.ReverseEdges[aa.MethodKey], ReverseEdge{
						CallerKey: targetMethodKey, Line: 0, FilePath: "AOP",
					})
				aspectClass := MethodKeyHelper{}.ClassName(aa.MethodKey)
				aspectMethod := MethodKeyHelper{}.MethodName(aa.MethodKey)
				edges = append(edges, callerEdgePair{
					CallerKey: targetMethodKey,
					Edge: CallEdge{
						CalleeClass: aspectClass, CalleeMethod: aspectMethod,
						Line: 0, FilePath: "", ArgCount: 0,
						Confidence: ConfHeuristic, Rule: "AOPCallRule",
					},
				})
			}
		}
	}
	return edges
}

func matchPointcutExpression(store *AnalysisStore, expr string) []string {
	var matched []string
	m := aopPointcutPattern.FindStringSubmatch(expr)
	if m == nil {
		return matched
	}
	packageClassPattern := strings.ReplaceAll(m[1], ".", `\.`)
	packageClassPattern = strings.ReplaceAll(packageClassPattern, "*", ".*")
	methodPattern := strings.ReplaceAll(m[2], "*", ".*")
	classRe := regexp.MustCompile(packageClassPattern)
	methodRe := regexp.MustCompile(methodPattern)
	for methodKey := range store.Methods.Functions {
		namePart := methodKey
		if parenIdx := strings.Index(methodKey, "("); parenIdx > 0 {
			namePart = methodKey[:parenIdx]
		}
		dotPos := strings.LastIndex(namePart, ".")
		if dotPos > 0 {
			clsName := namePart[:dotPos]
			methodName := namePart[dotPos+1:]
			simpleCls := clsName
			if dollarIdx := strings.Index(clsName, "$"); dollarIdx > 0 {
				simpleCls = clsName[dollarIdx+1:]
			}
			if classRe.MatchString(clsName) || classRe.MatchString(simpleCls) {
				if methodRe.MatchString(methodName) {
					matched = append(matched, methodKey)
				}
			}
		}
	}
	return matched
}

// ─── 5. SpringCallbackCallRule（Spring 生命周期回调） ───
type SpringCallbackCallRule struct{}

func (r SpringCallbackCallRule) Resolve(store *AnalysisStore) []callerEdgePair {
	// Spring 生命周期接口回调
	for ifaceName, callbackMethod := range springLifecycleCallbacks {
		for _, implCls := range store.Types.IfaceImplMap[ifaceName] {
			for _, implMethodKey := range store.Types.ClassAllMethods[implCls] {
				methodNamePart := MethodKeyHelper{}.MethodName(implMethodKey)
				if methodNamePart == callbackMethod {
					if !store.Calls.EntryPoints[implMethodKey] {
						store.Calls.EntryPoints[implMethodKey] = true
						store.Calls.EntryTypes[implMethodKey] = EntryContainer
					}
				}
			}
		}
	}
	// Repository 接口回调
	for ifaceName := range repositoryInterfaces {
		for _, implCls := range store.Types.IfaceImplMap[ifaceName] {
			for _, implMethodKey := range store.Types.ClassAllMethods[implCls] {
				methodNamePart := MethodKeyHelper{}.MethodName(implMethodKey)
				if methodNamePart == "equals" || methodNamePart == "hashCode" ||
					methodNamePart == "toString" || methodNamePart == "canEqual" ||
					methodNamePart == "getClass" || methodNamePart == "notify" ||
					methodNamePart == "notifyAll" || methodNamePart == "wait" {
					continue
				}
				if !store.Calls.EntryPoints[implMethodKey] {
					store.Calls.EntryPoints[implMethodKey] = true
					store.Calls.EntryTypes[implMethodKey] = EntryContainer
				}
			}
		}
	}
	return nil
}
