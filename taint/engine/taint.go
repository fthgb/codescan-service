package engine

import (
	"strconv"
	"strings"
)

// ============================================================
//  TaintRule 接口 + 9 条传播规则（镜像 7.py L1267-1505）
// ============================================================

type TaintRule interface {
	Propagate(fact TaintFact, store *AnalysisStore) []TaintFact
}

// ─── 1. ParamToFieldRule ───
type ParamToFieldRule struct{}

func (r ParamToFieldRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocMethodParam {
		return nil
	}
	var newFacts []TaintFact
	paramToFields := store.Methods.ParamToField[fact.LocationKey]
	if fieldKeys, ok := paramToFields[fact.ParamName]; ok {
		for _, fieldKey := range fieldKeys {
			step := fact.LocationKey + "." + fact.ParamName + " -> " + fieldKey
			newFacts = append(newFacts, TaintFact{
				LocationType:    LocField,
				LocationKey:     fieldKey,
				SourceType:      fact.SourceType,
				SourceMethod:    fact.SourceMethod,
				SourceField:     "",
				Provenance:      "ParamToField(" + fact.LocationKey + "." + fact.ParamName + ")",
				PropagationPath: append(copySlice(fact.PropagationPath), step),
			})
		}
	}
	return newFacts
}

// ─── 2. ParamToReturnRule ───
type ParamToReturnRule struct{}

func (r ParamToReturnRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocMethodParam {
		return nil
	}
	var newFacts []TaintFact
	paramToReturn := store.Methods.ParamToReturn[fact.LocationKey]
	for _, pn := range paramToReturn {
		if pn == fact.ParamName {
			step := fact.LocationKey + "." + fact.ParamName + " -> return:" + fact.LocationKey
			newFacts = append(newFacts, TaintFact{
				LocationType:    LocMethodReturn,
				LocationKey:     fact.LocationKey,
				SourceType:      fact.SourceType,
				SourceMethod:    fact.SourceMethod,
				SourceField:     "",
				Provenance:      "ParamToReturn(" + fact.LocationKey + "." + fact.ParamName + ")",
				PropagationPath: append(copySlice(fact.PropagationPath), step),
			})
			break
		}
	}
	return newFacts
}

// ─── 3. ReturnToCallerRule ───
type ReturnToCallerRule struct{}

func (r ReturnToCallerRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocMethodReturn {
		return nil
	}
	var newFacts []TaintFact
	for _, pair := range store.Calls.CallReturnToLocalMap[fact.LocationKey] {
		callerKey, localVarName := pair[0], pair[1]
		callerLocals := store.Methods.LocalVars[callerKey]
		localInfo, ok := callerLocals[localVarName]
		if !ok {
			continue
		}
		existing := toSet(localInfo.Sources)
		if existing[fact.SourceMethod] {
			continue
		}
		// local_return_vars 检查
		localReturnVars := toSet(store.Methods.LocalReturnVars[callerKey])
		if localReturnVars[localVarName] {
			step := "return:" + fact.LocationKey + " -> " + callerKey + "." + localVarName
			newFacts = append(newFacts, TaintFact{
				LocationType:    LocMethodReturn,
				LocationKey:     callerKey,
				SourceType:      fact.SourceType,
				SourceMethod:    fact.SourceMethod,
				SourceField:     "",
				Provenance:      "ReturnToCaller(" + fact.LocationKey + "->" + callerKey + "." + localVarName + ")",
				PropagationPath: append(copySlice(fact.PropagationPath), step),
			})
		}
		// local_to_field 检查
		if localToField, ok := store.Methods.LocalToField[callerKey]; ok {
			for _, fieldKey := range localToField[localVarName] {
				step := "return:" + fact.LocationKey + " -> " + callerKey + "." + localVarName + " -> " + fieldKey
				newFacts = append(newFacts, TaintFact{
					LocationType:    LocField,
					LocationKey:     fieldKey,
					SourceType:      TaintSrcFieldProp,
					SourceMethod:    fact.SourceMethod,
					SourceField:     "return:" + fact.LocationKey,
					Provenance:      "ReturnToField(" + callerKey + "." + localVarName + "->" + fieldKey + ")",
					PropagationPath: append(copySlice(fact.PropagationPath), step),
				})
			}
		}
	}
	return newFacts
}

// ─── 4. ReturnToFieldViaCallSiteRule ───
type ReturnToFieldViaCallSiteRule struct{}

func (r ReturnToFieldViaCallSiteRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocMethodReturn {
		return nil
	}
	var newFacts []TaintFact
	for _, csfa := range store.Fields.CallSiteFieldAssignsByCallee[fact.LocationKey] {
		for _, assignment := range store.Fields.Assignments[csfa.FieldKey] {
			if assignment.MethodKey != csfa.CallerKey || assignment.Line != csfa.AssignLine {
				continue
			}
			step := "return:" + fact.LocationKey + " -> " + csfa.FieldKey
			newFacts = append(newFacts, TaintFact{
				LocationType:    LocField,
				LocationKey:     csfa.FieldKey,
				SourceType:      TaintSrcFieldProp,
				SourceMethod:    fact.SourceMethod,
				SourceField:     "return:" + fact.LocationKey,
				Provenance:      "CallSiteFieldAssign(" + fact.LocationKey + "->" + csfa.FieldKey + ")",
				PropagationPath: append(copySlice(fact.PropagationPath), step),
			})
			break
		}
	}
	// None key（未解析 callee）
	for _, csfa := range store.Fields.CallSiteFieldAssignsByCallee[""] {
		if csfa.CalleeKey != "" {
			continue
		}
		pattern := csfa.CalleeClass + "." + csfa.CalleeMethod
		if strings.HasPrefix(fact.LocationKey, pattern+"(") {
			if pc, exists := store.Methods.ParamCounts[fact.LocationKey]; exists && pc == csfa.CalleeArgCnt {
				for _, assignment := range store.Fields.Assignments[csfa.FieldKey] {
					if assignment.MethodKey != csfa.CallerKey || assignment.Line != csfa.AssignLine {
						continue
					}
					step := "return:" + fact.LocationKey + " -> " + csfa.FieldKey
					newFacts = append(newFacts, TaintFact{
						LocationType:    LocField,
						LocationKey:     csfa.FieldKey,
						SourceType:      TaintSrcFieldProp,
						SourceMethod:    fact.SourceMethod,
						SourceField:     "return:" + fact.LocationKey,
						Provenance:      "CallSiteFieldAssign(" + fact.LocationKey + "->" + csfa.FieldKey + ")",
						PropagationPath: append(copySlice(fact.PropagationPath), step),
					})
					break
				}
			}
		}
	}
	return newFacts
}

// ─── 5. FieldToFieldRule ───
type FieldToFieldRule struct{}

func (r FieldToFieldRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocField {
		return nil
	}
	var newFacts []TaintFact
	for _, edge := range store.Fields.FieldToFieldEdgesIndex[fact.LocationKey] {
		step := fact.LocationKey + " -> " + edge.DstFieldKey
		newFacts = append(newFacts, TaintFact{
			LocationType:    LocField,
			LocationKey:     edge.DstFieldKey,
			SourceType:      TaintSrcFieldProp,
			SourceMethod:    fact.SourceMethod,
			SourceField:     fact.LocationKey,
			Provenance:      "FieldToField(" + fact.LocationKey + "->" + edge.DstFieldKey + ")",
			PropagationPath: append(copySlice(fact.PropagationPath), step),
		})
	}
	return newFacts
}

// ─── 6. FieldReadToReturnRule ───
type FieldReadToReturnRule struct{}

func (r FieldReadToReturnRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocField {
		return nil
	}
	var newFacts []TaintFact
	for _, methodKey := range store.Fields.FieldReturnIndex[fact.LocationKey] {
		existing := toSet(store.Methods.ReturnTaints[methodKey])
		if existing[fact.SourceMethod] {
			continue
		}
		step := fact.LocationKey + " -> return:" + methodKey
		newFacts = append(newFacts, TaintFact{
			LocationType:    LocMethodReturn,
			LocationKey:     methodKey,
			SourceType:      fact.SourceType,
			SourceMethod:    fact.SourceMethod,
			SourceField:     fact.LocationKey,
			Provenance:      "FieldReadToReturn(" + fact.LocationKey + "->" + methodKey + ")",
			PropagationPath: append(copySlice(fact.PropagationPath), step),
		})
	}
	return newFacts
}

// ─── 7. InterproceduralParamRule ───
type InterproceduralParamRule struct{}

func (r InterproceduralParamRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocMethodParam {
		return nil
	}
	var newFacts []TaintFact
	paramFlows := store.Methods.ParamToCallParam[fact.LocationKey]
	if paramFlows == nil {
		return nil
	}
	for _, cpt := range paramFlows[fact.ParamName] {
		pattern := cpt.CalleeClass + "." + cpt.CalleeMethod
		matchedKeys := store.Indices.MethodNameIndex[pattern]
		for _, calleeKey := range matchedKeys {
			calleeParamOrder := store.Methods.ParamOrder[calleeKey]
			for paramName, order := range calleeParamOrder {
				if order == cpt.ArgIndex {
					step := fact.LocationKey + "." + fact.ParamName + " -> " + calleeKey + "." + paramName
					newFacts = append(newFacts, TaintFact{
						LocationType:    LocMethodParam,
						LocationKey:     calleeKey,
						ParamName:       paramName,
						SourceType:      fact.SourceType,
						SourceMethod:    fact.SourceMethod,
						SourceField:     fact.SourceField,
						Provenance:      "Interprocedural(" + fact.LocationKey + "." + fact.ParamName + "->" + calleeKey + "." + paramName + ")",
						PropagationPath: append(copySlice(fact.PropagationPath), step),
					})
					break
				}
			}
		}
	}
	return newFacts
}

// ─── 8. FieldReadToParamRule ───
type FieldReadToParamRule struct{}

func (r FieldReadToParamRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocField {
		return nil
	}
	var newFacts []TaintFact
	for _, entry := range store.Methods.FieldReadLocals[fact.LocationKey] {
		for _, lvp := range entry.LocalInfos {
			step := fact.LocationKey + " -> " + entry.MethodKey + "." + lvp.ParamName + " (via " + lvp.LocalVar + ")"
			newFacts = append(newFacts, TaintFact{
				LocationType:    LocMethodParam,
				LocationKey:     entry.MethodKey,
				ParamName:       lvp.ParamName,
				SourceType:      fact.SourceType,
				SourceMethod:    fact.SourceMethod,
				SourceField:     fact.LocationKey,
				Provenance:      "FieldReadToParam(" + fact.LocationKey + "->" + entry.MethodKey + "." + lvp.ParamName + ")",
				PropagationPath: append(copySlice(fact.PropagationPath), step),
			})
		}
	}
	return newFacts
}

// ─── 9. CollectionElementTaintRule ───
type CollectionElementTaintRule struct{}

var collectionTypes = map[string]bool{
	"List": true, "ArrayList": true, "LinkedList": true,
	"Set": true, "HashSet": true, "TreeSet": true,
	"Map": true, "HashMap": true, "TreeMap": true,
	"Collection": true,
}

func (r CollectionElementTaintRule) Propagate(fact TaintFact, store *AnalysisStore) []TaintFact {
	if fact.LocationType != LocField {
		return nil
	}
	var newFacts []TaintFact
	fieldType := store.Types.GlobalFieldTypes[fact.LocationKey]
	baseType := fieldType
	if idx := strings.Index(fieldType, "<"); idx > 0 {
		baseType = strings.TrimSpace(fieldType[:idx])
	}
	if !collectionTypes[baseType] {
		return nil
	}
	for _, methodKey := range store.Fields.FieldReturnIndex[fact.LocationKey] {
		methodName := MethodKeyHelper{}.MethodName(methodKey)
		if collectionAccessMethods[methodName] {
			continue
		}
		step := fact.LocationKey + "[element] -> return:" + methodKey
		newFacts = append(newFacts, TaintFact{
			LocationType:    LocMethodReturn,
			LocationKey:     methodKey,
			SourceType:      fact.SourceType,
			SourceMethod:    fact.SourceMethod,
			SourceField:     fact.LocationKey,
			Provenance:      "CollectionElementTaint(" + fact.LocationKey + "->" + methodKey + ")",
			PropagationPath: append(copySlice(fact.PropagationPath), step),
		})
	}
	return newFacts
}

// ============================================================
//  TaintEngine — worklist 不动点 + 多轮传播（镜像 7.py L1506-1650）
// ============================================================

type TaintEngine struct {
	store           *AnalysisStore
	rules           []TaintRule
	facts           map[TaintFactKey]TaintFact
	pathsByIdentity map[TaintFactKey][][]string
}

func NewTaintEngine(store *AnalysisStore) *TaintEngine {
	return &TaintEngine{
		store: store,
		rules: []TaintRule{
			ParamToFieldRule{},
			ParamToReturnRule{},
			ReturnToCallerRule{},
			ReturnToFieldViaCallSiteRule{},
			FieldToFieldRule{},
			FieldReadToReturnRule{},
			InterproceduralParamRule{},
			FieldReadToParamRule{},
			CollectionElementTaintRule{},
		},
		facts:           make(map[TaintFactKey]TaintFact),
		pathsByIdentity: make(map[TaintFactKey][][]string),
	}
}

// SeedFromStore 从 store 的初始污点数据播种（镜像 7.py seed_from_store）。
func (te *TaintEngine) SeedFromStore() {
	// 字段污点种子
	for fieldKey, taints := range te.store.Fields.Taints {
		for _, t := range taints {
			te.addFact(TaintFact{
				LocationType:    LocField,
				LocationKey:     fieldKey,
				SourceType:      t.SourceType,
				SourceMethod:    t.SourceMethod,
				SourceField:     t.SourceField,
				Provenance:      "AST_Seed",
				PropagationPath: []string{"AST_Seed:" + fieldKey},
			})
		}
	}
	// 参数污点种子
	for methodKey, paramTaints := range te.store.Methods.ParamTaints {
		for paramName, taintSources := range paramTaints {
			for _, source := range taintSources {
				te.addFact(TaintFact{
					LocationType:    LocMethodParam,
					LocationKey:     methodKey,
					ParamName:       paramName,
					SourceType:      TaintSrcUserInput,
					SourceMethod:    source,
					Provenance:      "Param_Seed",
					PropagationPath: []string{"Param_Seed:" + methodKey + "." + paramName + "<-" + source},
				})
			}
		}
	}
	// 返回值污点种子
	for methodKey, returnTaints := range te.store.Methods.ReturnTaints {
		for _, source := range returnTaints {
			te.addFact(TaintFact{
				LocationType:    LocMethodReturn,
				LocationKey:     methodKey,
				SourceType:      TaintSrcUserInput,
				SourceMethod:    source,
				Provenance:      "Return_Seed",
				PropagationPath: []string{"Return_Seed:" + methodKey + "<-" + source},
			})
		}
	}
	// 调用参数污点种子
	for _, cpt := range te.store.Calls.CallParamTaints {
		pattern := cpt.CalleeClass + "." + cpt.CalleeMethod
		matchedKeys := te.store.Indices.MethodNameIndex[pattern]
		var calleeKey string
		for _, mk := range matchedKeys {
			pc := te.store.Methods.ParamCounts[mk]
			if pc > cpt.ParamIndex {
				calleeKey = mk
				break
			}
		}
		if calleeKey == "" && len(matchedKeys) > 0 {
			calleeKey = matchedKeys[0]
		}
		if calleeKey == "" {
			continue
		}
		calleeParamOrder := te.store.Methods.ParamOrder[calleeKey]
		for paramName, order := range calleeParamOrder {
			if order == cpt.ParamIndex {
				step := cpt.CallerKey + " -> " + calleeKey + "." + paramName + " (arg#" + itoa(cpt.ParamIndex) + ")"
				te.addFact(TaintFact{
					LocationType:    LocMethodParam,
					LocationKey:     calleeKey,
					ParamName:       paramName,
					SourceType:      TaintSrcUserInput,
					SourceMethod:    cpt.TaintSource,
					Provenance:      "Interprocedural(" + cpt.CallerKey + "->" + calleeKey + ")",
					PropagationPath: []string{step},
				})
				break
			}
		}
	}
}

func (te *TaintEngine) addFact(fact TaintFact) bool {
	key := fact.Key()
	// 保留所有传播路径
	pathCopy := copySlice(fact.PropagationPath)
	te.pathsByIdentity[key] = append(te.pathsByIdentity[key], pathCopy)
	if _, exists := te.facts[key]; exists {
		return false
	}
	te.facts[key] = fact
	return true
}

func (te *TaintEngine) GetPaths(fact TaintFact) [][]string {
	if paths, ok := te.pathsByIdentity[fact.Key()]; ok && len(paths) > 0 {
		return paths
	}
	return [][]string{fact.PropagationPath}
}

// Propagate worklist 不动点传播（镜像 7.py propagate）。
// 返回新增 fact 数。
func (te *TaintEngine) Propagate() int {
	// 初始化 worklist（从 facts 中取所有 fact）
	worklist := make([]TaintFact, 0, len(te.facts))
	for _, f := range te.facts {
		worklist = append(worklist, f)
	}
	newCount := 0
	maxIterations := te.store.Config.MaxTaintIterations
	iteration := 0
	for len(worklist) > 0 && iteration < maxIterations {
		iteration++
		current := worklist[0]
		worklist = worklist[1:]
		for _, rule := range te.rules {
			newFacts := rule.Propagate(current, te.store)
			for _, nf := range newFacts {
				if te.addFact(nf) {
					worklist = append(worklist, nf)
					newCount++
				}
			}
		}
	}
	return newCount
}

// SyncToStore 将传播结果同步回 store（镜像 7.py sync_to_store）。
func (te *TaintEngine) SyncToStore() {
	for _, fact := range te.facts {
		allPaths := te.GetPaths(fact)
		switch fact.LocationType {
		case LocField:
			existing := te.store.Fields.Taints[fact.LocationKey]
			already := false
			for _, t := range existing {
				if t.SourceMethod == fact.SourceMethod && t.SourceType == fact.SourceType {
					already = true
					break
				}
			}
			if !already {
				var firstPath []string
				if len(allPaths) > 0 {
					firstPath = allPaths[0]
				}
				info := TaintInfo{
					SourceType:          fact.SourceType,
					SourceMethod:        fact.SourceMethod,
					SourceField:         fact.SourceField,
					AssignMethod:        fact.Provenance,
					AssignType:          AssignRuntime,
					PropagationPath:     firstPath,
					AllPropagationPaths: allPaths,
				}
				te.store.Fields.Taints[fact.LocationKey] = append(
					te.store.Fields.Taints[fact.LocationKey], info)
			}
		case LocMethodReturn:
			existing := toSet(te.store.Methods.ReturnTaints[fact.LocationKey])
			if !existing[fact.SourceMethod] {
				te.store.Methods.ReturnTaints[fact.LocationKey] = append(
					te.store.Methods.ReturnTaints[fact.LocationKey], fact.SourceMethod)
			}
		case LocMethodParam:
			if te.store.Methods.ParamTaints[fact.LocationKey] == nil {
				te.store.Methods.ParamTaints[fact.LocationKey] = make(map[string][]string)
			}
			existing := toSet(te.store.Methods.ParamTaints[fact.LocationKey][fact.ParamName])
			if !existing[fact.SourceMethod] {
				te.store.Methods.ParamTaints[fact.LocationKey][fact.ParamName] = append(
					te.store.Methods.ParamTaints[fact.LocationKey][fact.ParamName], fact.SourceMethod)
			}
		}
	}
}

// ─── 辅助函数 ───

func copySlice(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	return out
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
