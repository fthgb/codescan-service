package engine

import (
	"strings"

	"github.com/odvcencio/gotreesitter"
)

// ============================================================
//  TaintChecker — 污点检测（镜像 7.py TaintChecker L1654-1826）
//  sanitizer 三表已在 types.go 定义
// ============================================================

type TaintChecker struct {
	store        *AnalysisStore
	typeResolver *TypeResolver
}

func NewTaintChecker(store *AnalysisStore, tr *TypeResolver) *TaintChecker {
	return &TaintChecker{store: store, typeResolver: tr}
}

// Check 检查节点是否污点，返回 (是否污点, 污点来源描述)。
func (tc *TaintChecker) Check(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, depth int, cache map[[2]int]taintCheckResult) (bool, string) {
	if node == nil || depth > 100 {
		return false, ""
	}
	if cache != nil {
		// R6-2：identifier 的污点完全取决于作用域（动态 Define/Reassign），
		// 不缓存其判定结果——否则 lambda 参数在注入上游污点前被 Check 出的 false 会被
		// 固化，导致注入失效（如 Stream.of(cmd).forEach(x->exec(x)) 的 x 污点丢失）。
		nodeT0 := nodeType(node)
		// R5-2/R6-2：identifier 与 field_access 的污点取决于动态作用域（Define/Reassign/
		// SetFieldTaint 在运行时注入），不缓存其判定——否则字段污点注入前的 false 会被
		// 固化（如 cloneOf 返回对象的 .data 字段污点、Stream lambda 参数污点丢失）。
		if nodeT0 != "identifier" && nodeT0 != "field_access" {
			nid := [2]int{int(node.StartByte()), int(node.EndByte())}
			if cached, ok := cache[nid]; ok {
				return cached.tainted, cached.source
			}
		}
	}

	var tainted bool
	var source string
	nodeT := nodeType(node)
	switch nodeT {
	case "method_invocation":
		tainted, source = tc.checkMethodInvocation(node, src, scope, currentClass, filePath, depth, cache)
	case "identifier":
		tainted, source = tc.checkIdentifier(node, src, scope)
	case "field_access":
		tainted, source = tc.checkFieldAccess(node, src, scope, currentClass, filePath, depth, cache)
	case "ternary_expression":
		tainted, source = tc.checkTernary(node, src, scope, currentClass, filePath, depth, cache)
	case "binary_expression":
		tainted, source = tc.checkBinary(node, src, scope, currentClass, filePath, depth, cache)
	case "unary_expression":
		tainted, source = tc.checkUnary(node, src, scope, currentClass, filePath, depth, cache)
	default:
		tainted, source = tc.checkChildren(node, src, scope, currentClass, filePath, depth, cache)
	}

	if cache != nil {
		nid := [2]int{int(node.StartByte()), int(node.EndByte())}
		cache[nid] = taintCheckResult{tainted: tainted, source: source}
	}
	return tainted, source
}

type taintCheckResult struct {
	tainted bool
	source  string
}

func (tc *TaintChecker) checkChildren(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, depth int, cache map[[2]int]taintCheckResult) (bool, string) {
	for _, child := range nodeChildren(node) {
		isT, s := tc.Check(child, src, scope, currentClass, filePath, depth+1, cache)
		if isT {
			return true, s
		}
	}
	return false, ""
}

func (tc *TaintChecker) checkMethodInvocation(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, depth int, cache map[[2]int]taintCheckResult) (bool, string) {
	nameNode := fieldChild(node, "name")
	objNode := fieldChild(node, "object")
	methodName := ""
	if nameNode != nil {
		methodName = nodeText(src, nameNode)
	}

	// TAINT_SOURCE_METHODS 检查
	if taintSourceMethods[methodName] {
		var objClass string
		if objNode != nil {
			objText := nodeText(src, objNode)
			if objText == "super" {
				objClass = tc.store.Types.ClassExtends[currentClass]
			} else {
				objClass = tc.typeResolver.ResolveType(objNode, currentClass, src, filePath, scope)
			}
		}
		if objClass == "HttpServletRequest" || objClass == "ServletRequest" || objClass == "Request" ||
			objClass == "MultipartFile" || objClass == "ResponseEntity" {
			return true, methodName
		}
		// R-A1（架构级，F41）：环境变量/系统属性 source——System.getenv / System.getProperty。
		// 识别 JDK 标准 API 调用模式（objClass==System），不 hardcode 特定变量名/键。
		if objClass == "System" && (methodName == "getenv" || methodName == "getProperty") {
			return true, "System." + methodName
		}
		if objNode != nil && objClass == "" {
			objVarName := lower(nodeText(src, objNode))
			if heuristicRequestVars[objVarName] {
				return true, methodName
			}
		}
		if objNode == nil {
			clsAnns := tc.store.Types.ClassAnnotations[currentClass]
			for _, ann := range clsAnns {
				if controllerAnnotations[ann.Name] {
					return true, methodName
				}
			}
		}
	}

	// COLLECTION_ACCESS_METHODS 检查
	if nameNode != nil && collectionAccessMethods[methodName] && objNode != nil {
		isObjTainted, objSource := tc.Check(objNode, src, scope, currentClass, filePath, depth+1, cache)
		if isObjTainted {
			return true, objSource
		}
	}

	// 检查 object 是否污点
	objTainted := false
	objSource := ""
	if objNode != nil {
		objTainted, objSource = tc.Check(objNode, src, scope, currentClass, filePath, depth+1, cache)
	}

	// 检查参数是否污点
	argTainted := false
	argSource := ""
	args := fieldChild(node, "arguments")
	if args != nil {
		for _, arg := range nodeChildren(args) {
			if !skipArgTypes[nodeType(arg)] {
				isT, aSrc := tc.Check(arg, src, scope, currentClass, filePath, depth+1, cache)
				if isT {
					argTainted = true
					argSource = aSrc
					break
				}
			}
		}
	}

	// sanitizer 检测
	isSanitizer := false
	objClassName := ""
	if nameNode != nil {
		calledMethodName := nodeText(src, nameNode)
		if objNode != nil {
			objText := nodeText(src, objNode)
			if objText == "super" {
				objClassName = tc.store.Types.ClassExtends[currentClass]
				if objClassName == "" {
					objClassName = currentClass
				}
			} else {
				objClassName = tc.typeResolver.ResolveType(objNode, currentClass, src, filePath, scope)
			}
		}
		if objClassName != "" || calledMethodName != "" {
			isSanitizer = isSanitizerMethod(calledMethodName, objClassName)
		}
	}

	// sanitizer 处理：object 污点则透传，否则截断
	if isSanitizer {
		if objTainted {
			return true, objSource
		}
		return false, ""
	}

	if objTainted {
		return true, objSource
	}
	if argTainted {
		return true, argSource
	}
	return false, ""
}

func (tc *TaintChecker) checkIdentifier(node *gotreesitter.Node, src []byte, scope *MethodScope) (bool, string) {
	name := nodeText(src, node)
	if scope != nil {
		taintSources := scope.ResolveTaint(name)
		if taintSources != nil {
			for s := range taintSources {
				return true, s
			}
		}
	}
	return false, ""
}

func (tc *TaintChecker) checkFieldAccess(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, depth int, cache map[[2]int]taintCheckResult) (bool, string) {
	objNode := fieldChild(node, "object")
	if objNode != nil {
		isT, source := tc.Check(objNode, src, scope, currentClass, filePath, depth+1, cache)
		if isT {
			return true, source
		}
		// R5-2：对象字段污点穿透返回值。当 `copy.data` 的 copy 是局部变量且其字段污点已
		// 继承（来自深拷贝 cloneOf 返回值的字段污点），直接返回该字段污点。
		if nodeType(objNode) == "identifier" && scope != nil {
			fldNode := fieldChild(node, "field")
			if fldNode != nil {
				oName := nodeText(src, objNode)
				fName := nodeText(src, fldNode)
				fs, ok := scope.GetFieldTaint(oName, fName)
				if ok && fs != "" {
					return true, fs
				}
			}
		}
	}
	return false, ""
}

func (tc *TaintChecker) checkTernary(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, depth int, cache map[[2]int]taintCheckResult) (bool, string) {
	consequence := fieldChild(node, "consequence")
	if consequence != nil {
		isT, source := tc.Check(consequence, src, scope, currentClass, filePath, depth+1, cache)
		if isT {
			return true, source
		}
	}
	alternative := fieldChild(node, "alternative")
	if alternative != nil {
		return tc.Check(alternative, src, scope, currentClass, filePath, depth+1, cache)
	}
	return false, ""
}

func (tc *TaintChecker) checkBinary(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, depth int, cache map[[2]int]taintCheckResult) (bool, string) {
	for _, child := range nodeChildren(node) {
		if nonTaintPropagatingOps[nodeType(child)] {
			return false, ""
		}
	}
	for _, child := range nodeChildren(node) {
		if comparisonOperators[nodeType(child)] {
			continue
		}
		isT, source := tc.Check(child, src, scope, currentClass, filePath, depth+1, cache)
		if isT {
			return true, source
		}
	}
	return false, ""
}

func (tc *TaintChecker) checkUnary(node *gotreesitter.Node, src []byte, scope *MethodScope, currentClass, filePath string, depth int, cache map[[2]int]taintCheckResult) (bool, string) {
	for _, child := range nodeChildren(node) {
		if nodeType(child) == "!" {
			return false, ""
		}
	}
	for _, child := range nodeChildren(node) {
		ct := nodeType(child)
		if ct != "-" && ct != "+" && ct != "~" && ct != "!" && ct != "--" && ct != "++" {
			isT, source := tc.Check(child, src, scope, currentClass, filePath, depth+1, cache)
			if isT {
				return true, source
			}
		}
	}
	return false, ""
}

// ============================================================
//  ValidationChecker — 验证检查器（镜像 7.py ValidationChecker L1830-1877）
// ============================================================

var securityAnnotations = map[string]bool{
	"PreAuthorize": true, "PostAuthorize": true,
	"Secured": true, "RolesAllowed": true,
	"DenyAll": true, "PermitAll": true,
}

type ValidationChecker struct {
	store *AnalysisStore
}

func NewValidationChecker(store *AnalysisStore) *ValidationChecker {
	return &ValidationChecker{store: store}
}

// Check 检查节点是否在验证上下文中，返回 (是否验证, 验证描述)。
func (vc *ValidationChecker) Check(node *gotreesitter.Node, src []byte, currentClass string) (bool, string) {
	if node == nil {
		return false, ""
	}

	// 向上遍历找方法/构造器声明，检查安全注解
	parent := node.Parent()
	depth := 0
	for parent != nil && depth < 10 {
		pt := nodeType(parent)
		if pt == "method_declaration" || pt == "constructor_declaration" {
			for _, child := range nodeChildren(parent) {
				if nodeType(child) == "modifiers" {
					for _, mod := range nodeChildren(child) {
						mt := nodeType(mod)
						if mt == "marker_annotation" || mt == "annotation" {
							nameNode := fieldChild(mod, "name")
							if nameNode != nil {
								annName := nodeText(src, nameNode)
								if securityAnnotations[annName] {
									return true, "@" + annName
								}
							}
						}
					}
				}
			}
			break
		} else if pt == "class_declaration" || pt == "interface_declaration" || pt == "lambda_expression" {
			break
		}
		parent = parent.Parent()
		depth++
	}

	// 向上遍历找 if 语句，检查验证模式
	parent = node.Parent()
	depth = 0
	for parent != nil && depth < 5 {
		pt := nodeType(parent)
		if pt == "if_statement" {
			condition := fieldChild(parent, "condition")
			if condition != nil {
				condText := nodeText(src, condition)
				for validMethod := range validationMethods {
					if contains(condText, validMethod) {
						return true, validMethod
					}
				}
				for _, pattern := range validationPatterns {
					if pattern.MatchString(condText) {
						return true, "conditional_check"
					}
				}
			}
			break
		} else if pt == "method_declaration" || pt == "constructor_declaration" ||
			pt == "class_declaration" || pt == "lambda_expression" {
			break
		}
		parent = parent.Parent()
		depth++
	}

	return false, ""
}

// ============================================================
//  isSanitizerMethod — 公共 sanitizer 检测函数
// ============================================================

// ⚠ 本函数被**两处**使用，语义完全不同，扩表前必须分清（2026-08-23 实测）：
//
//	checker.go:179  污点**传播**：命中即截断污点（return false）
//	                → 往表里加条目会让引擎**少发现**污点，可能藏掉真漏洞。危险方向。
//	controlflow.go  HasSanitizer **查询**：只回答「这里有没有净化」
//	                → 加条目只会让答案更全，永不抑制发现。安全方向。
//
// 且这张表是**漏洞族无关的平表** —— `URLEncoder.encode` 对路径穿越根本不是净化，
// 却同样会在传播侧截断污点。净化器本质是**按漏洞族**的知识（CWE registry 的
// taint_model.sanitizers 就是按族组织的），做成平表是设计缺陷，已记 ROADMAP。
//
// 在那之前：**只往查询侧加**（见 isSanitizerForQuery），传播侧这张表一个字不动。
func isSanitizerMethod(methodName, objClassName string) bool {
	if objClassName != "" {
		fullKey := objClassName + "." + methodName
		if sanitizerMethodsFull[fullKey] {
			return true
		}
	}
	if universalSanitizerNames[methodName] {
		return true
	}
	if allowedCtx, ok := contextSensitiveSanitizers[methodName]; ok {
		if objClassName != "" {
			for ctx := range allowedCtx {
				if contains(objClassName, ctx) {
					return true
				}
			}
		}
	}
	return false
}

// ─── 辅助函数 ───

func lower(s string) string {
	return strings.ToLower(s)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// —— 查询侧净化器目录（2026-08-23）——————————————————————————
//
// EXCULPATORY-FACT: engine_sanitizer_catalog
//
// `HasSanitizer` 回答的是「这个方法体里有没有对该变量的净化」。答 false 是**确定性否定**，
// 下游会据此认为「没净化」。原目录只覆盖 **XSS/编码一族**（URLEncoder / StringEscapeUtils /
// Encode.for* / ESAPI encodeFor*），**零条路径与文件名净化器** —— 于是对上传/路径穿越族
// 一律答 false，实测 ceshi uploadLocal 里明明有 `FileUtils.getFileName(orgName)`，
// 精确询问仍答 false。语料契约(internal/factguard)兜住「下一个漏掉的族」。
//
// **只用于查询侧**：传播侧加条目会截断污点、藏掉真漏洞（见 isSanitizerMethod 头注）。
func isSanitizerForQuery(methodName, objClassName string) bool {
	if isSanitizerMethod(methodName, objClassName) {
		return true
	}
	if pathSanitizersFull[objClassName+"."+methodName] {
		return true
	}
	if allowed, ok := pathSanitizersByReceiver[methodName]; ok && objClassName != "" {
		for recv := range allowed {
			if contains(objClassName, recv) {
				return true
			}
		}
	}
	return false
}

// pathSanitizersFull —— 路径/文件名族的净化器（receiver 明确者）。
// 只收**标准库与通用库**，不收某个项目自己的 util 类名（那是 case-by-case 污染）。
var pathSanitizersFull = map[string]bool{
	"FilenameUtils.getName": true, "FilenameUtils.getBaseName": true, "FilenameUtils.normalize": true,
	"File.getCanonicalPath": true, "File.getCanonicalFile": true,
	"UUID.randomUUID": true, // 服务端生成名 = 丢弃客户端文件名（CWE-434 registry 明列的净化器）
}

// pathSanitizersByReceiver —— key=方法名, value=允许的 receiver 类名片段。
// 用 receiver 收窄，避免裸 `getName`/`normalize` 这类高频名把任意调用当净化。
var pathSanitizersByReceiver = map[string]map[string]bool{
	// getName / getFileName 都是「从路径取纯文件名」的**约定级**命名：commons-io 是
	// FilenameUtils.getName，各家 util 常写成 FileUtils.getFileName。receiver 门控保证
	// 只认工具类上的调用，不会把任意 getter 当净化（裸名已在语料的负样本里钉住）。
	"getName":          {"FilenameUtils": true, "FileUtils": true, "PathUtils": true},
	"getFileName":      {"FilenameUtils": true, "FileUtils": true, "PathUtils": true},
	"normalize":        {"FilenameUtils": true, "Path": true, "Paths": true},
	"getCanonicalPath": {"File": true},
	"getCanonicalFile": {"File": true},
}
