package engine

import (
	"strings"

	"github.com/odvcencio/gotreesitter"
)

// ControlFlowAnalyzer — 控制流可行性剪枝（RepoAudit B-54）
type ControlFlowAnalyzer struct{ store *AnalysisStore }

func NewControlFlowAnalyzer(store *AnalysisStore) *ControlFlowAnalyzer {
	return &ControlFlowAnalyzer{store: store}
}

func (cfa *ControlFlowAnalyzer) CheckControlFeasibility(methodKey string, srcLine, sinkLine int) ControlFlowCheck {
	fn, ok := cfa.store.Methods.Functions[methodKey]
	if !ok {
		return ControlFlowCheck{IsFeasible: true, Reason: "ok"}
	}
	pf, err := parseJavaFile(fn.FilePath)
	if err != nil {
		return ControlFlowCheck{IsFeasible: true, Reason: "ok"}
	}
	methodNode := cfa.findMethodNode(pf.Root, pf.Src, fn.Class, fn.Method, fn.Line)
	if methodNode == nil {
		return ControlFlowCheck{IsFeasible: true, Reason: "ok"}
	}
	ifStmts := cfa.collectIfStatements(methodNode)
	for _, ifStmt := range ifStmts {
		cs, ce := cfa.rangeOf(fieldChild(ifStmt, "consequence"))
		alt := fieldChild(ifStmt, "alternative")
		as, ae := 0, 0
		if alt != nil {
			as, ae = cfa.rangeOf(alt)
		}
		if cs > 0 && as > 0 {
			if (srcLine >= cs && srcLine <= ce && sinkLine >= as && sinkLine <= ae) ||
				(sinkLine >= cs && sinkLine <= ce && srcLine >= as && srcLine <= ae) {
				return ControlFlowCheck{IsFeasible: false, Reason: "mutual_exclusion"}
			}
		}
	}
	if srcLine > sinkLine {
		if cfa.inSameLoop(methodNode, srcLine, sinkLine) {
			return ControlFlowCheck{IsFeasible: true, Reason: "loop_back_edge"}
		}
		return ControlFlowCheck{IsFeasible: false, Reason: "sequential"}
	}
	return ControlFlowCheck{IsFeasible: true, Reason: "ok"}
}

// findMethodNode 在 AST 里定位 (cls, method, line) 对应的方法节点。
//
// ⚠ 调用方传的是 `MethodFunc.Method`,那是 **DisplayName(类限定)** —— `Cls.method`,
// 不是裸方法名;而 AST 的 name 节点是裸名。首版直接 `==` 比较 → **永不匹配** →
// findMethodNode 恒返 nil → `HasSanitizerOnPath` **从来没工作过**(2026-08-23 实测:
// 对 ceshi uploadLocal 里真实存在的 FileUtils.getFileName,任何变量都答 false)。
// 故在此归一,两个调用点(控制流可行性、净化器查询)一并受益。
//
// 同类隐患:query.go:269/284 也拿 `fn.Method` 去比裸的 callee 名,只剥了 `(` 没剥类前缀。
// 那条路径尚未证伪(callee 解析在跑),未在本次改动范围内 —— 已记 ROADMAP 待查。
func (cfa *ControlFlowAnalyzer) findMethodNode(root *gotreesitter.Node, src []byte, cls, method string, line int) *gotreesitter.Node {
	method = bareMethodDisplayName(method)
	var found *gotreesitter.Node
	var walk func(n *gotreesitter.Node, cs []string)
	walk = func(n *gotreesitter.Node, cs []string) {
		if found != nil {
			return
		}
		nt := nodeType(n)
		if nt == "class_declaration" || nt == "interface_declaration" || nt == "enum_declaration" || nt == "record_declaration" {
			nn := fieldChild(n, "name")
			if nn != nil {
				cn := nodeText(src, nn)
				if len(cs) > 0 {
					cn = cs[len(cs)-1] + "$" + cn
				}
				cs = append(cs, cn)
			}
		}
		cc := ""
		if len(cs) > 0 {
			cc = cs[len(cs)-1]
		}
		if (nt == "method_declaration" || nt == "constructor_declaration") && cc == cls {
			nn := fieldChild(n, "name")
			if nn != nil && nodeText(src, nn) == method && startLine1(n) == line {
				found = n
				return
			}
		}
		for _, c := range nodeChildren(n) {
			walk(c, cs)
		}
	}
	walk(root, nil)
	return found
}

func (cfa *ControlFlowAnalyzer) collectIfStatements(n *gotreesitter.Node) []*gotreesitter.Node {
	var out []*gotreesitter.Node
	var walk func(n *gotreesitter.Node)
	walk = func(n *gotreesitter.Node) {
		if nodeType(n) == "if_statement" {
			out = append(out, n)
		}
		for _, c := range nodeChildren(n) {
			walk(c)
		}
	}
	walk(n)
	return out
}

func (cfa *ControlFlowAnalyzer) rangeOf(n *gotreesitter.Node) (int, int) {
	if n == nil {
		return 0, 0
	}
	return startLine1(n), endLine1(n)
}

func (cfa *ControlFlowAnalyzer) inSameLoop(mn *gotreesitter.Node, l1, l2 int) bool {
	var loops []*gotreesitter.Node
	var walk func(n *gotreesitter.Node)
	walk = func(n *gotreesitter.Node) {
		nt := nodeType(n)
		if nt == "for_statement" || nt == "while_statement" || nt == "do_statement" || nt == "enhanced_for_statement" {
			loops = append(loops, n)
		}
		for _, c := range nodeChildren(n) {
			walk(c)
		}
	}
	walk(mn)
	for _, l := range loops {
		s, e := startLine1(l), endLine1(l)
		if l1 >= s && l1 <= e && l2 >= s && l2 <= e {
			return true
		}
	}
	return false
}

// HasSanitizerOnPath 检查方法体内是否有 sanitizer 调用作用于污点变量。
func (cfa *ControlFlowAnalyzer) HasSanitizerOnPath(methodKey, taintVar string) (bool, string) {
	fn, ok := cfa.store.Methods.Functions[methodKey]
	if !ok {
		return false, ""
	}
	pf, err := parseJavaFile(fn.FilePath)
	if err != nil {
		return false, ""
	}
	mn := cfa.findMethodNode(pf.Root, pf.Src, fn.Class, fn.Method, fn.Line)
	if mn == nil {
		return false, ""
	}
	found, at := cfa.scanSanitizer(mn, pf.Src, taintVar, fn.Class)
	return found, at
}

// scanSanitizer 在方法体内找「作用于污点变量的净化器调用」。
//
// EXCULPATORY-FACT: engine_sanitizer_effective
//
// 它的 true 是**开脱性**结论：下游据此宣布「经文件名的路径穿越不成立」，错一次就
// 静默删掉一处真漏洞。危险方向在 true 一侧。
//
// 当前实现只回答「有没有一个净化器调用的实参/receiver **字面上就是**这个变量」，
// 而净化真正生效需要五个条件同时成立（身份/时序/路径/持久/族），本实现只覆盖了族
// （靠 isSanitizerForQuery + 调用方的 AcceptAt），其余四个一概不看：
// 不做方法体内 def-use（故活体的 `orgName = mf.getOriginalFilename(); orgName = f(orgName)`
// 答不出）、不比行号（sink 在净化之前也算）、不看分支（只在 if 一支里净化也算）、
// 不管重新污染。语料契约在 internal/factguard 按这五条穷举，改这里前先跑它。
func (cfa *ControlFlowAnalyzer) scanSanitizer(n *gotreesitter.Node, src []byte, taintVar, cls string) (bool, string) {
	var walk func(n *gotreesitter.Node) (bool, string)
	walk = func(n *gotreesitter.Node) (bool, string) {
		if nodeType(n) == "method_invocation" {
			nameNode := fieldChild(n, "name")
			objNode := fieldChild(n, "object")
			if nameNode != nil {
				methodName := nodeText(src, nameNode)
				objClass := ""
				if objNode != nil {
					objClass = nodeText(src, objNode)
				}
				// 查询侧用扩展目录（含路径/文件名族）；传播侧仍用原表，绝不因此截断污点。
				if isSanitizerForQuery(methodName, objClass) {
					// 检查参数是否引用污点变量
					args := fieldChild(n, "arguments")
					if args != nil {
						for _, arg := range nodeChildren(args) {
							if nodeType(arg) == "identifier" && strings.EqualFold(nodeText(src, arg), taintVar) {
								return true, cls + "." + methodName + ":" + itoa(startLine1(n))
							}
						}
					}
					// 检查 object 是否污点变量
					if objNode != nil && nodeType(objNode) == "identifier" && strings.EqualFold(nodeText(src, objNode), taintVar) {
						return true, cls + "." + methodName + ":" + itoa(startLine1(n))
					}
				}
			}
		}
		for _, c := range nodeChildren(n) {
			if found, at := walk(c); found {
				return found, at
			}
		}
		return false, ""
	}
	return walk(n)
}

// bareMethodDisplayName 把 `MethodFunc.Method`(DisplayName,类限定)还原成裸方法名。
// `Cls.m` → `m`;`<lambda@12>` / `<instance_init>` 等合成名原样返回(无点号)。
func bareMethodDisplayName(display string) string {
	if i := strings.LastIndex(display, "."); i >= 0 {
		return display[i+1:]
	}
	return display
}
