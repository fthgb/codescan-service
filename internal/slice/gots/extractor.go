package gots

import (
	"os"
	"strings"

	"appsecgo/internal/contract"
	"appsecgo/internal/slice"
)

// Compile-time assertion: Extractor satisfies the slicing seam.
var _ slice.FunctionExtractor = (*Extractor)(nil)

// Extractor is the Go-native Java slicer: pure-Go tree-sitter, no Python
// subprocess, no CGO. Construction cannot fail (no external resources).
type Extractor struct{}

// New returns a ready Extractor. It never errors.
func New() *Extractor { return &Extractor{} }

// Close is a no-op (pure-Go, no subprocess/C memory). Satisfies the seam.
func (e *Extractor) Close() error { return nil }

// tree mirrors slicer.py TreeSitterJavaExtractor._tree: read file, normalize
// to UTF-8, parse. Returns UTF-8 source bytes + parsed tree.
func (e *Extractor) tree(file_path string) ([]byte, *Tree, error) {
	raw, err := os.ReadFile(file_path)
	if err != nil {
		return nil, nil, err
	}
	src := toUTF8(raw)
	tr, err := ParseJavaUTF8(src)
	if err != nil {
		return nil, nil, err
	}
	return src, tr, nil
}

// findMethod mirrors slicer.py _find_method: DFS stack, first
// method_declaration whose "name" field text == name. src is needed because
// Go tree-sitter nodes do not store their source (unlike Python's .text).
func findMethod(root Node, name string, src []byte) (Node, bool) {
	stack := []Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if NodeType(n) == "method_declaration" {
			if ident, ok := FieldChild(n, "name"); ok && NodeText(src, ident) == name {
				return n, true
			}
		}
		stack = append(stack, Children(n)...)
	}
	return Node{}, false
}

// findMethodAtLine mirrors slicer.py _find_method_at_line: 1-based line →
// the last method_declaration (in DFS pop order) whose span encloses it.
func findMethodAtLine(root Node, line int) (Node, bool) {
	target := line - 1
	var best Node
	found := false
	stack := []Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if NodeType(n) == "method_declaration" {
			if StartLine(n) <= target && target <= EndLine(n) {
				best = n
				found = true
			}
		}
		stack = append(stack, Children(n)...)
	}
	return best, found
}

// extractFromNode mirrors slicer.py _extract_from_node.
func extractFromNode(src []byte, m Node) (string, int, int) {
	return NodeText(src, m), StartLine(m) + 1, EndLine(m) + 1
}

// enclosingDecls mirrors slicer.py _class_context_from_node _ENCLOSING.
var enclosingDecls = map[string]bool{
	"class_declaration":     true,
	"interface_declaration": true,
	"enum_declaration":      true,
	"record_declaration":    true,
}

// classContextFromNode mirrors slicer.py _class_context_from_node. Walks to
// the enclosing class/interface/enum/record, collects annotations, finds a
// class-level @RequestMapping. ClassAnnotations is non-nil (JSON `[]`
// roundtrip); ClassLevelPath is set only when found.
func classContextFromNode(src []byte, m Node) *contract.ClassContext {
	cls, ok := Parent(m)
	for ok && !enclosingDecls[NodeType(cls)] {
		cls, ok = Parent(cls)
	}
	if !ok {
		return nil
	}
	nameNode, hasName := FieldChild(cls, "name")
	annotations := []string{} // non-nil: Python sends [] not null
	for _, child := range Children(cls) {
		if NodeType(child) == "modifiers" {
			for _, mod := range Children(child) {
				mt := NodeType(mod)
				if mt == "annotation" || mt == "marker_annotation" {
					annotations = append(annotations, NodeText(src, mod))
				}
			}
		}
	}
	var classLevelPath *string
	for _, a := range annotations {
		if strings.Contains(a, "@RequestMapping") {
			cp := a
			classLevelPath = &cp
			break
		}
	}
	cn := "?"
	if hasName {
		cn = NodeText(src, nameNode)
	}
	return &contract.ClassContext{
		ClassName:        cn,
		ClassAnnotations: annotations,
		ClassLevelPath:   classLevelPath,
	}
}

// Extract mirrors slicer.py TreeSitterJavaExtractor.extract.
func (e *Extractor) Extract(path, fn string) (body string, start, end int, ok bool, err error) {
	src, tr, err := e.tree(path)
	if err != nil {
		return "", 0, 0, false, err
	}
	m, found := findMethod(RootNode(tr), fn, src)
	if !found {
		return "", 0, 0, false, nil
	}
	b, s, en := extractFromNode(src, m)
	return b, s, en, true, nil
}

// ExtractByLine mirrors slicer.py extract_by_line.
func (e *Extractor) ExtractByLine(path string, line int) (body string, start, end int, name string, ok bool, err error) {
	src, tr, err := e.tree(path)
	if err != nil {
		return "", 0, 0, "", false, err
	}
	m, found := findMethodAtLine(RootNode(tr), line)
	if !found {
		return "", 0, 0, "", false, nil
	}
	ident, hasName := FieldChild(m, "name")
	nm := "?"
	if hasName {
		nm = NodeText(src, ident)
	}
	b, s, en := extractFromNode(src, m)
	return b, s, en, nm, true, nil
}

// ClassContext mirrors slicer.py class_context.
func (e *Extractor) ClassContext(path, fn string) (*contract.ClassContext, bool, error) {
	src, tr, err := e.tree(path)
	if err != nil {
		return nil, false, err
	}
	m, found := findMethod(RootNode(tr), fn, src)
	if !found {
		return nil, false, nil
	}
	return classContextFromNode(src, m), true, nil
}

// ClassContextByLine mirrors slicer.py class_context_by_line.
func (e *Extractor) ClassContextByLine(path string, line int) (*contract.ClassContext, bool, error) {
	src, tr, err := e.tree(path)
	if err != nil {
		return nil, false, err
	}
	m, found := findMethodAtLine(RootNode(tr), line)
	if !found {
		return nil, false, nil
	}
	return classContextFromNode(src, m), true, nil
}

// classFieldsFromNode returns the field_declaration direct children text of
// the body-declarations node enclosing method m (joined by \n). v1.7 (spec
// §3.2 b1): unlike classContextFromNode (which walks up to the *_declaration),
// this takes Parent(m) directly — field_declaration is a direct child of the
// method's immediate parent body, not the type declaration. Only direct
// children (not recursive) → no descent into nested class bodies (outer
// methods don't reference nested-class instance fields; direct children also
// keeps it clean from any nested-class field pollution). field_declaration is
// class-scope only — method locals are local_variable_declaration and are
// never matched (zero cross-method pollution, the b2→b1 fix).
//
// §7 PR-gate (2026-08-25 AST inspect, binding_test.go-style) confirmed the
// enclosing-body node types: class + record use class_body; enum uses
// enum_body_declarations (NOT enum_body — the original HasSuffix("_body")
// guard missed it, dropping enum instance fields `private String code;` in
// `enum Color { RED("r"); private String code; }`, a real receiver scenario).
// Hence the guard accepts both *_body and *_declarations suffixes. interface
// uses interface_body whose field-like children are constant_declaration
// (not field_declaration) → empty here — acceptable: interfaces have no
// instance fields, and static constants are accessed via the uppercase
// interface name (handled by the v1.5 isUpper+ClassDeclared path, not this
// class-field path). No enclosing body (top-level/script) → "" (fail-safe keep).
func classFieldsFromNode(src []byte, m Node) string {
	body, ok := Parent(m)
	if !ok {
		return ""
	}
	bt := NodeType(body)
	if !strings.HasSuffix(bt, "_body") && !strings.HasSuffix(bt, "_declarations") {
		return "" // method not in a type body (top-level/script) → fail-safe
	}
	var fields []string
	for _, c := range Children(body) { // direct children, named+anonymous
		if NodeType(c) == "field_declaration" {
			fields = append(fields, NodeText(src, c))
		}
	}
	return strings.Join(fields, "\n")
}

// ClassFields mirrors ClassContext (extractor.go:168) in shape: tree(path) →
// findMethod → classFieldsFromNode. v1.7 spec §3.3 Path B1: called lazily via
// RepositoryIndex.ClassFieldsFor from PrejudgeCalleeReachability (NOT threaded
// through IterMethods/MethodInfo/HopSlice → zero golden change, class_fields
// never enters hop JSON → judge never sees it, spec §3.3 non-breaking).
func (e *Extractor) ClassFields(path, fn string) (string, bool, error) {
	src, tr, err := e.tree(path)
	if err != nil {
		return "", false, err
	}
	m, found := findMethod(RootNode(tr), fn, src)
	if !found {
		return "", false, nil
	}
	return classFieldsFromNode(src, m), true, nil
}

// IterMethods mirrors slicer.py iter_methods: DFS, every method_declaration
// with name/body/line_range/class_name. Order = DFS pop order (callers must
// not assume source order). ClassName is *string (nil when no enclosing
// class). Returns non-nil slice (JSON []).
func (e *Extractor) IterMethods(path string) ([]slice.MethodInfo, error) {
	src, tr, err := e.tree(path)
	if err != nil {
		return nil, err
	}
	out := []slice.MethodInfo{} // non-nil
	stack := []Node{RootNode(tr)}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if NodeType(n) == "method_declaration" {
			ident, hasName := FieldChild(n, "name")
			name := "?"
			if hasName {
				name = NodeText(src, ident)
			}
			var className *string
			if cc := classContextFromNode(src, n); cc != nil {
				cn := cc.ClassName
				className = &cn
			}
			out = append(out, slice.MethodInfo{
				Name:      name,
				Body:      NodeText(src, n),
				LineRange: [2]int{StartLine(n) + 1, EndLine(n) + 1},
				ClassName: className,
			})
		}
		stack = append(stack, Children(n)...)
	}
	return out, nil
}

// MethodInvocations mirrors slicer.py method_invocations: every
// method_invocation in a code snippet (NOT a file) with callee name, raw arg
// text, receiver expression. One entry per call site.
func (e *Extractor) MethodInvocations(code string) ([]slice.InvocationInfo, error) {
	src := []byte(code)
	tr, err := ParseJavaUTF8(src)
	if err != nil {
		return nil, err
	}
	out := []slice.InvocationInfo{} // non-nil
	stack := []Node{RootNode(tr)}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if NodeType(n) == "method_invocation" {
			ident, ok := FieldChild(n, "name")
			if ok {
				argsNode, hasArgs := FieldChild(n, "arguments")
				objNode, hasObj := FieldChild(n, "object")
				inv := slice.InvocationInfo{
					Name: NodeText(src, ident),
				}
				if hasArgs {
					inv.Args = NodeText(src, argsNode)
				}
				if hasObj {
					inv.Receiver = NodeText(src, objNode)
				}
				out = append(out, inv)
			}
		}
		stack = append(stack, Children(n)...)
	}
	return out, nil
}

// MethodParams mirrors slicer.py: the first method_declaration in the snippet
// -> its formal_parameter children -> (type, name). Returns non-nil. Verified
// against the binding: method_declaration field "parameters" is a
// formal_parameters node whose named children are formal_parameter, each with
// fields "type" (type_identifier / generic_type, text preserved verbatim) and
// "name" (identifier). spread_parameter (varargs) is a different node type and
// is naturally skipped by the formal_parameter filter.
func (e *Extractor) MethodParams(code string) ([]slice.Param, error) {
	src := []byte(code)
	tr, err := ParseJavaUTF8(src)
	if err != nil {
		return nil, err
	}
	out := []slice.Param{} // non-nil
	stack := []Node{RootNode(tr)}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if NodeType(n) == "method_declaration" {
			if params, ok := FieldChild(n, "parameters"); ok {
				for _, c := range Children(params) {
					if NodeType(c) != "formal_parameter" {
						continue // skip ( ) , tokens; spread_parameter stays out
					}
					p := slice.Param{}
					if t, ok := FieldChild(c, "type"); ok {
						p.Type = NodeText(src, t)
					}
					if nm, ok := FieldChild(c, "name"); ok {
						p.Name = NodeText(src, nm)
					}
					out = append(out, p)
				}
			}
			return out, nil // first method_declaration only (hop body = one method)
		}
		stack = append(stack, Children(n)...)
	}
	return out, nil
}
var loopNodes = map[string]bool{
	"for_statement":          true,
	"while_statement":        true,
	"do_statement":           true,
	"enhanced_for_statement": true,
}

// ControlFlowMutex mirrors slicer.py control_flow_mutex (inc21/B-54):
// sound single-function if/else branch mutual-exclusion check. Returns true
// ONLY when src/sink sit in consequence-vs-alternative of the SAME
// if_statement inside ONE method with no enclosing loop. Conservative by
// construction: any unmodeled shape returns false.
func (e *Extractor) ControlFlowMutex(path string, srcLine, sinkLine int) (bool, error) {
	if srcLine <= 0 || sinkLine <= 0 {
		return false, nil
	}
	src0, sink0 := srcLine-1, sinkLine-1
	_, tr, err := e.tree(path)
	if err != nil {
		return false, err
	}
	root := RootNode(tr)
	srcM, sok := findMethodAtLine(root, srcLine)
	sinkM, dok := findMethodAtLine(root, sinkLine)
	if !sok || !dok || !sameNode(srcM, sinkM) {
		return false, nil // not both inside the same single method
	}
	stack := []Node{srcM}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if NodeType(n) == "if_statement" {
			cons, hasCons := FieldChild(n, "consequence")
			alt, hasAlt := FieldChild(n, "alternative")
			if hasCons && hasAlt {
				mutuallyExclusive :=
					(spans(cons, src0) && spans(alt, sink0)) ||
						(spans(alt, src0) && spans(cons, sink0))
				if mutuallyExclusive && !loopEnclosed(n, srcM) {
					return true, nil
				}
			}
		}
		stack = append(stack, Children(n)...)
	}
	return false, nil
}

// spans mirrors slicer.py _spans: 0-based line within node's row span.
func spans(node Node, line0 int) bool {
	return StartLine(node) <= line0 && line0 <= EndLine(node)
}

// loopEnclosed mirrors slicer.py _loop_enclosed: any ancestor of node up to
// (not incl.) stop is a loop (a back-edge could carry taint across iters).
func loopEnclosed(node, stop Node) bool {
	p, ok := Parent(node)
	for ok {
		if sameNode(p, stop) {
			break
		}
		if loopNodes[NodeType(p)] {
			return true
		}
		p, ok = Parent(p)
	}
	return false
}

// sameNode compares two Nodes by byte span. Go tree-sitter Nodes are value
// types (not interned), so pointer identity is unreliable; [start,end) is a
// unique key per node in a parse tree. slicer.py uses `is` (identity) and
// start_byte for method equality — this matches both.
func sameNode(a, b Node) bool {
	return StartByte(a) == StartByte(b) && EndByte(a) == EndByte(b)
}
