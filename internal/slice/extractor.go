// Package slice is the seam for Java source slicing: it defines the
// FunctionExtractor interface and result types, plus the production
// implementation. The pipeline depends ONLY on this interface, never on a
// concrete binding — so the slicing strategy can be swapped without touching
// downstream code.
//
// Production slicer: the Go-native pure-Go tree-sitter implementation
// (internal/slice/gots). No Python subprocess, no CGO, always available.
//
// Result shapes mirror appsec/nodes/slicer.py + appsec/state.py:ClassContext
// (algorithmic lineage; the Python reference itself is not part of this repo).
// Line numbers are 1-based (the Python extractor already adds 1).
package slice

import "appsecgo/internal/contract"

// ClassContext now lives in internal/contract (it is part of the SlicedContext
// contract surface). See contract.ClassContext.

// MethodInfo is one entry from iter_methods: a method's name, full body text,
// 1-based line range, and enclosing class name (nil if none).
type MethodInfo struct {
	Name      string  `json:"name"`
	Body      string  `json:"body"`
	LineRange [2]int  `json:"line_range"`
	ClassName *string `json:"class_name"`
}

// InvocationInfo is one call site from method_invocations: callee name, raw
// argument text (taint-arg targeting), and the receiver expression (e.g.
// "AccessPolicy" in AccessPolicy.check(x)) — empty when there is no receiver.
type InvocationInfo struct {
	Name     string `json:"name"`
	Args     string `json:"args"`
	Receiver string `json:"receiver"`
}

// Param is one formal parameter of a method: its declared name and type text
// (type preserved verbatim incl. generics, e.g. "List<String>"). Used by
// MethodParams to derive an entry-method taint set (names) and to detect
// callee param types absent from the scanned repo (B2, type).
type Param struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// FunctionExtractor is the slicing seam. Every method's ok flag / nil result
// distinguishes "not found" (ok=false / nil) from a real error (returned as
// error). file_path is read by the implementation; method_invocations takes a
// code snippet (NOT a file path), matching the Python reference.
type FunctionExtractor interface {
	// Extract returns the full method body text + 1-based line range for the
	// named method in the file. ok=false when no such method exists.
	Extract(path, fn string) (body string, start, end int, ok bool, err error)

	// ExtractByLine returns the body + line range + method name of the
	// innermost method enclosing the 1-based line. ok=false when no method
	// encloses the line.
	ExtractByLine(path string, line int) (body string, start, end int, name string, ok bool, err error)

	// ClassContext returns the enclosing class's name + annotations +
	// class-level @RequestMapping for the named method, or nil/false when the
	// method or its enclosing class is absent.
	ClassContext(path, fn string) (*contract.ClassContext, bool, error)

	// ClassContextByLine is ClassContext keyed by enclosing line.
	ClassContextByLine(path string, line int) (*contract.ClassContext, bool, error)

	// ClassFields returns the enclosing class/interface/enum/record body's
	// field_declaration direct children text (joined by \n) for the named
	// method — feeding the reachability var→type map so a class-field receiver
	// (e.g. `reentrantLockServiceImpl.releaseLock()`, declared `private
	// LockService reentrantLockServiceImpl;` in the class body) resolves to its
	// declared type and can be dropped when that type is external to the repo
	// (② fire-noise, v1.7 spec). ok=false when the method is absent or a parse
	// error occurs; ok=true with empty string when the method has no enclosing
	// type body or the body has no field_declaration children (fail-safe keep).
	// Only field_declaration direct children (class scope); method locals are
	// local_variable_declaration and NOT included — zero cross-method pollution
	// (v1.7 spec §3.1/§4 b1, not b2).
	ClassFields(path, fn string) (string, bool, error)

	// IterMethods enumerates every method in the file with name, body, line
	// range, and class name. Order matches the Python reference (DFS pop
	// order); callers must not assume source order.
	IterMethods(path string) ([]MethodInfo, error)

	// MethodInvocations returns every method_invocation in a code snippet
	// (not a file): callee name, raw arg text, receiver expression.
	MethodInvocations(code string) ([]InvocationInfo, error)

	// MethodParams returns the formal parameter names+types declared on the
	// first method_declaration in the code snippet, in declaration order.
	// Returns a non-nil empty slice when the snippet has no
	// method_declaration or no parameters. Mirrors RepoAudit
	// Java_TS_analyzer.get_parameters_in_single_function (tree-sitter
	// formal_parameter -> identifier). Symmetric with MethodInvocations: takes
	// a code snippet (NOT a file path), so it parses the hop's own body and
	// avoids overload ambiguity from re-resolving by name.
	MethodParams(code string) (params []Param, err error)

	// ControlFlowMutex reports whether srcLine and sinkLine sit in
	// mutually-exclusive if/else branches of the SAME single method with no
	// enclosing loop — conservative: any unmodeled shape returns false.
	ControlFlowMutex(path string, srcLine, sinkLine int) (bool, error)

	// Close releases worker resources (subprocesses, etc.). Safe to call
	// once; implementations must tolerate a second Close.
	Close() error
}
