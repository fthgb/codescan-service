// Package gots is the Go-native Java slicer (P1b B-stage): a pure-Go
// tree-sitter implementation of slice.FunctionExtractor with NO Python
// subprocess and NO CGO. It wraps github.com/odvcencio/gotreesitter behind
// the same stable helper API the deleted CGO tsjava binding exposed, so the
// high-level extractor (extractor.go) mirrors appsec/nodes/slicer.py
// line-for-line.
//
// Grammar alignment is proven by the node-type gate (TestNodeTypeSetMatchesPython)
// against testdata/golden/slice/Simple.nodetypes.json, dumped from the Python
// tree-sitter-java 0.23.5 reference. Field-child access — the gate the
// codeberg hum3/gotreesitter FAILED — is proven by TestFieldChildSmoke.
package gots

import (
	"fmt"
	"sync"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

var (
	langOnce sync.Once
	lang     *gotreesitter.Language
)

// language is a process-wide singleton (mirrors slicer.py _get_java and the
// CGO tsjava lazy singleton).
func language() *gotreesitter.Language {
	langOnce.Do(func() {
		lang = grammars.JavaLanguage()
	})
	return lang
}

// Tree owns a parsed syntax tree. Pure-Go (GC'd) — unlike the CGO tsjava
// binding there is NO Close(): gotreesitter allocations are reclaimed by the
// runtime, so callers need not defer anything.
type Tree struct{ t *gotreesitter.Tree }

// Node wraps a tree-sitter node. Passed by value; the wrapped pointer is
// stable for the lifetime of its Tree. The zero Node is invalid; helpers
// return valid nodes or a false ok flag.
type Node struct{ n *gotreesitter.Node }

// ParseJavaUTF8 parses src (MUST be valid UTF-8 — callers normalize via
// toUTF8 first) as Java source and returns the resulting tree. Mirrors
// slicer.py default parse (partial-tree behavior; errors stay nil).
func ParseJavaUTF8(src []byte) (*Tree, error) {
	p := gotreesitter.NewParser(language())
	t, err := p.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("gots: parse: %w", err)
	}
	if t == nil {
		return nil, fmt.Errorf("gots: parse returned no tree")
	}
	return &Tree{t: t}, nil
}

// RootNode returns the root node of the tree.
func RootNode(t *Tree) Node { return Node{n: t.t.RootNode()} }

// NodeType returns the grammar node type (e.g. "method_invocation").
func NodeType(n Node) string { return n.n.Type(language()) }

// FieldChild returns the child reached by the named grammar field. ok is
// false when the field is absent — callers must not crash on missing fields.
func FieldChild(n Node, field string) (Node, bool) {
	c := n.n.ChildByFieldName(field, language())
	if c == nil {
		return Node{}, false
	}
	return Node{n: c}, true
}

// NodeText returns the source text spanned by n, decoded from src as UTF-8.
// Go tree-sitter nodes do NOT store their source (unlike Python's .text), so
// src must be threaded through every caller.
func NodeText(src []byte, n Node) string { return n.n.Text(src) }

// StartLine/EndLine return 0-based start/end rows. Callers add 1 for 1-based.
func StartLine(n Node) int { return int(n.n.StartPoint().Row) }
func EndLine(n Node) int   { return int(n.n.EndPoint().Row) }

// StartByte returns the 0-based start byte offset; EndByte is exclusive.
func StartByte(n Node) int { return int(n.n.StartByte()) }
func EndByte(n Node) int   { return int(n.n.EndByte()) }

// Children returns all direct children (named AND anonymous, in order) —
// matches Python tree-sitter Node.children, which the node-type gate and
// every DFS walk in slicer.py depend on.
func Children(n Node) []Node {
	kids := n.n.Children() // []*gotreesitter.Node, includes anonymous tokens
	out := make([]Node, len(kids))
	for i, k := range kids {
		out[i] = Node{n: k}
	}
	return out
}

// Parent returns the parent of n. ok is false at the root.
func Parent(n Node) (Node, bool) {
	p := n.n.Parent()
	if p == nil {
		return Node{}, false
	}
	return Node{n: p}, true
}
