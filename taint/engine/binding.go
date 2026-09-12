package engine

import (
	"fmt"
	"os"
	"sync"
	"unicode/utf8"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ============================================================
//  gotreesitter 薄封装（参考 internal/slice/gots/binding.go 模式，独立实现）
// ============================================================

var (
	langOnce sync.Once
	lang     *gotreesitter.Language
)

func javaLanguage() *gotreesitter.Language {
	langOnce.Do(func() {
		lang = grammars.JavaLanguage()
	})
	return lang
}

// ParsedFile 持有源码字节 + AST 根节点。
type ParsedFile struct {
	Src  []byte
	Root *gotreesitter.Node
}

// parseJavaFile 读取文件 → toUTF8 编码归一化 → 解析 → 返回 ParsedFile。
func parseJavaFile(path string) (*ParsedFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	src := toUTF8(raw)
	p := gotreesitter.NewParser(javaLanguage())
	t, err := p.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if t == nil {
		return nil, fmt.Errorf("parse %s: no tree", path)
	}
	return &ParsedFile{Src: src, Root: t.RootNode()}, nil
}

// ─── 薄封装：减少 language() 线程化 ───

func nodeType(n *gotreesitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Type(javaLanguage())
}

func fieldChild(n *gotreesitter.Node, field string) *gotreesitter.Node {
	if n == nil {
		return nil
	}
	c := n.ChildByFieldName(field, javaLanguage())
	return c
}

// nodeBytes 零拷贝：热路径用（方法体遍历数千次），避免 string 堆分配。
func nodeBytes(src []byte, n *gotreesitter.Node) []byte {
	if n == nil {
		return nil
	}
	return src[n.StartByte():n.EndByte()]
}

// nodeText 返回 string（标识符比较 / map key / JSON 输出场景）。
func nodeText(src []byte, n *gotreesitter.Node) string {
	return string(nodeBytes(src, n))
}

func nodeChildren(n *gotreesitter.Node) []*gotreesitter.Node {
	if n == nil {
		return nil
	}
	return n.Children()
}

func nodeParent(n *gotreesitter.Node) *gotreesitter.Node {
	if n == nil {
		return nil
	}
	return n.Parent()
}

// startLine1 返回 1-based 起始行（gotreesitter 是 0-based）。
func startLine1(n *gotreesitter.Node) int {
	if n == nil {
		return 0
	}
	return int(n.StartPoint().Row) + 1
}

// endLine1 返回 1-based 结束行。
func endLine1(n *gotreesitter.Node) int {
	if n == nil {
		return 0
	}
	return int(n.EndPoint().Row) + 1
}

func startByte(n *gotreesitter.Node) int {
	if n == nil {
		return 0
	}
	return int(n.StartByte())
}

func endByte(n *gotreesitter.Node) int {
	if n == nil {
		return 0
	}
	return int(n.EndByte())
}

// sameNode 用 [StartByte, EndByte) 做同一性比较（Node 按值传递不可靠）。
func sameNode(a, b *gotreesitter.Node) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

// ============================================================
//  编码归一化（复用 gots/encoding.go 三级降级模式）
// ============================================================

// toUTF8 三级降级：UTF-8 → GB18030 → Latin-1。返回 UTF-8 字节，
// 使所有下游 byte offset 在 UTF-8 空间，与 Python 参考一致。
func toUTF8(raw []byte) []byte {
	if utf8.Valid(raw) {
		return raw
	}
	if out, _, err := transform.Bytes(simplifiedchinese.GB18030.NewDecoder(), raw); err == nil {
		return out
	}
	// latin-1: 每字节 → U+0000..U+00FF，再 UTF-8 编码。永不报错。
	runes := make([]rune, len(raw))
	for i, b := range raw {
		runes[i] = rune(b)
	}
	return []byte(string(runes))
}
