package slice

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// MapperXmlBlock is one MyBatis <select|insert|update|delete id="X">...</...>
// block pre-scanned from a mapper XML. by_method values are lists (a method
// name may appear in multiple namespaces — disambiguated by the eager walk
// following real call edges + namespace class filter, not bare-name reverse).
type MapperXmlBlock struct {
	MethodName string
	XmlRel     string
	Namespace  string
	Block      string
	HasDollar  bool
	HasParam   bool
}

// MapperXmlIndex pre-scans repo *.xml for MyBatis mapper blocks; maps
// method_name -> block metadata. Pure regex (no XML parser dep), fail-open
// per file — mirrors appsec/mapper_xml_index.py exactly.
//
// Python uses _BLOCK_RE with a \1 backreference to match closing=opening tag.
// RE2 has no backreferences, so the block pattern is split into 4 literal-close
// regexes (one per tag). Each close is literal -> <select>...</insert> won't
// mismatch. Faithful + RE2-clean.
var (
	mapperNsRe = regexp.MustCompile(`<mapper\s+[^>]*namespace="([^"]+)"`)
	// (?s) = dotall; .*? non-greedy; literal close </tag> (no backref).
	mapperBlockRes = []*regexp.Regexp{
		regexp.MustCompile(`(?s)<select\b[^>]*\bid="(\w+)"[^>]*>(.*?)</select>`),
		regexp.MustCompile(`(?s)<insert\b[^>]*\bid="(\w+)"[^>]*>(.*?)</insert>`),
		regexp.MustCompile(`(?s)<update\b[^>]*\bid="(\w+)"[^>]*>(.*?)</update>`),
		regexp.MustCompile(`(?s)<delete\b[^>]*\bid="(\w+)"[^>]*>(.*?)</delete>`),
	}
	mapperDollarRe = regexp.MustCompile(`\$\{`)
	mapperParamRe  = regexp.MustCompile(`#\{`)
)

type MapperXmlIndex struct {
	repoRoot string
	ByMethod map[string][]MapperXmlBlock
	built    bool
}

func NewMapperXmlIndex(repoRoot string) *MapperXmlIndex {
	x := &MapperXmlIndex{repoRoot: repoRoot, ByMethod: map[string][]MapperXmlBlock{}}
	x.build()
	return x
}

// build walks repo *.xml (skip target/ build output), regex-scans namespace +
// statement blocks. Fail-open per file: a read error skips that file, never
// panics. Mirrors _build() verbatim. (Receiver named x to avoid clashing with
// the match-slice locals mm/subm inside the closure.)
func (x *MapperXmlIndex) build() {
	if x.built {
		return
	}
	_ = filepath.Walk(x.repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // fail-open
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".xml") {
			return nil
		}
		rel, _ := filepath.Rel(x.repoRoot, path)
		rel = filepath.ToSlash(rel)
		if strings.Contains(rel, "/target/") || strings.HasPrefix(rel, "target/") {
			return nil // skip build output (dedup src vs target/classes)
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // fail-open
		}
		// Python opens with mode="r" (universal-newline): \r\n and lone \r are
		// translated to \n on read, so the captured block text never carries \r.
		// os.ReadFile preserves \r; on Windows the dumped fixtures are CRLF, so
		// without normalization the mybatis_xml_eager hop body would carry stray
		// \r and fail field-for-field parity. Normalize to match Python exactly.
		content := strings.ReplaceAll(string(raw), "\r\n", "\n")
		content = strings.ReplaceAll(content, "\r", "\n")
		ns := ""
		if mm := mapperNsRe.FindStringSubmatch(content); mm != nil {
			ns = mm[1]
		}
		for _, re := range mapperBlockRes {
			for _, subm := range re.FindAllStringSubmatch(content, -1) {
				mid, block := subm[1], subm[2]
				x.ByMethod[mid] = append(x.ByMethod[mid], MapperXmlBlock{
					MethodName: mid, XmlRel: rel, Namespace: ns, Block: block,
					HasDollar: mapperDollarRe.MatchString(block),
					HasParam:  mapperParamRe.MatchString(block),
				})
			}
		}
		return nil
	})
	x.built = true
}
