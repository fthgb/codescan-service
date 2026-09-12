package slice

import (
	"strings"

	"appsecgo/internal/contract"
)

// eagerMapperXml mirrors config.EAGER_MAPPER_XML (default "on", design §4.3).
// When on, the eager tier DFS-walks callees from each taint-path Java hop and
// appends matched MyBatis mapper XML blocks + walked intermediate callees.
const eagerMapperXml = true

// EagerResolveMapperXmlForTest is a test-only export of the package-private
// eagerResolveMapperXml (keeps the SliceAlert seam signature stable; the
// parity test exercises eager via SliceAlert, focused tests via this alias).
var EagerResolveMapperXmlForTest = eagerResolveMapperXml

// eagerResolveMapperXml ports slicer._eager_resolve_mapper_xml. DFS-walks
// from each taint-path hop's first Java def (depth=3, visited-cap=20)
// following real call edges; on hitting a MyBatis mapper method, appends the
// XML block (expanded_from="mybatis_xml_eager") + walked intermediate callees
// (expanded_from="eager_callee"). Returns new hops (may contain dups; the
// caller dedups against slice_alert's seen). fail-open: any panic -> nil.
//
// TWO SETS (do not conflate): the local `visited` (DFS cycle detection +
// cap=20, shared across all hops' DFS) is distinct from slice_alert's `seen`
// (taint-path/fallback, mutated per append to catch intra-new_hops dups).
func eagerResolveMapperXml(hops []contract.HopSlice, index *RepositoryIndex, ext FunctionExtractor, repoRoot string) (out []contract.HopSlice) {
	defer func() { recover() }() // fail-open (mirrors Python try/except -> [])
	if !eagerMapperXml || index == nil || repoRoot == "" {
		return nil
	}
	mxi := NewMapperXmlIndex(repoRoot)
	if len(mxi.ByMethod) == 0 {
		return nil
	}
	visited := map[[2]string]bool{} // ★ DFS-internal (cycle + cap=20), NOT slice_alert's seen
	xmlTag := "mybatis_xml_eager"
	calleeTag := "eager_callee"

	// resolveCallee ports _resolve_callee: <=1 def, case-INSENSITIVE receiver
	// disambig + TrimSpace. CANNOT reuse repoindex.resolveWithReceiver
	// (case-sensitive, no strip, may return multi).
	resolveCallee := func(inv InvocationInfo) []FunctionDef {
		cn := bareName(inv.Name)
		defs := index.Resolve(cn)
		if len(defs) == 0 {
			return nil
		}
		receiver := strings.TrimSpace(inv.Receiver)
		if receiver != "" && len(defs) > 1 {
			rl := strings.ToLower(receiver)
			for _, d := range defs {
				if d.ClassName != nil && strings.ToLower(*d.ClassName) == rl {
					return []FunctionDef{d}
				}
			}
		}
		return []FunctionDef{defs[0]}
	}

	xmlMatchesDef := func(e MapperXmlBlock, fd FunctionDef) bool {
		if fd.ClassName == nil {
			return true
		}
		return strings.HasSuffix(e.Namespace, *fd.ClassName)
	}

	var dfs func(fd FunctionDef, depth int, path []FunctionDef)
	dfs = func(fd FunctionDef, depth int, path []FunctionDef) {
		// Cycle check + mark visited first (before the XML-hit check): a matched
		// mapper-mid is a TERMINAL emit (returns, never recurses into the stub
		// body), so it must NOT be gated by the depth/cap guard below. The cap
		// bounds only non-matching fan-out recursion. Without this reorder, a
		// service whose DFS burns the visited=20 budget on in-repo VO/DTO
		// getters (e.g. ceshi parseMapByExcelData → getOutTotal/... ) starves a
		// later legitimate direct-mapper call (getBillItemByParam ${barCodes})
		// that is reached at visitedLen=21 → the real sink XML never emits and
		// only the .java interface stub hop reaches the judge. See spec
		// 2026-08-21-slicer-cap-starvation-xml-hop-design.md.
		k := [2]string{fd.FilePath, fd.Name}
		if visited[k] {
			return
		}
		visited[k] = true
		var hits []MapperXmlBlock
		for _, e := range mxi.ByMethod[fd.Name] {
			if (e.HasDollar || e.HasParam) && xmlMatchesDef(e, fd) {
				hits = append(hits, e)
			}
		}
		if len(hits) > 0 {
			for _, e := range hits {
				e := e
				out = append(out, contract.HopSlice{
					HopIndex: 0, FilePath: e.XmlRel, FunctionName: e.MethodName,
					FunctionBody: e.Block, TaintVariable: "",
					LineRange: [2]int{0, 0}, ExpandedFrom: &xmlTag,
				})
			}
			for _, pfd := range path {
				pfd := pfd
				out = append(out, contract.HopSlice{
					HopIndex: 0, FilePath: pfd.FilePath, FunctionName: pfd.Name,
					FunctionBody: pfd.Body, TaintVariable: "",
					LineRange: pfd.LineRange, ExpandedFrom: &calleeTag,
				})
			}
			return
		}
		// depth/cap guard bounds only the non-matching recursion fan-out
		// (terminal mapper-mid emits above already returned).
		if depth < 0 || len(visited) > 20 {
			return
		}
		invs, err := ext.MethodInvocations(fd.Body)
		if err != nil {
			return // fail-open: skip this def's callees
		}
		for _, inv := range invs {
			cn := bareName(inv.Name)
			if cn == "" || noiseCallees[cn] {
				continue
			}
			for _, cfd := range resolveCallee(inv) {
				// Go slice append reuses backing array -> sibling recursive
				// branches would corrupt `path`. Python `path + [fd]` builds a
				// new list each call. Explicit copy to match Python semantics.
				newPath := append([]FunctionDef(nil), path...)
				newPath = append(newPath, fd)
				dfs(cfd, depth-1, newPath)
			}
		}
	}

	for _, h := range hops {
		if !strings.HasSuffix(h.FilePath, ".java") || h.FunctionName == "" {
			continue
		}
		defs := index.Resolve(h.FunctionName)
		if len(defs) == 0 {
			continue
		}
		dfs(defs[0], 3, nil) // break: only first def per hop
	}
	return out
}
