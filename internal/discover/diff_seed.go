// Package discover implements Line B (diff-seeded discovery audit): a unified git
// diff -> changed functions -> open-ended discovery judge per unit -> aggregated
// report. Complementary to Line A (SAST triage /api/scan): discover finds
// newly-introduced vulns from a diff with no SAST input (vulnerability_type is
// an OUTPUT, not an input).
//
// Ported from appsec/nodes/diff_seed.py + discover.py + discover_run.py.
// Reuses slice.EnrichSlice / RepositoryIndex.CallersOf / judge.ParseJudgeOutput /
// judge.VerdictOf / prompts.RenderAppContext / bughash.ComputeBughash across packages
// (铁律 A: talk through public contracts only).
package discover

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"appsecgo/internal/paths"
	"appsecgo/internal/slice"
)

// newFileRE mirrors diff_seed._NEWFILE: `+++ b/<path>`.
var newFileRE = regexp.MustCompile(`^\+\+\+ b/(.+)$`)

// hunkRE mirrors diff_seed._HUNK: new-side `@@ -old,n +new,m @@`.
var hunkRE = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// ChangedFunction is one unit a discovery judge analyses: a changed Java method
// (reason="changed") or a 1-hop caller pulled in (reason="caller"). Mirrors the
// dict shape returned by diff_seed.changed_functions.
type ChangedFunction struct {
	File      string  `json:"file"`
	Function  string  `json:"function"`
	Body      string  `json:"body"`
	LineRange [2]int  `json:"line_range"`
	ClassName *string `json:"class_name"`
	Reason    string  `json:"reason"`
}

// ParseDiff mirrors diff_seed.parse_diff: map each changed file (head path) ->
// list of new-side [start, end] line ranges (1-based, inclusive). A pure-deletion
// hunk (count 0) is anchored as a single-line range at the start.
func ParseDiff(diffText string) map[string][][2]int {
	files := map[string][][2]int{}
	var current string
	haveCurrent := false
	for _, line := range splitDiffLines(diffText) {
		if m := newFileRE.FindStringSubmatch(line); m != nil {
			current = strings.TrimSpace(m[1])
			haveCurrent = true
			if _, ok := files[current]; !ok {
				files[current] = nil // setdefault: present even with no hunks
			}
			continue
		}
		if !haveCurrent {
			continue
		}
		if h := hunkRE.FindStringSubmatch(line); h != nil {
			start, _ := strconv.Atoi(h[1])
			count := 1
			if h[2] != "" {
				if n, err := strconv.Atoi(h[2]); err == nil {
					count = n
				}
			}
			if count == 0 { // pure deletion hunk; anchor at the line
				count = 1
			}
			files[current] = append(files[current], [2]int{start, start + count - 1})
		}
	}
	return files
}

// ChangedFunctions mirrors diff_seed.changed_functions: return changed Java
// functions (.java, non-test, line range overlapping a hunk), deduped by
// (file, function). When includeCallers is set and index is non-nil, also adds
// 1-hop in-repo callers of each changed function (reason="caller") — a change
// can introduce a bug reachable only via its callers. Non-existent files and
// unparseable files are silently skipped (one bad file never breaks the seed).
func ChangedFunctions(diffText, repoRoot string, extractor slice.FunctionExtractor,
	index *slice.RepositoryIndex, includeCallers bool) []ChangedFunction {
	out := []ChangedFunction{}
	seen := map[[2]string]bool{}
	for rel, hunks := range ParseDiff(diffText) {
		if !strings.HasSuffix(rel, ".java") || len(hunks) == 0 || paths.IsTestFile(rel) {
			continue // test code is never audited (parity with HE-002)
		}
		fpath := filepath.Join(repoRoot, rel)
		st, err := os.Stat(fpath)
		if err != nil || st.IsDir() {
			continue
		}
		methods, err := extractor.IterMethods(fpath)
		if err != nil {
			continue
		}
		for _, m := range methods {
			s, e := m.LineRange[0], m.LineRange[1]
			if !overlaps(s, e, hunks) {
				continue
			}
			key := [2]string{rel, m.Name}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ChangedFunction{
				File: rel, Function: m.Name, Body: m.Body,
				LineRange: m.LineRange, ClassName: m.ClassName, Reason: "changed",
			})
		}
	}

	if includeCallers && index != nil {
		// Snapshot out before iterating callers (Python `for unit in list(out)`)
		// so appending caller units does not extend the loop and double-walk.
		snapshot := append([]ChangedFunction{}, out...)
		for _, unit := range snapshot {
			for _, fd := range index.CallersOf(unit.Function) {
				key := [2]string{fd.FilePath, fd.Name}
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, ChangedFunction{
					File: fd.FilePath, Function: fd.Name, Body: fd.Body,
					LineRange: fd.LineRange, ClassName: fd.ClassName, Reason: "caller",
				})
			}
		}
	}
	return out
}

// overlaps mirrors diff_seed._overlaps: true if [s,e] intersects any range.
func overlaps(s, e int, ranges [][2]int) bool {
	for _, r := range ranges {
		if !(e < r[0] || s > r[1]) {
			return true
		}
	}
	return false
}

// splitDiffLines mirrors Python str.splitlines on \r\n / \r / \n. A trailing
// boundary does not yield a trailing empty element (matches Python semantics);
// an extra "" element is harmless here since neither regex matches it.
func splitDiffLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
