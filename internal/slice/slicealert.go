package slice

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"appsecgo/internal/contract"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// SliceAlert builds a SlicedContext by extracting function bodies for each taint
// hop. This is the BASE path (P1b-2a): hop extraction + non-Java passthrough +
// source/sink fallback + class context + control-flow mutex + degrade. The
// reverse-caller (2b), eager mapper-XML (2c), sink_param_style (2d), and argflow
// (default off) tiers are NOT here — they slot into the marked gaps. Ported from
// appsec/nodes/slicer.py:slice_alert. `index` is unused in the base path but
// kept in the signature so the tier additions don't change callers.
//
// Parity: extractor outputs are golden-verified; the orchestration logic here
// is the Go port, validated against (alert → SlicedContext) golden fixtures.
//
// Defaults mirror the Python committed config (parity baseline, design §2):
// SLICE_NON_JAVA_PASSTHROUGH=true, SLICE_NARROW_MODE=off, MAX_CONTEXT_TOKENS=30000,
// NON_JAVA_SNIPPET_RADIUS=20.

const (
	maxContextTokens       = 30000
	nonJavaSnippetRadius   = 20
	sliceNonJavaPassthrough = true
	// reverseCallerTier mirrors config.REVERSE_CALLER_TIER (default True). When
	// the SAST taint path is incomplete, pull the sink's caller chain backwards
	// so the judge can reason reachability. Off -> base path only (2a).
	reverseCallerTier = true
	// sliceSinkParamStyle mirrors config.SLICE_SINK_PARAM_STYLE (default "on").
	// When on, classify the SQL sink's ${} vs #{} binding and freeze it into
	// decisive_facts so the judge prompt sees ground truth + the contract guard
	// can reject a non-uncertain verdict on an unresolved fact. "" (None) =
	// not applicable (no MyBatis placeholder signal) -> not filled, guard no-op.
	sliceSinkParamStyle = true
	// sliceNarrowMode base is "off" -> computeNarrowHint returns nil.
)

// sourceParamPatterns mirror slicer._SOURCE_PARAM_PATTERNS. RE2 \w/\s/\b are
// ASCII-only (Java identifiers/annotations are ASCII); patterns target
// @RequestParam-style syntax, safe under CJK comments.
var sourceParamPatterns = []*regexp.Regexp{
	regexp.MustCompile(`MultipartFile\s+(\w+)`),
	regexp.MustCompile(`@(?:RequestParam|PathVariable|RequestBody|RequestPart|CookieValue|RequestHeader)\b[^\n;]*?\s+([A-Za-z_]\w*)\s*[),;]`),
}

// SliceAlert is the base slice_alert. Never returns a nil context on a well-formed
// alert; hop-extraction failures degrade to skip notes (fail-open, 铁律 D).
func SliceAlert(alert *contract.SASTResult, repoRoot string, ext FunctionExtractor, index *RepositoryIndex) (*contract.SlicedContext, error) {
	var hops []contract.HopSlice = []contract.HopSlice{}
	var sanitizers []string
	seen := map[[2]string]bool{}
	var enrichmentNote *string
	var skipReasons []map[string]any = []map[string]any{}

	for i, hop := range alert.TaintPath {
		res, ok := extractHop(hop, repoRoot, ext)
		if !ok {
			// Route B: non-.java hops pass through raw (line±N) so the judge
			// sees mapper ${} vs #{} in a single round.
			if sliceNonJavaPassthrough {
				body, start, end, snipOK := extractNonJavaSnippet(hop, repoRoot)
				if snipOK {
					file := contract.GetStr(hop, "file")
					key := [2]string{file, "<raw>"}
					if !seen[key] {
						seen[key] = true
						tl := lineOrNil(hop)
						tag := "raw_passthrough"
						hops = append(hops, contract.HopSlice{
							HopIndex: i, FilePath: file, FunctionName: "",
							FunctionBody: body, TaintVariable: inferTaintVariable(body, alert.Source),
							LineRange: [2]int{start, end}, TaintLine: tl, ExpandedFrom: &tag,
						})
					}
					continue
				}
			}
			// Drop can't be a black hole (铁律 D): record the skip reason.
			if f := contract.GetStr(hop, "file"); f != "" {
				reason := dropReason(hop, repoRoot)
				skipReasons = append(skipReasons, map[string]any{
					"file": f, "reason": reason,
				})
			}
			continue
		}
		body, start, end, funcName, taintLine := res.body, res.start, res.end, res.name, res.taintLine
		key := [2]string{contract.GetStr(hop, "file"), funcName}
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, hint := range sanitizerHints {
			if strings.Contains(strings.ToLower(body), hint) {
				sanitizers = append(sanitizers, hint)
			}
		}
		hops = append(hops, contract.HopSlice{
			HopIndex: i, FilePath: contract.GetStr(hop, "file"), FunctionName: funcName,
			FunctionBody: body, TaintVariable: inferTaintVariable(body, alert.Source),
			LineRange: [2]int{start, end}, TaintLine: taintLine,
		})
	}

	// Fallback to source/sink locations when no taint-path hops extracted.
	if len(hops) == 0 {
		for _, locKey := range []string{"source", "sink"} {
			loc := locMap(alert, locKey)
			res, ok := extractHop(loc, repoRoot, ext)
			if !ok {
				continue
			}
			key := [2]string{contract.GetStr(loc, "file"), res.name}
			if seen[key] {
				continue
			}
			seen[key] = true
			for _, hint := range sanitizerHints {
				if strings.Contains(strings.ToLower(res.body), hint) {
					sanitizers = append(sanitizers, hint)
				}
			}
			hops = append(hops, contract.HopSlice{
				HopIndex: 0, FilePath: contract.GetStr(loc, "file"), FunctionName: res.name,
				FunctionBody: res.body, TaintVariable: inferTaintVariable(res.body, alert.Source),
				LineRange: [2]int{res.start, res.end}, TaintLine: res.taintLine,
			})
		}
	}

	// (2b reverse-caller tier) — prepend the sink's caller chain when the SAST
	// taint path is incomplete so the judge can reason reachability.
	if reverseCallerTier && !alert.TaintPathComplete {
		callerHops, skipReason, truncated := reverseCallerHops(alert, ext, index)
		if len(callerHops) > 0 {
			hops = append(callerHops, hops...) // entry -> ... -> direct caller -> [existing sink hop]
			if truncated {
				note := "reverse_caller: truncated_by_node_cap (chain may have more callers)"
				enrichmentNote = &note
			}
		} else {
			note := "reverse_caller_skipped: " + skipReason
			enrichmentNote = &note
		}
	}

	// Reindex so hop_index reflects final position (after reverse prepend).
	for i := range hops {
		hops[i].HopIndex = i
	}

	// (2c eager mapper-XML tier) — ports slicer.py:751-759. DFS-walks callees,
	// appends matched mapper XML blocks + intermediate callees, dedup vs seen
	// (the existing taint-path/fallback set; mutated per append to also catch
	// intra-new_hops dups). index==nil or no .xml -> no-op.
	if eagerMapperXml && index != nil {
		eagerHops := eagerResolveMapperXml(hops, index, ext, repoRoot)
		if len(eagerHops) > 0 {
			for _, eh := range eagerHops {
				k := [2]string{eh.FilePath, eh.FunctionName}
				if !seen[k] {
					seen[k] = true
					hops = append(hops, eh)
				}
			}
			for i := range hops { // reindex#2 after eager append
				hops[i].HopIndex = i
			}
		}
	}

	srcCC := getClassContext(alert.Source, repoRoot, ext)
	sinkCC := getClassContext(alert.Sink, repoRoot, ext)

	entrySig := contract.GetStr(alert.Source, "function")
	if entrySig == "" && len(hops) > 0 {
		entrySig = hops[0].FunctionName
	}

	joined := joinBodies(hops)
	sanitizationCandidates := sortedUnique(sanitizers)
	sliced := &contract.SlicedContext{
		AlertID:              alert.AlertID,
		Bughash:              alert.Bughash,
		VulnerabilityType:    alert.VulnerabilityType,
		CweID:                alert.CweID,
		EntryPointSignature:  entrySig,
		SourceClassContext:  srcCC,
		SinkClassContext:    sinkCC,
		Hops:                hops,
		SkipReasons:         skipReasons,
		SanitizationCandidates: sanitizationCandidates,
		// Python model_dump emits [] for these base-empty fields; non-nil empty
		// slices keep JSON parity ([] not null) and reflect.DeepEqual parity.
		FrameworkAnnotations: []string{},
		Drafts:               []contract.HopDraft{},
		TokenCount:          approxTokens(joined),
		MaxConfidence:       10,
		EnrichmentNote:      enrichmentNote,
		ControlFlowMutex:    computeControlFlowMutex(alert, repoRoot, ext),
		NarrowHint:          nil, // base: SLICE_NARROW_MODE=off
		DecisiveFacts:       map[string]string{},
	}
	sliced = degradeReverseChain(sliced, maxContextTokens)
	sliced = maybeDegrade(sliced)
	// sink_param_style decisive fact (slicer.py:789-793). Reads the FINAL
	// (post-degrade) hops; "" = not applicable -> not filled, guard no-op.
	// DecisiveFacts is a non-nil empty map from the struct literal above.
	if sliceSinkParamStyle {
		if style := classifySinkParamStyle(sliced); style != "" {
			sliced.DecisiveFacts["sink_param_style"] = style
		}
	}
	return sliced, nil
}

// reverseCallerHops ports slicer._reverse_caller_hops: build caller-chain hops
// from the sink backwards (entry->sink order) via RepositoryIndex.CallersOfTransitive.
// Returns (hops, skipReason, truncated). Never panics — Go's CallersOfTransitive
// can't throw, so the Python "exception" skip reason is unreachable here.
// skipReason is "" when callers were found, else "no_index"|"missing_callee".
func reverseCallerHops(alert *contract.SASTResult, _ FunctionExtractor, index *RepositoryIndex) ([]contract.HopSlice, string, bool) {
	if index == nil {
		return nil, "no_index", false
	}
	sinkFn := contract.GetStr(alert.Sink, "function")
	if sinkFn == "" {
		return nil, "missing_callee", false
	}
	chain := index.CallersOfTransitive(sinkFn, 5, 15)
	if len(chain.Defs) == 0 {
		return nil, "missing_callee", chain.Truncated
	}
	hops := make([]contract.HopSlice, 0, len(chain.Defs))
	tag := "reverse_caller"
	for _, fd := range chain.Defs { // already entry->sink order from CallersOfTransitive
		hops = append(hops, contract.HopSlice{
			HopIndex: 0, // placeholder; SliceAlert reindexes after prepend
			FilePath: fd.FilePath, FunctionName: fd.Name, FunctionBody: fd.Body,
			TaintVariable: "", LineRange: fd.LineRange, ExpandedFrom: &tag,
		})
	}
	return hops, "", chain.Truncated
}

type hopResult struct {
	body      string
	start     int
	end       int
	name      string
	taintLine *int
}

// extractHop: name-based lookup, fall back to line-based. ok=false when the hop
// can't be sliced (file missing / no function / no line).
func extractHop(hop map[string]any, repoRoot string, ext FunctionExtractor) (hopResult, bool) {
	file := contract.GetStr(hop, "file")
	if file == "" {
		return hopResult{}, false
	}
	fpath := filepath.Join(repoRoot, file)
	if _, err := os.Stat(fpath); err != nil {
		return hopResult{}, false
	}
	taintLine := lineOrNil(hop)
	fname := contract.GetStr(hop, "function")
	if fname != "" {
		body, start, end, ok, err := ext.Extract(fpath, fname)
		if err == nil && ok {
			return hopResult{body, start, end, fname, taintLine}, true
		}
	}
	line := contract.GetInt(hop, "line")
	if line != 0 {
		body, start, end, name, ok, err := ext.ExtractByLine(fpath, line)
		if err == nil && ok {
			return hopResult{body, start, end, name, taintLine}, true
		}
		return hopResult{}, false
	}
	return hopResult{}, false
}

// extractNonJavaSnippet: Route B — non-.java hop raw passthrough (line±N).
func extractNonJavaSnippet(hop map[string]any, repoRoot string) (body string, start, end int, ok bool) {
	f := contract.GetStr(hop, "file")
	if strings.HasSuffix(f, ".java") || f == "" {
		return "", 0, 0, false
	}
	line := contract.GetInt(hop, "line")
	if line == 0 {
		return "", 0, 0, false
	}
	fpath := filepath.Join(repoRoot, f)
	raw, err := os.ReadFile(fpath)
	if err != nil {
		return "", 0, 0, false
	}
	text := decodeSource(raw)
	lines := strings.Split(text, "\n")
	// Python splitlines() splits on more line boundaries than "\n" (e.g. \r\n,
	// \v, \f,  ...). For parity on typical CRLF/Java files, emulate
	// splitlines by splitting on \n then stripping a trailing \r per line.
	for i, ln := range lines {
		lines[i] = strings.TrimSuffix(ln, "\r")
	}
	// splitlines does NOT emit a trailing empty element when the text ends with
	// a newline; strings.Split("\n") keeps one. Drop it so len(lines) and the
	// window end match Python (a final "\n" was inflating the .xml passthrough
	// hop's line_range end by 1 and adding a trailing "\n" to the body — 2d
	// sinkstyle_concat_xml fixture). \v/\f/other Unicode boundaries still differ
	// (not a realistic case for source files; same asymmetry as 2a).
	if endsInNewline(text) && len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	start = max2(1, line-nonJavaSnippetRadius)
	end = min2(len(lines), line+nonJavaSnippetRadius)
	if start > end || start > len(lines) {
		return "", 0, 0, false
	}
	body = strings.Join(lines[start-1:end], "\n")
	if strings.TrimSpace(body) == "" {
		return "", 0, 0, false
	}
	return body, start, end, true
}

func getClassContext(loc map[string]any, repoRoot string, ext FunctionExtractor) *contract.ClassContext {
	file := contract.GetStr(loc, "file")
	if file == "" {
		return nil
	}
	fpath := filepath.Join(repoRoot, file)
	if _, err := os.Stat(fpath); err != nil {
		return nil
	}
	fname := contract.GetStr(loc, "function")
	if fname != "" {
		cc, ok, err := ext.ClassContext(fpath, fname)
		if err == nil && ok {
			return cc
		}
		return nil
	}
	line := contract.GetInt(loc, "line")
	if line != 0 {
		cc, ok, err := ext.ClassContextByLine(fpath, line)
		if err == nil && ok {
			return cc
		}
	}
	return nil
}

func computeControlFlowMutex(alert *contract.SASTResult, repoRoot string, ext FunctionExtractor) bool {
	src, snk := alert.Source, alert.Sink
	if contract.GetStr(src, "file") == "" || contract.GetStr(src, "file") != contract.GetStr(snk, "file") {
		return false
	}
	if contract.GetInt(src, "line") == 0 || contract.GetInt(snk, "line") == 0 {
		return false
	}
	fpath := filepath.Join(repoRoot, contract.GetStr(src, "file"))
	if _, err := os.Stat(fpath); err != nil {
		return false
	}
	mutex, err := ext.ControlFlowMutex(fpath, contract.GetInt(src, "line"), contract.GetInt(snk, "line"))
	if err != nil {
		return false
	}
	return mutex
}

func dropReason(hop map[string]any, repoRoot string) string {
	f := contract.GetStr(hop, "file")
	if !strings.HasSuffix(f, ".java") {
		return "non_java"
	}
	if _, err := os.Stat(filepath.Join(repoRoot, f)); err != nil {
		return "file_not_found"
	}
	return "no_function"
}

// javaIdentRe —— Java 标识符。`taint_variable` 是**变量名**，不是描述。
//
// SAST(codesafe) 的 `variable` 字段有时给的是一句中文叙述（「来自于http请求的数据从
// getListWithStock()方法的第10个参数流入」）。全部 1229 条 trace 里 223 条(18%) 因此
// 在入口 hop 存着一句话。活体的 11 个合法取值全是纯标识符，故这道门不误杀。
//
// 该值不止喂切片：还流进 prompt(messages.go:427 / falsify.go:65) 与 verifier 的
// hopTaintVariables（Crack C strong_type_param 相关性回退的「本案真污点源变量集合」）。
// 故在此**入口边界**一处挡下，不让每个消费方各自防御（铁律 A）。
var javaIdentRe = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

func inferTaintVariable(body string, source map[string]any) string {
	if v := contract.GetStr(source, "variable"); v != "" {
		if javaIdentRe.MatchString(v) {
			return v
		}
		// SAST 给了值但不可用 —— **留空，不猜**（GR-8）。
		//
		// 首版让它继续走下面的函数体正则，活体重切当场证伪：那些正则取的是函数体里
		// **第一个** @RequestParam 式参数，未必是带污点的那个。rt 的上传告警因此拿到
		// `bizId` —— 正是 verifier(helpers.go:97) 明写「不属 uploadFile 污点路径」的那个
		// 参数；ceshi 拿到 `currentPage`。用一个**错的**变量名比留空更糟：留空会让
		// repoindex.go:283 把污点集回退成「入口方法全部形参」，错名则把它钉死在一个
		// 不相干的变量上。
		//
		// SAST 什么都没给时仍走下面的正则 —— 那是既有行为，与本门无关。
		return ""
	}
	for _, pat := range sourceParamPatterns {
		if m := pat.FindStringSubmatch(body); m != nil {
			return m[1]
		}
	}
	return ""
}

func approxTokens(text string) int {
	// Python len(str) counts Unicode CODE POINTS, not bytes — a Go len(string)
	// is the byte length, which inflates token_count on CJK bodies (3 bytes per
	// Han char) and breaks parity. Use the rune count to match Python.
	n := utf8.RuneCountInString(text) / 4
	if n < 1 {
		return 1
	}
	return n
}

// maybeDegrade caps max_confidence at 7 when context exceeds the token budget,
// keeping critical hops (first/last/sanitizer-containing).
func maybeDegrade(s *contract.SlicedContext) *contract.SlicedContext {
	if s.TokenCount <= maxContextTokens || len(s.Hops) == 0 {
		return s
	}
	last := len(s.Hops) - 1
	var critical []contract.HopSlice
	for _, h := range s.Hops {
		if h.HopIndex == 0 || h.HopIndex == last {
			critical = append(critical, h)
			continue
		}
		bodyLow := strings.ToLower(h.FunctionBody)
		for _, s2 := range s.SanitizationCandidates {
			if strings.Contains(bodyLow, s2) {
				critical = append(critical, h)
				break
			}
		}
	}
	s.Hops = critical
	s.Degraded = true
	s.MaxConfidence = 7
	return s
}

// degradeReverseChain is a no-op in the base (no reverse_caller hops). Ported
// faithfully for 2b — keeps entry + direct caller, elides middle reverse hops.
func degradeReverseChain(s *contract.SlicedContext, budgetTokens int) *contract.SlicedContext {
	var reverseIdx []int
	for i, h := range s.Hops {
		if h.ExpandedFrom != nil && *h.ExpandedFrom == "reverse_caller" {
			reverseIdx = append(reverseIdx, i)
		}
	}
	if len(reverseIdx) <= 3 || s.TokenCount <= budgetTokens {
		return s
	}
	keep := map[int]bool{reverseIdx[0]: true, reverseIdx[len(reverseIdx)-1]: true}
	for _, i := range reverseIdx {
		if keep[i] {
			continue
		}
		h := s.Hops[i]
		// Python: f"# {name} (body elided; see {file_path}:{line_range[0]})"
		body := "# " + h.FunctionName + " (body elided; see " + h.FilePath + ":" + strconv.Itoa(h.LineRange[0]) + ")"
		s.Hops[i].FunctionBody = body
	}
	s.Degraded = true
	s.TokenCount = approxTokens(joinBodies(s.Hops))
	note := "reverse caller chain degraded: middle hops elided (entry + direct caller + sink kept)"
	if s.EnrichmentNote == nil {
		s.EnrichmentNote = &note
	} else {
		combined := *s.EnrichmentNote + "; " + note
		s.EnrichmentNote = &combined
	}
	return s
}

func lineOrNil(hop map[string]any) *int {
	l := contract.GetInt(hop, "line")
	if l == 0 {
		return nil
	}
	return &l
}

func locMap(alert *contract.SASTResult, key string) map[string]any {
	if key == "source" {
		return alert.Source
	}
	return alert.Sink
}

func joinBodies(hops []contract.HopSlice) string {
	parts := make([]string, len(hops))
	for i, h := range hops {
		parts[i] = h.FunctionBody
	}
	return strings.Join(parts, "\n")
}

func sortedUnique(in []string) []string {
	// Non-nil even when empty — Python model_dump emits [] for an empty
	// sanitization_candidates list; a nil Go slice marshals to null and breaks
	// field-for-field parity.
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// Python sorted(set(...)) — sort for stable parity output.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// decodeSource mirrors slicer._detect_encoding + decode(errors="replace"):
// utf-8 if valid; else gb18030 (strict-detected: only if no U+FFFD replacement);
// else latin-1 (every byte a rune).
func decodeSource(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	// Try gb18030 strict: decode, accept only if no U+FFFD was produced.
	decoded, err := simplifiedchinese.GB18030.NewDecoder().Bytes(raw)
	if err == nil && !bytes.Contains(decoded, bomFFFD) {
		return string(decoded)
	}
	// latin-1 fallback.
	out := make([]rune, 0, len(raw))
	for _, b := range raw {
		out = append(out, rune(b))
	}
	return string(out)
}

var bomFFFD = []byte{0xEF, 0xBF, 0xBD}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// endsInNewline reports whether text ends with a \n (LF or CRLF — both end in
// \n). Used to emulate Python splitlines, which does not emit a trailing empty
// element for a final newline.
func endsInNewline(text string) bool {
	return strings.HasSuffix(text, "\n")
}
