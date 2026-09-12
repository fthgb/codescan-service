package slice

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// sanitizerHints mirrors slicer._SANITIZER_HINTS: substring match (case-insensitive)
// on a callee name to flag it as a sanitizer/validator candidate.
var sanitizerHints = []string{
	"sanitize", "filter", "escape", "validate",
	"encode", "clean", "safe", "check",
}

// noiseCallees mirrors index._NOISE_CALLEES: callees so common they are noise, not
// security-relevant helpers worth inlining.
var noiseCallees = map[string]bool{
	"toString": true, "equals": true, "hashCode": true, "valueOf": true,
	"get": true, "set": true, "size": true, "length": true,
	"isEmpty": true, "add": true, "put": true, "append": true,
	"format": true, "println": true, "print": true,
}

// stripSig mirrors index._strip_sig: drop the "(args)" suffix from a signature-bearing
// name -> "sanitizePath(String)" becomes "sanitizePath".
func stripSig(name string) string {
	if i := strings.Index(name, "("); i >= 0 {
		return name[:i]
	}
	return name
}

// bareName mirrors index._bare_name: normalize a possibly qualified / signature-bearing
// callee name to the bare method identifier the callers map is keyed by.
// "B.target" / "target(int)" / "a$b.c" -> "c".
func bareName(name string) string {
	s := stripSig(name)
	for _, sep := range []string{".", "$"} {
		if i := strings.LastIndex(s, sep); i >= 0 {
			s = s[i+len(sep):]
		}
	}
	return strings.TrimSpace(s)
}

func isSanitizerName(name string) bool {
	low := strings.ToLower(name)
	for _, h := range sanitizerHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// argContainsVar mirrors index._arg_contains_var: true if var appears as a whole
// identifier in the argument list. RE2 \b is ASCII-word-boundary (Java identifiers
// are ASCII) — safe for the arg-text use here.
// argContainsAny is true if any var in set appears as a whole identifier in args.
// Empty set (and empty strings within) never match. When taintVar != "" the
// caller passes [taintVar] (byte-identical to argContainsVar); when taintVar
// == "" the caller passes the entry-method formal param names as the fallback
// taint set (tightened α).
func argContainsAny(args string, set []string) bool {
	for _, v := range set {
		if argContainsVar(args, v) {
			return true
		}
	}
	return false
}

func argContainsVar(args, v string) bool {
	if v == "" {
		return false
	}
	re, err := regexp.Compile(`\b` + regexp.QuoteMeta(v) + `\b`)
	if err != nil {
		return false
	}
	return re.MatchString(args)
}

// FunctionDef mirrors index.FunctionDef: an in-repo function definition. FilePath is
// repo-relative, forward slashes.
type FunctionDef struct {
	Name      string
	FilePath  string
	Body      string
	LineRange [2]int
	ClassName *string
}

// TransitiveCallers mirrors index.TransitiveCallers: the reverse caller chain
// (entry->sink order) + whether the node cap truncated it.
type TransitiveCallers struct {
	Defs      []FunctionDef
	Truncated bool
}

// RepositoryIndex lazily indexes every method in a repo by name and resolves
// in-repo callees. Pure source analysis, SAST-agnostic. Ported from
// appsec/index.py over the FunctionExtractor seam.
type RepositoryIndex struct {
	repoRoot  string
	extractor FunctionExtractor
	byName    map[string][]FunctionDef
	callers   map[string][]FunctionDef
	classes   map[string]bool
	built     bool
}

// NewRepositoryIndex constructs an index; call Build (or let the first lookup
// build lazily) to populate it.
func NewRepositoryIndex(repoRoot string, extractor FunctionExtractor) *RepositoryIndex {
	return &RepositoryIndex{
		repoRoot:  repoRoot,
		extractor: extractor,
		byName:    nil,
		callers:   map[string][]FunctionDef{},
	}
}

// RepoRoot is the repo root for path-scoped raw reads (mapper XML, etc.).
func (r *RepositoryIndex) RepoRoot() string { return r.repoRoot }

// ClassDeclared reports whether a class/interface/enum/record named cn has at
// least one indexed method in the repo (B2: callee param types absent from the
// repo are annotated as unavailable to the judge). Field-only DTOs with no
// methods yield false here even when present — conservative (over-annotates,
// never under-annotates an absent type).
func (r *RepositoryIndex) ClassDeclared(cn string) bool {
	r.ensureBuilt()
	return r.classes[cn]
}

// ClassFieldsFor returns the enclosing type body's field_declaration direct
// children text for the named method (repo-relative file, forward slashes —
// mirrored on getClassContext slicealert.go:338: filepath.Join(repoRoot, file)
// → abs path → extractor.ClassFields). v1.7 spec §3.3 Path B1: feeds the
// reachability var→type map so a class-field receiver resolves to its
// declared type. ok=false on absent method / parse error / empty name or file
// (fail-safe: reachability treats miss as no-op keep, v1.5 behavior unchanged).
// Does NOT touch HopSlice/MethodInfo → no golden impact (class_fields never
// serialized into hop JSON).
func (r *RepositoryIndex) ClassFieldsFor(file, name string) (string, bool) {
	r.ensureBuilt()
	if file == "" || name == "" {
		return "", false
	}
	fpath := filepath.Join(r.repoRoot, file)
	cf, ok, err := r.extractor.ClassFields(fpath, name)
	if err != nil || !ok {
		return "", false
	}
	return cf, true
}

// Build walks the repo's .java files and populates the name->defs and
// reverse-caller maps. One unparseable file never breaks the whole index.
func (r *RepositoryIndex) Build() {
	byName := map[string][]FunctionDef{}
	callers := map[string][]FunctionDef{}
	classes := map[string]bool{}
	_ = filepath.Walk(r.repoRoot, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".java") {
			return nil
		}
		rel, err := filepath.Rel(r.repoRoot, fpath)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		methods, err := r.extractor.IterMethods(fpath)
		if err != nil {
			return nil // never let one unparseable file break the index
		}
		for _, m := range methods {
			fd := FunctionDef{
				Name: m.Name, FilePath: rel, Body: m.Body,
				LineRange: m.LineRange, ClassName: m.ClassName,
			}
			byName[fd.Name] = append(byName[fd.Name], fd)
			if fd.ClassName != nil {
				classes[*fd.ClassName] = true
			}
			// Reverse edge: every callee in fd's body has fd as a caller.
			invocations, err := r.extractor.MethodInvocations(fd.Body)
			if err != nil {
				continue
			}
			for _, inv := range invocations {
				k := stripSig(inv.Name)
				callers[k] = append(callers[k], fd)
			}
		}
		return nil
	})
	r.byName = byName
	r.callers = callers
	r.classes = classes
	r.built = true
}

func (r *RepositoryIndex) ensureBuilt() {
	if !r.built {
		r.Build()
	}
}

// EnsureBuild builds the index eagerly so parallel fan-out workers don't race on
// the lazy first build.
func (r *RepositoryIndex) EnsureBuilt() *RepositoryIndex {
	r.ensureBuilt()
	return r
}

// Resolve returns all in-repo definitions matching a (possibly signature-bearing)
// name.
func (r *RepositoryIndex) Resolve(name string) []FunctionDef {
	r.ensureBuilt()
	return append([]FunctionDef(nil), r.byName[stripSig(name)]...)
}

// CallersOf returns in-repo functions that call name (1-hop reverse), deduped by
// (file, function). name is bareName-normalized so a qualified/signature-bearing
// sink.function still matches.
func (r *RepositoryIndex) CallersOf(name string) []FunctionDef {
	r.ensureBuilt()
	out := []FunctionDef{}
	seen := map[[2]string]bool{}
	for _, fd := range r.callers[bareName(name)] {
		k := [2]string{fd.FilePath, fd.Name}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, fd)
	}
	return out
}

// CallersOfTransitive is a reverse BFS from name's callers up to maxDepth,
// bounded by maxNodes. Returns entry->sink order (sink's direct callers nearest
// the sink end of the list). Cycle-safe (visited by (file, name)); node-capped
// with a truncated flag. name is bareName-normalized.
func (r *RepositoryIndex) CallersOfTransitive(name string, maxDepth, maxNodes int) TransitiveCallers {
	r.ensureBuilt()
	if maxDepth < 0 {
		maxDepth = 5
	}
	if maxNodes <= 0 {
		maxNodes = 15
	}
	visited := map[[2]string]bool{}
	ordered := []FunctionDef{} // direct callers first, then their callers...
	frontier := []string{bareName(name)}
	truncated := false
	for depth := 0; depth < maxDepth; depth++ {
		var nextFrontier []string
		for _, calleeName := range frontier {
			for _, fd := range r.callers[calleeName] {
				k := [2]string{fd.FilePath, fd.Name}
				if visited[k] {
					continue
				}
				visited[k] = true
				ordered = append(ordered, fd)
				nextFrontier = append(nextFrontier, bareName(fd.Name))
				if len(ordered) >= maxNodes {
					return TransitiveCallers{Defs: reverseDefs(ordered), Truncated: true}
				}
			}
		}
		if len(nextFrontier) == 0 {
			break
		}
		frontier = nextFrontier
	}
	return TransitiveCallers{Defs: reverseDefs(ordered), Truncated: truncated}
}

// ResolveCallees returns the targeted in-repo functions called within body:
// sanitizer-named callees OR callees receiving the tainted variable as an
// argument. Sanitizer-named come first (decisive FP evidence). External/noise/
// excluded calls and the function itself are skipped.
func (r *RepositoryIndex) ResolveCallees(body, taintVar string, exclude []string) []FunctionDef {
	r.ensureBuilt()
	excl := map[string]bool{}
	for _, e := range exclude {
		excl[stripSig(e)] = true
	}
	// Tightened α: when taintVar is empty (SAST gave no taint var, common for
	// CWE-915 framework-binding where the taint is the bound param object),
	// fall back to the entry method's declared formal param names as the
	// default taint set, so cross-class callees that receive an entry param
	// are pulled. When taintVar != "" the set is [taintVar] -> byte-identical
	// to the prior argContainsVar(args, taintVar) behavior.
	taintSet := []string{taintVar}
	if taintVar == "" {
		if params, err := r.extractor.MethodParams(body); err == nil && len(params) > 0 {
			taintSet = make([]string, 0, len(params))
			for _, p := range params {
				taintSet = append(taintSet, p.Name)
			}
		}
	}
	var sanitizerHits, taintHits []FunctionDef
	seen := map[[2]string]bool{}
	invocations, err := r.extractor.MethodInvocations(body)
	if err != nil {
		return nil
	}
	for _, inv := range invocations {
		name := inv.Name
		if noiseCallees[name] || excl[stripSig(name)] {
			continue
		}
		byName := isSanitizerName(name)
		byTaint := argContainsAny(inv.Args, taintSet) // was argContainsVar(inv.Args, taintVar)
		if !byName && !byTaint {
			continue
		}
		for _, fd := range r.resolveWithReceiver(name, inv.Receiver) {
			k := [2]string{fd.FilePath, fd.Name}
			if seen[k] {
				continue
			}
			seen[k] = true
			if byName {
				sanitizerHits = append(sanitizerHits, fd)
			} else {
				taintHits = append(taintHits, fd)
			}
		}
	}
	return append(sanitizerHits, taintHits...)
}

// resolveWithReceiver resolves a callee, disambiguating overloaded names by
// receiver class when a qualified call lets us. Case-insensitive class match
// (EqualFold) — (δ) fix: Java convention names the receiver var after its type
// (lowercase var `proposalComponent` vs ClassName `ProposalComponent`), so the
// prior exact-case `==` never matched instance calls ⇒ flood (`return defs`, :373;
// F7:
// wrong-class hops spliced, A17 FP / B19 FN). Narrowing to the ci-matching
// subset when the convention holds clears the flood (GR-5: deviates from the
// Python mirror's exact-case `_resolve_with_receiver` to fix verdict FP floods;
// the eager ResolveMapperXml tier keeps its own ci at eagermapperxml.go).
// NO nil-fallback: ci-match==0 still returns all defs (flood unchanged) — a nil
// fallback (α) was net-negative: it cuts legit inherited callees (the def's
// ClassName is the defining base, not the receiver's subtype) ⇒ FN. See
// docs/superpowers/plans/2026-09-04-f7-hop-splice-same-name-method-resolution-impl-plan.md §2.0.
// Callers: ResolveCallees (:329), ResolveCalleesTransitive (:530, flood path),
// ResolvableCallees (:572).
func (r *RepositoryIndex) resolveWithReceiver(name, receiver string) []FunctionDef {
	defs := r.Resolve(name)
	if receiver != "" && len(defs) > 1 {
		var byClass []FunctionDef
		for _, d := range defs {
			if d.ClassName != nil && strings.EqualFold(*d.ClassName, receiver) {
				byClass = append(byClass, d)
			}
		}
		if len(byClass) > 0 {
			return byClass
		}
	}
	return defs
}

// CalleeGate is the strategy boundary (铁律 D 抗绑定) deciding whether a callee
// invocation is pulled into the slice. The forward walker only recurses; the gate
// only decides pull; the CWE registry only selects the gate — three orthogonal.
// P1 transitive is wired for StateMutatingGate (missing-auth: harm = unauth entry
// reaching a state-mutating action, no taint propagation needed). TaintGate
// transitive needs real dataflow (which var is tainted per level) — deferred §8.5.
type CalleeGate interface {
	Pull(inv InvocationInfo, taintSet []string) bool
}

// TaintGate replicates ResolveCallees' single-level decision: sanitizer-named OR
// taint-arg. depth=1 + TaintGate == byte-identical to ResolveCallees (zero-regression
// guard). Var=="" triggers the tightened-α fallback (entry formal param names).
type TaintGate struct {
	Var string
}

func (g TaintGate) Pull(inv InvocationInfo, taintSet []string) bool {
	return isSanitizerName(inv.Name) || argContainsAny(inv.Args, taintSet)
}

// stateMutatingVerbs — callee names containing these verbs are state-mutating.
// missing-auth (CWE-862) harm is not "taint reached sink" but "unauth entry
// reached a state-mutating action", so the gate matches verbs, not taint.
// P1 inlined const (待外置到 cwe_registry，§8.3；项目/框架定制时再提 JSON)。
var stateMutatingVerbs = []string{
	"cancel", "delete", "remove", "revoke", "update", "insert",
	"save", "persist", "submit", "commit", "drop", "truncate",
}
// F6 §1.5(2026-09-03,mechanism C 修):补 `persist`——JPA/repository 规范写动词
// (proposalRespository.persist 等),原 verb-list 遗漏致 StateMutatingGate.Pull
// 拒写 sink(repoindex.go:517,resolveWithReceiver 之前)⇒ underwrite problem #4
// 5 persist-链漏杀(dump_f6_p4_test.go §3.1 probe 实据)。tier-2(reversible,同
// save/insert)。corpus probe(TestDump_F6_P4_CorpusWriteVerbsGateRejected)验:
// 10 persist-substring write-performer 名被 substring 覆尽(含 5 miss sink);
// 假阳 collateral=2 非-write persist 名(orderPersistForSubmit/persistenceFactor,
// 1-def,R2-step2 bodyWriteSignal rank0 排出 top-5 prompt)。GR-1 + frozen baseline
// scoped 重冻为安全门(spec §1.5)。56 非-persist write-performer 仍 gate-rejected
// ⇒ 通用 gate 完备是点修;body-write-signal gate 别 spec(gated on GR-9 验 56 真 miss)。

// stateMutatingTier ranks state-mutating verbs by reversibility (GR-7 治类:
// real-data 3de4b5c0 验证发现 updateTask 在 8 文件同名碰撞——receiver 字段名
// taskRepository 不匹配 class TaskRepository（§8.4 field→type 解析 deferred）→
// resolveWithReceiver 退全同名 def → 24 节点泛淹，MaxEnrichHops cap 把真 sink
// cancelTask（irreversible，tier-1）截掉。tier 分级 + severe-first 排序让
// irreversible（cancel/delete/remove/revoke/drop/truncate）在 cap 前置位存活。
// tier 0=非改状态；1=irreversible；2=reversible。§8.3 specificity 的 P1 子集。
var stateMutatingTier1 = map[string]bool{
	"cancel": true, "delete": true, "remove": true, "revoke": true,
	"drop": true, "truncate": true,
}

func isStateMutatingName(name string) bool {
	return stateMutatingTier(name) > 0
}

// stateMutatingTier returns 0 (not state-mutating), 1 (irreversible), or 2 (reversible).
func stateMutatingTier(name string) int {
	low := strings.ToLower(name)
	for v := range stateMutatingTier1 {
		if strings.Contains(low, v) {
			return 1
		}
	}
	for _, v := range stateMutatingVerbs {
		if stateMutatingTier1[v] {
			continue
		}
		if strings.Contains(low, v) {
			return 2
		}
	}
	return 0
}

// bodyWriteSignal 报 callee body 是否含强 DB 写原语（R2 第二步，OrderController:103
// gap 修法；spec docs/superpowers/specs/2026-08-28-r2-step2-body-write-signal-rank-design.md）。
// 仅 transactionTemplate.execute（programmatic transaction 拥有者，含 executeWithoutResult）
// + *Tunnel.insert|update|delete（直接写原语）。排除 *Repository.update 等弱信号——
// 3de4b5c0 updateTask-noise 4/7 命中 repository.update → 泛淹 rank0 会位移 cancelTask
// （spec §3.1 证伪了 §0.1 的 broad pattern）。铁律 C：判 sink 真伪靠 body 真写事务，非
// sink 名（cancel/update 名皆可真可假）。case-insensitive（与 stateMutatingTier 一致）。
func bodyWriteSignal(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "transactiontemplate.execute") {
		return true
	}
	for _, v := range []string{"tunnel.insert", "tunnel.update", "tunnel.delete"} {
		if strings.Contains(low, v) {
			return true
		}
	}
	return false
}

// StateMutatingGate pulls callees whose names match a state-mutating verb or a
// sanitizer hint (decisive FP evidence retained), regardless of taint args.
type StateMutatingGate struct{}

func (StateMutatingGate) Pull(inv InvocationInfo, _ []string) bool {
	return isStateMutatingName(inv.Name) || isSanitizerName(inv.Name)
}

// entryTaintSet builds the entry's taint set for a gate (called once per walk).
// TaintGate: [Var] when Var != "" (byte-identical to ResolveCallees), else
// tightened-α formal-param fallback. StateMutatingGate: nil (unused).
func (r *RepositoryIndex) entryTaintSet(body string, gate CalleeGate) []string {
	g, ok := gate.(TaintGate)
	if !ok {
		return nil // StateMutatingGate etc. — no taint propagation
	}
	if g.Var != "" {
		return []string{g.Var}
	}
	if params, err := r.extractor.MethodParams(body); err == nil && len(params) > 0 {
		s := make([]string, 0, len(params))
		for _, p := range params {
			s = append(s, p.Name)
		}
		return s
	}
	return nil
}

// ResolveCalleesTransitive — forward BFS callee walk mirroring the reverse
// CallersOfTransitive (repoindex.go:230). Recurses into each pulled callee's
// Body up to `depth`, cycle-safe (seen by (file,name)), node-capped with a
// truncated flag (GR-8: omission must be signaled, never silent).
//
// Unlike ResolveCallees (depth-1, sanitizer-first ordering), this returns pulled
// callees in walk order (invocation-then-BFS) — callers not depending on order.
// gate decides pull at each invocation; taintSet is the entry taint set passed
// to gate (StateMutatingGate ignores it). Returns pulled FunctionDefs excluding
// the entry's own def, deduped.
func (r *RepositoryIndex) ResolveCalleesTransitive(entryBody string, depth int, gate CalleeGate, exclude []string) (pulled []FunctionDef, truncated bool) {
	r.ensureBuilt()
	if gate == nil {
		gate = TaintGate{}
	}
	if depth < 1 {
		depth = 1
	}
	excl := map[string]bool{}
	for _, e := range exclude {
		excl[stripSig(e)] = true
	}
	taintSet := r.entryTaintSet(entryBody, gate)
	seen := map[[2]string]bool{}
	const maxNodes = 24 // node cap — truncated signaling (GR-8 不静默省略)
	frontier := []string{entryBody}
	for d := 0; d < depth; d++ {
		var nextFrontier []string
		for _, body := range frontier {
			invocations, err := r.extractor.MethodInvocations(body)
			if err != nil {
				continue
			}
			for _, inv := range invocations {
				name := inv.Name
				if noiseCallees[name] || excl[stripSig(name)] {
					continue
				}
				if !gate.Pull(inv, taintSet) {
					continue
				}
				for _, fd := range r.resolveWithReceiver(name, inv.Receiver) {
					k := [2]string{fd.FilePath, fd.Name}
					if seen[k] {
						continue
					}
					seen[k] = true
					pulled = append(pulled, fd)
					if fd.Body != "" {
						nextFrontier = append(nextFrontier, fd.Body)
					}
					if len(pulled) >= maxNodes {
						return pulled, true
					}
				}
			}
		}
		if len(nextFrontier) == 0 {
			break
		}
		frontier = nextFrontier
	}
	return pulled, false
}

// ResolvableCallees returns the in-repo functions called within body
// (i.e. resolvable here), as resolved FunctionDefs deduped by (file, name).
// Used to flag callees referenced but not pulled into the slice — keyed by
// (file, name) so a same-name cross-class callee is not masked by an
// entry hop that shares its name (defect-2 fix).
func (r *RepositoryIndex) ResolvableCallees(body string) []FunctionDef {
	r.ensureBuilt()
	seen := map[[2]string]bool{}
	out := []FunctionDef{} // non-nil
	invocations, err := r.extractor.MethodInvocations(body)
	if err != nil {
		return nil
	}
	for _, inv := range invocations {
		nm := stripSig(inv.Name)
		if noiseCallees[nm] {
			continue
		}
		for _, fd := range r.resolveWithReceiver(inv.Name, inv.Receiver) {
			k := [2]string{fd.FilePath, fd.Name}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, fd)
		}
	}
	return out
}

func reverseDefs(in []FunctionDef) []FunctionDef {
	out := make([]FunctionDef, len(in))
	for i, d := range in {
		out[len(in)-1-i] = d
	}
	return out
}
