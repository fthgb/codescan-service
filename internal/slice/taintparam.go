package slice

import "strings"

// taintparam.go —— 「污点值在被调方叫什么名字」（2026-08-23）。
//
// # 为什么需要它
//
// 切片只在**入口 hop** 记 `taint_variable`（实测上传流 129 个 hop 里只有 18 个带，
// 且全是 hop0，变量全是原始 MultipartFile 句柄），而文件名中和这类事实几乎都发生在
// 下游 hop —— 于是引擎的 `HasSanitizer(方法, 变量)` 只能在「答案必然为否」的那一个
// 位置被提问，三仓实测 0/18。瓶颈不在引擎，在切片没把变量名带下去。
//
// 污点值到了被调方就是某个**形参**，而切片器在决定拉这个 callee 时
// （`ResolveCallees` 的 `argContainsAny(inv.Args, taintSet)`）已经知道是哪个实参带的污点。
// 缺的只是「实参位置 → 形参名」这一步，信息全在手上。
//
// # 三态纪律
//
// 凡有歧义 —— 多个实参带污点 / 同名调用出现多处 / 形参数量对不上 —— 一律**留空不猜**。
// 一个错的变量名会让引擎对着不相干的变量作答，比留空更糟；这与 `inferTaintVariable`
// 拒绝拿函数体正则去猜是同一条纪律（GR-8）。

// TaintParamFor 回答：被调方 fd 的哪个**形参**接住了调用方的污点。空 = 未确定。
//
// callerBody 是调用方函数体，taintVar 是调用方的污点变量（为空时按 `ResolveCallees`
// 同一口径回退成调用方全部形参名）。判定链上任一环有歧义即返回 ""。
func (r *RepositoryIndex) TaintParamFor(callerBody, taintVar string, fd FunctionDef) string {
	r.ensureBuilt()
	if callerBody == "" || fd.Body == "" {
		return ""
	}
	// 污点集：与 ResolveCallees 同口径（repoindex.go:282-290），保证「谁被拉进来」
	// 和「污点在它那儿叫什么」用的是同一个集合，不会各算各的。
	taintSet := []string{taintVar}
	if taintVar == "" {
		params, err := r.extractor.MethodParams(callerBody)
		if err != nil || len(params) == 0 {
			return ""
		}
		taintSet = make([]string, 0, len(params))
		for _, p := range params {
			taintSet = append(taintSet, p.Name)
		}
	}

	invocations, err := r.extractor.MethodInvocations(callerBody)
	if err != nil {
		return ""
	}
	// 同名调用出现多处 → 不同调用点可能传不同实参 → 无法确定是哪一个把它拉进来的 → 不猜。
	idx := -1
	hits := 0
	for _, inv := range invocations {
		if inv.Name != fd.Name {
			continue
		}
		hits++
		if hits > 1 {
			return ""
		}
		idx = taintArgIndex(inv.Args, taintSet)
	}
	if hits == 0 || idx < 0 {
		return ""
	}

	params, err := r.extractor.MethodParams(fd.Body)
	if err != nil || idx >= len(params) {
		return "" // 形参数量对不上（可变参数/解析差异）→ 不猜
	}
	name := params[idx].Name
	if !javaIdentRe.MatchString(name) {
		return ""
	}
	return name
}

// taintArgIndex 返回**唯一**带污点的顶层实参下标；零命中或多命中都返 -1（不猜）。
func taintArgIndex(args string, taintSet []string) int {
	idx := -1
	for i, a := range splitTopLevelArgs(args) {
		if !argContainsAny(a, taintSet) {
			continue
		}
		if idx >= 0 {
			return -1 // 多个实参带污点，选哪个都是猜
		}
		idx = i
	}
	return idx
}

// splitTopLevelArgs 按**顶层**逗号切实参。
//
// 嵌套调用 `f(a, g(b, c), d)`、数组初始化 `new int[]{1, 2}`、字符串/字符字面量里的逗号
// 都不是分隔符 —— 天真地 strings.Split 会把实参错位，而错位一个位置就是错一个形参名。
func splitTopLevelArgs(args string) []string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	var out []string
	depth := 0
	start := 0
	var quote byte // 0=不在字面量内，否则为 '"' 或 '\''
	for i := 0; i < len(args); i++ {
		c := args[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++ // 跳过转义的下一个字节（`"a\", b"` 不得被读成字符串结束）
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(args[start:i]))
				start = i + 1
			}
		}
	}
	if s := strings.TrimSpace(args[start:]); s != "" {
		out = append(out, s)
	}
	return out
}
