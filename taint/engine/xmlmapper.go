package engine

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ============================================================
//  R10: MyBatis XML mapper 解析（独立于 Java 注解式）
//  MyBatis 的 SQL 也可定义在 resources 下的 *.xml 中：
//    <mapper namespace="com.example.UserMapper">
//      <select id="findByDynamic" ...>
//        SELECT * FROM t WHERE name = ${name}
//      </select>
//  其中 ${...} 为危险直接拼接（SQL 注入），#{...} 为安全预编译占位。
//  解析层把每个 statement 的 SQL 存入 store.XmlMappers，key 双向：
//    namespace.id（全限定，如 com.example.UserMapper.findByDynamic）
//    shortClass.id（短类名，如 UserMapper.findByDynamic，与调用图 Mapper 接口方法键对齐）
//  供 query.go 的 sink 判定层消费（直接边命中 Mapper 接口方法时查此索引）。
// ============================================================

var (
	reMapperOpen = regexp.MustCompile(`(?is)<mapper\b[^>]*\bnamespace\s*=\s*["']([^"']+)["']`)
	// 开标签：<select|insert|update|delete ... id="...">  （RE2 不支持反向引用，故分两步取块）
	reStmtOpen     = regexp.MustCompile(`(?is)<(select|insert|update|delete)\b[^>]*\bid\s*=\s*["']([^"']+)["'][^>]*>`)
	reXmlSQLConcat = regexp.MustCompile(`\$\{([^}]*)\}`) // 危险：${...} 直接拼接(捕获组 1=参数名,供 MapperSqlInfo 抽取)
	reXmlSQLParam  = regexp.MustCompile(`#\{([^}]*)\}`)  // 安全：#{...} 预编译占位(捕获组 1=参数名,供 MapperSqlInfo 抽取)
)

// extractXmlParams 从 SQL 文本抽取 ${param}/#{param} 参数名列表。
// 供 MapperSqlInfo 富化 reachable_sinks(ConcatParams=危险拼接参数,SafeParams=参数化参数)。
// 双 key 查找已保证命中的是真实 mapper statement,此处只做参数名抽取(不判 sink)。
func extractXmlParams(sql string) (concatParams, safeParams []string) {
	for _, m := range reXmlSQLConcat.FindAllStringSubmatch(sql, -1) {
		concatParams = append(concatParams, m[1])
	}
	for _, m := range reXmlSQLParam.FindAllStringSubmatch(sql, -1) {
		safeParams = append(safeParams, m[1])
	}
	return
}

// parseXmlMappers 遍历仓库下所有 *.xml，提取 MyBatis mapper statement 写入 store.XmlMappers。
func (a *JavaRepoAnalyzer) parseXmlMappers() {
	if a.repoRoot == "" || a.store == nil {
		return
	}
	count := 0
	_ = filepath.Walk(a.repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".xml") {
			return nil
		}
		data, e := ioutil.ReadFile(path)
		if e != nil {
			return nil
		}
		count += extractXmlMappers(a.store, path, string(data))
		return nil
	})
	if count > 0 {
		fmt.Fprintf(os.Stderr, "[XMLMAPPER] 解析到 %d 个 MyBatis XML statement\n", count)
	}
}

// extractXmlMappers 从单个 xml 文本提取所有 mapper 块及其 statement。
// 返回提取到的 statement 总数。
// 因 Go RE2 不支持反向引用，statement 块采用「开标签定位 + 配对闭标签截取」两段式解析。
func extractXmlMappers(store *AnalysisStore, path, text string) int {
	total := 0
	// 先按 mapper 块切分（应对多 <mapper> 块），再在每个块内匹配 statement。
	mapperMatches := reMapperOpen.FindAllStringSubmatchIndex(text, -1)
	if len(mapperMatches) == 0 {
		return 0
	}
	for i, mm := range mapperMatches {
		ns := text[mm[2]:mm[3]] // namespace 全限定名
		shortClass := ns
		if dot := strings.LastIndex(ns, "."); dot >= 0 {
			shortClass = ns[dot+1:]
		}
		// 块范围：从 namespace 属性结束到下一个 <mapper 起始（或文本末尾）
		blockStart := mm[1]
		blockEnd := len(text)
		if i+1 < len(mapperMatches) {
			blockEnd = mapperMatches[i+1][0]
		}
		block := text[blockStart:blockEnd]
		// 遍历所有开标签，逐个配对闭标签截取 SQL
		for _, sm := range reStmtOpen.FindAllStringSubmatchIndex(block, -1) {
			tag := block[sm[2]:sm[3]] // select/insert/update/delete
			id := block[sm[4]:sm[5]]
			afterOpen := sm[1] // 开标签之后的位置
			closeTag := "</" + tag + ">"
			ci := strings.Index(strings.ToLower(block[afterOpen:]), strings.ToLower(closeTag))
			if ci < 0 {
				continue
			}
			bodyEnd := afterOpen + ci
			sql := block[afterOpen:bodyEnd]
			sql = cleanXmlSQL(sql)
			stmt := XmlMapperStmt{
				Namespace:  ns,
				ShortClass: shortClass,
				Id:         id,
				SQLText:    sql,
				FilePath:   path,
				Line:       lineOf(text, afterOpen),
				HasConcat:  reXmlSQLConcat.MatchString(sql),
				HasParam:   reXmlSQLParam.MatchString(sql),
			}
			// 双向 key：全限定 + 短类名（与调用图 Mapper 接口方法键对齐）
			store.XmlMappers[ns+"."+id] = stmt
			store.XmlMappers[shortClass+"."+id] = stmt
			total++
		}
	}
	return total
}

// cleanXmlSQL 清理 statement 内部 SQL：去注释、折叠空白，保留 ${...} / #{...} 标记供判定。
func cleanXmlSQL(s string) string {
	// 去掉 XML 注释 <!-- ... -->
	if i := strings.Index(s, "<!--"); i >= 0 {
		var b strings.Builder
		rest := s
		for {
			si := strings.Index(rest, "<!--")
			if si < 0 {
				b.WriteString(rest)
				break
			}
			b.WriteString(rest[:si])
			ei := strings.Index(rest[si:], "-->")
			if ei < 0 {
				break
			}
			rest = rest[si+ei+3:]
		}
		s = b.String()
	}
	// 折叠空白
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimSpace(s)
}

// lineOf 根据子串偏移量估算行号（1-based）。
func lineOf(full string, offset int) int {
	if offset > len(full) {
		offset = len(full)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if full[i] == '\n' {
			line++
		}
	}
	return line
}
