// Package codescan implements a REST client for the CodeSafe (codescan) SAST
// platform — a faithful port of appsec/codescan/client.py.
//
// 铁律 D (ADR-0005): codescan-specific field names (projectInfoVOS/
// codescfgBatchs/bugsVOList/bugTraces/ruleVO/kind/fatherTraceid/tool bitmap)
// live ONLY inside this package. Externally we expose the schemas contract
// (Project/Task/...) or, for FetchAll, the raw []map[string]any handed
// verbatim to adapter.CodeSafeAdapter.Parse (seed is opaque). Swapping
// codescan = rewrite this package + config (boundary isolated).
//
// Zero new deps: stdlib only (net/http + mime/multipart + os/exec + crypto/tls
// + sync). Concurrency via channel semaphore (mirrors Python ThreadPoolExecutor).
// Caching via sync.Map + TTL entries (mirrors Python module-level dict + time).
package codescan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CodeScanError mirrors Python CodeScanError — codescan call failure
// (network/HTTP/parse). Routes map this to HTTP 502.
type CodeScanError struct{ msg string }

func (e *CodeScanError) Error() string { return e.msg }

func newCodeScanError(format string, args ...any) error {
	return &CodeScanError{msg: fmt.Sprintf(format, args...)}
}

// cacheEntry is a generic TTL cache entry shared by summary/detail/listPage caches.
type cacheEntry struct {
	at   time.Time
	data any
}

// Options configures a Client. New applies defaults for zero fields.
type Options struct {
	BaseURL        string
	AuthToken      string
	AuthCookie     string
	InsecureSSL    bool
	Timeout        time.Duration
	RepoCacheDir   string
	// RepoCacheTTL 控制克隆仓库的保留时长。每次 CloneSource 前清理超过此时长
	// 未修改的仓库目录。0 = 不清理（本地开发默认）；48h = K8s 生产推荐值。
	RepoCacheTTL    time.Duration
	DetailCacheTTL time.Duration
	FetchWorkers   int
	// GitAdminUser/GitAdminPassword 注入 CloneSource 的 http(s) clone/fetch URL
	// userinfo，使超级管理员可拉取所有私有仓库。两者须同时非空才生效；
	// 非 http(s) URI 或留空时使用裸 svnGitUri（行为不变）。
	GitAdminUser     string
	GitAdminPassword string
}

// Client is the codescan REST client. Holds config + HTTP client + 3 TTL caches.
// Tests inject an httptest.Server URL (BaseURL) + reuse the default HTTPClient.
type Client struct {
	BaseURL        string
	AuthToken      string
	AuthCookie     string
	InsecureSSL    bool
	Timeout        time.Duration
	HTTPClient     *http.Client
	RepoCacheDir   string
	RepoCacheTTL   time.Duration
	DetailCacheTTL time.Duration
	FetchWorkers   int

	GitAdminUser     string
	GitAdminPassword string

	summaryCache  sync.Map // string -> cacheEntry (TTL 120s)
	detailCache   sync.Map // "pkTask:bugId" -> cacheEntry (TTL DetailCacheTTL)
	listPageCache sync.Map // "pkTask:pageIdx" -> cacheEntry (TTL DetailCacheTTL)
}

// New builds a Client from Options, filling defaults (timeout 30s, detail TTL 600s,
// workers 8, repo cache "./codescan_repos"). HTTPClient gets a TLS config honoring
// InsecureSSL (mirrors Python ssl._create_unverified_context).
func New(o Options) *Client {
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.DetailCacheTTL == 0 {
		o.DetailCacheTTL = 600 * time.Second
	}
	if o.FetchWorkers == 0 {
		o.FetchWorkers = 8
	}
	if o.RepoCacheDir == "" {
		o.RepoCacheDir = "./codescan_repos"
	}
	return &Client{
		BaseURL:      o.BaseURL,
		AuthToken:    o.AuthToken,
		AuthCookie:   o.AuthCookie,
		InsecureSSL:  o.InsecureSSL,
		Timeout:      o.Timeout,
		HTTPClient: &http.Client{
			Timeout: o.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: o.InsecureSSL},
			},
		},
		RepoCacheDir:   o.RepoCacheDir,
		RepoCacheTTL:   o.RepoCacheTTL,
		DetailCacheTTL: o.DetailCacheTTL,
		FetchWorkers:   o.FetchWorkers,

		GitAdminUser:     o.GitAdminUser,
		GitAdminPassword: o.GitAdminPassword,
	}
}

const (
	summaryTTL     = 120 * time.Second // mirrors Python _SUMMARY_TTL
	listPageSize   = 50                // mirrors Python _LIST_PAGE_SIZE
	unknownRuleKey = "__UNKNOWN__"     // sentinel for null/empty ruleCode (aligns fetch_all filter)
)

// levelOrder mirrors Python _LEVEL_ORDER: 5=高危, 3=中危, 1=低危 (fixed order).
var levelOrder = []struct {
	lvl   int
	label string
}{{5, "高危"}, {3, "中危"}, {1, "低危"}}

// ---- HTTP helpers ----

func (c *Client) buildHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "appsec-codescan/1.0")
	if c.AuthCookie != "" {
		req.Header.Set("Cookie", c.AuthCookie)
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", c.AuthToken)
	}
}

// httpGetJSON GETs url and returns the parsed full JSON body (NOT unwrapped).
// HTTP >=400 → CodeScanError("codescan HTTP {code}: {body[:200]}").
func (c *Client) httpGetJSON(targetURL string) (any, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, newCodeScanError("codescan GET 失败 %s: %v", targetURL, err)
	}
	c.buildHeaders(req)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, newCodeScanError("codescan GET 失败 %s: %v", targetURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, newCodeScanError("codescan HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, newCodeScanError("codescan GET 解析失败 %s: %v", targetURL, err)
	}
	return v, nil
}

// httpPostMultipart POSTs multipart/form-data (codescan list-projects endpoint).
// Each field: dict/list → JSON string (ensure_ascii=False, no HTML escape, mirrors
// Python json.dumps(ensure_ascii=False)); else fmt.Sprintf("%v"). Single "data"
// field in practice. Boundary auto-generated (Python hand-rolled; server parses
// standard multipart, boundary value irrelevant).
func (c *Client) httpPostMultipart(targetURL string, fields map[string]any) (any, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic order (Python dict insertion; single-field in practice)
	for _, k := range keys {
		s, err := multipartValue(fields[k])
		if err != nil {
			_ = mw.Close()
			return nil, newCodeScanError("codescan POST 失败 %s: %v", targetURL, err)
		}
		fw, err := mw.CreateFormField(k)
		if err != nil {
			_ = mw.Close()
			return nil, newCodeScanError("codescan POST 失败 %s: %v", targetURL, err)
		}
		_, _ = fw.Write([]byte(s))
	}
	if err := mw.Close(); err != nil {
		return nil, newCodeScanError("codescan POST 失败 %s: %v", targetURL, err)
	}
	req, err := http.NewRequest("POST", targetURL, &body)
	if err != nil {
		return nil, newCodeScanError("codescan POST 失败 %s: %v", targetURL, err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c.buildHeaders(req)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, newCodeScanError("codescan POST 失败 %s: %v", targetURL, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, newCodeScanError("codescan HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	var v any
	if err := json.Unmarshal(respBody, &v); err != nil {
		return nil, newCodeScanError("codescan POST 解析失败 %s: %v", targetURL, err)
	}
	return v, nil
}

// multipartValue serializes a field value for multipart: dict/list → JSON
// (no HTML escape, mirrors Python json.dumps(ensure_ascii=False)); else %v.
func multipartValue(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case map[string]any, []any:
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(x); err != nil {
			return "", err
		}
		return strings.TrimRight(b.String(), "\n"), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

// joinURL mirrors Python _join: BaseURL.rstrip("/") + "/" + parts joined by "/",
// each part strip("/") (path segments only; query appended separately by callers).
func (c *Client) joinURL(parts ...string) string {
	base := strings.TrimRight(c.BaseURL, "/")
	cleaned := make([]string, len(parts))
	for i, p := range parts {
		cleaned[i] = strings.Trim(p, "/")
	}
	return base + "/" + strings.Join(cleaned, "/")
}

// unwrap mirrors Python _unwrap: o["data"] if o is a dict containing "data", else o.
func unwrap(o any) any {
	if m, ok := o.(map[string]any); ok {
		if d, exists := m["data"]; exists {
			return d
		}
	}
	return o
}

// s2s mirrors Python _s: boundary type normalization. codescan REST doesn't
// guarantee id/string field types (pkPj/pkTask/bugId empirically may be int);
// coerce to string for the contract. nil → nil (*string).
func s2s(v any) *string {
	if v == nil {
		return nil
	}
	s := fmt.Sprintf("%v", v)
	return &s
}

// asString coerces any to string (nil → "", mirroring Python str(v) on the
// consumption side). Used for required fields like pjName/bugId.
func asString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	default:
		return fmt.Sprintf("%v", v)
	}
}

// nullableInt coerces any to *int (nil → nil). Mirrors Python
// `int(x) if x is not None else None`. Non-numeric string → nil (Atoi fails).
func nullableInt(v any) *int {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case float64:
		n := int(x)
		return &n
	case int:
		return &x
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return &n
		}
		return nil
	default:
		if n, err := strconv.Atoi(fmt.Sprintf("%v", v)); err == nil {
			return &n
		}
		return nil
	}
}

// intFromAny coerces any to int (nil → 0). Used for counts/levels where 0 is
// a safe default (mirrors Python int(x) on the consumption side).
func intFromAny(v any) int {
	if p := nullableInt(v); p != nil {
		return *p
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- Public methods (6, mirroring appsec/codescan/client.py) ----

// DiscoverProjects lists projects (paged). codescan POST
// /codesafeapi/project/queryallpjSimple/paged → data.totalCount + data.projectInfoVOS[].
// Drops the meaningless tool bitmap ("0,0,1"); keeps bugTemplateName/exeNum/projectOrg.
func (c *Client) DiscoverProjects(keyword string, pageIndex, pageSize int) (ProjectPage, error) {
	targetURL := c.joinURL("/codesafeapi/project/queryallpjSimple/paged")
	payload := map[string]any{
		"page":       map[string]any{"pageIndex": pageIndex, "pageSize": pageSize},
		"conditions": map[string]any{"name": keyword},
	}
	o, err := c.httpPostMultipart(targetURL, map[string]any{"data": payload})
	if err != nil {
		return ProjectPage{}, err
	}
	d := unwrap(o)
	dm, _ := d.(map[string]any)
	var pjs []any
	totalSet := false
	total := 0
	if dm != nil {
		pjs, _ = dm["projectInfoVOS"].([]any)
		if t := dm["totalCount"]; t != nil {
			total = intFromAny(t)
			totalSet = true
		}
	}
	out := []Project{}
	for _, itAny := range pjs {
		it, ok := itAny.(map[string]any)
		if !ok {
			continue
		}
		pjName := asString(it["pjName"])
		if pjName == "" {
			continue
		}
		out = append(out, Project{
			PjName:          pjName,
			PkPj:            s2s(it["pkPj"]),
			BugTemplateName: s2s(it["bugTemplateName"]),
			ExeNum:          nullableInt(it["exeNum"]),
			ProjectOrg:      s2s(it["projectOrg"]),
		})
	}
	if !totalSet {
		total = len(out)
	}
	return ProjectPage{
		TotalCount: total,
		PageIndex:  pageIndex,
		PageSize:   pageSize,
		Items:      out,
	}, nil
}

// DiscoverTasks lists a project's latest-batch tasks. codescan GET
// /codesafeapi/project/{pj}/task/latest → data.codescfgBatchs[].lastTaskVOList[].
func (c *Client) DiscoverTasks(pjName string) ([]Task, error) {
	if pjName == "" {
		return []Task{}, nil
	}
	// url.PathEscape encodes "/" (parity with Python quote(pj,"")); sub-delims
	// (!$&'()*+,;=:@) are left unescaped — a deviation from Python quote("","")
	// which escapes them, but project names are CJK/alnum in practice (unreachable).
	targetURL := c.joinURL("/codesafeapi/project", url.PathEscape(pjName), "task/latest")
	o, err := c.httpGetJSON(targetURL)
	if err != nil {
		return nil, err
	}
	d := unwrap(o)
	dm, _ := d.(map[string]any)
	out := []Task{}
	if dm == nil {
		return out, nil
	}
	batches, _ := dm["codescfgBatchs"].([]any)
	for _, cbAny := range batches {
		cb, ok := cbAny.(map[string]any)
		if !ok {
			continue
		}
		pkconf := s2s(cb["pkPjConfig"])
		codevo, _ := cb["codeVO"].(map[string]any)
		if codevo == nil {
			codevo = map[string]any{}
		}
		codeName := s2s(codevo["codeName"])
		svn := s2s(codevo["svnGitUri"])
		branch := s2s(codevo["gitBranchName"])
		commit := s2s(codevo["commitId"])
		lastTasks, _ := cb["lastTaskVOList"].([]any)
		for _, ltAny := range lastTasks {
			lt, ok := ltAny.(map[string]any)
			if !ok {
				continue
			}
			if lt["pkTask"] == nil {
				continue
			}
			out = append(out, Task{
				PkTask:            asString(lt["pkTask"]),
				PkPjConfig:        pkconf,
				CodeName:          codeName,
				TaskBeginTime:     s2s(lt["taskBeginTime"]),
				TaskEndTime:       s2s(lt["taskEndTime"]),
				ProblemNum:        nullableInt(lt["problemNum"]),
				ProblemNumHigh:    nullableInt(lt["problemNum5"]),
				ProblemNumMid:     nullableInt(lt["problemNum3"]),
				ProblemNumLow:     nullableInt(lt["problemNum1"]),
				TaskResultDesc:    s2s(lt["taskResultDesc"]),
				CheckTemplateName: s2s(lt["checkTemplateName"]),
				SvnGitUri:         svn,
				GitBranchName:     branch,
				CommitId:          commit,
			})
		}
	}
	return out, nil
}

// DiscoverBugs lists task defect summaries (paged). codescan GET
// /codesafeapi/result/{taskId}/bug?pageIndex=&pageSize= → data.bugsVOList[] + data.count.
func (c *Client) DiscoverBugs(pkTask string, pageIndex, pageSize int) (BugPage, error) {
	qs := url.Values{}
	qs.Set("pageIndex", strconv.Itoa(pageIndex))
	qs.Set("pageSize", strconv.Itoa(pageSize))
	targetURL := c.joinURL("/codesafeapi/result", pkTask, "bug") + "?" + qs.Encode()
	o, err := c.httpGetJSON(targetURL)
	if err != nil {
		return BugPage{}, err
	}
	d := unwrap(o)
	var bugsRaw []any
	countSet := false
	count := 0
	switch dm := d.(type) {
	case map[string]any:
		bugsRaw, _ = dm["bugsVOList"].([]any)
		if c2 := dm["count"]; c2 != nil {
			count = intFromAny(c2)
			countSet = true
		}
	case []any:
		bugsRaw = dm
	}
	bugs := []BugSummary{}
	for _, bAny := range bugsRaw {
		b, ok := bAny.(map[string]any)
		if !ok {
			continue
		}
		bugId := asString(b["bugId"])
		if bugId == "" {
			continue
		}
		bugs = append(bugs, BugSummary{
			BugId:        bugId,
			RuleCode:     s2s(b["ruleCode"]),
			RuleName:     s2s(b["ruleName"]),
			Level:        s2s(b["level"]),
			BugFile:      s2s(b["bugFile"]),
			BugBeginline: nullableInt(b["bugBeginline"]),
			BugFunc:      s2s(b["bugFunc"]),
		})
	}
	if !countSet {
		count = len(bugs)
	}
	return BugPage{Count: count, Bugs: bugs}, nil
}

// SummarizeBugs aggregates level×type distribution (list-only, no detail fetch).
// Returns BugTypeSummary: levels fixed 高→中→低 order, each level's types by count desc.
// ruleCode null/empty → "__UNKNOWN__" group (aligned with fetch_all rule_codes sentinel),
// restored to nil on output. Cache 120s; forceRefresh bypasses (test-only).
func (c *Client) SummarizeBugs(pkTask string, forceRefresh bool) (BugTypeSummary, error) {
	if pkTask == "" {
		return BugTypeSummary{PkTask: "", Total: 0, Levels: []LevelTypes{}}, nil
	}
	if !forceRefresh {
		if v, ok := c.summaryCache.Load(pkTask); ok {
			ce := v.(cacheEntry)
			if time.Since(ce.at) < summaryTTL {
				return ce.data.(BugTypeSummary), nil
			}
		}
	}
	type aggKey struct {
		level   int
		ruleKey string
	}
	type aggVal struct {
		ruleName *string
		count    int
	}
	// sentinel level for null/unparseable level — won't match 5/3/1 (mirrors Python None).
	const levelNil = -999
	agg := map[aggKey]*aggVal{}
	total := 0
	pidx, psize := 1, listPageSize
	for {
		qs := url.Values{}
		qs.Set("pageIndex", strconv.Itoa(pidx))
		qs.Set("pageSize", strconv.Itoa(psize))
		targetURL := c.joinURL("/codesafeapi/result", pkTask, "bug") + "?" + qs.Encode()
		o, err := c.httpGetJSON(targetURL)
		if err != nil {
			return BugTypeSummary{}, err
		}
		d := unwrap(o)
		dm, _ := d.(map[string]any)
		var bugs []any
		if dm != nil {
			bugs, _ = dm["bugsVOList"].([]any)
		}
		if len(bugs) == 0 {
			break
		}
		for _, bAny := range bugs {
			b, ok := bAny.(map[string]any)
			if !ok {
				continue
			}
			blI := levelNil
			if p := nullableInt(b["level"]); p != nil {
				blI = *p
			}
			rkey := unknownRuleKey
			if rc := b["ruleCode"]; rc != nil {
				rcs := asString(rc)
				if strings.TrimSpace(rcs) != "" {
					rkey = rcs
				}
			}
			var rname *string
			if rn := b["ruleName"]; rn != nil {
				rns := asString(rn)
				if strings.TrimSpace(rns) != "" {
					rname = &rns
				}
			}
			k := aggKey{level: blI, ruleKey: rkey}
			v, exists := agg[k]
			if !exists {
				v = &aggVal{ruleName: rname, count: 0}
				agg[k] = v
			}
			v.count++
			if v.ruleName == nil && rname != nil {
				v.ruleName = rname // keep first non-empty ruleName
			}
			total++
		}
		if len(bugs) < psize {
			break
		}
		pidx++
	}
	levelsOut := []LevelTypes{}
	for _, lo := range levelOrder {
		type row struct {
			ruleKey  string
			ruleName *string
			count    int
		}
		rows := []row{}
		for k, v := range agg {
			if k.level == lo.lvl {
				rows = append(rows, row{ruleKey: k.ruleKey, ruleName: v.ruleName, count: v.count})
			}
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].count != rows[j].count {
				return rows[i].count > rows[j].count // count desc
			}
			return rows[i].ruleKey < rows[j].ruleKey // ruleKey tiebreak
		})
		typeCounts := []TypeCount{}
		for _, r := range rows {
			var rc *string
			if r.ruleKey != unknownRuleKey {
				rck := r.ruleKey
				rc = &rck
			}
			typeCounts = append(typeCounts, TypeCount{RuleCode: rc, RuleName: r.ruleName, Count: r.count})
		}
		lvlTotal := 0
		for _, r := range rows {
			lvlTotal += r.count
		}
		levelsOut = append(levelsOut, LevelTypes{Level: lo.lvl, Label: lo.label, Total: lvlTotal, Types: typeCounts})
	}
	summary := BugTypeSummary{PkTask: pkTask, Total: total, Levels: levelsOut}
	c.summaryCache.Store(pkTask, cacheEntry{at: time.Now(), data: summary})
	return summary, nil
}

// fetchListPage fetches one page (unwrapped data dict, with bugsVOList + count).
// (pkTask,pidx) TTL cache. Empty/abnormal → {} (not cached, mirrors Python).
func (c *Client) fetchListPage(pkTask string, pidx, psize int) (map[string]any, error) {
	key := pkTask + ":" + strconv.Itoa(pidx)
	if v, ok := c.listPageCache.Load(key); ok {
		ce := v.(cacheEntry)
		if time.Since(ce.at) < c.DetailCacheTTL {
			return ce.data.(map[string]any), nil
		}
	}
	qs := url.Values{}
	qs.Set("pageIndex", strconv.Itoa(pidx))
	qs.Set("pageSize", strconv.Itoa(psize))
	targetURL := c.joinURL("/codesafeapi/result", pkTask, "bug") + "?" + qs.Encode()
	o, err := c.httpGetJSON(targetURL)
	if err != nil {
		return map[string]any{}, err
	}
	d := unwrap(o)
	dm, _ := d.(map[string]any)
	if dm == nil {
		return map[string]any{}, nil // not cached (parity: Python returns {} uncached)
	}
	c.listPageCache.Store(key, cacheEntry{at: time.Now(), data: dm})
	return dm, nil
}

// fetchOneDetail fetches a single bug detail (unwrapped data dict). (pkTask,bugId)
// TTL cache. Non-dict → nil, not cached (upstream treats as missing; parity Python).
func (c *Client) fetchOneDetail(pkTask, bid string) (map[string]any, error) {
	key := pkTask + ":" + bid
	if v, ok := c.detailCache.Load(key); ok {
		ce := v.(cacheEntry)
		if time.Since(ce.at) < c.DetailCacheTTL {
			return ce.data.(map[string]any), nil
		}
	}
	targetURL := c.joinURL("/codesafeapi/result", pkTask, "bug", bid)
	o, err := c.httpGetJSON(targetURL)
	if err != nil {
		return nil, err
	}
	d := unwrap(o)
	dm, _ := d.(map[string]any)
	if dm == nil {
		return nil, nil
	}
	c.detailCache.Store(key, cacheEntry{at: time.Now(), data: dm})
	return dm, nil
}

// FetchAll bulk-fetches all defect details (single-bug endpoint, bugTraces with kind).
// Returns raw []map[string]any — NOT modeled, bit-for-bit transparent to
// adapter.CodeSafeAdapter.Parse (铁律 D: seed opaque). limit=0 = unlimited.
// levels: optional int set (1=低/3=中/5=高); nil = all. ruleCodes: optional string
// set (may include "__UNKNOWN__" sentinel matching null/empty ruleCode); nil = no
// type filter. AND relation. List bugs carry level/ruleCode → client-side filter
// saves detail traffic. Ordered by list bugId (deterministic, for repro/tests).
func (c *Client) FetchAll(pkTask string, limit int, levels []int, ruleCodes []string) ([]map[string]any, error) {
	if pkTask == "" {
		return []map[string]any{}, nil
	}
	cap := limit
	if cap == 0 {
		cap = 1 << 30
	}
	var lvlSet map[int]bool
	if len(levels) > 0 {
		lvlSet = map[int]bool{}
		for _, l := range levels {
			lvlSet[l] = true
		}
	}
	var rcSet map[string]bool
	if len(ruleCodes) > 0 {
		rcSet = map[string]bool{}
		for _, rc := range ruleCodes {
			rcSet[rc] = true
		}
	}
	psize := listPageSize

	// 1. page1 → count → total pages → concurrent fetch remaining → merge by page order.
	d1, err := c.fetchListPage(pkTask, 1, psize)
	if err != nil {
		return nil, err
	}
	totalBugs := 0
	if cnt, ok := d1["count"]; ok && cnt != nil {
		totalBugs = intFromAny(cnt)
	} else if bl, ok := d1["bugsVOList"].([]any); ok {
		totalBugs = len(bl)
	}
	numPages := (totalBugs + psize - 1) / psize // ceil
	if numPages < 1 {
		numPages = 1
	}
	pages := map[int]map[string]any{1: d1}
	if numPages > 1 {
		workers := c.FetchWorkers
		if workers < 1 {
			workers = 1
		}
		sem := make(chan struct{}, workers)
		var mu sync.Mutex
		var wg sync.WaitGroup
		for p := 2; p <= numPages; p++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(page int) {
				defer wg.Done()
				defer func() { <-sem }()
				d, err := c.fetchListPage(pkTask, page, psize)
				if err == nil {
					mu.Lock()
					pages[page] = d
					mu.Unlock()
				}
			}(p)
		}
		wg.Wait()
	}
	pageIdxs := make([]int, 0, len(pages))
	for k := range pages {
		pageIdxs = append(pageIdxs, k)
	}
	sort.Ints(pageIdxs)
	allBugs := []any{}
	for _, p := range pageIdxs {
		if bl, ok := pages[p]["bugsVOList"].([]any); ok {
			allBugs = append(allBugs, bl...)
		}
	}

	// 2. client-side filter → ordered dedup bugId collection.
	targets := []string{}
	seenBid := map[string]bool{}
	for _, bAny := range allBugs {
		if len(targets) >= cap {
			break
		}
		b, ok := bAny.(map[string]any)
		if !ok {
			continue
		}
		bidStr := asString(b["bugId"])
		if bidStr == "" || seenBid[bidStr] {
			continue
		}
		if lvlSet != nil {
			if p := nullableInt(b["level"]); p == nil || !lvlSet[*p] {
				continue
			}
		}
		if rcSet != nil {
			rkey := unknownRuleKey
			if rc := b["ruleCode"]; rc != nil {
				rcs := asString(rc)
				if strings.TrimSpace(rcs) != "" {
					rkey = rcs
				}
			}
			if !rcSet[rkey] {
				continue
			}
		}
		seenBid[bidStr] = true
		targets = append(targets, bidStr)
	}
	if len(targets) == 0 {
		return []map[string]any{}, nil
	}

	// 3. concurrent detail fetch (TTL-cached) → reorder by list bugId (deterministic).
	workers := c.FetchWorkers
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	byID := map[string]map[string]any{}
	var wg sync.WaitGroup
	for _, bid := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(b string) {
			defer wg.Done()
			defer func() { <-sem }()
			dd, err := c.fetchOneDetail(pkTask, b)
			if err != nil || dd == nil {
				return
			}
			if bidStr := asString(dd["bugId"]); bidStr != "" {
				mu.Lock()
				byID[bidStr] = dd
				mu.Unlock()
			}
		}(bid)
	}
	wg.Wait()

	out := []map[string]any{}
	for _, bid := range targets {
		if dd, ok := byID[bid]; ok {
			out = append(out, dd)
		}
	}
	return out, nil
}

// repoNameFromURI mirrors Python _repo_name_from_uri: last path segment, strip ".git".
// cleanupStaleRepos 删除 RepoCacheDir 下修改时间超过 RepoCacheTTL 的仓库目录。
// best-effort：失败只 stderr 留痕，不阻断 CloneSource。RepoCacheTTL=0 时跳过（本地开发）。
func (c *Client) cleanupStaleRepos() {
	if c.RepoCacheTTL <= 0 {
		return
	}
	entries, err := os.ReadDir(c.RepoCacheDir)
	if err != nil {
		return // 目录不存在 = 无需清理
	}
	cutoff := time.Now().Add(-c.RepoCacheTTL)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			dir := filepath.Join(c.RepoCacheDir, e.Name())
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintf(os.Stderr, "cleanupStaleRepos: remove %s: %v\n", dir, err)
			} else {
				fmt.Fprintf(os.Stderr, "cleanupStaleRepos: removed %s (last modified %s)\n", dir, info.ModTime().Format("2006-01-02 15:04"))
			}
		}
	}
}

func repoNameFromURI(uri string) string {
	s := strings.TrimRight(uri, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, ".git")
	if s == "" {
		return "repo"
	}
	return s
}

// CloneSource git-clones a codescan project's source into the local cache dir
// (boundary seed, 铁律 D: swap VCS = rewrite this func). Full clone (no --depth)
// so any commitId codescan scanned can be checked out. Reuses dir for same
// repo+commit. Returns dest absolute path. argv list (no shell=True, parity Python).
//
// 超级管理员拉取：GitAdminUser/GitAdminPassword 同时非空且 svnGitUri 为 http/https
// 时，把 user:pass 注入 URL userinfo 用于 clone/fetch（使一个管理员账密可拉所有
// 私有仓库）。clone 后用 `remote set-url` 把 remote.origin.url 复位为裸 URI，避免
// 账密持久化到 codescan_repos/*/.git/config；fetch 改用带账密的显式 URL 一击即取，
// 不依赖 remote.origin.url，故复位不影响后续拉取。非 http(s) 或账密留空 → 行为不变。
func (c *Client) CloneSource(svnGitUri, branch, commitID string) (string, error) {
	c.cleanupStaleRepos() // best-effort: 清理过期克隆，防止 codescan_repos/ 无限增长
	repo := repoNameFromURI(svnGitUri)
	ref := commitID
	if ref == "" {
		ref = "latest"
	}
	ref8 := ref
	if len(ref8) > 8 {
		ref8 = ref8[:8]
	}
	dest := filepath.Join(c.RepoCacheDir, repo+"-"+ref8)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", newCodeScanError("git clone 异常: %v", err)
	}
	runGit := func(timeout time.Duration, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		// Windows MAX_PATH=260:Java 深嵌套包路径(cn/com/.../strategy/productCollection/X.java)
		// 连 dest 前缀后易破 260 → git checkout 阶段 "cannot stat '...': Filename too long"。
		// core.longpaths=true 解锁;非 Windows 平台为 no-op 无副作用。配置随命令走(铁律 D:
		// 不依赖机器全局 git config,换机即生效)。clone/fetch/checkout/remote-set-url 全覆盖。
		fullArgs := append([]string{"-c", "core.longpaths=true"}, args...)
		cmd := exec.CommandContext(ctx, "git", fullArgs...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				return newCodeScanError("git clone 失败: %s", truncate(stderr.String(), 300))
			}
			return newCodeScanError("git clone 异常: %v", err)
		}
		return nil
	}
	credURL := withGitCredentials(svnGitUri, c.GitAdminUser, c.GitAdminPassword)
	gitDir := filepath.Join(dest, ".git")
	if isGitDir(gitDir) {
		// 带账密的显式 URL fetch（remote.origin.url 已是裸 URI，故须显式传账密 URL）
		if credURL != "" {
			if err := runGit(1800*time.Second, "-C", dest, "fetch", credURL); err != nil {
				return "", err
			}
		} else {
			if err := runGit(1800*time.Second, "-C", dest, "fetch", "--all"); err != nil {
				return "", err
			}
		}
		// 复用 dest:上次 clone/checkout 可能中途失败（longpaths 等）留下 index 与工作树
		// 脱节的脏状态（staged deletion / 残留 untracked），令本次 checkout 报 "untracked
		// working tree files would be overwritten by checkout"。dest 是自动 clone 缓存（无
		// 人工改动价值），fetch 后 checkout 前先 reset --hard 把 index/工作树对齐 HEAD +
		// clean -fdx 删 untracked，回到干净 tracked 状态。走 runGit（带 core.longpaths，
		// 深路径 Java 文件写盘不撞 MAX_PATH）。仅 fetch 分支跑——此处 isGitDir 已确认 dest
		// 有自己的 .git，git 不向上找父仓，不会误伤父仓库文件。
		if err := runGit(300*time.Second, "-C", dest, "reset", "--hard"); err != nil {
			return "", err
		}
		_ = runGit(60*time.Second, "-C", dest, "clean", "-fdx")
	} else {
		cloneArg := svnGitUri
		if credURL != "" {
			cloneArg = credURL
		}
		if err := runGit(1800*time.Second, "clone", cloneArg, dest); err != nil {
			return "", err
		}
		// 复位 remote.origin.url 为裸 URI，避免账密落盘 codescan_repos/*/.git/config
		if credURL != "" {
			_ = runGit(60*time.Second, "-C", dest, "remote", "set-url", "origin", svnGitUri)
		}
	}
	if commitID != "" {
		if err := runGit(120*time.Second, "-C", dest, "checkout", commitID); err != nil {
			return "", err
		}
	} else if branch != "" {
		if err := runGit(120*time.Second, "-C", dest, "checkout", branch); err != nil {
			return "", err
		}
	}
	abs, _ := filepath.Abs(dest)
	return abs, nil
}

// withGitCredentials injects user:pass into the URL userinfo of an http/https
// svnGitUri, URL-encoding both components (handles @:/ and CJK). Returns "" (→
// caller uses bare URI) when scheme isn't http/https, or either cred is empty,
// or parsing fails. Mirrors no existing Python helper (new capability).
func withGitCredentials(rawURI, user, pass string) string {
	if user == "" || pass == "" {
		return ""
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	u.User = url.UserPassword(user, pass)
	return u.String()
}

func isGitDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
