// Package labels — append-only human ground-truth label store (labelled_alerts.jsonl).
//
// 1:1 移植 appsec/webapp/labels.py。铁律 A：纯 stdlib，无内部依赖。
//
// 每行 harness-compatible：始终携带 sliced + label（eval/harness.py 只读这两个键），
// 外加审计/多用户元数据（harness 忽略）。
package labels

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// writeMu 串行化同进程并发 AppendLabel（file lock 保护跨进程）。
var writeMu sync.Mutex

// LabelVocab — ANNOTATION_GUIDELINE §2 四态词表（非二值）。
// uncertain（证据不可见）+ needs-hardening（真 bug 但超威胁模型）必须可存。
var LabelVocab = []string{"false_positive", "true_positive", "uncertain", "needs-hardening"}

// StatusVocab — §1/§4 分层元数据：只有 confirmed 进正式基线。
var StatusVocab = []string{"candidate", "confirmed"}

// ErrInvalidLabel / ErrInvalidStatus — 非法词表（对齐 Python ValueError）。
var (
	ErrInvalidLabel  = errors.New("label must be one of [false_positive true_positive uncertain needs-hardening]")
	ErrInvalidStatus = errors.New("status must be one of [candidate confirmed]")
)

func contains(vocab []string, s string) bool {
	for _, v := range vocab {
		if v == s {
			return true
		}
	}
	return false
}

// AppendLabelArgs — append_label 的关键字参数等价（Go 无 kwargs，用 struct）。
// lang 默认 "java"（slicer Java-only，服务端自动填，客户端不传）。
type AppendLabelArgs struct {
	Sliced               map[string]any // 必填：full SlicedContext（harness-valid labelling）
	Label                string          // 必填：四态之一
	Bughash              string
	AlertID              string
	RunID                string
	VulnerabilityType    string
	Labeler              string
	Note                 *string
	AIVerdict            *string
	AIConfidence         *int
	CWE                  string // 默认 ""
	Lang                 string // 默认 "java"
	Status               string // 默认 "candidate"
	NeedsHardeningReason *string
}

// AppendLabel 追加一条 ground-truth 标签记录，返回写入的 record。
//
// 四态词表 + 分层元数据（ANNOTATION_GUIDELINE §1/§2/§4）：label 是 TP/FP/uncertain/needs-hardening；
// cwe/lang/status 让集合可按 CWE/语言切片，candidate vs confirmed 分离（只有 confirmed 进正式基线）。
func AppendLabel(labelsPath string, args AppendLabelArgs) (map[string]any, error) {
	if !contains(LabelVocab, args.Label) {
		return nil, ErrInvalidLabel
	}
	if args.Status == "" {
		args.Status = "candidate"
	}
	if !contains(StatusVocab, args.Status) {
		return nil, ErrInvalidStatus
	}
	if args.Lang == "" {
		args.Lang = "java"
	}
	// 可选字段 dereference：Python dict 存实际值（None/str/int），非指针。
	// nil 指针 → nil（JSON null）；非 nil → 解引用存值，保 in-memory record 与 Python 等价。
	var note, needsHardeningReason, aiVerdict any
	var aiConfidence any
	if args.Note != nil {
		note = *args.Note
	}
	if args.NeedsHardeningReason != nil {
		needsHardeningReason = *args.NeedsHardeningReason
	}
	if args.AIVerdict != nil {
		aiVerdict = *args.AIVerdict
	}
	if args.AIConfidence != nil {
		aiConfidence = *args.AIConfidence
	}
	record := map[string]any{
		"sliced":                 args.Sliced,
		"label":                  args.Label,
		"bughash":                args.Bughash,
		"alert_id":               args.AlertID,
		"run_id":                 args.RunID,
		"vulnerability_type":     args.VulnerabilityType,
		"cwe":                    args.CWE,
		"lang":                   args.Lang,
		"status":                 args.Status,
		"labeler":                args.Labeler,
		"note":                   note,
		"needs_hardening_reason": needsHardeningReason,
		"labelled_at":            time.Now().UTC().Format(time.RFC3339),
		"ai_verdict":             aiVerdict,
		"ai_confidence":          aiConfidence,
	}
	if err := os.MkdirAll(filepath.Dir(labelsPath), 0o755); err != nil {
		return nil, err
	}
	// 进程内互斥：串行化 OpenFile+lockFile+Write，防 Windows O_APPEND 多 fd 共享冲突。
	// file lock（lockFile/unlockFile）保护跨进程；mutex 保护同进程多 goroutine。
	writeMu.Lock()
	defer writeMu.Unlock()
	f, err := os.OpenFile(labelsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// 文件锁保证跨进程写原子不交错。锁获取失败 → abort 写入（return err，
	// defer f.Close() 关闭文件，不注册 unlockFile —— 未锁定的 fd 不应 unlock）。
	// 成功后 defer unlockFile(f)，LIFO 保证 unlock 先于 Close。
	if err := lockFile(f); err != nil {
		return nil, err
	}
	defer unlockFile(f)
	b, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return nil, err
	}
	return record, nil
}

// ReadAll 读全量标签记录（append-ordered = chronological）。
// 容忍 malformed JSON 行 + bughash-less 行（skip 不 crash，对齐 Python _read_all）。
// 跳过空行 + "//" 注释行。
func ReadAll(labelsPath string) []map[string]any {
	data, err := os.ReadFile(labelsPath)
	if err != nil {
		return nil // 文件不存在 → nil（对齐 Python path.exists() False → []）
	}
	var out []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue // malformed JSON → skip
		}
		out = append(out, rec)
	}
	return out
}

// LatestByBughash 返回某 run 内每个 bughash 的最新标签（文件 append-ordered = 后写覆盖先写）。
// 跳过无 bughash 键的记录（对齐 Python latest[bh] 不写无 bh 的）。
func LatestByBughash(labelsPath, runID string) map[string]map[string]any {
	latest := map[string]map[string]any{}
	for _, rec := range ReadAll(labelsPath) {
		bh, _ := rec["bughash"].(string)
		rid, _ := rec["run_id"].(string)
		if rid == runID && bh != "" {
			latest[bh] = rec // later lines overwrite earlier
		}
	}
	return latest
}

// HistoryFor 返回某 alert 的完整标签历史（oldest first）。
func HistoryFor(labelsPath, runID, bughash string) []map[string]any {
	var out []map[string]any
	for _, rec := range ReadAll(labelsPath) {
		rid, _ := rec["run_id"].(string)
		bh, _ := rec["bughash"].(string)
		if rid == runID && bh == bughash {
			out = append(out, rec)
		}
	}
	return out
}
