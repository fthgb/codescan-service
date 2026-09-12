package bughash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const bughashVersion = 5

var (
	reLineComment  = regexp.MustCompile(`//[^\n]*`)
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reWS           = regexp.MustCompile(`\s+`)
)

func Normalize(code string) string {
	code = reBlockComment.ReplaceAllString(code, " ")
	code = reLineComment.ReplaceAllString(code, "")
	code = reWS.ReplaceAllString(code, " ")
	return strings.TrimSpace(code)
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func fingerprint(srcBody, sinkBody string) string {
	return sha256hex(Normalize(srcBody) + Normalize(sinkBody))[:16]
}

func PathSignature(taintPath []map[string]any) string {
	if len(taintPath) == 0 {
		return ""
	}
	parts := make([]string, 0, len(taintPath))
	for _, h := range taintPath {
		file, _ := h["file"].(string)
		line := 0
		switch v := h["line"].(type) {
		case float64:
			line = int(v)
		case int:
			line = v
		}
		parts = append(parts, fmt.Sprintf("%s:%d", file, line))
	}
	return sha256hex(strings.Join(parts, "|"))[:12]
}

func ComputeBughash(vulnType, cweID, srcFile, srcSig, sinkFile, sinkSig,
	srcBody, sinkBody string, srcLine, sinkLine int, pathSig string) string {
	bf := fingerprint(srcBody, sinkBody)
	srcID := srcSig
	if srcID == "" {
		srcID = fmt.Sprintf("%s#%d", srcFile, srcLine)
	}
	sinkID := sinkSig
	if sinkID == "" {
		sinkID = fmt.Sprintf("%s#%d", sinkFile, sinkLine)
	}
	key := fmt.Sprintf("v%d:%s:%s:%s:%s:%s:%s:%s:%s",
		bughashVersion, vulnType, cweID, srcFile, srcID, sinkFile, sinkID, bf, pathSig)
	return sha256hex(key)
}
