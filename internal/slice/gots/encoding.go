package gots

import (
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// toUTF8 mirrors slicer.py _detect_encoding + TreeSitterJavaExtractor._tree
// normalization: try utf-8, then gb18030 (superset of GBK/GB2312, common for
// Chinese Java repos), then latin-1 fallback (never errors). The returned
// bytes are UTF-8 so every downstream byte offset is in UTF-8 space, matching
// the Python reference. NO line-ending normalization: offsets must match
// slicer.py byte-for-byte.
//
// Parity note: Python's gb18030 codec may raise UnicodeDecodeError on some
// byte sequences that Go's x/text gb18030 decoder accepts (inserting U+FFFD).
// For VALID gb18030 source files (the corpus GBK fixture) both agree; the
// divergence only affects malformed input, which is best-effort (latin-1
// fallback). The Phase 1b golden cross-check on the GBK fixture confirms
// byte-for-byte parity for real source.
func toUTF8(raw []byte) []byte {
	if utf8.Valid(raw) {
		return raw
	}
	if out, _, err := transform.Bytes(simplifiedchinese.GB18030.NewDecoder(), raw); err == nil {
		return out
	}
	// latin-1: every byte -> U+0000..U+00FF, then UTF-8 encode. Never errors.
	runes := make([]rune, len(raw))
	for i, b := range raw {
		runes[i] = rune(b)
	}
	return []byte(string(runes))
}
