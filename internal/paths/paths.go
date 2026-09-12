package paths

import "regexp"

var testFileRE = regexp.MustCompile(`(?i)(Test|Tests|IT)\.java$|/test/|/tests/`)

func IsTestFile(path string) bool {
	return testFileRE.MatchString(path)
}
