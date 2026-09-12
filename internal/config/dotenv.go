package config

import (
	"bufio"
	"os"
	"strings"
)

// LoadDotenv reads a dotenv (.env) file at path and injects KEY=VALUE pairs into
// the process environment via os.Setenv. It is a no-op (returns nil) when the
// file does not exist, so a missing .env never breaks startup.
//
// Rules (mirrors godotenv default behavior):
//   - blank lines and lines whose first non-space char is '#' are skipped
//   - the first '=' splits KEY from VALUE; surrounding quotes (' or ") on the
//     value are stripped
//   - a key already present in the environment is NOT overwritten — explicit
//     shell env always wins, so CI/prod overrides a locally committed .env
//
// config.init() calls LoadDotenv(".env") so any cmd importing this package picks
// up <cwd>/.env before config.Load() reads env. The .env file holds secrets and
// MUST be gitignored (see .gitignore); commit .env.example as the template only.
func LoadDotenv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if n := len(val); n >= 2 {
			first, last := val[0], val[n-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				val = val[1 : n-1]
			}
		}
		if key == "" {
			continue
		}
		if _, ok := os.LookupEnv(key); !ok {
			_ = os.Setenv(key, val)
		}
	}
	return sc.Err()
}
