package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

var safeRe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func safeFilename(s string) string { return safeRe.ReplaceAllString(s, "_") }

// StepCheckpoint writes one JSON file per bughash result under dir (checkpoint resume).
type StepCheckpoint struct{ dir string }

// NewStepCheckpoint mkdir -p dir.
func NewStepCheckpoint(dir string) (*StepCheckpoint, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &StepCheckpoint{dir: dir}, nil
}

// Save writes <safe(bughash)>.json = resultJSON.
func (c *StepCheckpoint) Save(bughash string, resultJSON []byte) error {
	return os.WriteFile(filepath.Join(c.dir, safeFilename(bughash)+".json"), resultJSON, 0o644)
}

// CompletedIDs 逐字移植 checkpoint.py:completed_ids:
// glob *.json,parse,无 fail_reason 才计为完成。
func (c *StepCheckpoint) CompletedIDs() map[string]bool {
	done := map[string]bool{}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return done
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.dir, name))
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if fr, ok := m["fail_reason"]; ok && fr != nil && fr != "" {
			continue // 有 fail_reason → 不计为完成(parity)
		}
		stem := name[:len(name)-len(".json")]
		done[stem] = true
	}
	return done
}
