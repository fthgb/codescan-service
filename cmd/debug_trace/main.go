package main

import (
	"fmt"
	"os"

	"appsecgo/internal/runsread"
)

func main() {
	runsDir := "runs"

	type check struct {
		runID    string
		bughash  string
		shortBh  string
	}

	checks := []check{
		{"2026-09-07T104500_ff-underwrite-offline",
			"4daf292a981db4999bd738c98b508ce11a6b3e9696b56afed0041392d432240b",
			"4daf292a981db499"},
		{"2026-09-07T033324_codeup-probe-core",
			"761c300590746799a85831a3c4201509d63ae95345a0af585b6744b4ca61524d",
			"761c300590746799"},
	}

	for _, c := range checks {
		fmt.Printf("\n{'status': 'completed', 'content': '=== %s ===\n", c.runID)
		data := runsread.GetRun(runsDir, c.runID, "data/labels.jsonl")
		if data == nil {
			fmt.Println("  GetRun returned nil!")
			continue
		}

		details, _ := data["details"].([]map[string]any)
		fmt.Printf("  details count: %d\n", len(details))

		var primary map[string]any
		for _, d := range details {
			bh, _ := d["bughash"].(string)
			if bh == c.bughash {
				primary = d
				break
			}
		}
		if primary == nil {
			fmt.Println("  ALERT NOT FOUND in details!")
			continue
		}

		fmt.Printf("  verdict: %v\n", primary["verdict"])
		fmt.Printf("  vulnerability_type: %v\n", primary["vulnerability_type"])

		// Check exploit_path in detail
		ep, _ := primary["exploit_path"].(map[string]any)
		if ep == nil {
			fmt.Println("  ❌ exploit_path: MISSING from detail")
		} else {
			fmt.Println("  ✓ exploit_path: present in detail")
			df, _ := ep["data_flow"].([]any)
			fmt.Printf("    data_flow steps: %d\n", len(df))
			for i, s := range df {
				fmt.Printf("    step %d: %.80s...\n", i, s)
			}
			fmt.Printf("    sink_reached: %v\n", ep["sink_reached"])
			se, _ := ep["sink_evidence"].(map[string]any)
			if se != nil {
				sc, _ := se["sink_code"].(string)
				if sc != "" {
					fmt.Printf("    sink_code: %d chars (first 50: %.50s)\n", len(sc), sc)
				} else {
					fmt.Println("    sink_code: EMPTY")
				}
			} else {
				fmt.Println("    sink_evidence: MISSING")
			}
		}

		// Check trace
		trace := runsread.Trace(runsDir, c.runID, c.bughash)
		if trace == nil {
			fmt.Println("  ❌ trace: nil (file not found)")
			continue
		}
		tm, _ := trace.(map[string]any)
		if tm == nil {
			fmt.Println("  ❌ trace: not a map")
			continue
		}
		fmt.Println("  ✓ trace: loaded")

		sliced, _ := tm["sliced"].(map[string]any)
		if sliced == nil {
			fmt.Println("  ❌ sliced: MISSING from trace")
		} else {
			hops, _ := sliced["hops"].([]any)
			fmt.Printf("  ✓ sliced: present, hops count: %d\n", len(hops))
			for i, h := range hops {
				hm, _ := h.(map[string]any)
				if hm == nil {
					continue
				}
				fb, _ := hm["function_body"].(string)
				fp, _ := hm["file_path"].(string)
				fn, _ := hm["function_name"].(string)
				fmt.Printf("    hop %d: file=%s fn=%s body_len=%d\n", i, fp, fn, len(fb))
			}
		}

		// Also check if exploit_path is in the TRACE (LLM raw response)
		epTrace, _ := tm["exploit_path"].(map[string]any)
		if epTrace != nil {
			fmt.Println("  ✓ exploit_path also in trace")
		}
	}
	os.Exit(0)
}
