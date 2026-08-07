package main

import (
	"encoding/json"
	"os"

	"tunnel-suite/internal/report"
)

func writeJSON(path string, rep *report.Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
