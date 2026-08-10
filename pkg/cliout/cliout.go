// Package cliout renders CLI command output for the --format / --json flags,
// so commands share one code path instead of hand-rolling json.Marshal + print.
//
// Only "json" ships today: this is deliberately the *output* half of the codec
// pattern. The decode half already lives in pkg/evidence (Parse / ParseSBOM).
// `fides report --format oscal` is NOT a client codec — the OSCAL document is
// produced server-side and the CLI just prints the bytes.
package cliout

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Render writes v to w in the named output format (case-insensitive). Only
// "json" is supported; any other format returns a "supported: json" error.
func Render(w io.Writer, format string, v any) error {
	if strings.ToLower(format) != "json" {
		return fmt.Errorf("unsupported output format %q (supported: json)", format)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
