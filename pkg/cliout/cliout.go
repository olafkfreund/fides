// Package cliout is a tiny registry of output encoders for the CLI's
// --format / --json flags. Commands call Render(w, format, v) instead of
// hand-rolling json.Marshal + print, and new formats self-register via Register.
//
// Only the "json" encoder ships today: this is deliberately the *output* half of
// the codec pattern. The decode half already lives in pkg/evidence (Parse /
// ParseSBOM). `fides report --format oscal` is NOT a client codec — the OSCAL
// document is produced server-side and the CLI just prints the bytes — so it is
// intentionally not registered here.
package cliout

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Encoder writes v to w in one output format.
type Encoder func(w io.Writer, v any) error

var registry = map[string]Encoder{
	"json": encodeJSON,
}

// Render encodes v to w using the named format (case-insensitive), or returns a
// "supported: …" error for an unknown format.
func Render(w io.Writer, format string, v any) error {
	enc, ok := registry[strings.ToLower(format)]
	if !ok {
		return fmt.Errorf("unsupported output format %q (supported: %s)", format, Supported())
	}
	return enc(w, v)
}

// Register adds (or overrides) an output format so future formats self-register
// with a single call instead of editing a switch in every command.
func Register(name string, e Encoder) { registry[strings.ToLower(name)] = e }

// Supported returns the registered format names, sorted, for help/error text.
func Supported() string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func encodeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
