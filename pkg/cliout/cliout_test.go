package cliout

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestRenderJSON(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "json", map[string]int{"n": 1}); err != nil {
		t.Fatalf("json: %v", err)
	}
	// Indented, with the trailing newline the old fmt.Println emitted.
	if got, want := b.String(), "{\n  \"n\": 1\n}\n"; got != want {
		t.Fatalf("json output = %q, want %q", got, want)
	}
}

func TestRenderCaseInsensitive(t *testing.T) {
	if err := Render(io.Discard, "JSON", 1); err != nil {
		t.Fatalf("uppercase format rejected: %v", err)
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	err := Render(io.Discard, "yaml", 1)
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "supported: json") {
		t.Fatalf("error should list supported formats, got %q", err.Error())
	}
}

func TestRegister(t *testing.T) {
	Register("raw", func(w io.Writer, v any) error { _, e := fmt.Fprintf(w, "%v", v); return e })
	var b bytes.Buffer
	if err := Render(&b, "raw", 42); err != nil {
		t.Fatalf("raw: %v", err)
	}
	if b.String() != "42" {
		t.Fatalf("raw output = %q", b.String())
	}
	if !strings.Contains(Supported(), "raw") {
		t.Fatalf("Supported() missing registered format: %s", Supported())
	}
}
