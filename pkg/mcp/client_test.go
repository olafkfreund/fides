package mcp

import (
	"strings"
	"testing"
)

func TestAllowedStdioCommandsParsing(t *testing.T) {
	t.Setenv("FIDES_MCP_ALLOWED_COMMANDS", " npx , uvx ,, docker ")
	allowed := allowedStdioCommands()
	for _, want := range []string{"npx", "uvx", "docker"} {
		if !allowed[want] {
			t.Errorf("expected %q to be allowlisted", want)
		}
	}
	if allowed[""] {
		t.Errorf("empty entries must be ignored")
	}
	if len(allowed) != 3 {
		t.Errorf("expected 3 allowlisted commands, got %d", len(allowed))
	}
}

// TestCallToolStdioRejectsNonAllowlisted is the regression test for C2: a
// command that is not allowlisted must be refused before any exec happens.
func TestCallToolStdioRejectsNonAllowlisted(t *testing.T) {
	t.Setenv("FIDES_MCP_ALLOWED_COMMANDS", "npx")

	_, err := CallToolStdio("/bin/sh", []string{"-c", "echo pwned"}, nil, "tool", nil)
	if err == nil {
		t.Fatalf("expected non-allowlisted command to be rejected")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("expected an allowlist error, got: %v", err)
	}
}

func TestCallToolStdioDeniesWhenAllowlistEmpty(t *testing.T) {
	t.Setenv("FIDES_MCP_ALLOWED_COMMANDS", "")

	_, err := CallToolStdio("echo", []string{"hi"}, nil, "tool", nil)
	if err == nil {
		t.Fatalf("expected stdio exec to be denied with an empty allowlist (fail closed)")
	}
}
