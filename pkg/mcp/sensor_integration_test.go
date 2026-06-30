package mcp

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Builds the real cmd/mcp-sensor binary and drives it through CallToolStdio,
// proving "Verify Compliance" works against a protocol-correct MCP server
// (unlike /bin/echo). This is the regression test for the broken demo.
func TestCallToolStdioAgainstRealSensor(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	bin := filepath.Join(t.TempDir(), "mcp-sensor")
	build := exec.Command("go", "build", "-o", bin, "fides/cmd/mcp-sensor")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build mcp-sensor: %v", err)
	}

	// Allowlist the freshly built binary.
	t.Setenv("FIDES_MCP_ALLOWED_COMMANDS", bin)

	want := `{"pods":[{"name":"a","status":"Ready","replicas":2,"readyReplicas":2}]}`
	out, err := CallToolStdio(bin, nil, map[string]string{"MCP_SENSOR_RESPONSE": want}, "get_pods", nil)
	if err != nil {
		t.Fatalf("CallToolStdio against real sensor: %v", err)
	}
	if out != want {
		t.Fatalf("tool output = %q, want %q", out, want)
	}
}
