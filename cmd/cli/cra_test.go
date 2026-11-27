package main

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCRAStageCommands(t *testing.T) {
	if endpoint := os.Getenv("FIDES_TEST_CRA_ENDPOINT"); endpoint != "" {
		handleCRA(CLIConfig{ServerURL: endpoint, Token: "fixture"}, os.Args[3:])
		return
	}
	const id = "d90baabe-29a9-4069-84c9-2f16211b3ebd"
	const payload = `{"stage":"notification"}`
	file := filepath.Join(t.TempDir(), "notification.json")
	if err := os.WriteFile(file, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ command, endpoint string }{
		{"export", "exports"},
		{"submit", "submissions"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			srv, got := recordingServer(t, `{"id":"fixture"}`)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCRAStageCommands$", "--",
				tc.command, "--case", id, "--file", file)
			cmd.Env = append(os.Environ(), "FIDES_TEST_CRA_ENDPOINT="+srv.URL)
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), `{"id":"fixture"}`) {
				t.Fatalf("CRA %s returned %v, output %q", tc.command, err, output)
			}
			wantPath := "/api/v1/cra/cases/" + id + "/" + tc.endpoint
			if got.method != http.MethodPost || got.path != wantPath || got.raw != payload {
				t.Fatalf("unexpected CRA request: %+v", got)
			}
		})
	}
}
