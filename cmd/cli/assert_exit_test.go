package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"fides/pkg/exitcode"
)

func TestAssertCommand(t *testing.T) {
	if os.Getenv("FIDES_SUBPROCESS") == "1" {
		os.Args = append([]string{os.Args[0]}, os.Args[3:]...)
		main()
		return
	}
	for _, tt := range []struct {
		name   string
		status int
		body   string
		policy string
		exit   int
		output string
	}{
		{name: "compliant", status: 200, body: `{"compliant":true}`, output: "COMPLIANCE PASS"},
		{name: "noncompliant", status: 200, body: `{"compliant":false,"violations":["failed control"]}`, exit: 2, output: "failed control"},
		{name: "HTTP error with verdict", status: 403, body: `{"compliant":true}`, exit: 1, output: "HTTP 403"},
		{name: "HTTP error with text", status: 500, body: "internal error", exit: 1, output: "HTTP 500"},
		{name: "invalid JSON", status: 200, body: "{", exit: 1, output: "Failed to parse response"},
		{name: "trailing JSON", status: 200, body: `{"compliant":true}{}`, exit: 1, output: "Failed to parse response"},
		{name: "missing verdict", status: 200, body: "{}", exit: 1, output: "expected a boolean compliant field"},
		{name: "null verdict", status: 200, body: `{"compliant":null}`, exit: 1, output: "expected a boolean compliant field"},
		{name: "string verdict", status: 200, body: `{"compliant":"false"}`, exit: 1, output: "expected a boolean compliant field"},
		{name: "transport failure", exit: 1, output: "Server check failed"},
		{name: "unsupported policy", status: 200, policy: "prod", exit: 1, output: "--policy is unsupported"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.policy != "" {
					t.Error("unsupported selector sent a request")
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			if tt.status == 0 {
				srv.Close()
			}
			args := []string{"-test.run=^TestAssertCommand$", "--", "assert", "--sha256", "digest"}
			if tt.policy != "" {
				args = append(args, "--policy", tt.policy)
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "FIDES_SUBPROCESS=1", "FIDES_SERVER_URL="+srv.URL)
			output, err := cmd.CombinedOutput()
			exit := 0
			if err != nil {
				var processErr *exec.ExitError
				if !errors.As(err, &processErr) {
					t.Fatal(err)
				}
				exit = processErr.ExitCode()
			}
			if exit != tt.exit || !strings.Contains(string(output), tt.output) {
				t.Fatalf("exit %d, output %q, want exit %d and %q", exit, output, tt.exit, tt.output)
			}
		})
	}
}

// A non-compliant artifact must exit 2 (Violation), not 1 — so CI gates the
// same way it does for verify-image/change-gate. Compliant exits 0.
func TestAssertExit(t *testing.T) {
	if got := assertExit(true); got != exitcode.OK {
		t.Errorf("compliant => %d, want %d", got, exitcode.OK)
	}
	if got := assertExit(false); got != exitcode.Violation {
		t.Errorf("non-compliant => %d, want %d (2)", got, exitcode.Violation)
	}
	if exitcode.Violation != 2 || exitcode.Error != 1 || exitcode.OK != 0 {
		t.Fatalf("exit-code convention drifted: OK=%d Error=%d Violation=%d", exitcode.OK, exitcode.Error, exitcode.Violation)
	}
}
