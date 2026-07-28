package main

import (
	"testing"

	"fides/pkg/exitcode"
)

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
