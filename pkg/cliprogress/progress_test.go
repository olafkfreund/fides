package cliprogress

import (
	"io"
	"os"
	"strings"
	"testing"
)

// New must return a Nop when the writer isn't a terminal (a pipe never is) or
// when quiet — so progress never lands in a piped/CI stdout|stderr.
func TestNewReturnsNopWhenNotTTYOrQuiet(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	if _, ok := New(w, false).(Nop); !ok {
		t.Error("non-TTY writer: expected Nop")
	}
	if _, ok := New(w, true).(Nop); !ok {
		t.Error("quiet: expected Nop")
	}
	if _, ok := New(nil, false).(Nop); !ok {
		t.Error("nil writer: expected Nop")
	}
}

func TestNopIsSilentAndSafe(t *testing.T) {
	var n Nop
	n.StartStage("x")
	n.AdvanceStage(1, 2)
	n.CompleteStage("y") // must not panic
}

// CompleteStage promotes a finished stage to a "✔ summary" line; "" just erases.
func TestSpinnerCompleteWrites(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	s := newSpinner(w)
	s.CompleteStage("collected 12 artifacts")
	s.CompleteStage("") // safe with no active stage; erases only
	w.Close()

	buf, _ := io.ReadAll(r)
	if !strings.Contains(string(buf), "✔ collected 12 artifacts") {
		t.Errorf("missing checkmark line, got %q", buf)
	}
}
