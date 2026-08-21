// Package cliprogress shows live, TTY-only progress for long-running fides CLI
// commands. Commands depend on the small Reporter interface, never on the
// renderer — so they stay UI-agnostic and are trivially testable with Nop, and
// progress never pollutes stdout or a CI pipeline (it goes to stderr, and only
// when stderr is a terminal).
package cliprogress

import (
	"os"

	"golang.org/x/term"
)

// Reporter is what a command depends on to report progress.
type Reporter interface {
	StartStage(label string)      // begin a phase, e.g. "Snapshotting docker runtime"
	AdvanceStage(done, total int) // optional counter; total<=0 means indeterminate
	CompleteStage(summary string) // finish the phase; "" prints nothing
}

// Nop is the default Reporter: it prints nothing. Used under --json, when
// stderr is not a terminal (piped / CI), and in tests.
type Nop struct{}

func (Nop) StartStage(string)     {}
func (Nop) AdvanceStage(int, int) {}
func (Nop) CompleteStage(string)  {}

// New returns a live stderr spinner when w is a terminal and !quiet, otherwise
// a Nop. Pass os.Stderr so progress never lands on stdout.
func New(w *os.File, quiet bool) Reporter {
	if quiet || w == nil || !term.IsTerminal(int(w.Fd())) {
		return Nop{}
	}
	return newSpinner(w)
}
