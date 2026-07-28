package cliprogress

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// spinnerFrames is the classic Braille dot cycle (bomly uses the same MiniDot look).
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinner redraws a single \r-prefixed line on w every ~100ms from a background
// goroutine, guarded by a mutex so a command can update the counter concurrently.
type spinner struct {
	w   *os.File
	mu  sync.Mutex
	rem chan struct{} // closed to stop the current stage's goroutine

	label string
	cur   int
	total int
}

func newSpinner(w *os.File) *spinner { return &spinner{w: w} }

func (s *spinner) StartStage(label string) {
	s.stop() // end any prior stage's line without promoting it
	s.mu.Lock()
	s.label, s.cur, s.total = label, 0, 0
	s.rem = make(chan struct{})
	stop := s.rem
	s.mu.Unlock()
	go s.run(stop)
}

func (s *spinner) AdvanceStage(done, total int) {
	s.mu.Lock()
	s.cur, s.total = done, total
	s.mu.Unlock()
}

func (s *spinner) CompleteStage(summary string) {
	s.stop()
	if summary != "" {
		fmt.Fprintf(s.w, "\r\033[K✔ %s\n", summary) // promote to a ✔ line
	} else {
		fmt.Fprint(s.w, "\r\033[K") // just erase the spinner line
	}
}

func (s *spinner) stop() {
	s.mu.Lock()
	if s.rem != nil {
		close(s.rem)
		s.rem = nil
	}
	s.mu.Unlock()
}

func (s *spinner) run(stop <-chan struct{}) {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-stop:
			return
		case <-t.C:
			s.mu.Lock()
			label, cur, total := s.label, s.cur, s.total
			s.mu.Unlock()
			count := ""
			if total > 0 {
				count = fmt.Sprintf(" %d/%d", cur, total)
			}
			fmt.Fprintf(s.w, "\r\033[K%s %s%s", spinnerFrames[i%len(spinnerFrames)], label, count)
		}
	}
}
