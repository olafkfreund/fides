package events

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDispatchBatchCanceledClaim(t *testing.T) {
	pool, err := sql.Open("postgres", "")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := NewDispatcher(pool).DispatchBatch(ctx)
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("DispatchBatch = (%d, %v), want (0, context.Canceled)", n, err)
	}
}

type recordingSink struct {
	name      string
	mu        sync.Mutex
	delivered []uuid.UUID
	failFirst int // fail this many initial calls, then succeed
	calls     int
}

func (r *recordingSink) Name() string { return r.name }

func (r *recordingSink) Deliver(_ context.Context, ev Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls <= r.failFirst {
		return errors.New("simulated sink failure")
	}
	r.delivered = append(r.delivered, ev.ID)
	return nil
}

func (r *recordingSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.delivered)
}

func TestBackoffIsMonotonicAndCapped(t *testing.T) {
	d := NewDispatcher(nil)
	d.BaseBackoff = time.Second
	d.MaxBackoff = 30 * time.Second

	var prev time.Duration
	for attempts := 1; attempts <= 12; attempts++ {
		got := d.backoff(attempts)
		if got < prev {
			t.Fatalf("backoff decreased at attempt %d: %v < %v", attempts, got, prev)
		}
		if got > d.MaxBackoff {
			t.Fatalf("backoff exceeded cap at attempt %d: %v", attempts, got)
		}
		prev = got
	}
	if prev != d.MaxBackoff {
		t.Fatalf("backoff should reach the cap, got %v", prev)
	}
}
