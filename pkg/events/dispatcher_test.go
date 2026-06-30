package events

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

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

func TestDeliverFanOut(t *testing.T) {
	d := &Dispatcher{sinks: []Sink{&recordingSink{name: "a"}, &recordingSink{name: "b"}}}
	if err := d.deliver(context.Background(), Event{ID: uuid.New()}); err != nil {
		t.Fatalf("expected all sinks to succeed, got %v", err)
	}
}

func TestDeliverFailsIfAnySinkFails(t *testing.T) {
	d := &Dispatcher{sinks: []Sink{
		&recordingSink{name: "ok"},
		&recordingSink{name: "bad", failFirst: 1},
	}}
	err := d.deliver(context.Background(), Event{ID: uuid.New()})
	if err == nil {
		t.Fatalf("expected an error when one sink fails")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error should name the failing sink, got %v", err)
	}
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
