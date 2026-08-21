package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// The whole point of the lock is that concurrent starters do not overlap. A
// lock that is taken and released without excluding anyone would still let
// every test that only checks "fn ran" pass, so this asserts the exclusion
// itself: peak concurrency inside fn must never exceed 1.
//
// Reproduces the rolling-update shape that produced
// "pq: tuple concurrently updated (XX000)" on every sarc-aws deploy.
func TestWithSchemaLockSerialisesConcurrentCallers(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run schema lock integration tests")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := pool.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	const callers = 6
	var inside, peak, ran int32

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithSchemaLock(context.Background(), pool, func(context.Context) error {
				n := atomic.AddInt32(&inside, 1)
				for {
					p := atomic.LoadInt32(&peak)
					if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
						break
					}
				}
				// Hold it long enough that an ineffective lock would overlap.
				time.Sleep(40 * time.Millisecond)
				atomic.AddInt32(&inside, -1)
				atomic.AddInt32(&ran, 1)
				return nil
			})
			if err != nil {
				t.Errorf("WithSchemaLock: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&peak); got != 1 {
		t.Fatalf("peak concurrency inside the lock was %d, want 1 — the lock is not excluding anyone", got)
	}
	if got := atomic.LoadInt32(&ran); got != callers {
		t.Fatalf("only %d of %d callers ran; the lock must serialise, not drop work", got, callers)
	}
}

// A caller that fails must still release the lock, or one bad boot wedges every
// later one. The connection close would cover it, but the assertion is that the
// NEXT caller can proceed promptly.
func TestWithSchemaLockReleasesAfterError(t *testing.T) {
	dsn := os.Getenv("FIDES_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set FIDES_TEST_DB_DSN to run schema lock integration tests")
	}
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	boom := context.DeadlineExceeded
	if err := WithSchemaLock(context.Background(), pool, func(context.Context) error {
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("the callback's error must propagate unchanged, got %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- WithSchemaLock(context.Background(), pool, func(context.Context) error { return nil })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second caller: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock was not released after the callback errored — a failed boot would wedge every later one")
	}
}
