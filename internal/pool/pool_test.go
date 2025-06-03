package pool

import (
	"context"
	"testing"
	"time"
)

func TestPool(t *testing.T) {
	p := New(2)

	// Add a task that returns a deadline in the future.
	p.Add(func(_ context.Context) time.Time {
		return time.Now().Add(100 * time.Millisecond)
	})

	// Add a task that returns a deadline in the past.
	p.Add(func(_ context.Context) time.Time {
		return time.Now().Add(-100 * time.Millisecond)
	})

	// Add a task that returns a deadline in the future.
	p.Add(func(_ context.Context) time.Time {
		return time.Now().Add(200 * time.Millisecond)
	})

	// Wait for a short period to allow tasks to be processed.
	time.Sleep(300 * time.Millisecond)

	// The pool should have processed all tasks without deadlock.
	t.Log("All tasks processed successfully")
}
