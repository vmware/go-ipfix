package collector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFakeAfterFunc(t *testing.T) {
	start := time.Now()
	f := newFakeClock(start)
	ch := make(chan time.Time, 1)
	timer := f.AfterFunc(1*time.Second, func() {
		ch <- f.Now()
	})
	// After 1s, the timer should fire.
	f.Step(1 * time.Second)
	select {
	case v := <-ch:
		assert.Equal(t, start.Add(1*time.Second), v)
	default:
		t.Fatalf("timer didn't fire")
	}
	assert.False(t, timer.Stop(), "Stop should return false as timer has already been expired")
	// After resetting the timer, it should fire again after another 1s.
	assert.False(t, timer.Reset(1*time.Second), "Reset should return false as timer had expired")
	f.Step(1 * time.Second)
	select {
	case v := <-ch:
		assert.Equal(t, start.Add(2*time.Second), v)
	default:
		t.Fatalf("timer didn't fire")
	}

	assert.False(t, timer.Reset(1*time.Second), "Reset should return false as timer had expired")
	assert.True(t, timer.Stop(), "Stop should return true as call stops the timer")
	assert.False(t, timer.Stop(), "Stop should return false as timer has already been stopped")
	assert.False(t, timer.Reset(1*time.Second), "Reset should return false as timer had been stopped")

	// The timer should not fire until the target time is reached.
	f.Step(999 * time.Millisecond)
	select {
	case <-ch:
		t.Fatalf("timer should not have fired")
	default:
	}
	assert.True(t, timer.Reset(1*time.Second), "Reset should return true as timer had been active")
	f.Step(1 * time.Millisecond)
	select {
	case <-ch:
		t.Fatalf("timer should not have fired")
	default:
	}
	f.Step(999 * time.Millisecond)
	select {
	case v := <-ch:
		assert.Equal(t, start.Add(3999*time.Millisecond), v)
	default:
		t.Fatalf("timer didn't fire")
	}
}
