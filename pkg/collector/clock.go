// Copyright 2024 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"sync"
	"time"
)

// timer allows for injecting fake or real timers into code that needs to do arbitrary things based
// on time. We do not include the C() method, as we only support timers created with AfterFunc.
type timer interface {
	Stop() bool
	Reset(d time.Duration) bool
}

// clock allows for injecting fake or real clocks into code that needs to do arbitrary things based
// on time. We only support a very limited interface at the moment, with only the methods required
// by CollectingProcess.
type clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) timer
}

// realClock implements the clock interface using functions from the time package.
type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

func (realClock) AfterFunc(d time.Duration, f func()) timer {
	return time.AfterFunc(d, f)
}

type fakeTimer struct {
	targetTime time.Time
	f          func()
	clock      *fakeClock
}

func (t *fakeTimer) Stop() bool {
	clock := t.clock
	clock.m.Lock()
	defer clock.m.Unlock()
	newTimers := make([]*fakeTimer, 0, len(clock.timers))
	fired := true
	for i := range clock.timers {
		if clock.timers[i] != t {
			newTimers = append(newTimers, t)
			continue
		}
		// timer is found so it hasn't been fired yet
		fired = false
	}
	clock.timers = newTimers
	return !fired
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	clock := t.clock
	clock.m.Lock()
	defer clock.m.Unlock()
	fired := true
	t.targetTime = clock.now.Add(d)
	for i := range clock.timers {
		if clock.timers[i] == t {
			// timer is found so it hasn't been fired yet
			fired = false
			break
		}
	}
	if fired {
		clock.timers = append(clock.timers, t)
	}
	return !fired
}

// fakeClock implements the clock interface as a virtual clock meant to be used in tests. Time can
// be advanced arbitrarily, but does not change on its own.
type fakeClock struct {
	m           sync.RWMutex
	isAdvancing bool
	now         time.Time
	timers      []*fakeTimer
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{
		now: t,
	}
}

func (c *fakeClock) Now() time.Time {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) timer {
	if d <= 0 {
		panic("negative duration not supported")
	}
	c.m.Lock()
	defer c.m.Unlock()
	t := &fakeTimer{
		targetTime: c.now.Add(d),
		f:          f,
		clock:      c,
	}
	c.timers = append(c.timers, t)
	return t
}

func (c *fakeClock) Step(d time.Duration) {
	if d < 0 {
		panic("invalid duration")
	}
	timerFuncs := []func(){}
	func() {
		c.m.Lock()
		defer c.m.Unlock()
		if c.isAdvancing {
			panic("concurrent calls to Step() not allowed")
		}
		c.isAdvancing = true
		c.now = c.now.Add(d)
		// Collect timer functions to run and remove them from list.
		newTimers := make([]*fakeTimer, 0, len(c.timers))
		for _, t := range c.timers {
			if !t.targetTime.After(c.now) {
				timerFuncs = append(timerFuncs, t.f)
			} else {
				newTimers = append(newTimers, t)
			}
		}
		c.timers = newTimers
	}()
	// Run the timer functions, without holding a lock. This allows these functions to call
	// clock.Now(), but also timer.Stop().
	for _, f := range timerFuncs {
		f()
	}
	c.m.Lock()
	defer c.m.Unlock()
	c.isAdvancing = false
}
