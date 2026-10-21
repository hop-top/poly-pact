package clock_test

import (
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/core/clock"
)

var (
	_ clock.Clock = clock.SystemClock{}
	_ clock.Clock = (*clock.Fake)(nil)
)

func TestSystemClockTracksWallTime(t *testing.T) {
	before := time.Now()
	got := clock.SystemClock{}.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("Now() = %v, want within [%v, %v]", got, before, after)
	}
}

func TestFake(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	f := clock.NewFake(start)
	if got := f.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %v, want %v", got, start)
	}
	if got := f.Now(); !got.Equal(start) {
		t.Fatalf("a fake clock moved on its own: %v", got)
	}

	f.Advance(90 * time.Second)
	if got, want := f.Now(), start.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("after Advance, Now() = %v, want %v", got, want)
	}
	f.Advance(-30 * time.Second)
	if got, want := f.Now(), start.Add(60*time.Second); !got.Equal(want) {
		t.Fatalf("after negative Advance, Now() = %v, want %v", got, want)
	}

	reset := time.Unix(5, 500)
	f.Set(reset)
	if got := f.Now(); !got.Equal(reset) {
		t.Fatalf("after Set, Now() = %v, want %v", got, reset)
	}
}

func TestFakeIsSafeForConcurrentUse(t *testing.T) {
	f := clock.NewFake(time.Unix(0, 0))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				f.Advance(time.Second)
				_ = f.Now()
			}
		}()
	}
	wg.Wait()
	if got, want := f.Now(), time.Unix(800, 0); !got.Equal(want) {
		t.Fatalf("Now() = %v, want %v (an Advance was lost)", got, want)
	}
}
