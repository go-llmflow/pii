package pii

import (
	"strings"
	"testing"
	"time"
)

// TestLongRunsStayLinear: long runs of the bytes each pattern is made of.
// v0.1.0 tried every end of an unbounded card candidate: 1 MiB of "1 " took
// 11 min 56 s (measured 2026-10-26 under load). The test compares growth,
// not durations, so that it holds on a slow or loaded runner and under the
// race detector: from 128 KiB to 2 MiB, linear is ×16, quadratic ×256; the
// threshold, ×64, sits far from both (at load 80, linear measured ×9–×13
// for ×4 of size).
func TestLongRunsStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("MiB inputs")
	}
	s := New()
	timeOf := func(unit string, n int) time.Duration {
		text := strings.Repeat(unit, n/len(unit))
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 2; i++ {
			t0 := time.Now()
			s.Find(text)
			best = min(best, time.Since(t0))
		}
		return best
	}
	for _, unit := range []string{"0", "1 ", "+1", "a", "a@", "1.", ":", "::1", "FR", "4111 ", "0-", "+33 6 "} {
		small, big := timeOf(unit, 128<<10), timeOf(unit, 2<<20)
		t.Logf("%q: 128 KiB %v, 2 MiB %v", unit, small, big)
		if big > 64*small+100*time.Millisecond {
			t.Errorf("%q: 128 KiB in %v but 2 MiB in %v: not linear", unit, small, big)
		}
	}
}
