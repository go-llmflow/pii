package pii

import (
	"strings"
	"testing"
	"time"
)

// TestLongRunsStayLinear: 1 MiB of the bytes each pattern is made of. Before
// the bound on card candidates, a long run of digits tried every end of a
// match as long as the run (quadratic); the restart after a refused
// candidate must not bring that back. The bound is generous (a timing test
// on a shared machine), the failure it guards against is minutes.
func TestLongRunsStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("1 MiB inputs")
	}
	s := New()
	for _, unit := range []string{"0", "1 ", "+1", "a", "a@", "1.", ":", "::1", "FR", "4111 ", "0-", "+33 6 "} {
		text := strings.Repeat(unit, (1<<20)/len(unit))
		t0 := time.Now()
		s.Find(text)
		d := time.Since(t0)
		t.Logf("%q: %v", unit, d)
		if d > 5*time.Second {
			t.Errorf("%q × %d: %v", unit, len(text)/len(unit), d)
		}
	}
}
