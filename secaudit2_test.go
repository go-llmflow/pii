package pii

// Security audit 2026-11-05 (2): untracked proof tests. Each value is in a
// form the README says is recognised; only the surrounding byte differs.

import (
	"strings"
	"testing"
)

func TestSecAudit2ContextLeavesValueInClear(t *testing.T) {
	s := New()
	for _, c := range []struct{ text, secret string }{
		{"write to me...john.doe@example.org", "john.doe@example.org"},
		{"IPv6:2001:db8::1 is down", "2001:db8::1"},
		{"host 2001:db8::1: unreachable", "2001:db8::1"},
		{"the gateway 2001:db8::1:, then", "2001:db8::1"},
		{"IBAN fr7630006000011234567890189", "fr7630006000011234567890189"},
		{"card 4111 1111 1111 1111", "4111 1111 1111 1111"},
		// controls: the same values in a neutral context
		{"write to me: john.doe@example.org", "john.doe@example.org"},
		{"host 2001:db8::1 unreachable", "2001:db8::1"},
		{"IBAN FR7630006000011234567890189", "FR7630006000011234567890189"},
	} {
		masked := Mask(c.text, s.Find(c.text), Placeholder)
		if c.secret != "" && strings.Contains(masked, c.secret) {
			t.Errorf("%q -> %q: %q left in clear", c.text, masked, c.secret)
		} else {
			t.Logf("%q -> %q", c.text, masked)
		}
	}
	// Corsica: the key computed independently (2A = 19 in the 13 digits).
	for _, dep := range []string{"2A", "2B"} {
		sub := map[string]int64{"2A": 19, "2B": 18}[dep]
		n := int64(2690500004018) + sub*1_000_000 // 2 69 05 [dep] 004 018
		key := 97 - n%97
		nir := "2 69 05 " + dep + " 004 018 " + string(rune('0'+key/10)) + string(rune('0'+key%10))
		if ms := s.Find("NIR " + nir); len(ms) != 1 || ms[0].Kind != NIR {
			t.Errorf("Corsica %s: %q not found: %v", dep, nir, ms)
		}
	}
}
