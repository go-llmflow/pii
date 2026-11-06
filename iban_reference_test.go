package pii

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// ibanReference is the regexp form of findIBAN, which reads the text by hand
// (for speed): the two must give the same matches.
var (
	ibanReferenceRE    = regexp.MustCompile(`[A-Za-z]{2}[0-9]{2}(?: ?[A-Za-z0-9]){11,30}`)
	ibanReferenceClass = newClass(anyOf(isAlpha, isDigit, oneOf(" ")), isDigit, 15, ibanReferenceRE)
)

func ibanReference(s string) []Match {
	var out []Match
	var compact [34]byte
	scanWhole(ibanReferenceRE, ibanReferenceClass, s, true, func(a, end int) (int, bool) {
		if isAlnum(before(s, a)) {
			return 0, false
		}
		cc := [2]byte{upper(s[a]), upper(s[a+1])}
		n, ok := ibanLen[string(cc[:])]
		if !ok {
			return 0, false
		}
		k, b := 0, a
		for b < end && k < n {
			if s[b] != ' ' {
				compact[k] = s[b]
				k++
			}
			b++
		}
		if k != n || isAlnum(after(s, b)) || !ValidIBAN(string(compact[:k])) {
			return 0, false
		}
		out = append(out, Match{IBAN, a, b})
		return b, true
	})
	return out
}

func sameMatches(a, b []Match) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFindIBANMatchesItsRegexpReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	valid := []string{"GB82WEST12345698765432", "gb82west12345698765432", "FR76 3000 6000 0112 3456 7890 189",
		"fr7630006000011234567890189", "DE89 3704 0044 0532 0130 00", "NO9386011117947"}
	alphabet := []string{" ", "  ", "A", "z", "0", "9", ".", ",", "-", "FR", "76", "GB", "82", "\n"}
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := rng.Intn(8); j >= 0; j-- {
			if rng.Intn(3) == 0 {
				b.WriteString(valid[rng.Intn(len(valid))])
			} else {
				b.WriteString(alphabet[rng.Intn(len(alphabet))])
			}
		}
		s := b.String()
		if got, want := findIBAN(s), ibanReference(s); !sameMatches(got, want) {
			t.Fatalf("%q: findIBAN %v, reference %v", s, got, want)
		}
	}
}
