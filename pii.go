// Package pii finds personal data in text: e-mail addresses, phone numbers,
// IBANs, French social security numbers (NIR), payment card numbers and IP
// addresses.
//
// Every recogniser that has a check digit uses it — mod-97 for IBAN (ISO
// 13616) and NIR (INSEE), Luhn for cards (ISO/IEC 7812-1 annex B) — and IP
// addresses are confirmed by net/netip, so a match is a value that could be
// real, not merely something with the right number of digits. Phone numbers
// and e-mail addresses have no checksum; they are matched on their format
// (E.164 and the French national plan; a practical subset of RFC 5322).
//
// The package only finds; what to do with a match is the caller's choice.
// [Mask] replaces matches, and [MaxLen] bounds the length of any match so
// that a caller masking a stream knows how much text to hold back.
package pii

import (
	"sort"
	"strings"
)

// Kind is a type of personal data.
type Kind string

const (
	Email Kind = "email"
	Phone Kind = "phone"
	IBAN  Kind = "iban"
	NIR   Kind = "nir"
	Card  Kind = "card"
	IPv4  Kind = "ipv4"
	IPv6  Kind = "ipv6"
)

// Kinds lists every kind, in the order overlapping matches are preferred
// when they start at the same place and have the same length: checksum-
// validated kinds first.
var Kinds = []Kind{IBAN, NIR, Card, Email, IPv6, IPv4, Phone}

// ParseKind returns the Kind named s.
func ParseKind(s string) (Kind, bool) {
	for _, k := range Kinds {
		if string(k) == s {
			return k, true
		}
	}
	return "", false
}

// MaxLen is the longest match, in bytes, of any kind: an e-mail address of
// at most 254 bytes (RFC 5321 §4.5.3.1.3 path limit). A streaming caller that
// holds back the last MaxLen bytes never releases the beginning of a match
// whose end it has not seen yet.
const MaxLen = 254

// Match is one finding: text[Start:End] is a value of the kind.
type Match struct {
	Kind       Kind
	Start, End int
}

// Scanner finds the kinds it was made for.
type Scanner struct {
	kinds map[Kind]bool
}

// New returns a Scanner for the given kinds, or every kind when none is
// given. An unknown kind is ignored by Find; use ParseKind to validate names.
func New(kinds ...Kind) *Scanner {
	if len(kinds) == 0 {
		kinds = Kinds
	}
	s := &Scanner{kinds: map[Kind]bool{}}
	for _, k := range kinds {
		s.kinds[k] = true
	}
	return s
}

// Find returns the matches in text, ordered by position and without overlap.
// Where two candidates overlap, the one that starts first wins, then the
// longer one, then the one earlier in Kinds.
func (s *Scanner) Find(text string) []Match {
	var all []Match
	for _, k := range Kinds {
		if s.kinds[k] {
			all = append(all, finders[k](text)...)
		}
	}
	rank := map[Kind]int{}
	for i, k := range Kinds {
		rank[k] = i
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End > b.End
		}
		return rank[a.Kind] < rank[b.Kind]
	})
	out := all[:0]
	end := 0
	for _, m := range all {
		if m.Start < end {
			continue
		}
		out = append(out, m)
		end = m.End
	}
	return out
}

// Mask returns text with each match replaced by repl(m). The matches must
// be ordered and must not overlap, as Find returns them.
func Mask(text string, matches []Match, repl func(Match) string) string {
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(text[last:m.Start])
		b.WriteString(repl(m))
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// Placeholder is the default replacement: the kind in capitals between
// brackets, "[IBAN]".
func Placeholder(m Match) string { return "[" + strings.ToUpper(string(m.Kind)) + "]" }

var finders = map[Kind]func(string) []Match{
	Email: findEmail,
	Phone: findPhone,
	IBAN:  findIBAN,
	NIR:   findNIR,
	Card:  findCard,
	IPv4:  findIPv4,
	IPv6:  findIPv6,
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// before and after return the byte around a candidate, 0 at the edges.
func before(s string, i int) byte {
	if i == 0 {
		return 0
	}
	return s[i-1]
}

func after(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}
