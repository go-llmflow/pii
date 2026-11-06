package pii

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// ---- e-mail: a practical subset of RFC 5322 §3.4.1 addr-spec ----
//
// local-part is a dot-atom (RFC 5322 §3.2.3) over atext minus the characters
// that in practice delimit an address in prose or a URL ("/", "|", "{", "}",
// "`"); quoted local parts and domain literals are left out. The domain is
// LDH labels with a letter-only top-level label. Lengths follow RFC 5321
// §4.5.3.1: local part at most 64 octets, the whole address at most 254.

const atext = `A-Za-z0-9!#$%&'*+=?^_~-`

// atextChars is atext's punctuation, as bytes (the letters and digits are
// tested with isAlnum).
const atextChars = `!#$%&'*+=?^_~-`

var emailRE = regexp.MustCompile(`[` + atext + `]+(?:\.[` + atext + `]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}`)

func findEmail(s string) []Match {
	var out []Match
	scan(emailRE, emailClass, s, false, func(a, b int) (int, bool) {
		at := strings.IndexByte(s[a:b], '@')
		if at > 64 || b-a > MaxLen {
			return 0, false
		}
		if before(s, a) == '@' {
			return 0, false
		}
		// A dot before the match is not part of the address ("...john@x.org",
		// an ellipsis) or begins a malformed dotted name ("a..b@x.org"): the
		// whole run of atext and dots is masked, bar the leading dots, so
		// that no part of the local part stays in clear.
		if before(s, a) == '.' {
			lo := 0
			if len(out) > 0 {
				lo = out[len(out)-1].End
			}
			start := a
			for start > lo && (s[start-1] == '.' || strings.IndexByte(atextChars, s[start-1]) >= 0 || isAlnum(s[start-1])) {
				start--
			}
			for start < a && s[start] == '.' {
				start++
			}
			if at := strings.IndexByte(s[start:b], '@'); at > 64 || b-start > MaxLen {
				return 0, false
			}
			a = start
		}
		if c := after(s, b); isAlnum(c) || c == '-' || c == '@' {
			return 0, false
		}
		// git@github.com:org/repo.git is an SSH login and a host, not a
		// mailbox: a colon glued to a path.
		if after(s, b) == ':' && b+1 < len(s) && s[b+1] != ' ' && s[b+1] != '\n' {
			return 0, false
		}
		out = append(out, Match{Email, a, b})
		return b, true
	})
	return out
}

// ---- phone: E.164 and the French national plan ----
//
// E.164 numbers are "+" then at most 15 digits, the country code first
// (ITU-T E.164; written with "+" per E.123). French numbers are 10 digits
// starting with 0 and a non-zero digit, customarily written as five pairs; in
// international form the 0 is replaced by +33 (or 0033).

var (
	frPhoneRE   = regexp.MustCompile(`(?:\+33[ .-]?(?:\(0\)[ .-]?)?|0033[ .-]?|0)[1-9](?:[ .-]?[0-9]{2}){4}`)
	e164PhoneRE = regexp.MustCompile(`\+[1-9](?:[ .-]?[0-9]){7,14}`)

	phonePatterns = []struct {
		re, whole *regexp.Regexp // whole: anchored at both ends
		class     *class
	}{
		{frPhoneRE, regexp.MustCompile(`\A(?:` + frPhoneRE.String() + `)\z`), frPhoneCls},
		{e164PhoneRE, regexp.MustCompile(`\A(?:` + e164PhoneRE.String() + `)\z`), e164Class},
	}
)

func findPhone(s string) []Match {
	var out []Match
	for _, c := range phoneCandidates(s) {
		out = append(out, c.Match)
	}
	return out
}

// phoneCandidates runs the French pattern, then E.164. A number shortened
// to end before a separator is a weak candidate (Find lets any overlapping
// candidate win over it).
func phoneCandidates(s string) []candidate {
	var out []candidate
	var fr []Match // the French pattern's matches, in order, disjoint
	for pi, p := range phonePatterns {
		scan(p.re, p.class, s, true, func(a, b int) (int, bool) {
			if c := before(s, a); isAlnum(c) || c == '+' || c == '.' || c == '-' {
				return 0, false
			}
			// The regexp is greedy: "+10000010 0100000000" gives
			// "+10000010 010000", refused below because a digit follows.
			// The shorter "+10000010" is a number too, and masking the
			// rest would leave it in clear (found by FuzzFind). So the
			// longest prefix that ends before a separator, matches the
			// whole pattern and passes the checks is taken.
			for end := b; end > a; end-- {
				if end != b && s[end] != ' ' && s[end] != '.' && s[end] != '-' {
					continue
				}
				if end != b && !p.whole.MatchString(s[a:end]) {
					continue
				}
				if c := after(s, end); isDigit(c) || (c == '.' || c == '-') && isDigit(after(s, end+1)) {
					continue
				}
				if digits(s[a:end]) > 15 {
					continue
				}
				// An end that cuts a French number found by the first
				// pattern would hide its tail: overlapping matches are
				// resolved by start, so "+10000010 06 12 34" would win
				// over "06 12 34 56 78" and leave "56 78" in clear.
				if end != b && cuts(fr, end) {
					continue
				}
				m := Match{Phone, a, end}
				out = append(out, candidate{Match: m, weak: end != b})
				if pi == 0 {
					fr = append(fr, m)
				}
				return end, true
			}
			return 0, false
		})
	}
	return out
}

// cuts reports whether position end falls strictly inside one of ms, which
// are ordered and disjoint (binary search: a text full of numbers must not
// make this quadratic).
func cuts(ms []Match, end int) bool {
	i := sort.Search(len(ms), func(i int) bool { return ms[i].Start >= end })
	return i > 0 && end < ms[i-1].End
}

func digits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			n++
		}
	}
	return n
}

// ---- IBAN: ISO 13616 ----
//
// Two letters of country, two check digits, then the national account
// number; the length is fixed per country, at most 34. Valid when, the first
// four characters moved to the end and each letter replaced by two digits
// (A=10 … Z=35), the number mod 97 is 1. Printed in groups of four separated
// by spaces, which are accepted.

// Letters of either case are accepted, and read as capitals by the check
// (ISO 13616 writes an IBAN in capitals, but people and models type
// "fr76 3000 ...").

// ibanLen is the IBAN length of each country in the SWIFT registry
// (as listed under "IBAN formats by country").
var ibanLen = map[string]int{
	"AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28, "BE": 16, "BA": 20, "BR": 29, "BG": 22,
	"BI": 27, "CR": 22, "HR": 21, "CY": 28, "CZ": 24, "DK": 18, "DJ": 27, "DO": 28, "TL": 23, "EG": 29,
	"SV": 28, "EE": 20, "FK": 18, "FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22, "GI": 23, "GR": 27,
	"GL": 18, "GT": 28, "HN": 28, "HU": 28, "IS": 26, "IQ": 23, "IE": 22, "IL": 23, "IT": 27, "JO": 30,
	"KZ": 20, "XK": 20, "KW": 30, "LV": 21, "LB": 28, "LY": 25, "LI": 21, "LT": 20, "LU": 20, "MT": 31,
	"MR": 27, "MU": 30, "MC": 27, "MD": 24, "MN": 20, "ME": 22, "NL": 18, "NI": 28, "MK": 19, "NO": 15,
	"OM": 23, "PK": 24, "PS": 29, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "RU": 33, "LC": 32, "SM": 27,
	"ST": 25, "SA": 24, "RS": 22, "SC": 31, "SK": 24, "SI": 19, "SO": 23, "ES": 24, "SD": 18, "SE": 24,
	"CH": 21, "TN": 24, "TR": 26, "UA": 29, "AE": 23, "GB": 22, "VA": 22, "VG": 24, "YE": 30,
}

// findIBAN reads the text by hand, not with a regexp: letters of either case
// are accepted (a lower-case "fr76 3000 ..." is read as capitals), which made
// the byte class of a run-based regexp scan cover every word of a prose text.
// The shape is the one of the pattern
// `[A-Za-z]{2}[0-9]{2}(?: ?[A-Za-z0-9]){11,30}` (ibanReference in the tests is
// that pattern, and the two are compared), and a refused candidate resumes just
// after its start, as every other recogniser does.
func findIBAN(s string) []Match {
	var out []Match
	var compact [34]byte
	for i := 0; i+4 <= len(s); {
		if !isDigit(s[i+2]) || !isDigit(s[i+3]) || !isAlpha(s[i]) || !isAlpha(s[i+1]) || isAlnum(before(s, i)) {
			i++
			continue
		}
		cc := [2]byte{upper(s[i]), upper(s[i+1])}
		n, ok := ibanLen[string(cc[:])]
		if !ok {
			i++
			continue
		}
		// Take exactly n characters, skipping single spaces.
		copy(compact[:4], s[i:i+4])
		k, b := 4, i+4
		for k < n && b < len(s) {
			c := s[b]
			if isAlnum(c) {
				compact[k] = c
				k++
				b++
			} else if c == ' ' && isAlnum(after(s, b+1)) {
				b++
			} else {
				break
			}
		}
		if k != n || isAlnum(after(s, b)) || !ValidIBAN(string(compact[:k])) {
			i++
			continue
		}
		out = append(out, Match{IBAN, i, b})
		i = b
	}
	return out
}

// upper is the ASCII capital of c.
func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

// ValidIBAN reports whether s, without spaces, is an IBAN of its country's
// length whose ISO 13616 check (mod 97 = 1) holds.
func ValidIBAN(s string) bool {
	if len(s) < 5 || len(s) > 34 {
		return false
	}
	cc := [2]byte{upper(s[0]), upper(s[1])}
	if ibanLen[string(cc[:])] != len(s) {
		return false
	}
	r := s[4:] + s[:4]
	m := 0
	for i := 0; i < len(r); i++ {
		c := upper(r[i])
		switch {
		case isDigit(c):
			m = (m*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			m = (m*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return m == 1
}

// ---- NIR: the French social security number (INSEE) ----
//
// 13 characters then a 2-digit key: sex (1, 2; 3, 4, 7, 8 during
// registration), year, month (01-12, or 13 and 20-42, 50-99 for incomplete
// civil records), department (2 characters, 2A/2B for Corsica, or 3 digits
// overseas), commune and order number. key = 97 − (the 13 digits mod 97),
// with 2A read as 19 and 2B as 18. Spaces between the parts are accepted.

var nirRE = regexp.MustCompile(`[1-478](?: ?[0-9]){4} ?(?:[0-9]{2}|2[ABab])(?: ?[0-9]){8}`)

func findNIR(s string) []Match {
	var out []Match
	scan(nirRE, nirClass, s, true, func(a, b int) (int, bool) {
		if isAlnum(before(s, a)) || isAlnum(after(s, b)) {
			return 0, false
		}
		if !ValidNIR(strings.ReplaceAll(s[a:b], " ", "")) {
			return 0, false
		}
		out = append(out, Match{NIR, a, b})
		return b, true
	})
	return out
}

// ValidNIR reports whether s (15 characters, no spaces) is a NIR whose key
// matches.
func ValidNIR(s string) bool {
	if len(s) != 15 {
		return false
	}
	switch s[0] {
	case '1', '2', '3', '4', '7', '8':
	default:
		return false
	}
	month := s[3:5]
	if !isDigit(month[0]) || !isDigit(month[1]) {
		return false
	}
	switch mm := int(month[0]-'0')*10 + int(month[1]-'0'); {
	case mm >= 1 && mm <= 13, mm >= 20 && mm <= 42, mm >= 50:
	default:
		return false
	}
	body := s[:13]
	switch strings.ToUpper(s[5:7]) {
	case "2A":
		body = s[:5] + "19" + s[7:13]
	case "2B":
		body = s[:5] + "18" + s[7:13]
	}
	m := 0
	for i := 0; i < 13; i++ {
		if !isDigit(body[i]) {
			return false
		}
		m = (m*10 + int(body[i]-'0')) % 97
	}
	if !isDigit(s[13]) || !isDigit(s[14]) {
		return false
	}
	key := int(s[13]-'0')*10 + int(s[14]-'0')
	return key == 97-m
}

// ---- payment cards: ISO/IEC 7812 ----
//
// 13 to 19 digits whose last is a Luhn check digit (ISO/IEC 7812-1 annex B),
// with an issuer prefix of a major network: Visa 4 (13, 16, 19), Mastercard
// 51-55 and 2221-2720 (16), American Express 34, 37 (15), Discover 6011,
// 644-649, 65 (16-19), JCB 3528-3589 (16-19), Diners 30, 36, 38, 39 (14-19).
// Digits may be grouped by single spaces or dashes.

// Bounded at 19 digits: with the restart after a refused candidate, an
// unbounded pattern would read the rest of a long run of digits again for
// each start.
var cardRE = regexp.MustCompile(`[0-9](?:[ -]?[0-9]){12,18}`)

// maxCardText is the longest card text: 19 digits, 18 separators.
const maxCardText = 19 + 18

func findCard(s string) []Match {
	var out []Match
	scan(cardRE, cardClass, s, true, func(a, b int) (int, bool) {
		if isAlnum(before(s, a)) {
			return 0, false
		}
		// The whole run, or a prefix of it ending before a separator (a card
		// followed by more grouped digits: "4111 1111 1111 1111 2028"). A
		// card is at most 19 digits and 18 separators: ends beyond that
		// cannot validate, and trying them all made a long run of digits
		// quadratic.
		// The digits once, with the number of digits before each byte, so
		// that each end costs one check instead of re-reading the text.
		var d [19]byte
		var seen [maxCardText + 1]int8
		n := 0
		top := min(b, a+maxCardText)
		for i := a; i < top; i++ {
			seen[i-a] = int8(n)
			if isDigit(s[i]) {
				if n == len(d) {
					top = i
					break
				}
				d[n] = s[i]
				n++
			}
		}
		seen[top-a] = int8(n)
		if n < 13 || !knownNetworkPrefix(d[:n]) {
			return 0, false
		}
		for end := top; end > a; end-- {
			if end != b && s[end] != ' ' && s[end] != '-' {
				continue
			}
			if end == b && isAlnum(after(s, b)) {
				continue
			}
			if k := int(seen[end-a]); k >= 13 && ValidCard(string(d[:k])) {
				out = append(out, Match{Card, a, end})
				return end, true
			}
		}
		return 0, false
	})
	return out
}

func validCardText(t string) bool {
	var d [19]byte
	n := 0
	for i := 0; i < len(t); i++ {
		if isDigit(t[i]) {
			if n == len(d) {
				return false
			}
			d[n] = t[i]
			n++
		}
	}
	return ValidCard(string(d[:n]))
}

// ValidCard reports whether s (digits only) has a known network's prefix and
// length and a valid Luhn check digit.
func ValidCard(s string) bool {
	n := len(s)
	if n < 13 || n > 19 || !knownNetwork(s) {
		return false
	}
	return Luhn(s)
}

func prefix(s string, k int) int {
	v := 0
	for i := 0; i < k && i < len(s); i++ {
		v = v*10 + int(s[i]-'0')
	}
	return v
}

// knownNetworkPrefix: the first digit of every network's prefix (2 to 6);
// a cheap refusal before any length is tried.
func knownNetworkPrefix(d []byte) bool { return len(d) > 0 && d[0] >= '2' && d[0] <= '6' }

func knownNetwork(s string) bool {
	n := len(s)
	p1, p2, p3, p4 := prefix(s, 1), prefix(s, 2), prefix(s, 3), prefix(s, 4)
	switch {
	case p1 == 4:
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
		return n == 16
	case p2 == 34 || p2 == 37:
		return n == 15
	case p4 == 6011, p3 >= 644 && p3 <= 649, p2 == 65:
		return n >= 16
	case p4 >= 3528 && p4 <= 3589:
		return n >= 16
	case p2 == 30 || p2 == 36 || p2 == 38 || p2 == 39:
		return n >= 14
	}
	return false
}

// Luhn reports whether the digit string s passes the Luhn check.
func Luhn(s string) bool {
	if s == "" {
		return false
	}
	sum := 0
	for i := 0; i < len(s); i++ {
		c := s[len(s)-1-i]
		if !isDigit(c) {
			return false
		}
		d := int(c - '0')
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// ---- IP addresses ----
//
// IPv4 in dotted-decimal and IPv6 in the three text forms of RFC 4291 §2.2
// (full, "::"-compressed, and with a trailing dotted IPv4), each confirmed by
// net/netip (which also refuses IPv4 octets with leading zeros).

var (
	ipv4RE = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	// The form with a trailing IPv4 is tried first: otherwise the hex run
	// stops at "::ffff:192" and the rest reads as an IPv4 address.
	ipv6RE = regexp.MustCompile(`[0-9A-Fa-f:]*:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]*`)
)

func findIPv4(s string) []Match {
	var out []Match
	scan(ipv4RE, ipv4Class, s, true, func(a, b int) (int, bool) {
		if c := before(s, a); isAlnum(c) || c == '.' {
			return 0, false
		}
		// Not a version number or an OID: 1.2.3.4.5.
		if c := after(s, b); isAlnum(c) || c == '.' && isDigit(after(s, b+1)) {
			return 0, false
		}
		if ip, err := netip.ParseAddr(s[a:b]); err != nil || !ip.Is4() {
			return 0, false
		}
		out = append(out, Match{IPv4, a, b})
		return b, true
	})
	return out
}

func findIPv6(s string) []Match {
	var out []Match
	// No restart: the pattern is unbounded ([0-9A-Fa-f:]*), so resuming
	// inside a refused candidate would read a long run again for each start.
	scan(ipv6RE, ipv6Class, s, false, func(a, b int) (int, bool) {
		// The whole candidate first. Then what a neighbouring character hides:
		// a label glued to the address ("IPv6:2001:db8::1", "host:fe80::1"),
		// so that the candidate starts inside the label, and a colon closing
		// the address ("2001:db8::1: unreachable"). The starts tried are just
		// after the first colons only, and only a short candidate is split:
		// the pattern is unbounded, and a long run must not be tried at every
		// start.
		starts := [...]int{a, -1, -1, -1, -1}
		//
		// Only a letter before the candidate is a label: after a digit or a
		// dot, the text is a longer number whose other parts (a card, a
		// phone number) must not be cut by a start inside it.
		if b-a <= 2*maxIPv6Text && isAlpha(before(s, a)) {
			k := 1
			for i := a; i < b-1 && k < len(starts); i++ {
				if s[i] == ':' && s[i+1] != ':' {
					starts[k] = i + 1
					k++
				}
			}
		}
		for _, v := range starts {
			if v < 0 {
				break
			}
			for _, e := range [...]int{b, b - 1} {
				// Only one colon is trimmed, and not from a "::" (":::" is no
				// address followed by a colon).
				if e <= v || e < b && (s[e] != ':' || s[e-1] == ':') {
					continue
				}
				cand := s[v:e]
				if strings.Count(cand, ":") < 2 || !strings.ContainsAny(cand, "0123456789abcdefABCDEF") {
					continue
				}
				if v == a {
					if c := before(s, a); isAlnum(c) || c == ':' || c == '.' {
						continue
					}
				}
				// A colon that was trimmed closes the address, as it does a
				// sentence; it is no part of a longer address.
				if c := after(s, e); isAlnum(c) || c == ':' && e == b || c == '.' && isDigit(after(s, e+1)) {
					continue
				}
				if ip, err := netip.ParseAddr(cand); err != nil || !ip.Is6() || ip.Zone() != "" {
					continue
				}
				out = append(out, Match{IPv6, v, e})
				return e, true
			}
		}
		return 0, false
	})
	return out
}

// maxIPv6Text is the longest text form of an IPv6 address (RFC 4291 §2.2: 39
// for the full form, 45 with a trailing IPv4).
const maxIPv6Text = 45
