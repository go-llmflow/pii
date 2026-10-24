package pii

import (
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
)

// nirKey computes a NIR key with math/big and, for Corsica, the article's
// OTHER method (A and B read as 0, then 1 000 000 or 2 000 000 subtracted),
// so the oracle shares no code with ValidNIR.
func nirKey(body13 string) string {
	sub := int64(0)
	switch {
	case strings.Contains(body13, "A"):
		body13, sub = strings.Replace(body13, "A", "0", 1), 1000000
	case strings.Contains(body13, "B"):
		body13, sub = strings.Replace(body13, "B", "0", 1), 2000000
	}
	n, _ := new(big.Int).SetString(body13, 10)
	n.Sub(n, big.NewInt(sub))
	m := new(big.Int).Mod(n, big.NewInt(97)).Int64()
	return fmt.Sprintf("%02d", 97-m)
}

// ibanFor builds a valid IBAN with math/big from a country and a BBAN.
func ibanFor(cc, bban string) string {
	var num strings.Builder
	for _, c := range bban + cc + "00" {
		if c >= 'A' && c <= 'Z' {
			fmt.Fprintf(&num, "%d", c-'A'+10)
		} else {
			num.WriteRune(c)
		}
	}
	n, _ := new(big.Int).SetString(num.String(), 10)
	check := 98 - new(big.Int).Mod(n, big.NewInt(97)).Int64()
	return fmt.Sprintf("%s%02d%s", cc, check, bban)
}

func TestValidators(t *testing.T) {
	for _, s := range []string{
		"GB82WEST12345698765432", // ISO 13616 example
		"FR1420041010050500013M02606",
		"DE89370400440532013000",
		ibanFor("FR", "30006000011234567890189"),
		ibanFor("NO", "86011117947"),
	} {
		if !ValidIBAN(s) {
			t.Errorf("ValidIBAN(%s) = false", s)
		}
	}
	for _, s := range []string{"GB82WEST12345698765433", "FR1420041010050500013M0260", "XX82WEST12345698765432", "GB82west12345698765432"} {
		if ValidIBAN(s) {
			t.Errorf("ValidIBAN(%s) = true", s)
		}
	}
	for _, body := range []string{"1840576451089", "2690549588157", "185022A123456", "275122B345678", "1850597123456", "2991399123456"} {
		s := body + nirKey(body)
		if !ValidNIR(s) {
			t.Errorf("ValidNIR(%s) = false", s)
		}
		bad := body + fmt.Sprintf("%02d", (atoi(nirKey(body))%97)+1)
		if ValidNIR(bad) {
			t.Errorf("ValidNIR(%s) = true", bad)
		}
	}
	if ValidNIR("5840576451089" + nirKey("5840576451089")) {
		t.Error("sex digit 5 accepted")
	}
	if ValidNIR("1841476451089" + nirKey("1841476451089")) {
		t.Error("month 14 accepted")
	}
	// Test card numbers published by the networks.
	for _, s := range []string{"4111111111111111", "5555555555554444", "2223003122003222", "378282246310005", "6011111111111117", "3530111333300000", "30569309025904", "4222222222222"} {
		if !ValidCard(s) {
			t.Errorf("ValidCard(%s) = false", s)
		}
	}
	for _, s := range []string{"4111111111111112", "1234567812345670" /* Luhn-valid, no network */, "411111111111111"} {
		if ValidCard(s) {
			t.Errorf("ValidCard(%s) = true", s)
		}
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func kinds(ms []Match, text string) []string {
	var out []string
	for _, m := range ms {
		out = append(out, string(m.Kind)+"="+text[m.Start:m.End])
	}
	return out
}

func TestFindPositives(t *testing.T) {
	nir := "1840576451089" + nirKey("1840576451089")
	corsica := "275092B012345" + nirKey("275092B012345")
	cases := []struct{ text, want string }{
		{"write to jean.dupont@example.fr today", "email=jean.dupont@example.fr"},
		{"<a.b+tag@sub.example.co.uk>", "email=a.b+tag@sub.example.co.uk"},
		{"appelez le 06 12 34 56 78.", "phone=06 12 34 56 78"},
		{"tel: +33 6 12 34 56 78", "phone=+33 6 12 34 56 78"},
		{"tel +33 (0)1 23 45 67 89 ok", "phone=+33 (0)1 23 45 67 89"},
		{"call 01.23.45.67.89", "phone=01.23.45.67.89"},
		{"US: +1 202 555 0143", "phone=+1 202 555 0143"},
		{"IBAN FR14 2004 1010 0505 0001 3M02 606 merci", "iban=FR14 2004 1010 0505 0001 3M02 606"},
		{"GB82WEST12345698765432.", "iban=GB82WEST12345698765432"},
		{"NIR " + nir, "nir=" + nir},
		{"n° 1 84 05 76 451 089 " + nir[13:], "nir=1 84 05 76 451 089 " + nir[13:]},
		{"corse " + corsica, "nir=" + corsica},
		{"card 4111 1111 1111 1111 exp", "card=4111 1111 1111 1111"},
		{"card 4111-1111-1111-1111", "card=4111-1111-1111-1111"},
		{"amex 378282246310005", "card=378282246310005"},
		{"card 4111 1111 1111 1111 2028", "card=4111 1111 1111 1111"},
		{"host 192.168.1.20:8080", "ipv4=192.168.1.20"},
		{"v6 2001:db8::1 and fe80::1", "ipv6=2001:db8::1,ipv6=fe80::1"},
		{"mapped ::ffff:192.0.2.1 here", "ipv6=::ffff:192.0.2.1"},
		{"[2001:db8:0:0:0:0:2:1]:443", "ipv6=2001:db8:0:0:0:0:2:1"},
	}
	s := New()
	for _, tc := range cases {
		got := strings.Join(kinds(s.Find(tc.text), tc.text), ",")
		if got != tc.want {
			t.Errorf("Find(%q) = %s, want %s", tc.text, got, tc.want)
		}
	}
}

func TestScannerKinds(t *testing.T) {
	text := "a@b.example 4111111111111111 10.0.0.1"
	got := strings.Join(kinds(New(Card, IPv4).Find(text), text), ",")
	if got != "card=4111111111111111,ipv4=10.0.0.1" {
		t.Errorf("%s", got)
	}
	if k, ok := ParseKind("iban"); !ok || k != IBAN {
		t.Error("ParseKind iban")
	}
	if _, ok := ParseKind("ssn"); ok {
		t.Error("ParseKind ssn")
	}
}

func TestMask(t *testing.T) {
	text := "mail a@b.example, IBAN GB82 WEST 1234 5698 7654 32"
	got := Mask(text, New().Find(text), Placeholder)
	if got != "mail [EMAIL], IBAN [IBAN]" {
		t.Errorf("%q", got)
	}
}

// TestFalsePositives runs every recogniser over text that holds no personal
// data by construction — prose, code, versions, dates, identifiers and
// numbers shaped like the real thing — and fails above the counts measured
// when the recognisers were written (and reported in the README).
func TestFalsePositives(t *testing.T) {
	raw, err := os.ReadFile("testdata/benign.txt")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	got := map[Kind][]string{}
	for _, m := range New().Find(text) {
		got[m.Kind] = append(got[m.Kind], text[m.Start:m.End])
	}
	// Measured: the one phone is "ref 0123456789", a valid French number in
	// every respect but its meaning; nothing without a checksum can tell.
	allowed := map[Kind]int{Phone: 1}
	for _, k := range Kinds {
		t.Logf("%-5s %d %q", k, len(got[k]), got[k])
		if len(got[k]) > allowed[k] {
			t.Errorf("%s: %d false positives, at most %d: %q", k, len(got[k]), allowed[k], got[k])
		}
	}
	lines := strings.Count(text, "\n")
	t.Logf("corpus: %d lines, %d bytes", lines, len(text))
}

func TestMaxLen(t *testing.T) {
	long := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 58) + ".fr"
	if len(long) != 254 {
		t.Fatalf("len %d", len(long))
	}
	ms := New().Find(long)
	if len(ms) != 1 || ms[0].End-ms[0].Start != MaxLen {
		t.Fatalf("%+v", ms)
	}
	if ms := New().Find(long + "x.fr"); len(ms) != 0 {
		t.Fatalf("a 258-byte address matched: %+v", ms)
	}
}

// BenchmarkFind scans the benign corpus, repeated to 64 KiB: the cost of
// one large prompt with nothing to find.
func BenchmarkFind(b *testing.B) {
	raw, err := os.ReadFile("testdata/benign.txt")
	if err != nil {
		b.Fatal(err)
	}
	text := strings.Repeat(string(raw), 64<<10/len(raw)+1)[:64<<10]
	s := New()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		s.Find(text)
	}
}

func FuzzFind(f *testing.F) {
	f.Add("jean.dupont@example.fr 06 12 34 56 78 FR14 2004 1010 0505 0001 3M02 606")
	f.Add("4111 1111 1111 1111 2001:db8::1 192.168.0.1 ::ffff:1.2.3.4")
	f.Add("1840576451089" + nirKey("1840576451089") + " 275092B012345" + nirKey("275092B012345"))
	f.Add("+33 (0)1 23 45 67 89 +1 202 555 0143")
	s := New()
	f.Fuzz(func(t *testing.T, text string) {
		ms := s.Find(text)
		end := 0
		for _, m := range ms {
			if m.Start < end || m.End <= m.Start || m.End > len(text) || m.End-m.Start > MaxLen {
				t.Fatalf("bad match %+v after %d", m, end)
			}
			end = m.End
			// Every checksum-validated match re-validates on its own.
			v := strings.NewReplacer(" ", "", "-", "").Replace(text[m.Start:m.End])
			switch m.Kind {
			case IBAN:
				if !ValidIBAN(v) {
					t.Fatalf("IBAN %q does not validate", v)
				}
			case NIR:
				if !ValidNIR(v) {
					t.Fatalf("NIR %q does not validate", v)
				}
			case Card:
				if !ValidCard(v) {
					t.Fatalf("card %q does not validate", v)
				}
			}
		}
		masked := Mask(text, ms, Placeholder)
		if strings.Contains(text, "[") || strings.Contains(text, "]") {
			return
		}
		// Placeholders hold no personal data: masking twice is masking once.
		if again := Mask(masked, s.Find(masked), Placeholder); again != masked {
			// Masking can join two halves into a new candidate only across a
			// placeholder, which is bracketed; anything else is a defect.
			for _, m := range s.Find(masked) {
				if !strings.ContainsAny(masked[max(0, m.Start-1):min(len(masked), m.End+1)], "[]") {
					t.Fatalf("%q masked to %q still has %+v", text, masked, m)
				}
			}
		}
	})
}
