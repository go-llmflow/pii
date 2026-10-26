package pii

import (
	"os"
	"strings"
	"testing"
)

// benchPrompt is the 2 KB prompt of the gateway benchmark (gwbench): French
// prose with an e-mail address, an IBAN, a phone number and a fake GitHub
// token. The token is assembled here so that no token-shaped string is
// committed.
func benchPrompt(tb testing.TB) string {
	b, err := os.ReadFile("testdata/prompt-2k.txt")
	if err != nil {
		tb.Fatal(err)
	}
	return strings.Replace(string(b), "{{TOKEN}}", "ghp_"+strings.Repeat("0", 36), 1)
}

func BenchmarkFindPrompt(b *testing.B) {
	s := New()
	text := benchPrompt(b)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		s.Find(text)
	}
}

// Per recogniser, to see where the time goes.
func BenchmarkFindPromptKind(b *testing.B) {
	text := benchPrompt(b)
	for _, k := range Kinds {
		b.Run(string(k), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for b.Loop() {
				finders[k](text)
			}
		})
	}
}

func TestPromptFindings(t *testing.T) {
	text := benchPrompt(t)
	got := map[Kind]int{}
	for _, m := range New().Find(text) {
		got[m.Kind]++
	}
	if got[Email] != 1 || got[IBAN] != 1 || got[Phone] != 1 || len(got) != 3 {
		t.Fatalf("%v", got)
	}
}
