package pii

import (
	"math/rand/v2"
	"os"
	"reflect"
	"regexp"
	"testing"
)

// findWith runs every recogniser with the given locate function.
func findWith(sc func(re *regexp.Regexp, c *class, s string, restart bool, accept acceptFunc), s string) map[Kind][]Match {
	saved := scan
	scan = sc
	defer func() { scan = saved }()
	out := map[Kind][]Match{}
	for _, k := range Kinds {
		out[k] = finders[k](s)
	}
	return out
}

// sameAsWholeText fails when scanning run by run finds anything different
// from the whole-text scan the recognisers used before.
func sameAsWholeText(t *testing.T, s string) {
	t.Helper()
	runs, whole := findWith(scanRuns, s), findWith(scanWhole, s)
	if !reflect.DeepEqual(runs, whole) {
		t.Fatalf("%q:\nruns  %v\nwhole %v", s, runs, whole)
	}
}

// alphabet favours the bytes the patterns care about, so that random text
// is dense in candidates and near-misses.
const alphabet = "0123456789012345678901234567890123456789 .-+:@()abcdefABCDEFGHIJKLMNOPQRSTUVWXYZxyz_!#$%&'*=?^~\n\té€"

func TestRunsMatchWholeText(t *testing.T) {
	prompt := benchPrompt(t)
	benign, err := os.ReadFile("testdata/benign.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		prompt, string(benign), "",
		"jean.dupont@example.fr 06 12 34 56 78 FR14 2004 1010 0505 0001 3M02 606",
		"4111 1111 1111 1111 2001:db8::1 192.168.0.1 ::ffff:1.2.3.4",
		"+33 (0)1 23 45 67 89 +1 202 555 0143", "a@b.cc:x", "1.2.3.4.5", "::", "+12345678",
	} {
		sameAsWholeText(t, s)
	}
	r := rand.New(rand.NewPCG(1, 2))
	ab := []rune(alphabet)
	for i := 0; i < 20000; i++ {
		n := r.IntN(80)
		b := make([]rune, n)
		for j := range b {
			b[j] = ab[r.IntN(len(ab))]
		}
		sameAsWholeText(t, string(b))
	}
}

func FuzzRunsMatchWholeText(f *testing.F) {
	f.Add("jean.dupont@example.fr 06 12 34 56 78 FR14 2004 1010 0505 0001 3M02 606")
	f.Add("4111 1111 1111 1111 2001:db8::1 192.168.0.1 ::ffff:1.2.3.4")
	f.Add("+33 (0)1 23 45 67 89 +1 202 555 0143 1840576451089")
	f.Fuzz(func(t *testing.T, s string) { sameAsWholeText(t, s) })
}
