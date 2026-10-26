package pii

import (
	"os"
	"strings"
	"testing"

	"github.com/go-llmflow/pii/internal/labelled"
)

// TestLabelledCorpus checks the corpus itself (every checksum-validated gold
// value validates) and holds pii's precision and recall on it to what was
// measured on 2026-10-26; bench/presidiocmp compares with Presidio.
func TestLabelledCorpus(t *testing.T) {
	f, err := os.Open("testdata/labelled.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	docs, err := labelled.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	strip := strings.NewReplacer(" ", "", "-", "")
	scores := map[string]*labelled.Counts{}
	s := New()
	for _, d := range docs {
		for _, g := range d.Gold {
			v := strip.Replace(d.Text[g.Start:g.End])
			switch g.Kind {
			case "iban":
				if !ValidIBAN(v) {
					t.Errorf("%s: gold IBAN %q does not validate", d.Name, v)
				}
			case "nir":
				if !ValidNIR(v) {
					t.Errorf("%s: gold NIR %q does not validate", d.Name, v)
				}
			case "card":
				if !ValidCard(v) {
					t.Errorf("%s: gold card %q does not validate", d.Name, v)
				}
			}
		}
		var pred []labelled.Span
		for _, m := range s.Find(d.Text) {
			pred = append(pred, labelled.Span{Kind: string(m.Kind), Start: m.Start, End: m.End})
		}
		labelled.Score(scores, d.Gold, pred, nil)
		for _, p := range pred {
			if !hit(d.Gold, p) {
				t.Logf("%s: false positive %s %q", d.Name, p.Kind, d.Text[p.Start:p.End])
			}
		}
		for _, g := range d.Gold {
			if !hit(pred, g) {
				t.Logf("%s: missed %s %q", d.Name, g.Kind, d.Text[g.Start:g.End])
			}
		}
	}
	// Measured on 2026-10-26. Phone numbers in a national format other than
	// the French one ("(212) 555-1234", "030 901820") are not recognised,
	// and a 10-digit reference starting with 0 is taken for a French number.
	floor := map[string][2]float64{"phone": {13.0 / 14, 13.0 / 15}}
	for _, k := range labelled.SortedKinds(scores) {
		c := scores[k]
		t.Logf("%-5s gold %2d found %2d  pred %2d right %2d  precision %.2f recall %.2f", k, c.Gold, c.Found, c.Pred, c.TruePred, c.Precision(), c.Recall())
		want, ok := floor[k]
		if !ok {
			want = [2]float64{1, 1}
		}
		if c.Precision() < want[0]-1e-9 || c.Recall() < want[1]-1e-9 {
			t.Errorf("%s: precision %.2f recall %.2f, measured %.2f and %.2f on 2026-10-26", k, c.Precision(), c.Recall(), want[0], want[1])
		}
	}
}

func hit(spans []labelled.Span, x labelled.Span) bool {
	for _, s := range spans {
		if s.Kind == x.Kind && s.Start < x.End && x.Start < s.End {
			return true
		}
	}
	return false
}
