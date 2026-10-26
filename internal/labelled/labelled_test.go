package labelled

import (
	"strings"
	"testing"
)

func TestParseAndScore(t *testing.T) {
	docs, err := Parse(strings.NewReader("# comment\n\n=== a\nmail [[email:x@y.fr]] tel [[phone:01 23 45 67 89]]\n\n=== b\nnone é\n"))
	if err != nil || len(docs) != 2 {
		t.Fatalf("%v %v", docs, err)
	}
	d := docs[0]
	if d.Text != "mail x@y.fr tel 01 23 45 67 89" || len(d.Gold) != 2 || d.Text[d.Gold[0].Start:d.Gold[0].End] != "x@y.fr" ||
		d.Text[d.Gold[1].Start:d.Gold[1].End] != "01 23 45 67 89" {
		t.Fatalf("%+v", d)
	}
	if docs[1].Text != "none é" || len(docs[1].Gold) != 0 {
		t.Fatalf("%+v", docs[1])
	}
	m := map[string]*Counts{}
	Score(m, d.Gold, []Span{{"email", 5, 11}, {"phone", 16, 20}, {"phone", 0, 4}}, nil)
	if c := m["email"]; c.Precision() != 1 || c.Recall() != 1 {
		t.Fatalf("email %+v", c)
	}
	if c := m["phone"]; c.Recall() != 1 || c.Precision() != 0.5 {
		t.Fatalf("phone %+v", c)
	}
	for _, bad := range []string{"text first\n", "=== a\n[[nope:x]]\n", "=== a\n[[email:x\n", "=== a\n[[email:]]\n"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
