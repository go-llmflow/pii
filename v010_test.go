package pii

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

// TestMasksAtLeastV010 compares with v0.1.0 (before the run scan, the
// restart after a refused candidate and the bounded card pattern): on the
// recorded corpus (testdata/v0.1.0-golden.json.gz, what v0.1.0 found on
// 5,000 mixes of real values, noise and separators and 20,000 random
// strings), every byte v0.1.0 masked is still inside a match. The changes may
// find more; they must never find less.
func TestMasksAtLeastV010(t *testing.T) {
	f, err := os.Open("testdata/v0.1.0-golden.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var recs []struct {
		In      string
		Matches []Match
	}
	if err := json.NewDecoder(zr).Decode(&recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) < 1000 {
		t.Fatalf("only %d records: the corpus did not load", len(recs))
	}
	s := New()
	more := 0
	for _, r := range recs {
		now := s.Find(r.In)
		covered := make([]bool, len(r.In))
		for _, m := range now {
			for i := m.Start; i < m.End; i++ {
				covered[i] = true
			}
		}
		for _, m := range r.Matches {
			for i := m.Start; i < m.End; i++ {
				if !covered[i] {
					t.Fatalf("%q: v0.1.0 masked %+v, now %+v", r.In, m, now)
				}
			}
		}
		if len(now) > len(r.Matches) {
			more++
		}
	}
	t.Logf("%d inputs, %d with more matches than v0.1.0", len(recs), more)
}
