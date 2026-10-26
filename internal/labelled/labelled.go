// Package labelled reads the labelled corpus (testdata/labelled.txt) and
// scores findings against it: precision and recall per kind.
package labelled

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Span is a labelled or found value: text[Start:End] (bytes) of a kind.
type Span struct {
	Kind       string
	Start, End int
}

// Doc is one document with its gold spans.
type Doc struct {
	Name string
	Text string
	Gold []Span
}

// Kinds that may be labelled.
var Kinds = []string{"email", "phone", "iban", "nir", "card", "ipv4", "ipv6"}

// Parse reads documents: a line "=== name" starts one; lines starting with
// "#" before the first document are comments; [[kind:value]] marks a gold
// span. The text of a document is its lines joined by "\n", without the
// trailing blank lines.
func Parse(r io.Reader) ([]Doc, error) {
	var docs []Doc
	var cur *Doc
	var lines []string
	flush := func() error {
		if cur == nil {
			return nil
		}
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		text, gold, err := unmark(strings.Join(lines, "\n"))
		if err != nil {
			return fmt.Errorf("%s: %w", cur.Name, err)
		}
		cur.Text, cur.Gold = text, gold
		docs = append(docs, *cur)
		return nil
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "=== "):
			if err := flush(); err != nil {
				return nil, err
			}
			cur, lines = &Doc{Name: strings.TrimSpace(line[4:])}, nil
		case cur == nil && (strings.HasPrefix(line, "#") || strings.TrimSpace(line) == ""):
		case cur == nil:
			return nil, fmt.Errorf("text before the first document: %q", line)
		default:
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return docs, nil
}

// unmark removes the [[kind:value]] marks and returns the gold spans.
func unmark(s string) (string, []Span, error) {
	var b strings.Builder
	var gold []Span
	for {
		i := strings.Index(s, "[[")
		if i < 0 {
			b.WriteString(s)
			return b.String(), gold, nil
		}
		b.WriteString(s[:i])
		j := strings.Index(s[i:], "]]")
		if j < 0 {
			return "", nil, fmt.Errorf("unclosed mark at %q", s[i:])
		}
		mark := s[i+2 : i+j]
		kind, value, ok := strings.Cut(mark, ":")
		if !ok || !known(kind) || value == "" {
			return "", nil, fmt.Errorf("bad mark %q", mark)
		}
		start := b.Len()
		b.WriteString(value)
		gold = append(gold, Span{kind, start, b.Len()})
		s = s[i+j+2:]
	}
}

func known(k string) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Counts are the scores of one kind.
type Counts struct {
	Gold, Found    int // gold spans, gold spans overlapped by a finding of the kind
	Pred, TruePred int // findings, findings overlapping a gold span of the kind
}

// Precision is TruePred / Pred (1 when nothing was predicted).
func (c Counts) Precision() float64 {
	if c.Pred == 0 {
		return 1
	}
	return float64(c.TruePred) / float64(c.Pred)
}

// Recall is Found / Gold (1 when there is no gold span).
func (c Counts) Recall() float64 {
	if c.Gold == 0 {
		return 1
	}
	return float64(c.Found) / float64(c.Gold)
}

// Score adds one document's counts per kind. A finding is right when it
// overlaps a gold span of the same kind; a gold span is found when a
// finding of its kind overlaps it. (Overlap rather than exact bounds: two
// tools draw the edges of a phone number differently, and masking either
// span hides the value.) mapKind folds kinds before comparing (nil: none),
// e.g. ipv4 and ipv6 into "ip" for a tool that does not tell them apart.
func Score(into map[string]*Counts, gold, pred []Span, mapKind func(string) string) {
	if mapKind == nil {
		mapKind = func(k string) string { return k }
	}
	get := func(k string) *Counts {
		if into[k] == nil {
			into[k] = &Counts{}
		}
		return into[k]
	}
	overlaps := func(a, b Span) bool { return a.Start < b.End && b.Start < a.End }
	for _, g := range gold {
		c := get(mapKind(g.Kind))
		c.Gold++
		for _, p := range pred {
			if mapKind(p.Kind) == mapKind(g.Kind) && overlaps(g, p) {
				c.Found++
				break
			}
		}
	}
	for _, p := range pred {
		c := get(mapKind(p.Kind))
		c.Pred++
		for _, g := range gold {
			if mapKind(p.Kind) == mapKind(g.Kind) && overlaps(g, p) {
				c.TruePred++
				break
			}
		}
	}
}

// SortedKinds returns the keys of a score map in order.
func SortedKinds(m map[string]*Counts) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
