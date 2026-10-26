package pii

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// Running a recogniser's regexp over the whole text cost almost all of Find:
// Go's regexp has no literal to search for in these patterns, so it steps its
// automaton through every byte, nine times (measured on the gateway's 2 KB
// benchmark prompt: about 0.6 ms, two thirds in regexp, a third in the
// backtracker's bitmaps sized to the whole text).
//
// Every one of these patterns matches only bytes of a small ASCII class and
// has no assertion (no ^, $ or \b). A match therefore lies inside one
// maximal run of bytes of its class, and the matches of the whole text are
// exactly the matches of each run, in order: FindAll on the text and FindAll
// run by run return the same positions. A run that lacks the byte every
// match must contain (the trigger: '@' for an e-mail, a digit for a number)
// or that is shorter than the shortest match cannot hold one and is skipped
// without running the regexp at all. On prose, almost every run is a word of
// letters, so the regexps run on a handful of short strings.
//
// TestRunsMatchWholeText and FuzzRunsMatchWholeText check the equivalence
// against the whole-text scan.

type class struct {
	in, trigger [256]bool
	min         int
	// max is the longest match of the class's pattern in bytes, -1 when
	// unbounded (computed from the pattern by maxMatchLen).
	max int
	// triggers lists the trigger bytes, for strings.IndexByte (one byte,
	// vectorised) or strings.IndexAny.
	triggers string
}

func newClass(in, trigger func(c byte) bool, min int, re *regexp.Regexp) *class {
	c := &class{min: min, max: maxMatchLen(re)}
	for i := 0; i < 256; i++ {
		c.in[i] = in(byte(i))
		c.trigger[i] = in(byte(i)) && trigger(byte(i))
		if c.trigger[i] {
			c.triggers += string(rune(i)) // ASCII only: every class is
		}
	}
	return c
}

// nextTrigger returns the index of the first trigger byte in s at or after
// i, or -1.
func (c *class) nextTrigger(s string, i int) int {
	var j int
	if len(c.triggers) == 1 {
		j = strings.IndexByte(s[i:], c.triggers[0])
	} else {
		j = strings.IndexAny(s[i:], c.triggers)
	}
	if j < 0 {
		return -1
	}
	return i + j
}

// maxMatchLen is the longest text re can match, in bytes, or -1 when it is
// unbounded.
func maxMatchLen(re *regexp.Regexp) int {
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		panic(err)
	}
	return maxLen(tree.Simplify())
}

func maxLen(r *syntax.Regexp) int {
	switch r.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		n := 0
		for _, c := range r.Rune {
			n += utf8.RuneLen(c)
		}
		return n
	case syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		top := rune(0x10FFFF)
		if r.Op == syntax.OpCharClass && len(r.Rune) > 0 {
			top = r.Rune[len(r.Rune)-1]
		}
		return utf8.RuneLen(top)
	case syntax.OpCapture:
		return maxLen(r.Sub[0])
	case syntax.OpQuest:
		return maxLen(r.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		return -1
	case syntax.OpRepeat:
		m := maxLen(r.Sub[0])
		if r.Max < 0 || m < 0 {
			return -1
		}
		return m * r.Max
	case syntax.OpConcat:
		n := 0
		for _, s := range r.Sub {
			m := maxLen(s)
			if m < 0 {
				return -1
			}
			n += m
		}
		return n
	case syntax.OpAlternate:
		n := 0
		for _, s := range r.Sub {
			m := maxLen(s)
			if m < 0 {
				return -1
			}
			n = max(n, m)
		}
		return n
	}
	return -1
}

func oneOf(set string) func(byte) bool {
	return func(c byte) bool {
		for i := 0; i < len(set); i++ {
			if set[i] == c {
				return true
			}
		}
		return false
	}
}

func anyOf(fs ...func(byte) bool) func(byte) bool {
	return func(c byte) bool {
		for _, f := range fs {
			if f(c) {
				return true
			}
		}
		return false
	}
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isHex(c byte) bool   { return isDigit(c) || c|0x20 >= 'a' && c|0x20 <= 'f' }

// acceptFunc judges a candidate s[a:b]: it returns the end of the match it
// takes (b, or less when it keeps a shorter prefix), or false to refuse it.
type acceptFunc func(a, b int) (end int, ok bool)

// scan calls accept for each candidate of re in s, leftmost first. With
// restart, the search resumes one byte after a refused candidate's start,
// not after its end: a refused candidate must not hide one that overlaps
// it. FindAll did, and "+10010000 0100000000" kept a phone number in clear
// after masking (found by FuzzFind). Restart suits recognisers that refuse
// a candidate preceded by a letter or a digit, so that resuming inside a
// word finds nothing new; the e-mail recogniser does not (it would take the
// tail of ".bar@x.com"), and resumes after the candidate. Tests replace scan
// with the whole-text version to compare the two.
var scan = scanRuns

// scanRuns goes from trigger to trigger: the bytes between two runs that
// hold one are never looked at one by one (IndexByte is vectorised), which
// on prose is almost all of the text. The run around a trigger is expanded
// both ways; it cannot start before i, because i is the end of the previous
// run (a byte outside the class) or 0.
func scanRuns(re *regexp.Regexp, c *class, s string, restart bool, accept acceptFunc) {
	for i := 0; i < len(s); {
		j := c.nextTrigger(s, i)
		if j < 0 {
			return
		}
		a, b := j, j+1
		for a > i && c.in[s[a-1]] {
			a--
		}
		for b < len(s) && c.in[s[b]] {
			b++
		}
		if b-a >= c.min {
			scanSpan(re, c.max, s, a, b, restart, accept)
		}
		i = b
	}
}

// scanWhole is the reference the tests compare scanRuns with: the whole
// text, no window, no skip.
func scanWhole(re *regexp.Regexp, _ *class, s string, restart bool, accept acceptFunc) {
	for pos := 0; pos < len(s); {
		loc := re.FindStringIndex(s[pos:])
		if loc == nil {
			return
		}
		a, b := pos+loc[0], pos+loc[1]
		switch end, ok := accept(a, b); {
		case ok && end > a:
			pos = end
		case restart:
			pos = a + 1
		default:
			pos = b
		}
	}
}

// window is how much text a bounded pattern is searched in at once.
const window = 512

// scanSpan searches s[lo:hi]. The patterns have no assertion, so searching
// a substring is searching the text from there; every match is ASCII, so a
// candidate's start plus one is a character boundary.
//
// Two things keep a long run linear. A pattern of bounded length (max >= 0)
// is searched in windows of at most `window` bytes rather than in the rest
// of the run (one restart per position over a 1 MiB run of digits read the
// run again each time, and Go's regexp only uses its fast backtracker on
// short inputs). A candidate found at a in s[pos:w] is trusted only when
// a + max <= w: then every match starting at or before a fits in the window,
// so it is the leftmost match and complete; otherwise the window slides.
// And after a refusal, positions preceded by a letter or a digit are
// skipped: every recogniser that restarts refuses those anyway.
func scanSpan(re *regexp.Regexp, max int, s string, lo, hi int, restart bool, accept acceptFunc) {
	for pos := lo; pos < hi; {
		w := hi
		if max >= 0 && pos+window < hi && window > max {
			w = pos + window
		}
		loc := re.FindStringIndex(s[pos:w])
		if w < hi && (loc == nil || pos+loc[0]+max > w) {
			// Nothing trustworthy in this window: no match can start
			// before w-max that the window did not show.
			pos = w - max
			continue
		}
		if loc == nil {
			return
		}
		a, b := pos+loc[0], pos+loc[1]
		switch end, ok := accept(a, b); {
		case ok && end > a:
			pos = end
		case restart:
			pos = a + 1
			for pos < hi && isAlnum(s[pos-1]) {
				pos++
			}
		default:
			pos = b
		}
	}
}

// The class of each pattern is every byte it can match; the minimum is the
// length of its shortest match.
var (
	emailClass = newClass(anyOf(isAlnum, oneOf("!#$%&'*+=?^_~-.@")), oneOf("@"), len("a@b.cc"), emailRE)
	frPhoneCls = newClass(anyOf(isDigit, oneOf("+ .-()")), isDigit, 10, frPhoneRE)
	e164Class  = newClass(anyOf(isDigit, oneOf("+ .-")), oneOf("+"), 9, e164PhoneRE)
	ibanClass  = newClass(anyOf(isUpper, isDigit, oneOf(" ")), isDigit, 15, ibanRE)
	nirClass   = newClass(anyOf(isDigit, oneOf(" ABab")), isDigit, 15, nirRE)
	cardClass  = newClass(anyOf(isDigit, oneOf(" -")), isDigit, 13, cardRE)
	ipv4Class  = newClass(anyOf(isDigit, oneOf(".")), oneOf("."), 7, ipv4RE)
	ipv6Class  = newClass(anyOf(isHex, oneOf(":.")), oneOf(":"), 1, ipv6RE)
)
