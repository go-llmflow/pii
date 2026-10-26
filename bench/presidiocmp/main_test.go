package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/go-llmflow/pii/internal/labelled"
)

func TestRuneToByte(t *testing.T) {
	text := "é@x.fr ü 1.2.3.4"
	idx := runeToByte(text)
	// Python sees "1.2.3.4" at code points 9..16.
	if got := text[idx[9]:idx[16]]; got != "1.2.3.4" {
		t.Fatalf("%q", got)
	}
	if idx[len(idx)-1] != len(text) {
		t.Fatal("end not mapped")
	}
}

func TestStatsAndKinds(t *testing.T) {
	if median([]float64{3, 1, 2}) != 2 || median([]float64{4, 1, 2, 3}) != 2.5 || percentile([]float64{1, 2, 3, 4, 5}, 0.99) != 4 {
		t.Fatal("median/percentile")
	}
	if compared("ipv6") != "ip" || compared("ipv4") != "ip" || compared("email") != "email" || presidioKind["IBAN_CODE"] != "iban" {
		t.Fatal("kinds")
	}
	if l, err := decodeDarwinLoadavg(append([]byte{0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0x00, 0x08, 0, 0, 0, 0, 0, 0)); err != nil || l != 1 {
		t.Fatalf("loadavg %v %v", l, err)
	}
}

func TestReportScoresOnSharedKinds(t *testing.T) {
	docs := []labelled.Doc{{Name: "d", Text: "a@b.cc 1 84 05 76 451 089 31 10.0.0.1", Gold: []labelled.Span{
		{Kind: "email", Start: 0, End: 6}, {Kind: "nir", Start: 7, End: 28}, {Kind: "ipv4", Start: 29, End: 37}}}}
	goF := [][]labelled.Span{{{Kind: "email", Start: 0, End: 6}, {Kind: "nir", Start: 7, End: 28}, {Kind: "ipv4", Start: 29, End: 37}}}
	pyF := [][]labelled.Span{{{Kind: "ip", Start: 29, End: 37}, {Kind: "phone", Start: 7, End: 28}}}
	var out bytes.Buffer
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	report(&out, options{presidio: "p", model: "m", python: "3.12", rounds: 1, maxLoad: 4}, docs,
		[][]float64{{1000}}, [][]float64{{1e6}}, goF, pyF, now, now, []float64{1.5})
	s := out.String()
	for _, want := range []string{"email      1.00 / 1.00       1.00 / 0.00", "ip         1.00 / 1.00       1.00 / 1.00",
		"phone      1.00 / 1.00       0.00 / 1.00   (gold 0)", "nir", "Presidio has no French NIR", "1000×", "2026-10-26 10:00 UTC"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}

func TestRefusesUnderLoad(t *testing.T) {
	cmd := RootCmd()
	cmd.SetArgs([]string{"--max-load", "-1", "--wait", "0s", "--uv", "/nonexistent-uv"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err == nil {
		t.Fatal("ran without uv and with a negative load ceiling")
	}
}
