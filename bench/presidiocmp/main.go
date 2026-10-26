// Command presidiocmp compares go-llmflow/pii with Microsoft Presidio, the
// reference tool for finding personal data: detection quality (precision and
// recall per kind on testdata/labelled.txt) and latency per document, both
// single-threaded, measured in interleaved rounds and only when the machine
// is quiet (load average at most --max-load).
//
// Presidio is the program under test, driven by presidio_worker.py through
// `uv run`; everything else (scoring, offsets, statistics) is here.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-llmflow/pii"
	"github.com/go-llmflow/pii/internal/labelled"
	"github.com/spf13/cobra"
)

// osExit is replaced by tests.
var osExit = os.Exit

func main() {
	if err := RootCmd().Execute(); err != nil {
		osExit(1)
	}
}

type options struct {
	corpus, prompt, model, presidio, python, worker, uv string
	rounds                                              int
	maxLoad                                             float64
	wait                                                time.Duration
	qualityOnly, details                                bool
}

// RootCmd is the command line.
func RootCmd() *cobra.Command {
	o := options{}
	cmd := &cobra.Command{
		Use:          "presidiocmp",
		Short:        "Compare go-llmflow/pii with Microsoft Presidio: precision, recall and latency per document",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.corpus, "corpus", "../../testdata/labelled.txt", "labelled corpus")
	f.StringVar(&o.prompt, "prompt", "../../testdata/prompt-2k.txt", "the gateway benchmark's 2 KB prompt (timed as one more document)")
	f.StringVar(&o.model, "spacy-model", "en_core_web_lg", "spaCy model of Presidio's NLP engine (Presidio's default)")
	f.StringVar(&o.presidio, "presidio", "presidio-analyzer==2.2.364", "presidio-analyzer requirement")
	f.StringVar(&o.python, "python", "3.12", "Python version for uv")
	f.StringVar(&o.worker, "worker", "presidio_worker.py", "the Presidio driver")
	f.StringVar(&o.uv, "uv", "uv", "the uv executable")
	f.IntVar(&o.rounds, "rounds", 200, "interleaved timing rounds over every document")
	f.Float64Var(&o.maxLoad, "max-load", 4, "refuse to measure above this 1-minute load average")
	f.DurationVar(&o.wait, "wait", 12*time.Hour, "how long to wait for the load to fall")
	f.BoolVar(&o.qualityOnly, "quality-only", false, "precision and recall only: one round, no load gate, no latency")
	f.BoolVar(&o.details, "details", false, "list every false positive and miss")
	return cmd
}

// spacyWheel is the URL of a spaCy model's wheel (spaCy 3.8 models).
func spacyWheel(model string) string {
	return "https://github.com/explosion/spacy-models/releases/download/" + model + "-3.8.0/" + model + "-3.8.0-py3-none-any.whl"
}

func run(ctx context.Context, out, log io.Writer, o options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	docs, err := loadDocs(o.corpus, o.prompt)
	if err != nil {
		return err
	}
	runtime.GOMAXPROCS(1)
	w, err := startWorker(ctx, o)
	if err != nil {
		return err
	}
	defer w.close()

	if o.qualityOnly {
		// Precision and recall do not depend on the load; no timing is
		// printed.
		o.rounds = 1
	}
	load, err := loadAvg1()
	if !o.qualityOnly {
		load, err = waitForLoad(ctx, o.maxLoad, o.wait, func(l float64) { fmt.Fprintf(log, "load %.2f > %.2f, waiting\n", l, o.maxLoad) })
	}
	if err != nil {
		return err
	}
	started := time.Now()
	scanner := pii.New()
	goNS := make([][]float64, len(docs))
	pyNS := make([][]float64, len(docs))
	var goFound, pyFound [][]labelled.Span
	loads := []float64{load}
	for r := 0; r < o.rounds; r++ {
		if r%20 == 0 && r > 0 {
			l, err := loadAvg1()
			if err != nil {
				return err
			}
			loads = append(loads, l)
			if l > o.maxLoad && !o.qualityOnly {
				return fmt.Errorf("round %d: load %.2f > %.2f: measurement abandoned (results under load are meaningless)", r, l, o.maxLoad)
			}
		}
		for i, d := range docs {
			// Interleaved: pii then Presidio on the same document.
			t0 := time.Now()
			ms := scanner.Find(d.Text)
			goNS[i] = append(goNS[i], float64(time.Since(t0).Nanoseconds()))
			res, ns, err := w.analyze(i, d.Text)
			if err != nil {
				return err
			}
			pyNS[i] = append(pyNS[i], float64(ns))
			if r == 0 {
				goFound = append(goFound, fromPII(ms))
				pyFound = append(pyFound, res)
			}
		}
	}
	finished := time.Now()
	l, err := loadAvg1()
	if err == nil {
		loads = append(loads, l)
	}
	report(out, o, docs, goNS, pyNS, goFound, pyFound, started, finished, loads)
	return nil
}

func loadDocs(corpus, prompt string) ([]labelled.Doc, error) {
	f, err := os.Open(corpus)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	docs, err := labelled.Parse(f)
	if err != nil {
		return nil, err
	}
	if prompt != "" {
		b, err := os.ReadFile(prompt)
		if err != nil {
			return nil, err
		}
		// The token is assembled at run time (none is committed); the prompt
		// is timed, not scored.
		text := strings.Replace(string(b), "{{TOKEN}}", "ghp_"+strings.Repeat("0", 36), 1)
		docs = append(docs, labelled.Doc{Name: "prompt-2k (timed only)", Text: text, Gold: nil})
	}
	return docs, nil
}

func fromPII(ms []pii.Match) []labelled.Span {
	var out []labelled.Span
	for _, m := range ms {
		out = append(out, labelled.Span{Kind: string(m.Kind), Start: m.Start, End: m.End})
	}
	return out
}

// presidioKind maps Presidio's entity types to the corpus kinds.
var presidioKind = map[string]string{
	"EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone", "IBAN_CODE": "iban", "CREDIT_CARD": "card", "IP_ADDRESS": "ip",
}

// compared folds ipv4 and ipv6 into "ip" (Presidio has one IP_ADDRESS type).
func compared(k string) string {
	if k == "ipv4" || k == "ipv6" {
		return "ip"
	}
	return k
}

// runeToByte converts Python string indices (code points) to byte offsets.
func runeToByte(text string) []int {
	idx := make([]int, 0, utf8.RuneCountInString(text)+1)
	for i := range text {
		idx = append(idx, i)
	}
	return append(idx, len(text))
}

// ---- the worker ----

type worker struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func startWorker(ctx context.Context, o options) (*worker, error) {
	script, err := filepath.Abs(o.worker)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, o.uv, "run", "--no-project", "--python", o.python,
		"--with", o.presidio, "--with", spacyWheel(o.model), "python", script, o.model)
	// One thread for the numeric libraries under spaCy: the comparison is
	// single-threaded on both sides.
	cmd.Env = append(os.Environ(), "OMP_NUM_THREADS=1", "OPENBLAS_NUM_THREADS=1", "MKL_NUM_THREADS=1", "VECLIB_MAXIMUM_THREADS=1")
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	w := &worker{cmd: cmd, in: in, out: bufio.NewReaderSize(stdout, 1<<20)}
	line, err := w.out.ReadBytes('\n')
	if err != nil {
		w.close()
		return nil, fmt.Errorf("presidio worker did not start: %w", err)
	}
	var ready struct{ Ready bool }
	if json.Unmarshal(line, &ready) != nil || !ready.Ready {
		w.close()
		return nil, fmt.Errorf("presidio worker: unexpected first line %q", line)
	}
	return w, nil
}

func (w *worker) close() {
	w.in.Close()
	_ = w.cmd.Wait()
}

// analyze sends one document and returns Presidio's findings in byte
// offsets and the time spent in analyze().
func (w *worker) analyze(id int, text string) ([]labelled.Span, int64, error) {
	req, _ := json.Marshal(map[string]any{"id": id, "text": text})
	if _, err := w.in.Write(append(req, '\n')); err != nil {
		return nil, 0, err
	}
	line, err := w.out.ReadBytes('\n')
	if err != nil {
		return nil, 0, fmt.Errorf("presidio worker: %w", err)
	}
	var resp struct {
		ID      int
		NS      int64
		Results []struct {
			Type       string
			Start, End int
			Score      float64
		}
	}
	if err := json.Unmarshal(line, &resp); err != nil || resp.ID != id {
		return nil, 0, fmt.Errorf("presidio worker: bad answer %q", line)
	}
	idx := runeToByte(text)
	var spans []labelled.Span
	for _, r := range resp.Results {
		k, ok := presidioKind[r.Type]
		if !ok || r.Start < 0 || r.End > len(idx)-1 || r.Start >= r.End {
			continue
		}
		spans = append(spans, labelled.Span{Kind: k, Start: idx[r.Start], End: idx[r.End]})
	}
	return spans, resp.NS, nil
}

// ---- report ----

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	sort.Float64s(s)
	i := int(p * float64(len(s)-1))
	return s[i]
}

func report(out io.Writer, o options, docs []labelled.Doc, goNS, pyNS [][]float64, goFound, pyFound [][]labelled.Span,
	started, finished time.Time, loads []float64) {
	fmt.Fprintf(out, "presidiocmp: go-llmflow/pii vs Microsoft Presidio (%s, spaCy %s, Python %s)\n", o.presidio, o.model, o.python)
	fmt.Fprintf(out, "date %s → %s, %s/%s, GOMAXPROCS=1, Presidio single-threaded (OMP/BLAS 1 thread)\n",
		started.Format("2006-01-02 15:04 MST"), finished.Format("15:04"), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(out, "load averages (1 min) sampled every 20 rounds: %v (max allowed %.1f)\n", fmtLoads(loads), o.maxLoad)
	fmt.Fprintf(out, "%d documents, %d interleaved rounds; latency = time in Find / in AnalyzerEngine.analyze, per document\n\n", len(docs), o.rounds)

	// Quality on the kinds both tools cover.
	goS, pyS, goAll := map[string]*labelled.Counts{}, map[string]*labelled.Counts{}, map[string]*labelled.Counts{}
	for i, d := range docs {
		if d.Gold == nil && strings.Contains(d.Name, "timed only") {
			continue
		}
		var gold, goP []labelled.Span
		for _, g := range d.Gold {
			if g.Kind != "nir" {
				gold = append(gold, g)
			}
		}
		for _, p := range goFound[i] {
			if p.Kind != "nir" {
				goP = append(goP, p)
			}
		}
		labelled.Score(goS, gold, goP, compared)
		labelled.Score(pyS, gold, pyFound[i], compared)
		labelled.Score(goAll, d.Gold, goFound[i], nil)
	}
	fmt.Fprintf(out, "%-6s %18s %18s\n", "kind", "pii P / R", "Presidio P / R")
	union := map[string]*labelled.Counts{}
	for k := range goS {
		union[k] = nil
	}
	for k := range pyS {
		union[k] = nil
	}
	for _, k := range labelled.SortedKinds(union) {
		g, p := goS[k], pyS[k]
		if g == nil {
			g = &labelled.Counts{}
		}
		if p == nil {
			p = &labelled.Counts{}
		}
		fmt.Fprintf(out, "%-6s %8.2f / %-6.2f %8.2f / %-6.2f (gold %d)\n", k, g.Precision(), g.Recall(), p.Precision(), p.Recall(), g.Gold)
	}
	if c := goAll["nir"]; c != nil {
		fmt.Fprintf(out, "%-6s %8.2f / %-6.2f %18s (gold %d; Presidio has no French NIR recogniser)\n", "nir", c.Precision(), c.Recall(), "n/a", c.Gold)
	}

	if o.details {
		fmt.Fprintf(out, "\nfalse positives (FP) and misses (FN), shared kinds:\n")
		for i, d := range docs {
			if d.Gold == nil && strings.Contains(d.Name, "timed only") {
				continue
			}
			for _, tool := range []struct {
				name  string
				found []labelled.Span
			}{{"pii", goFound[i]}, {"Presidio", pyFound[i]}} {
				for _, p := range tool.found {
					if p.Kind != "nir" && !overlapsKind(d.Gold, p) {
						fmt.Fprintf(out, "  %-9s FP %-5s %-22s %q\n", tool.name, compared(p.Kind), d.Name, d.Text[p.Start:p.End])
					}
				}
				for _, g := range d.Gold {
					if g.Kind != "nir" && !overlapsKind(tool.found, g) {
						fmt.Fprintf(out, "  %-9s FN %-5s %-22s %q\n", tool.name, compared(g.Kind), d.Name, d.Text[g.Start:g.End])
					}
				}
			}
		}
	}
	if o.qualityOnly {
		fmt.Fprintf(out, "\n(quality only: no latency measured)\n")
		return
	}
	fmt.Fprintf(out, "\n%-28s %12s %12s %12s %12s %8s\n", "document", "pii p50", "pii p99", "Presidio p50", "Presidio p99", "ratio")
	var goMed, pyMed []float64
	for i, d := range docs {
		g, p := median(goNS[i]), median(pyNS[i])
		goMed, pyMed = append(goMed, g), append(pyMed, p)
		fmt.Fprintf(out, "%-28s %12s %12s %12s %12s %7.0f×\n", trunc(d.Name, 28), dur(g), dur(percentile(goNS[i], 0.99)),
			dur(p), dur(percentile(pyNS[i], 0.99)), p/g)
	}
	fmt.Fprintf(out, "%-28s %12s %12s %12s %12s %7.0f×\n", "median over documents", dur(median(goMed)), "", dur(median(pyMed)), "", median(pyMed)/median(goMed))
}

func overlapsKind(spans []labelled.Span, x labelled.Span) bool {
	for _, s := range spans {
		if compared(s.Kind) == compared(x.Kind) && s.Start < x.End && x.Start < s.End {
			return true
		}
	}
	return false
}

func fmtLoads(ls []float64) string {
	var parts []string
	for _, l := range ls {
		parts = append(parts, fmt.Sprintf("%.2f", l))
	}
	return strings.Join(parts, " ")
}

func dur(ns float64) string {
	switch {
	case ns >= 1e6:
		return fmt.Sprintf("%.2f ms", ns/1e6)
	case ns >= 1e3:
		return fmt.Sprintf("%.1f µs", ns/1e3)
	}
	return fmt.Sprintf("%.0f ns", ns)
}

func trunc(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// waitForLoad returns once the load is at most max, or fails after wait.
func waitForLoad(ctx context.Context, max float64, wait time.Duration, onWait func(float64)) (float64, error) {
	deadline := time.Now().Add(wait)
	for {
		l, err := loadAvg1()
		if err != nil {
			return 0, fmt.Errorf("cannot read the load average: %w", err)
		}
		if l <= max {
			return l, nil
		}
		if time.Now().After(deadline) {
			return l, fmt.Errorf("load average %.2f > %.2f after waiting %v: refusing to measure", l, max, wait)
		}
		onWait(l)
		select {
		case <-ctx.Done():
			return l, ctx.Err()
		case <-time.After(time.Minute):
		}
	}
}

var errNoLoad = errors.New("load average not available on this system")
