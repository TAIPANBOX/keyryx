package witness

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// The witness reads a bus it does not control. A stream it reads for the first
// time may already hold millions of lines (forge's bus, never rotated, killed a
// witness held to 256 MiB). What it keeps while reading must not grow with the
// stream: the bytes are hashed as they pass, and only the lines a checkpoint
// names are remembered.

// bigStream writes n chained lines straight to path, without the writer's lock
// per line, so a test can make a stream of a few hundred thousand lines fast.
func bigStream(t *testing.T, path string, n int, chained bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	prev := ""
	for i := 0; i < n; i++ {
		line := fmt.Sprintf(`{"agent_id":"agent://acme.example/one","data":{"i":%d},"schema":"taipanbox.dev/agent-event/v1.0","source":"wardryx","ts":"2026-10-18T12:00:00Z","type":"policy_allow"`, i)
		if chained && prev != "" {
			line += `,"prev_hash":"` + prev + `"`
		}
		line += "}"
		if chained {
			h, err := event.ChainHashRaw([]byte(line))
			if err != nil {
				t.Fatal(err)
			}
			prev = h
		}
		_, _ = w.WriteString(line + "\n")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// peakHeap runs f and returns the most heap it held above where it started,
// sampled while it runs, with the collector made eager so garbage does not
// pass for memory kept.
func peakHeap(f func()) uint64 {
	old := debug.SetGCPercent(5)
	defer debug.SetGCPercent(old)
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > base.HeapAlloc && m.HeapAlloc-base.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc - base.HeapAlloc)
			}
		}
	}()
	f()
	close(stop)
	wg.Wait()
	return peak.Load()
}

func TestAStreamReadForTheFirstTimeDoesNotHoldALineForEveryLine(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a stream of 400000 lines")
	}
	s := newStand(t, nil)
	const lines = 400_000
	bigStream(t, s.streamPath("wardryx.ndjson"), lines, true)
	var got []Finding
	peak := peakHeap(func() { got = s.tick() })
	if len(got) != 0 {
		t.Fatalf("an honest stream raised %d findings, first %+v", len(got), got[0])
	}
	// A line remembered per line read is some 200 bytes, 80 MB here. What the
	// read needs is its buffers and the lines a checkpoint names, none here.
	if peak > 24<<20 {
		t.Fatalf("reading a %d-line stream held %d MiB at its peak", lines, peak>>20)
	}
	if st := s.w.streams["wardryx.ndjson"]; st == nil || st.lines != lines {
		t.Fatalf("the stream was not read whole: %+v", st)
	}
}

func TestAStreamWithNoChainRaisesABoundedNumberOfFindings(t *testing.T) {
	s := newStand(t, nil)
	bigStream(t, s.streamPath("legacy.ndjson"), 20_000, false)
	got := s.tick()
	var single int
	var summary *Finding
	for i, f := range got {
		if f.Type != ChainRestarted {
			continue
		}
		if _, ok := f.Data["more_restarts"]; ok {
			summary = &got[i]
			continue
		}
		single++
	}
	if single != MaxRestartFindings || summary == nil {
		t.Fatalf("a stream of 20000 lines with no prev_hash raised %d single restart findings and summary %v, want %d and one", single, summary, MaxRestartFindings)
	}
	rest := int64(20_000 - 1 - MaxRestartFindings)
	if summary.Data["more_restarts"] != rest || summary.Data["unexplained_restarts"] != rest || summary.Severity != "high" {
		t.Fatalf("the summary: %+v", summary)
	}
	if n := len(s.log.Entries()); n > 64 {
		t.Fatalf("the witness's log took %d entries for one read", n)
	}
}

// appendLine writes one line to the stream: chained to the line before, or
// beginning a new chain.
func appendLine(t *testing.T, s *stand, name string, chained bool) {
	t.Helper()
	path := s.streamPath(name)
	raw, _ := os.ReadFile(path)
	line := fmt.Sprintf(`{"agent_id":"agent://acme.example/one","schema":"taipanbox.dev/agent-event/v1.0","source":"wardryx","ts":"2026-10-18T12:00:00Z","type":"policy_allow","data":{"n":%d}`, len(raw))
	if chained && len(raw) > 0 {
		ls := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		h, err := event.ChainHashRaw([]byte(ls[len(ls)-1]))
		if err != nil {
			t.Fatal(err)
		}
		line += `,"prev_hash":"` + h + `"`
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.WriteString(line + "}\n")
}

func TestAnUnexplainedRestartIsNeverHiddenBehindExplainedOnes(t *testing.T) {
	s := newStand(t, nil)
	appendLine(t, s, "wardryx.ndjson", false)
	appendLine(t, s, "wardryx.ndjson", true)
	// Nine restarts a resume record explains, more than are raised one by
	// one, then one nothing explains.
	for i := 0; i < MaxRestartFindings+1; i++ {
		s.checkpoint("wardryx.ndjson", "resume", true, nil)
		appendLine(t, s, "wardryx.ndjson", false)
		appendLine(t, s, "wardryx.ndjson", true)
	}
	appendLine(t, s, "wardryx.ndjson", false)
	got := s.tick()
	high := 0
	var summary map[string]any
	for _, f := range got {
		if f.Type == ChainRestarted && f.Severity == "high" {
			high++
		}
		if _, ok := f.Data["more_restarts"]; ok {
			summary = f.Data
		}
	}
	if high != 1 || summary == nil || summary["unexplained_restarts"] != int64(1) || summary["more_restarts"] != int64(2) || summary["explained"] != false {
		t.Fatalf("one unexplained restart behind %d explained ones: %d high findings, summary %v", MaxRestartFindings+1, high, summary)
	}
}

func TestALineLongerThanTheBoundIsHashedNotHeld(t *testing.T) {
	s := newStand(t, nil)
	path := s.streamPath("wardryx.ndjson")
	appendLine(t, s, "wardryx.ndjson", false)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	big := make([]byte, 40<<20)
	for i := range big {
		big[i] = 'x'
	}
	_, _ = f.Write(big)
	_, _ = f.Write([]byte("\n"))
	_ = f.Close()
	appendLine(t, s, "wardryx.ndjson", false)
	var got []Finding
	peak := peakHeap(func() { got = s.tick() })
	if peak > 16<<20 {
		t.Fatalf("a 40 MiB line held %d MiB at the read's peak", peak>>20)
	}
	raw, _ := os.ReadFile(path)
	sum := sha256.Sum256(raw)
	st := s.w.streams["wardryx.ndjson"]
	if st.lines != 3 || st.bytes != int64(len(raw)) || st.prefix != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the long line was not read and hashed whole: lines %d bytes %d of %d", st.lines, st.bytes, len(raw))
	}
	for _, f := range got {
		if f.Type == StreamRewritten || f.Type == StreamTruncated {
			t.Fatalf("an honest stream with a long line raised %s", f.Type)
		}
	}
	// A long final line with no LF yet is not counted and not hashed; once
	// its LF arrives, the stream reads on with nothing wrong.
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.Write(big[:10<<20])
	_ = f.Close()
	if got := s.tick(); len(got) != 0 || s.w.streams["wardryx.ndjson"].lines != 3 {
		t.Fatalf("a torn long line: %+v, lines %d", got, s.w.streams["wardryx.ndjson"].lines)
	}
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.Write([]byte("\n"))
	_ = f.Close()
	got = s.tick()
	raw, _ = os.ReadFile(path)
	sum = sha256.Sum256(raw)
	if st := s.w.streams["wardryx.ndjson"]; st.lines != 4 || st.prefix != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("after the LF arrived: lines %d, prefix right %v", st.lines, st.prefix == "sha256:"+hex.EncodeToString(sum[:]))
	}
	for _, f := range got {
		if f.Type == StreamRewritten {
			t.Fatal("a torn long line, completed, reads as a rewrite")
		}
	}
}

// flaky is custody that does not answer until the test says.
type flaky struct {
	inner Keys
	down  bool
}

func (f *flaky) Key(kid string, at, seen time.Time) (Certified, error) {
	if f.down {
		return Certified{}, ErrUnavailable
	}
	return f.inner.Key(kid, at, seen)
}

func TestCheckpointsLeftBehindAreAnsweredInOnePass(t *testing.T) {
	s := newStand(t, nil)
	fl := &flaky{inner: s.keys, down: true}
	s.custody = fl
	s.restart()
	for i := 0; i < 5; i++ {
		s.emit("wardryx.ndjson", 10)
		s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	}
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("custody down: %+v", got)
	}
	// The stream was read on; its five records wait behind it.
	fl.down = false
	before := rereads.Load()
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("custody back: %+v", got)
	}
	if n := rereads.Load() - before; n > 1 {
		t.Fatalf("five records left behind made %d reads of the stream from byte zero, want one", n)
	}
	kept := 0
	for _, e := range s.log.Entries() {
		if e.Kind == "checkpoint" {
			kept++
		}
	}
	if kept != 5 {
		t.Fatalf("%d checkpoints accepted, want 5", kept)
	}
}

func TestPendingCheckpointsAreAnsweredFromTheReadItself(t *testing.T) {
	s := newStand(t, nil)
	for i := 0; i < 3; i++ {
		s.emit("wardryx.ndjson", 10)
		s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	}
	before := rereads.Load()
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("an honest stream with three checkpoints raised %+v", got)
	}
	if n := rereads.Load() - before; n != 0 {
		t.Fatalf("three checkpoints read with the stream made %d reads of it from byte zero, want none", n)
	}
	kept := 0
	for _, e := range s.log.Entries() {
		if e.Kind == "checkpoint" {
			kept++
		}
	}
	if kept != 3 {
		t.Fatalf("%d checkpoints accepted, want 3", kept)
	}
}
