package export

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// What custody marks is written by the loop soon after, what failed is said
// and kept, and a start that cannot bring the directory to custody's state
// refuses.

// skewed is a source whose root key set fails, or which lists a kid it holds
// no statement for.
type skewed struct {
	*source
	rootErr error
	extra   string
}

func (s skewed) RootSet() ([]byte, error) {
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	return s.source.RootSet()
}

func (s skewed) Kids() []string {
	if s.extra != "" {
		return append(s.source.Kids(), s.extra)
	}
	return s.source.Kids()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunWritesWhatIsMarkedAndStopsWhenAsked(t *testing.T) {
	d := dir(t)
	src := newSource()
	e, err := Open(d, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { e.Run(stop); close(done) }()

	src.mu.Lock()
	src.revoked[kidA] = 1950000000
	src.root = []byte(`{"keys":[{"kid":"r2"}]}`)
	src.mu.Unlock()
	e.Mark(kidA)
	e.MarkRoot()
	waitFor(t, "the marked kid's copy", func() bool {
		raw, err := os.ReadFile(filepath.Join(d, kidA+".json"))
		return err == nil && strings.Contains(string(raw), `"revoked_at":1950000000`)
	})
	waitFor(t, "the marked root's copy", func() bool {
		raw, err := os.ReadFile(filepath.Join(d, RootFile))
		return err == nil && string(raw) == `{"keys":[{"kid":"r2"}]}`
	})
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop when asked")
	}
	if n := e.Unexported(); n != 0 {
		t.Fatalf("%d copies wait after the loop wrote them", n)
	}
}

func TestAFlushThatFailsSaysSoAndKeepsWhatWaits(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory whatever its mode")
	}
	d := dir(t)
	var mu sync.Mutex
	var logged []string
	e, err := Open(d, newSource(), func(f string, a ...any) { mu.Lock(); logged = append(logged, fmt.Sprintf(f, a...)); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	_ = os.Chmod(d, 0o555)
	defer os.Chmod(d, 0o755)
	e.Mark(kidA)
	e.MarkRoot()
	e.Flush()
	if n := e.Unexported(); n != 2 {
		t.Fatalf("%d copies wait after a failed flush, want 2", n)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(logged, "\n")
	if len(logged) != 2 || !strings.Contains(joined, "the root key set") || !strings.Contains(joined, kidA) || !strings.Contains(joined, "tried again in") {
		t.Fatalf("the failed flush logged:\n%s", joined)
	}
}

func TestOpenRefusesWhenTheDirectoryCannotBeBroughtToCustodysState(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "gone"), newSource(), nil); err == nil {
		t.Fatal("a directory that is not there opened")
	}
	boom := errors.New("the root key set does not render")
	if _, err := Open(dir(t), skewed{source: newSource(), rootErr: boom}, nil); !errors.Is(err, boom) {
		t.Fatalf("a root key set that fails: %v", err)
	}
	ghost := "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
	if _, err := Open(dir(t), skewed{source: newSource(), extra: ghost}, nil); err == nil || !strings.Contains(err.Error(), ghost) {
		t.Fatalf("a kid listed with no statement: %v", err)
	}
	d := dir(t)
	_ = os.WriteFile(filepath.Join(d, kidA+".json"), []byte("not json"), 0o644)
	if _, err := Open(d, newSource(), nil); err == nil || !strings.Contains(err.Error(), "does not read") {
		t.Fatalf("a copy that does not read: %v", err)
	}
	if raw, _ := os.ReadFile(filepath.Join(d, kidA+".json")); string(raw) != "not json" {
		t.Fatal("a refused start rewrote the copy it refused over")
	}
}
