package uselog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A write that failed once is never followed by one that succeeds, so a torn
// line can only be the last; what cannot be read refuses the open.

func TestAfterAFailedWriteEveryAppendFails(t *testing.T) {
	p := logPath(t)
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(entry(0)); err != nil {
		t.Fatalf("control: %v", err)
	}
	// The file goes away under the log, as a full or failing disk would.
	_ = l.f.Close()
	first := l.Append(entry(1))
	if first == nil || !strings.Contains(first.Error(), "stopped taking writes") {
		t.Fatalf("a write that failed: %v", first)
	}
	// A working file again does not bring the log back: the next line would
	// follow a line nobody can read.
	if l.f, err = os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(entry(2)); err != first {
		t.Fatalf("an append after a failed write: %v, want the first failure %v", err, first)
	}
	_ = l.Close()
	raw, _ := os.ReadFile(p)
	if bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("lines were written after a failed write:\n%s", raw)
	}
}

func TestCloseIsOnceAndThenEveryAppendFails(t *testing.T) {
	l, err := Open(logPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("a second Close: %v", err)
	}
	if err := l.Append(entry(0)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("an append after Close: %v", err)
	}
}

func TestAUseLogThatCannotBeReadRefusesTheOpen(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "reading the use log") {
		t.Fatalf("a directory: %v", err)
	}
	p := logPath(t)
	_ = os.WriteFile(p, append(bytes.Repeat([]byte("x"), 1<<20+1), '\n'), 0o600)
	if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "reading the use log") {
		t.Fatalf("a line over the scanner's cap: %v", err)
	}
	if _, err := Open(filepath.Join(dir, "missing", "use.ndjson")); err == nil || !strings.Contains(err.Error(), "opening the use log") {
		t.Fatalf("a log in a directory that is not there: %v", err)
	}
}

func TestATornTailThatCannotBeDiscardedRefusesTheOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	p := logPath(t)
	appendN(t, p, 2)
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.WriteString(`{"at":`)
	_ = f.Close()
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "torn last line") {
		t.Fatalf("a torn tail in a file that does not take the rewrite: %v", err)
	}
}
