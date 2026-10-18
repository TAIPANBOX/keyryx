package uselog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The key-use log is the operator's record of what signed what. A log that
// could be edited in the middle without anybody noticing would be a record of
// whatever the editor wanted.

func logPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "use.ndjson")
}

func entry(i int) Entry {
	return Entry{At: int64(1000 + i), Consumer: "wardryx", Op: "sign", Key: "wardryx-approval", Kid: "kid-1", Purpose: "approval", Digest: strings.Repeat("a", 64)}
}

func appendN(t *testing.T, p string, n int) {
	t.Helper()
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
}

func TestEveryAppendIsChainedAndSurvivesAReopen(t *testing.T) {
	p := logPath(t)
	appendN(t, p, 3)
	appendN(t, p, 2)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d lines after two sessions of 3 and 2", len(lines))
	}
	if !strings.Contains(lines[0], `"prev":""`) {
		t.Fatalf("the first line names a predecessor: %s", lines[0])
	}
	for i := 1; i < len(lines); i++ {
		if strings.Contains(lines[i], `"prev":""`) {
			t.Fatalf("line %d starts a new chain; a reopen must continue the old one: %s", i+1, lines[i])
		}
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the log is readable by group or other: %o", info.Mode().Perm())
	}
}

func TestATamperedLogRefusesToOpen(t *testing.T) {
	p := logPath(t)
	appendN(t, p, 4)
	if _, err := Open(p); err != nil {
		t.Fatalf("control: the untouched log was refused: %v", err)
	}
	raw, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(raw), "\n")
	lines = lines[:len(lines)-1] // the empty string after the last newline
	edits := map[string]string{
		"a middle line edited": strings.Join(lines[:1], "") + strings.Replace(lines[1], "wardryx-approval", "trailryx-root", 1) + strings.Join(lines[2:], ""),
		"a middle line gone":   strings.Join(lines[:1], "") + strings.Join(lines[2:], ""),
		"two lines swapped":    lines[0] + lines[2] + lines[1] + lines[3],
		"a line not JSON":      lines[0] + "not json\n" + strings.Join(lines[1:], ""),
		"the first line gone":  strings.Join(lines[1:], ""),
	}
	for what, body := range edits {
		q := logPath(t)
		if err := os.WriteFile(q, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(q); err == nil {
			t.Errorf("%s: the log opened", what)
		}
	}
}

func TestATornLastLineIsDiscardedAndTheChainContinues(t *testing.T) {
	p := logPath(t)
	appendN(t, p, 3)
	raw, _ := os.ReadFile(p)
	torn := append(append([]byte(nil), raw...), []byte(`{"at":9,"consumer":"wardr`)...)
	if err := os.WriteFile(p, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(p)
	if err != nil {
		t.Fatalf("a torn last line (a write that died before its sync) refused the open: %v", err)
	}
	if err := l.Append(entry(9)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if _, err := Open(p); err != nil {
		t.Fatalf("after appending past a torn line the log no longer opens: %v", err)
	}
	after, _ := os.ReadFile(p)
	if bytes.Contains(after, []byte(`"consumer":"wardr`+"\n")) || bytes.Contains(after, []byte(`"wardr{`)) {
		t.Fatal("the torn line was kept")
	}
}

// Every cut of a good log either opens (a prefix, possibly with a torn last
// line discarded) or refuses; nothing panics.
func TestEveryTruncationOpensAPrefixOrRefuses(t *testing.T) {
	p := logPath(t)
	appendN(t, p, 4)
	raw, _ := os.ReadFile(p)
	if _, err := Open(p); err != nil {
		t.Fatalf("control: %v", err)
	}
	for cut := 0; cut <= len(raw); cut++ {
		q := filepath.Join(t.TempDir(), "cut.ndjson")
		if err := os.WriteFile(q, raw[:cut], 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := Open(q)
		if err != nil {
			t.Fatalf("a cut at byte %d of %d refused the open: %v", cut, len(raw), err)
		}
		if err := l.Append(entry(99)); err != nil {
			t.Fatalf("cut %d: append: %v", cut, err)
		}
		_ = l.Close()
		if _, err := Open(q); err != nil {
			t.Fatalf("cut %d: after an append the log does not open: %v", cut, err)
		}
	}
}

func TestAnAppendAfterTheLogWasClosedFails(t *testing.T) {
	p := logPath(t)
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(entry(1)); err != nil {
		t.Fatalf("control: %v", err)
	}
	_ = l.Close()
	if err := l.Append(entry(2)); err == nil {
		t.Fatal("an append to a closed log answered success, so a signature could be answered with no record")
	}
}
