package announce

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTheBusStreamIsCustodysOwnRegularFile(t *testing.T) {
	dir := t.TempDir()
	me := os.Getuid()
	stream := filepath.Join(dir, "keyryx-custody.ndjson")

	// Not there yet, in a directory custody owns: made, and taken.
	w, err := OpenBus(stream, me)
	if err != nil {
		t.Fatalf("a stream custody makes itself: %v", err)
	}
	if c, ok := w.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	// There, custody's own: taken.
	if _, err := OpenBus(stream, me); err != nil {
		t.Fatalf("custody's own stream: %v", err)
	}

	// A link at custody's name, pointing at a file custody writes: refused,
	// and the target is not touched.
	target := filepath.Join(dir, "use.ndjson")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.ndjson")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBus(link, me); err == nil {
		t.Fatalf("a link at custody's name: %v", err)
	}
	if raw, _ := os.ReadFile(target); string(raw) != "{}\n" {
		t.Fatalf("the link's target was written: %q", raw)
	}

	// A second name for one file: refused.
	hard := filepath.Join(dir, "hard.ndjson")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBus(hard, me); err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("a file with two names: %v", err)
	}

	// A file another uid owns: refused.
	if _, err := OpenBus(stream, me+1); err == nil || !strings.Contains(err.Error(), "uid") {
		t.Fatalf("a stream another plane made: %v", err)
	}

	// What custody writes goes into the file it checked.
	w, err = OpenBus(stream, me)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Revoked("k", "z", "ES256").event(t0)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(stream)
	if err := w.Write(Rotated("k", "b", "a", "ES256").event(t0)); err != nil {
		t.Fatalf("a write through the descriptor's path: %v", err)
	}
	after, _ := os.ReadFile(stream)
	if len(after) <= len(before) || !strings.HasPrefix(string(after), string(before)) {
		t.Fatalf("the write did not land after what custody's stream held: %q then %q", before, after)
	}

	// A link swapped in at the name after the checks and before the writer
	// opens: the writer still writes the file custody checked.
	raced := filepath.Join(dir, "raced.ndjson")
	if err := os.WriteFile(raced, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	beforeTheWriterOpens = func(p string) {
		_ = os.Rename(p, p+".moved")
		_ = os.Symlink(target, p)
	}
	w, err = OpenBus(raced, me)
	beforeTheWriterOpens = func(string) {}
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Revoked("k", "a", "ES256").event(t0)); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(target); string(raw) != "{}\n" {
		t.Fatalf("a link swapped in during the open was written through: %q", raw)
	}
	if raw, _ := os.ReadFile(raced + ".moved"); len(raw) == 0 {
		t.Fatal("the write did not reach the file custody checked")
	}

	// A FIFO at the name: refused, and opening it does not hang.
	fifo := filepath.Join(dir, "fifo.ndjson")
	if err := mkfifo(fifo); err == nil {
		if _, err := OpenBus(fifo, me); err == nil {
			t.Fatal("a FIFO at custody's name was taken")
		}
	}

	// A directory at the name: refused.
	d := filepath.Join(dir, "dir.ndjson")
	_ = os.Mkdir(d, 0o700)
	if _, err := OpenBus(d, me); err == nil {
		t.Fatal("a directory at custody's name was taken")
	}
}

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
