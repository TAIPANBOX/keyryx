package announce

import (
	"os"
	"path/filepath"
	"strings"
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
	if _, err := OpenBus(link, me); err == nil || !strings.Contains(err.Error(), "regular") {
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

	// A directory at the name: refused.
	d := filepath.Join(dir, "dir.ndjson")
	_ = os.Mkdir(d, 0o700)
	if _, err := OpenBus(d, me); err == nil {
		t.Fatal("a directory at custody's name was taken")
	}
}
