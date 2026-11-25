package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	kidA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	kidB = "-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type source struct {
	mu      sync.Mutex
	root    []byte
	stmts   map[string][]byte
	revoked map[string]int64
}

func newSource() *source {
	return &source{root: []byte(`{"keys":[{"kid":"r1"}]}`),
		stmts:   map[string][]byte{kidA: []byte(`{"payload":"a"}`), kidB: []byte(`{"payload":"b"}`)},
		revoked: map[string]int64{kidB: 1700000000}}
}

func (s *source) RootSet() ([]byte, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.root, nil }
func (s *source) Statement(kid string) ([]byte, int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.stmts[kid]
	return raw, s.revoked[kid], ok
}
func (s *source) Kids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.stmts {
		out = append(out, k)
	}
	return out
}

func dir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "statements")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func readKid(t *testing.T, d, kid string) (string, int64) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(d, kid+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Statement json.RawMessage `json:"statement"`
		RevokedAt int64           `json:"revoked_at"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return string(v.Statement), v.RevokedAt
}

func TestCheckRefusesADirectoryCustodyMustNotWrite(t *testing.T) {
	base := t.TempDir()
	good := filepath.Join(base, "statements")
	data := filepath.Join(base, "data")
	events := filepath.Join(base, "events")
	for _, d := range []string{good, data, events} {
		_ = os.Mkdir(d, 0o755)
	}
	uid := os.Geteuid()
	avoid := []string{data, events}
	if err := Check(good, uid, avoid); err != nil {
		t.Fatalf("a directory of custody's own: %v", err)
	}
	link := filepath.Join(base, "link")
	_ = os.Symlink(good, link)
	file := filepath.Join(base, "file")
	_ = os.WriteFile(file, nil, 0o644)
	open := filepath.Join(base, "open")
	_ = os.Mkdir(open, 0o755)
	_ = os.Chmod(open, 0o775)
	inside := filepath.Join(data, "statements")
	_ = os.Mkdir(inside, 0o755)
	for name, c := range map[string]struct {
		dir string
		uid int
	}{
		"a link":                       {link, uid},
		"a file":                       {file, uid},
		"a directory its group writes": {open, uid},
		"another uid's directory":      {good, uid + 1},
		"inside custody's data":        {inside, uid},
		"custody's data itself":        {data, uid},
		"the bus's directory":          {events, uid},
		"a parent of the bus":          {base, uid},
		"a relative path":              {"statements", uid},
		"a path that is not clean":     {good + "/../statements", uid},
		"nothing there":                {filepath.Join(base, "absent"), uid},
	} {
		if err := Check(c.dir, c.uid, avoid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOpenBringsTheDirectoryToCustodysState(t *testing.T) {
	d := dir(t)
	_ = os.WriteFile(filepath.Join(d, ".tmp-left"), []byte("half"), 0o600)
	src := newSource()
	e, err := Open(d, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if raw, _ := os.ReadFile(filepath.Join(d, RootFile)); string(raw) != string(src.root) {
		t.Fatalf("the root key set: %q", raw)
	}
	if st, rev := readKid(t, d, kidA); st != `{"payload":"a"}` || rev != 0 {
		t.Fatalf("kid A: %s %d", st, rev)
	}
	if st, rev := readKid(t, d, kidB); st != `{"payload":"b"}` || rev != 1700000000 {
		t.Fatalf("kid B, revoked: %s %d", st, rev)
	}
	entries, _ := os.ReadDir(d)
	for _, de := range entries {
		if strings.HasPrefix(de.Name(), ".tmp-") {
			t.Fatalf("a temporary file is left: %s", de.Name())
		}
		info, _ := de.Info()
		if info.Mode().Perm() != 0o644 {
			t.Errorf("%s is mode %o, want 0644", de.Name(), info.Mode().Perm())
		}
	}
}

func TestOpenRefusesADirectoryHoldingWhatCustodyNeverWrites(t *testing.T) {
	for name, plant := range map[string]func(d string){
		"a foreign file":            func(d string) { _ = os.WriteFile(filepath.Join(d, "notes.txt"), nil, 0o644) },
		"a kid file that is a link": func(d string) { _ = os.Symlink("/etc/passwd", filepath.Join(d, kidA+".json")) },
		"a directory":               func(d string) { _ = os.Mkdir(filepath.Join(d, "sub"), 0o755) },
		"a short kid's file":        func(d string) { _ = os.WriteFile(filepath.Join(d, "abc.json"), nil, 0o644) },
	} {
		d := dir(t)
		plant(d)
		if e, err := Open(d, newSource(), nil); err == nil {
			_ = e.Close()
			t.Errorf("%s: opened", name)
		}
	}
}

func TestAWriteIsOfTheStateAsItStandsNotOneQueuedEarlier(t *testing.T) {
	d := dir(t)
	src := newSource()
	e, err := Open(d, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Mark(kidA) // marked while kid A was not revoked
	src.mu.Lock()
	src.revoked[kidA] = 1800000000
	src.mu.Unlock()
	e.Flush()
	if _, rev := readKid(t, d, kidA); rev != 1800000000 {
		t.Fatalf("the write carried revoked_at %d, not the state as it stood", rev)
	}
}

func TestAFailedWriteWaitsAndIsTriedAgain(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory whatever its mode")
	}
	d := dir(t)
	src := newSource()
	e, err := Open(d, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	_ = os.Chmod(d, 0o555)
	src.mu.Lock()
	src.revoked[kidA] = 1900000000
	src.mu.Unlock()
	if err := e.Kid(kidA); err == nil {
		t.Fatal("a write into a directory that takes none said nothing")
	}
	if err := e.Root(); err == nil {
		t.Fatal("the root's write said nothing")
	}
	if n := e.Unexported(); n != 2 {
		t.Fatalf("%d copies wait, want 2", n)
	}
	_ = os.Chmod(d, 0o755)
	e.Flush()
	if n := e.Unexported(); n != 0 {
		t.Fatalf("%d copies still wait", n)
	}
	if _, rev := readKid(t, d, kidA); rev != 1900000000 {
		t.Fatalf("the retried write: revoked_at %d", rev)
	}
}

func TestOnlyAKidNamesAFile(t *testing.T) {
	d := dir(t)
	e, err := Open(d, newSource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, bad := range []string{"../escape", "a/b", "", strings.Repeat("A", 44), strings.Repeat("A", 42), "delegation-root.jwks"} {
		if err := e.Kid(bad); err == nil {
			t.Errorf("%q named a file", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(d), "escape.json")); err == nil {
		t.Fatal("a file was written outside the directory")
	}
	if err := e.Kid("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"); err == nil || e.Unexported() != 0 {
		t.Fatalf("a kid custody never certified: %v, %d waiting", err, e.Unexported())
	}
}
