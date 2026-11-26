package wlog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// The edges of the log's own API: what it hands out is a copy within bounds,
// what it cannot write leaves no trace in memory or on disk, and a head never
// goes back in time even when the clock does.

func TestTheReadersHandOutCopiesWithinBounds(t *testing.T) {
	s := newStand(t)
	if _, ok := s.log.Latest(); ok {
		t.Fatal("an empty log has a latest head")
	}
	h := s.grow(t, 0, 4)
	if got, ok := s.log.Latest(); !ok || got != h {
		t.Fatalf("latest %+v %v, want %+v", got, ok, h)
	}
	raw, _ := os.ReadFile(filepath.Join(s.dir, LogFile))
	file := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines := s.log.Lines(1, 3)
	if len(lines) != 2 || string(lines[0]) != file[1] || string(lines[1]) != file[2] {
		t.Fatalf("Lines(1, 3) = %q, want %q", lines, file[1:3])
	}
	if all := s.log.Lines(0, 4); len(all) != 4 {
		t.Fatalf("Lines(0, 4) = %d lines", len(all))
	}
	for _, r := range [][2]int{{-1, 2}, {0, 5}, {3, 2}, {5, 5}} {
		if got := s.log.Lines(r[0], r[1]); got != nil {
			t.Errorf("Lines(%d, %d) = %q, want nothing", r[0], r[1], got)
		}
	}
	es := s.log.Entries()
	if len(es) != 4 || !reflect.DeepEqual(es[2], entry(2)) {
		t.Fatalf("entries %+v", es)
	}
	es[2].Stream = "edited"
	if s.log.Entries()[2].Stream != "wardryx.ndjson" {
		t.Fatal("an edit of the entries handed out reached the log")
	}
}

func TestWhatCannotBeWrittenIsNotAppended(t *testing.T) {
	s := newStand(t)
	if err := s.log.Append(); err != nil || s.log.Size() != 0 {
		t.Fatalf("an empty append: %v, size %d", err, s.log.Size())
	}
	if _, err := s.log.Sign(s.store); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("signing an empty log: %v", err)
	}
	big := entry(0)
	big.Stream = strings.Repeat("x", MaxLine)
	if err := s.log.Append(entry(0), big); err == nil || !strings.Contains(err.Error(), "line cap") {
		t.Fatalf("an entry over the line cap: %v", err)
	}
	if s.log.Size() != 0 {
		t.Fatalf("a refused batch left %d entries", s.log.Size())
	}
	if raw, _ := os.ReadFile(filepath.Join(s.dir, LogFile)); len(raw) != 0 {
		t.Fatalf("a refused batch reached the file: %q", raw)
	}
	s.grow(t, 0, 2)
	if err := s.log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.log.Append(entry(2)); err == nil || s.log.Size() != 2 {
		t.Fatalf("an append after Close: %v, size %d", err, s.log.Size())
	}
	if _, err := s.log.Sign(s.store); err == nil || len(s.log.Heads()) != 1 {
		t.Fatalf("a sign after Close: %v, %d heads", err, len(s.log.Heads()))
	}
}

// failingSigner signs the ES384 half and refuses the ML-DSA one.
type failingSigner struct{ statement.Signer }

func (f failingSigner) SignInput(name string, build func(policy.Alg, string) ([]byte, error)) (keystore.Signature, error) {
	if name == KeyMLDSA {
		return keystore.Signature{}, errors.New("the ML-DSA half is gone")
	}
	return f.Signer.SignInput(name, build)
}

func TestAHeadMissingAHalfIsNeitherKeptNorWritten(t *testing.T) {
	s := newStand(t)
	s.grow(t, 0, 2)
	if err := s.log.Append(entry(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.log.Sign(failingSigner{s.store}); err == nil || !strings.Contains(err.Error(), "ML-DSA half is gone") {
		t.Fatalf("a half that did not sign: %v", err)
	}
	if len(s.log.Heads()) != 1 {
		t.Fatalf("a head with one half was kept: %d heads", len(s.log.Heads()))
	}
	raw, _ := os.ReadFile(filepath.Join(s.dir, HeadsFile))
	if bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("a head with one half reached the file:\n%s", raw)
	}
}

func TestAHeadNeverGoesBackWhenTheClockDoes(t *testing.T) {
	s := newStand(t)
	h1 := s.grow(t, 0, 2)
	s.now = t0.Add(-time.Hour)
	if err := s.log.Append(entry(2)); err != nil {
		t.Fatal(err)
	}
	h2, err := s.log.Sign(s.store)
	if err != nil {
		t.Fatal(err)
	}
	if h2.At != h1.At {
		t.Fatalf("the second head is at %d, the first at %d: a clock that went back moved the head back", h2.At, h1.At)
	}
	s.reopen(t)
	if len(s.log.Heads()) != 2 {
		t.Fatal("the log does not reopen over a head clamped to the one before")
	}
}

func TestAnUnreadableOrOverlongLogRefusesTheOpen(t *testing.T) {
	s := newStand(t)
	keys := statement.StoreKeys(s.store, KeyES384, KeyMLDSA)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, LogFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, keys, time.Now); err == nil {
		t.Fatal("a log that is a directory opened")
	}
	dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, HeadsFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, keys, time.Now); err == nil {
		t.Fatal("a heads file that is a directory opened")
	}
	dir = t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, LogFile), append(bytes.Repeat([]byte("x"), MaxLine+1), '\n'), 0o600)
	if _, err := Open(dir, keys, time.Now); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("a line over the cap: %v", err)
	}
}

func TestVerifyDirSaysWhatIsUnsignedOrTornAndNeverOKAboutNoHead(t *testing.T) {
	s := newStand(t)
	keys := statement.StoreKeys(s.store, KeyES384, KeyMLDSA)
	if err := s.log.Append(entry(0), entry(1)); err != nil {
		t.Fatal(err)
	}
	rep := VerifyDir(s.dir, keys)
	if rep.Measured || rep.Broken || len(rep.Lines) != 1 || !strings.Contains(rep.Lines[0], "2 entries and no signed head") {
		t.Fatalf("a log with no head: %+v", rep)
	}
	s.now = s.now.Add(time.Minute)
	if _, err := s.log.Sign(s.store); err != nil {
		t.Fatal(err)
	}
	if err := s.log.Append(entry(2)); err != nil {
		t.Fatal(err)
	}
	rep = VerifyDir(s.dir, keys)
	if rep.Broken || !rep.Measured || !strings.Contains(strings.Join(rep.Lines, "\n"), "[weak] log: 1 entries after the last signed head") {
		t.Fatalf("an entry after the last head: %+v", rep)
	}
	f, _ := os.OpenFile(filepath.Join(s.dir, HeadsFile), os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.WriteString(`{"size":`)
	_ = f.Close()
	rep = VerifyDir(s.dir, keys)
	if rep.Broken || !rep.Measured || !strings.Contains(strings.Join(rep.Lines, "\n"), "[weak] log: a half-written last line") {
		t.Fatalf("a torn last head: %+v", rep)
	}
}
