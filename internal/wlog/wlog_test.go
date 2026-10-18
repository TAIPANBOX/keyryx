package wlog

import (
	"bytes"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/merkle"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// The witness's log is its word on what it saw. A log that opens after an
// edit is a witness that can be made to have seen something else.

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

type stand struct {
	dir   string
	now   time.Time
	store *keystore.Store
	log   *Log
}

func keysDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func newStand(t *testing.T) *stand {
	t.Helper()
	s := &stand{dir: t.TempDir(), now: t0}
	store, err := keystore.Open(keysDir(t), [32]byte{3, 1, 4}, Keys, func() time.Time { return s.now })
	if err != nil {
		t.Fatal(err)
	}
	s.store = store
	s.reopen(t)
	return s
}

func (s *stand) reopen(t *testing.T) {
	t.Helper()
	l, err := Open(s.dir, statement.StoreKeys(s.store, KeyES384, KeyMLDSA), func() time.Time { return s.now })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.log = l
}

func entry(i int) Entry {
	return Entry{Kind: "stream", SeenAt: t0.Add(time.Duration(i) * time.Second).Unix(), Stream: "wardryx.ndjson", Lines: int64(i), Bytes: int64(100 * i),
		Prefix: fmt.Sprintf("sha256:%064x", i), Mode: "full"}
}

func (s *stand) grow(t *testing.T, from, n int) Head {
	t.Helper()
	var es []Entry
	for i := from; i < from+n; i++ {
		es = append(es, entry(i))
	}
	if err := s.log.Append(es...); err != nil {
		t.Fatal(err)
	}
	s.now = s.now.Add(time.Minute)
	h, err := s.log.Sign(s.store)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return h
}

func TestTheLogIsAMerkleTreeAndEveryHeadIsSignedByBothHalves(t *testing.T) {
	s := newStand(t)
	h1 := s.grow(t, 0, 5)
	raw, _ := os.ReadFile(filepath.Join(s.dir, LogFile))
	var leaves []merkle.Hash
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		leaves = append(leaves, merkle.LeafHash([]byte(line)))
	}
	if len(leaves) != 5 || h1.Size != 5 || h1.Root != hex.EncodeToString(func() []byte { r := merkle.Root(leaves); return r[:] }()) {
		t.Fatalf("head %+v over %d lines is not the RFC 9162 root of those lines", h1, len(leaves))
	}
	root, _ := hex.DecodeString(h1.Root)
	var r merkle.Hash
	copy(r[:], root)
	in := HeadInput(h1.Size, r, h1.At)
	for _, half := range []struct {
		name string
		alg  policy.Alg
		sig  Sig
	}{{KeyES384, policy.ES384, h1.ES384}, {KeyMLDSA, policy.MLDSA65, h1.MLDSA65}} {
		rec, ok := s.store.Active(half.name)
		if !ok || rec.Kid != half.sig.Kid {
			t.Fatalf("%s: head signed by %s, active is %s", half.name, half.sig.Kid, rec.Kid)
		}
		if err := keystore.Verify(half.alg, rec.Public, in, mustB64(t, half.sig.Sig)); err != nil {
			t.Fatalf("%s: the head's signature does not verify: %v", half.name, err)
		}
	}
	h2 := s.grow(t, 5, 3)
	s.reopen(t)
	if s.log.Size() != 8 || len(s.log.Heads()) != 2 {
		t.Fatalf("after a reopen: %d leaves, %d heads", s.log.Size(), len(s.log.Heads()))
	}
	p, err := merkle.ConsistencyProof(s.log.Leaves(), int(h1.Size))
	if err != nil {
		t.Fatal(err)
	}
	if !merkle.VerifyConsistency(int(h1.Size), int(h2.Size), p, r, mustRoot(t, h2)) {
		t.Fatal("the second head is not an extension of the first")
	}
	if !bytes.HasPrefix(in, []byte("keyryx/witness-head/v1\x00")) {
		t.Fatal("the head input carries no domain separator")
	}
}

func TestAnEditedLogOrHeadRefusesTheStart(t *testing.T) {
	setup := func() *stand {
		s := newStand(t)
		s.grow(t, 0, 4)
		s.grow(t, 4, 4)
		return s
	}
	lines := func(path string) []string {
		raw, _ := os.ReadFile(path)
		return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	write := func(path string, ls []string) {
		_ = os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600)
	}
	other := newStand(t)
	other.grow(t, 0, 8)
	for name, edit := range map[string]func(s *stand){
		"a byte of an early entry changed": func(s *stand) {
			p := filepath.Join(s.dir, LogFile)
			ls := lines(p)
			ls[1] = strings.Replace(ls[1], `"lines":1`, `"lines":9`, 1)
			write(p, ls)
		},
		"a middle entry removed": func(s *stand) {
			p := filepath.Join(s.dir, LogFile)
			ls := lines(p)
			write(p, append(ls[:2], ls[3:]...))
		},
		"two entries swapped": func(s *stand) {
			p := filepath.Join(s.dir, LogFile)
			ls := lines(p)
			ls[0], ls[1] = ls[1], ls[0]
			write(p, ls)
		},
		"an unknown member in an entry": func(s *stand) {
			p := filepath.Join(s.dir, LogFile)
			ls := lines(p)
			ls[0] = strings.Replace(ls[0], `{"kind"`, `{"x":1,"kind"`, 1)
			write(p, ls)
		},
		"a head's root changed": func(s *stand) {
			p := filepath.Join(s.dir, HeadsFile)
			ls := lines(p)
			ls[0] = strings.Replace(ls[0], `"root":"`, `"root":"00`, 1)
			write(p, ls)
		},
		"a head larger than the log": func(s *stand) {
			p := filepath.Join(s.dir, HeadsFile)
			ls := lines(p)
			ls[1] = strings.Replace(ls[1], `"size":8`, `"size":9`, 1)
			write(p, ls)
		},
		"a head's ML-DSA half removed": func(s *stand) {
			p := filepath.Join(s.dir, HeadsFile)
			ls := lines(p)
			i := strings.Index(ls[0], `,"ml_dsa_65"`)
			ls[0] = ls[0][:i] + "}"
			write(p, ls)
		},
		"a head from another witness": func(s *stand) {
			write(filepath.Join(s.dir, HeadsFile), lines(filepath.Join(other.dir, HeadsFile)))
		},
		"the heads swapped": func(s *stand) {
			p := filepath.Join(s.dir, HeadsFile)
			ls := lines(p)
			ls[0], ls[1] = ls[1], ls[0]
			write(p, ls)
		},
	} {
		s := setup()
		edit(s)
		if _, err := Open(s.dir, statement.StoreKeys(s.store, KeyES384, KeyMLDSA), func() time.Time { return s.now }); err == nil {
			t.Errorf("%s: the log opened", name)
		}
	}
	s := setup()
	s.reopen(t)
}

func TestATornLastLineIsDiscardedAndTheLogContinues(t *testing.T) {
	s := newStand(t)
	s.grow(t, 0, 3)
	for _, f := range []string{LogFile, HeadsFile} {
		fh, _ := os.OpenFile(filepath.Join(s.dir, f), os.O_APPEND|os.O_WRONLY, 0o600)
		_, _ = fh.WriteString(`{"kind":"str`)
		_ = fh.Close()
	}
	s.reopen(t)
	if s.log.Size() != 3 || len(s.log.Heads()) != 1 {
		t.Fatalf("after a torn tail: %d leaves, %d heads", s.log.Size(), len(s.log.Heads()))
	}
	s.grow(t, 3, 2)
	s.reopen(t)
	if s.log.Size() != 5 || len(s.log.Heads()) != 2 {
		t.Fatalf("the log did not continue: %d leaves, %d heads", s.log.Size(), len(s.log.Heads()))
	}
}

func TestHostileLogFilesNeverPanicAndNeverOpenInconsistent(t *testing.T) {
	s := newStand(t)
	s.grow(t, 0, 6)
	s.grow(t, 6, 2)
	logPath := filepath.Join(s.dir, LogFile)
	orig, _ := os.ReadFile(logPath)
	r := mrand.New(mrand.NewPCG(20261018, 51))
	alphabet := []byte(`{}[]",:0123456789abcdef-_ ` + "\n")
	for i := 0; i < 1500; i++ {
		b := append([]byte(nil), orig...)
		for k := 0; k <= r.IntN(3); k++ {
			b[r.IntN(len(b))] = alphabet[r.IntN(len(alphabet))]
		}
		_ = os.WriteFile(logPath, b, 0o600)
		l, err := Open(s.dir, statement.StoreKeys(s.store, KeyES384, KeyMLDSA), func() time.Time { return s.now })
		if err != nil {
			continue
		}
		for _, h := range l.Heads() {
			if mustRoot(t, h) != merkle.Root(l.Leaves()[:h.Size]) {
				t.Fatalf("case %d: a log opened whose head does not match its leaves", i)
			}
		}
		_ = os.WriteFile(logPath, orig, 0o600)
	}
}

func TestVerifyDirSaysOkBrokenOrMeasuredNothing(t *testing.T) {
	s := newStand(t)
	s.grow(t, 0, 4)
	keys := statement.StoreKeys(s.store, KeyES384, KeyMLDSA)
	if rep := VerifyDir(s.dir, keys); rep.Broken || !rep.Measured {
		t.Fatalf("an honest log: %+v", rep)
	}
	p := filepath.Join(s.dir, LogFile)
	raw, _ := os.ReadFile(p)
	_ = os.WriteFile(p, bytes.Replace(raw, []byte(`"lines":2`), []byte(`"lines":3`), 1), 0o600)
	if rep := VerifyDir(s.dir, keys); !rep.Broken {
		t.Fatalf("an edited log: %+v", rep)
	}
	if rep := VerifyDir(t.TempDir(), keys); rep.Measured || rep.Broken {
		t.Fatalf("an empty directory: %+v", rep)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustRoot(t *testing.T, h Head) merkle.Hash {
	t.Helper()
	b, err := hex.DecodeString(h.Root)
	if err != nil || len(b) != 48 {
		t.Fatalf("head root %q", h.Root)
	}
	var r merkle.Hash
	copy(r[:], b)
	return r
}
