// Package wlog is the witness's own append-only log (CLAUDE.md invariant 33).
//
// `log.ndjson` holds one JSON entry per observation, each line a leaf of an
// RFC 9162 Merkle tree over SHA-384; `heads.ndjson` holds the signed tree
// heads, `{size, root, at}` signed by both halves of the witness key, ES384
// and ML-DSA-65, over a domain-separated input. A verifier that kept an old
// head can ask for a consistency proof and see that the log only grew, which
// is what makes the witness itself accountable.
//
// Opening the log verifies all of it: every entry is the form the witness
// writes, every head is the root of the entries it covers, signed by keys the
// witness holds, and no head goes back in size or time. Anything else refuses
// the open. Entries after the last signed head were never the witness's word,
// since a crash came between writing them and signing, so they are dropped and
// observed again.
package wlog

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/merkle"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

const (
	// KeyES384 and KeyMLDSA are the witness key's two halves, in the
	// witness's own store.
	KeyES384  = "keyryx.witness.es384"
	KeyMLDSA  = "keyryx.witness.ml-dsa-65"
	LogFile   = "log.ndjson"
	HeadsFile = "heads.ndjson"
	// MaxLine bounds one entry or head line.
	MaxLine = 64 << 10
)

// Keys are the witness key's two halves.
var Keys = []policy.Key{{Name: KeyES384, Alg: policy.ES384, Mode: policy.Held}, {Name: KeyMLDSA, Alg: policy.MLDSA65, Mode: policy.Held}}

// ShardSeen is one trailryx shard as witnessed.
type ShardSeen struct {
	Shard     uint16   `json:"shard"`
	Segments  uint64   `json:"segments"`
	Root      string   `json:"root"`
	Manifests []string `json:"manifests,omitempty"`
}

// Entry is one observation. Kind is stream, checkpoint, root, finding,
// anchor or delegation_root; the members a kind does not use are left out.
type Entry struct {
	Kind       string      `json:"kind"`
	SeenAt     int64       `json:"seen_at"`
	Stream     string      `json:"stream,omitempty"`
	Tenant     string      `json:"tenant,omitempty"`
	Lines      int64       `json:"lines,omitempty"`
	Bytes      int64       `json:"bytes,omitempty"`
	Prefix     string      `json:"prefix,omitempty"`
	Head       string      `json:"head,omitempty"`
	Mode       string      `json:"mode,omitempty"`
	CkptBytes  int64       `json:"checkpoint_bytes,omitempty"`
	CkptPrefix string      `json:"checkpoint_prefix,omitempty"`
	CkptLast   string      `json:"checkpoint_last,omitempty"`
	Count      int64       `json:"count,omitempty"`
	End        int64       `json:"end,omitempty"`
	CkptKind   string      `json:"checkpoint_kind,omitempty"`
	Record     string      `json:"record,omitempty"`
	StoreRoot  string      `json:"store_root,omitempty"`
	Segments   uint64      `json:"segments,omitempty"`
	Shards     []ShardSeen `json:"shards,omitempty"`
	LinesTotal int64       `json:"lines_total,omitempty"`
	Type       string      `json:"type,omitempty"`
	Severity   string      `json:"severity,omitempty"`
	Size       int64       `json:"size,omitempty"`
	Token      string      `json:"token,omitempty"`
	GenTime    int64       `json:"gen_time,omitempty"`
	Kids       []string    `json:"kids,omitempty"`
}

// Sig is one half of a head's signature.
type Sig struct {
	Kid string `json:"kid"`
	Sig string `json:"sig"`
}

// Head is a signed tree head.
type Head struct {
	Size    int64  `json:"size"`
	Root    string `json:"root"`
	At      int64  `json:"at"`
	ES384   Sig    `json:"es384"`
	MLDSA65 Sig    `json:"ml_dsa_65"`
}

// HeadInput is what both halves sign: a domain, the size, the root, the time.
func HeadInput(size int64, root merkle.Hash, at int64) []byte {
	b := []byte("keyryx/witness-head/v1\x00")
	b = binary.BigEndian.AppendUint64(b, uint64(size))
	b = append(b, root[:]...)
	return binary.BigEndian.AppendUint64(b, uint64(at))
}

func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }

// Log is the open log. Safe for concurrent use.
type Log struct {
	mu       sync.Mutex
	dir      string
	logF     *os.File
	headsF   *os.File
	lines    [][]byte
	entries  []Entry
	leaves   []merkle.Hash
	frontier merkle.Frontier
	heads    []Head
	now      func() time.Time
}

type loaded struct {
	lines   [][]byte
	entries []Entry
	leaves  []merkle.Hash
	heads   []Head
	// logTorn and headsTorn are how many bytes of a half-written last line
	// each file ends in; unsigned is how many whole entries no head covers.
	logTorn, headsTorn int
	unsigned           int
}

// readLines splits a file into its LF-terminated lines; a last line with no
// LF is torn and counted, not returned.
func readLines(path string) ([][]byte, int, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the witness's own data directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var out [][]byte
	for len(raw) > 0 {
		i := bytes.IndexByte(raw, '\n')
		if i < 0 {
			return out, len(raw), nil
		}
		if i > MaxLine {
			return nil, 0, fmt.Errorf("%s holds a line over %d bytes", path, MaxLine)
		}
		out = append(out, raw[:i])
		raw = raw[i+1:]
	}
	return out, 0, nil
}

func strictDecode(line []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the object")
	}
	return nil
}

// headRoot reads a head's root.
func headRoot(h Head) (merkle.Hash, error) {
	var r merkle.Hash
	b, err := hex.DecodeString(h.Root)
	if err != nil || len(b) != len(r) {
		return r, errors.New("a head's root is not 96 hex digits")
	}
	copy(r[:], b)
	return r, nil
}

// load reads and checks everything.
func load(dir string, keys statement.RootKey) (loaded, error) {
	var l loaded
	lines, torn, err := readLines(filepath.Join(dir, LogFile))
	if err != nil {
		return l, err
	}
	l.logTorn = torn
	for i, line := range lines {
		var e Entry
		if err := strictDecode(line, &e); err != nil {
			return l, fmt.Errorf("entry %d of %s is not an entry: %v", i+1, LogFile, err)
		}
		if again, _ := json.Marshal(e); !bytes.Equal(again, line) {
			return l, fmt.Errorf("entry %d of %s is not in the form the witness writes", i+1, LogFile)
		}
		l.lines, l.entries, l.leaves = append(l.lines, line), append(l.entries, e), append(l.leaves, merkle.LeafHash(line))
	}
	heads, htorn, err := readLines(filepath.Join(dir, HeadsFile))
	if err != nil {
		return l, err
	}
	l.headsTorn = htorn
	var f merkle.Frontier
	var last Head
	for i, line := range heads {
		var h Head
		if err := strictDecode(line, &h); err != nil {
			return l, fmt.Errorf("head %d of %s is not a head: %v", i+1, HeadsFile, err)
		}
		if h.Size < 1 || h.Size > int64(len(l.leaves)) {
			return l, fmt.Errorf("head %d covers %d entries and the log holds %d", i+1, h.Size, len(l.leaves))
		}
		if h.Size < last.Size || h.At < last.At {
			return l, fmt.Errorf("head %d goes back from the head before it", i+1)
		}
		for f.Size() < int(h.Size) {
			f.Add(l.leaves[f.Size()])
		}
		root, err := headRoot(h)
		if err != nil {
			return l, fmt.Errorf("head %d: %v", i+1, err)
		}
		if root != f.Root() {
			return l, fmt.Errorf("head %d is not the root of the %d entries it covers", i+1, h.Size)
		}
		in := HeadInput(h.Size, root, h.At)
		for _, half := range []struct {
			alg policy.Alg
			sig Sig
		}{{policy.ES384, h.ES384}, {policy.MLDSA65, h.MLDSA65}} {
			alg, pub, ok := keys(half.sig.Kid)
			sig, derr := decodeB64(half.sig.Sig)
			if !ok || alg != half.alg || derr != nil || keystore.Verify(alg, pub, in, sig) != nil {
				return l, fmt.Errorf("head %d: its %s half does not verify under the witness's keys", i+1, half.alg)
			}
		}
		l.heads, last = append(l.heads, h), h
	}
	l.unsigned = len(l.lines) - int(last.Size)
	return l, nil
}

// Open reads and verifies the log in dir, drops a torn last line and every
// entry no head covers, and opens both files for appending.
func Open(dir string, keys statement.RootKey, now func() time.Time) (*Log, error) {
	l, err := load(dir, keys)
	if err != nil {
		return nil, fmt.Errorf("the witness log in %s: %w", dir, err)
	}
	signed := len(l.lines) - l.unsigned
	if l.logTorn > 0 || l.unsigned > 0 {
		var b bytes.Buffer
		for _, line := range l.lines[:signed] {
			b.Write(line)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(filepath.Join(dir, LogFile), b.Bytes(), 0o600); err != nil {
			return nil, err
		}
	}
	if l.headsTorn > 0 {
		var b bytes.Buffer
		for _, h := range l.heads {
			line, _ := json.Marshal(h)
			b.Write(line)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(filepath.Join(dir, HeadsFile), b.Bytes(), 0o600); err != nil {
			return nil, err
		}
	}
	out := &Log{dir: dir, now: now, lines: l.lines[:signed], entries: l.entries[:signed], leaves: l.leaves[:signed], heads: l.heads}
	for _, lf := range out.leaves {
		out.frontier.Add(lf)
	}
	if out.logF, err = os.OpenFile(filepath.Join(dir, LogFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil { // #nosec G304 -- the witness's own data directory
		return nil, err
	}
	if out.headsF, err = os.OpenFile(filepath.Join(dir, HeadsFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil { // #nosec G304 -- the same directory
		_ = out.logF.Close()
		return nil, err
	}
	return out, nil
}

// Append writes entries and returns once they reached the disk.
func (l *Log) Append(es ...Entry) error {
	if len(es) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var b bytes.Buffer
	var lines [][]byte
	for _, e := range es {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if len(line) > MaxLine {
			return fmt.Errorf("an entry of %d bytes is over the line cap", len(line))
		}
		lines = append(lines, line)
		b.Write(line)
		b.WriteByte('\n')
	}
	if _, err := l.logF.Write(b.Bytes()); err != nil {
		return err
	}
	if err := l.logF.Sync(); err != nil {
		return err
	}
	for i, line := range lines {
		leaf := merkle.LeafHash(line)
		l.lines, l.entries, l.leaves = append(l.lines, line), append(l.entries, es[i]), append(l.leaves, leaf)
		l.frontier.Add(leaf)
	}
	return nil
}

// Sign signs a head over every entry appended so far, with both halves.
func (l *Log) Sign(s statement.Signer) (Head, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.leaves) == 0 {
		return Head{}, errors.New("the witness log is empty, so there is nothing to sign")
	}
	h := Head{Size: int64(len(l.leaves)), At: l.now().Unix()}
	if n := len(l.heads); n > 0 && h.At < l.heads[n-1].At {
		h.At = l.heads[n-1].At
	}
	root := l.frontier.Root()
	h.Root = hex.EncodeToString(root[:])
	in := HeadInput(h.Size, root, h.At)
	for _, half := range []struct {
		name string
		into *Sig
	}{{KeyES384, &h.ES384}, {KeyMLDSA, &h.MLDSA65}} {
		sig, err := s.SignInput(half.name, func(policy.Alg, string) ([]byte, error) { return in, nil })
		if err != nil {
			return Head{}, err
		}
		*half.into = Sig{Kid: sig.Kid, Sig: base64.RawURLEncoding.EncodeToString(sig.Sig)}
	}
	line, err := json.Marshal(h)
	if err != nil {
		return Head{}, err
	}
	if _, err := l.headsF.Write(append(line, '\n')); err != nil {
		return Head{}, err
	}
	if err := l.headsF.Sync(); err != nil {
		return Head{}, err
	}
	l.heads = append(l.heads, h)
	return h, nil
}

// Size is the number of entries.
func (l *Log) Size() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int64(len(l.leaves))
}

// Leaves are the entries' leaf hashes.
func (l *Log) Leaves() []merkle.Hash {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]merkle.Hash(nil), l.leaves...)
}

// Lines are the entries as written.
func (l *Log) Lines(start, end int) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if start < 0 || end > len(l.lines) || start > end {
		return nil
	}
	return append([][]byte(nil), l.lines[start:end]...)
}

// Entries are the entries.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entries...)
}

// Heads are the signed heads.
func (l *Log) Heads() []Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Head(nil), l.heads...)
}

// Latest is the newest signed head.
func (l *Log) Latest() (Head, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.heads) == 0 {
		return Head{}, false
	}
	return l.heads[len(l.heads)-1], true
}

// Close releases both files.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(l.logF.Close(), l.headsF.Close())
}

// Report is what VerifyDir found, in trailryx-verify's vocabulary.
type Report struct {
	Lines    []string
	Broken   bool
	Measured bool
}

// VerifyDir checks a witness log offline, against keys a verifier was given,
// writing nothing.
func VerifyDir(dir string, keys statement.RootKey) Report {
	var r Report
	_, e1 := os.Stat(filepath.Join(dir, LogFile))
	_, e2 := os.Stat(filepath.Join(dir, HeadsFile))
	if errors.Is(e1, os.ErrNotExist) && errors.Is(e2, os.ErrNotExist) {
		r.Lines = append(r.Lines, "[broken] log: no witness log in "+dir+", so this check measured nothing")
		return r
	}
	l, err := load(dir, keys)
	if err != nil {
		r.Measured, r.Broken = true, true
		r.Lines = append(r.Lines, "[broken] log: "+err.Error())
		return r
	}
	if len(l.heads) == 0 {
		r.Lines = append(r.Lines, fmt.Sprintf("[broken] log: %d entries and no signed head, so this check measured nothing", len(l.lines)))
		return r
	}
	r.Measured = true
	last := l.heads[len(l.heads)-1]
	r.Lines = append(r.Lines, fmt.Sprintf("[ok] log: %d entries under %d heads, each head the root of the entries it covers, signed by both halves of the witness key", last.Size, len(l.heads)))
	r.Lines = append(r.Lines, fmt.Sprintf("[ok] log: the heads only grow, from %d to %d entries", l.heads[0].Size, last.Size))
	if l.unsigned > 0 {
		r.Lines = append(r.Lines, fmt.Sprintf("[weak] log: %d entries after the last signed head are nobody's word yet", l.unsigned))
	}
	if l.logTorn > 0 || l.headsTorn > 0 {
		r.Lines = append(r.Lines, "[weak] log: a half-written last line, which a restart discards")
	}
	return r
}
