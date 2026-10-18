// Package witness is the witness role's observer (CLAUDE.md invariants 31 to
// 36): it reads every stream, its checkpoints and every trailryx data
// directory read-only, once an interval, and says when what it saw before is
// no longer there.
//
// # What it keeps, and where
//
// Its state is its own log (internal/wlog): for each stream the lines and
// bytes it has read, the SHA-256 of those bytes (the prefix, agent-passport
// SPEC 6.5.1's member), the chain hash of the last line and how far it has
// read the stream's checkpoint file; every checkpoint it accepted; for each
// trailryx tenant the store root and each shard's root and segment count. A
// restart rebuilds all of it from the log, so a rewrite made while the
// witness was down is caught on its first read.
//
// # What it checks each interval
//
//   - The bytes it saw are still there: it hashes the stream again from byte
//     zero up to what it read, and at each accepted checkpoint's N on the way,
//     so a rewrite, a re-link the SPEC 6.5 chain accepts and a whitespace edit
//     no chain hash sees are all caught, and the finding names the earliest
//     checkpoint the producer signed that the rewrite contradicts. A stream
//     larger than FullBytes is hashed from zero once every FullInterval and
//     forward from where it stopped in between, and its log entry says which.
//   - Nothing shrank.
//   - The new lines chain: a line with no prev_hash after the first, or one
//     whose prev_hash is not the chain hash of the line before, is a restart,
//     medium when an accepted resume checkpoint at the line before explains it
//     and high otherwise.
//   - Each new checkpoint holds, by SPEC 6.5.1's steps, its key valid at its
//     time and not revoked by the time the witness read it; a record ahead of
//     the stream waits for the stream.
//   - Each trailryx tenant's sealed manifests are still the ones it saw, and a
//     new store root is attested in trailryx-sign's byte format with the
//     witness key's ES384 half; a record that grew past a seal's worth with no
//     new root for two seal intervals is reported once.
//
// Every finding is an agent-event in keyryx.ndjson (SPEC 6.2's keyryx row)
// carrying counts and clipped hashes, never record content, and an entry in
// the log; the interval ends with a tree head signed by both halves.
package witness

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"

	"github.com/TAIPANBOX/keyryx/internal/checkpoint"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/trailryx"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// The finding types the witness writes, SPEC 6.2's keyryx row.
const (
	StreamRewritten   = "witness_stream_rewritten"
	StreamTruncated   = "witness_stream_truncated"
	ChainRestarted    = "witness_chain_restarted"
	CheckpointInvalid = "witness_checkpoint_invalid"
	CheckpointUnsign  = "witness_checkpoint_unsigned"
	RootMissing       = "witness_root_missing"
	RootEquivocated   = "witness_root_equivocated"
	// Subject is the witness's own subject on the bus.
	Subject = "agent://keyryx.internal/witness"
	// MaxLine bounds one stream line the witness reads.
	MaxLine = 4 << 20
)

// Tenant is one trailryx data directory.
type Tenant struct{ Name, Dir string }

// Config is what the witness reads and how often it reads it in full.
type Config struct {
	Events, Checkpoints, Attestations string
	Records                           []Tenant
	FullBytes                         int64
	FullInterval, SealEvery           time.Duration
	SealLines                         int64
	Name                              string
}

// Keys answers which public key certifies a checkpoint's kid at the record's
// time, given when the witness saw the record.
type Keys interface {
	Key(kid string, at, seen time.Time) ([]byte, error)
}

// Finding is one thing the witness disagrees with.
type Finding struct {
	Type, Severity string
	Data           map[string]any
}

// Alerter is where findings go.
type Alerter interface{ Alert(Finding) error }

// Attestation is a trailryx witness attestation: the fields trailryx's
// WitnessAttestation carries, and the tenant and root it is about.
type Attestation struct {
	Witness   string `json:"witness"`
	Tenant    string `json:"tenant"`
	StoreRoot string `json:"store_root"`
	Segments  uint64 `json:"segments"`
	SeenAt    uint64 `json:"seen_at"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type kept struct {
	count, end   int64
	prefix, kind string
}

type streamState struct {
	lines, bytes int64
	prefix, head string
	h            hash.Hash
	lastFull     time.Time
	kept         []kept
	ckptBytes    int64
	ckptPrefix   string
	ckptLast     string
	ckptHash     hash.Hash
}

type rootState struct {
	shards   []wlog.ShardSeen
	root     string
	segments uint64
}

// Witness is the observer. Tick is called from one goroutine.
type Witness struct {
	cfg         Config
	log         *wlog.Log
	signer      statement.Signer
	keys        Keys
	alerts      Alerter
	now         func() time.Time
	streams     map[string]*streamState
	roots       map[string]*rootState
	lastRootAt  map[string]time.Time
	linesAtRoot map[string]int64
	missing     map[string]bool
}

// New rebuilds the witness's state from its log.
func New(cfg Config, log *wlog.Log, signer statement.Signer, keys Keys, alerts Alerter, now func() time.Time) (*Witness, error) {
	if cfg.Events == "" {
		return nil, errors.New("witness: no events directory")
	}
	if err := trailryx.CheckWitnessName(cfg.Name); err != nil {
		return nil, err
	}
	if log == nil || signer == nil || alerts == nil || now == nil || (cfg.Checkpoints != "" && keys == nil) {
		return nil, errors.New("witness: a log, a signer, an alerter, a clock, and keys for checkpoints, are all required")
	}
	w := &Witness{cfg: cfg, log: log, signer: signer, keys: keys, alerts: alerts, now: now,
		streams: map[string]*streamState{}, roots: map[string]*rootState{}, lastRootAt: map[string]time.Time{},
		linesAtRoot: map[string]int64{}, missing: map[string]bool{}}
	for _, e := range log.Entries() {
		switch e.Kind {
		case "stream":
			st := w.streams[e.Stream]
			if st == nil || e.Mode == "rebaseline" {
				var old []kept
				if st != nil && e.Mode != "rebaseline" {
					old = st.kept
				}
				st = &streamState{kept: old}
				w.streams[e.Stream] = st
			}
			st.lines, st.bytes, st.prefix, st.head = e.Lines, e.Bytes, e.Prefix, e.Head
			st.ckptBytes, st.ckptPrefix, st.ckptLast = e.CkptBytes, e.CkptPrefix, e.CkptLast
			// The running hash is not in the log, so the first read after a
			// restart is a full one.
			st.h, st.ckptHash = nil, nil
		case "checkpoint":
			st := w.streams[e.Stream]
			if st == nil {
				st = &streamState{}
				w.streams[e.Stream] = st
			}
			st.kept = append(st.kept, kept{count: e.Count, end: e.End, prefix: e.Prefix, kind: e.CkptKind})
		case "root":
			w.roots[e.Tenant] = &rootState{shards: e.Shards, root: e.StoreRoot, segments: e.Segments}
			w.lastRootAt[e.Tenant], w.linesAtRoot[e.Tenant], w.missing[e.Tenant] = time.Unix(e.SeenAt, 0), e.LinesTotal, false
		case "finding":
			if e.Type == RootMissing {
				w.missing[e.Tenant] = true
			}
		}
	}
	return w, nil
}

func clip(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func severity(t string, explained bool) string {
	switch t {
	case CheckpointUnsign, RootMissing:
		return "medium"
	case ChainRestarted:
		if explained {
			return "medium"
		}
	}
	return "high"
}

type tick struct {
	now      time.Time
	entries  []wlog.Entry
	findings []Finding
}

func (t *tick) find(typ string, explained bool, data map[string]any) {
	t.findings = append(t.findings, Finding{Type: typ, Severity: severity(typ, explained), Data: data})
	e := wlog.Entry{Kind: "finding", SeenAt: t.now.Unix(), Type: typ, Severity: severity(typ, explained)}
	if s, ok := data["stream"].(string); ok {
		e.Stream = s
	}
	if s, ok := data["tenant"].(string); ok {
		e.Tenant = s
	}
	t.entries = append(t.entries, e)
}

// Tick observes once, writes every finding to the alerter and the log, and
// signs a tree head.
func (w *Witness) Tick() ([]Finding, error) {
	t := &tick{now: w.now()}
	entries, err := os.ReadDir(w.cfg.Events)
	if err != nil {
		return nil, fmt.Errorf("witness: reading %s: %w", w.cfg.Events, err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ndjson") && e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if err := w.stream(t, name); err != nil {
			return nil, err
		}
	}
	var total int64
	for _, st := range w.streams {
		total += st.lines
	}
	for _, tn := range w.cfg.Records {
		if err := w.root(t, tn, total); err != nil {
			return nil, err
		}
	}
	var alertErr error
	for _, f := range t.findings {
		alertErr = errors.Join(alertErr, w.alerts.Alert(f))
	}
	if len(t.entries) == 0 && w.log.Size() == 0 {
		// Nothing has been seen yet, so there is nothing to sign.
		return t.findings, alertErr
	}
	if err := w.log.Append(t.entries...); err != nil {
		return nil, fmt.Errorf("witness: the log does not take this interval: %w", err)
	}
	if _, err := w.log.Sign(w.signer); err != nil {
		return nil, fmt.Errorf("witness: signing the tree head: %w", err)
	}
	return t.findings, alertErr
}

// lineView answers what the stream holds at a line count from what this read
// saw, and by reading the stream again for a line before it.
type lineView struct {
	st     *streamState
	window []checkpoint.LineAt
	path   string
}

func (v lineView) At(count int64) (checkpoint.LineAt, bool) {
	if count < 1 || count > v.st.lines {
		return checkpoint.LineAt{}, false
	}
	if n := len(v.window); n > 0 && count >= v.window[0].Count {
		return v.window[count-v.window[0].Count], true
	}
	return lineAt(v.path, count)
}

// lineAt reads a stream from byte zero to its count-th line.
func lineAt(path string, count int64) (checkpoint.LineAt, bool) {
	f, err := os.Open(path) // #nosec G304 -- a stream in the events directory the operator named
	if err != nil {
		return checkpoint.LineAt{}, false
	}
	defer f.Close()
	h := sha256.New()
	r := bufio.NewReaderSize(f, 64<<10)
	var n, end int64
	for {
		line, err := readLine(r)
		if err != nil {
			return checkpoint.LineAt{}, false
		}
		h.Write(line)
		n, end = n+1, end+int64(len(line))
		if n == count {
			head, _ := event.ChainHashRaw(line[:len(line)-1])
			return checkpoint.LineAt{Count: n, End: end, Prefix: checkpoint.SumOf(h), Head: head}, true
		}
	}
}

// readLine reads one LF-terminated line, LF included; a final line with no LF
// is io.EOF, never a line.
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, io.EOF
	}
	return line, nil
}

// copyChecking hashes the first n bytes of f into h, comparing the running
// prefix at each kept checkpoint's end on the way; it returns the earliest
// kept checkpoint the bytes no longer match.
func copyChecking(h hash.Hash, f io.Reader, n int64, ks []kept) (*kept, error) {
	sorted := append([]kept(nil), ks...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].end < sorted[j].end })
	var pos int64
	var bad *kept
	for i := range sorted {
		k := sorted[i]
		if k.end > n || k.end < pos {
			continue
		}
		if _, err := io.CopyN(h, f, k.end-pos); err != nil {
			return nil, err
		}
		pos = k.end
		if bad == nil && checkpoint.SumOf(h) != k.prefix {
			bad = &sorted[i]
		}
	}
	if _, err := io.CopyN(h, f, n-pos); err != nil {
		return nil, err
	}
	return bad, nil
}

// rebaselined is a stream's state after a finding: the stream is read again
// from byte zero and its kept checkpoints are dropped, since they no longer
// describe it; how far the checkpoint file was read is kept, so one rewrite is
// one finding and not one for every record ever accepted.
func rebaselined(st *streamState) streamState {
	return streamState{ckptBytes: st.ckptBytes, ckptPrefix: st.ckptPrefix, ckptLast: st.ckptLast, ckptHash: st.ckptHash}
}

func (w *Witness) stream(t *tick, name string) error {
	path := filepath.Join(w.cfg.Events, name)
	st := w.streams[name]
	if st == nil {
		st = &streamState{}
		w.streams[name] = st
	}
	f, err := os.Open(path) // #nosec G304 -- a stream in the events directory the operator named
	if err != nil {
		return nil // removed between the listing and the read; the next interval says so
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	mode := "forward"
	if info.Size() < st.bytes {
		t.find(StreamTruncated, false, map[string]any{"stream": name, "lines_seen": st.lines, "bytes_seen": st.bytes, "bytes_now": info.Size()})
		*st = rebaselined(st)
		mode = "rebaseline"
	}
	full := st.h == nil || st.bytes <= w.cfg.FullBytes || t.now.Sub(st.lastFull) >= w.cfg.FullInterval
	var h hash.Hash
	if full {
		h = sha256.New()
		bad, err := copyChecking(h, f, st.bytes, st.kept)
		rewritten := err != nil || checkpoint.SumOf(h) != st.prefix
		if st.bytes == 0 {
			rewritten = false
		}
		if bad != nil || rewritten {
			data := map[string]any{"stream": name, "lines": st.lines, "bytes": st.bytes, "prefix_seen": clip(st.prefix), "prefix_now": clip(checkpoint.SumOf(h))}
			if bad != nil {
				data["checkpoint_count"] = bad.count
			}
			t.find(StreamRewritten, false, data)
			*st = rebaselined(st)
			mode = "rebaseline"
			h = sha256.New()
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil
			}
		} else if mode != "rebaseline" {
			mode = "full"
		}
		st.lastFull = t.now
	} else {
		h = st.h
		if _, err := f.Seek(st.bytes, io.SeekStart); err != nil {
			return nil
		}
	}
	before := st.bytes
	var window []checkpoint.LineAt
	var restarts []int64
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := readLine(r)
		if err != nil {
			break
		}
		h.Write(line)
		st.bytes += int64(len(line))
		st.lines++
		content := line[:len(line)-1]
		var probe struct {
			PrevHash *string `json:"prev_hash"`
		}
		head := ""
		if len(content) <= MaxLine && json.Unmarshal(content, &probe) == nil {
			switch {
			case probe.PrevHash == nil && st.lines > 1:
				restarts = append(restarts, st.lines)
			case probe.PrevHash != nil && st.head != "" && *probe.PrevHash != st.head:
				restarts = append(restarts, st.lines)
			}
			head, _ = event.ChainHashRaw(content)
		}
		st.head = head
		window = append(window, checkpoint.LineAt{Count: st.lines, End: st.bytes, Prefix: checkpoint.SumOf(h), Head: head})
	}
	st.prefix, st.h = checkpoint.SumOf(h), h
	ckptChanged := false
	if w.cfg.Checkpoints != "" {
		ckptChanged = w.checkpoints(t, name, st, lineView{st: st, window: window, path: path}, full)
	}
	for _, line := range restarts {
		explained := false
		for _, k := range st.kept {
			if k.kind == "resume" && k.count == line-1 {
				explained = true
			}
		}
		t.find(ChainRestarted, explained, map[string]any{"stream": name, "line": line, "explained": explained})
	}
	if st.bytes != before || mode != "forward" || ckptChanged {
		t.entries = append(t.entries, wlog.Entry{Kind: "stream", SeenAt: t.now.Unix(), Stream: name, Lines: st.lines, Bytes: st.bytes,
			Prefix: st.prefix, Head: st.head, Mode: mode, CkptBytes: st.ckptBytes, CkptPrefix: st.ckptPrefix, CkptLast: st.ckptLast})
	}
	return nil
}

// checkpoints reads the stream's checkpoint file from where it stopped, and
// reports whether it moved.
func (w *Witness) checkpoints(t *tick, name string, st *streamState, view lineView, full bool) bool {
	path := filepath.Join(w.cfg.Checkpoints, name+".ckpt.ndjson")
	f, err := os.Open(path) // #nosec G304 -- a checkpoint file in the directory the operator named
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	resetToEnd := func(why string) bool {
		t.find(CheckpointInvalid, false, map[string]any{"stream": name, "count": int64(0), "reason": why})
		// Start again from the file as it now stands, so one rewrite is one
		// finding rather than one every interval.
		h := sha256.New()
		_, _ = f.Seek(0, io.SeekStart)
		r := bufio.NewReaderSize(f, 64<<10)
		st.ckptBytes, st.ckptLast = 0, ""
		for {
			line, err := readLine(r)
			if err != nil {
				break
			}
			h.Write(line)
			st.ckptBytes += int64(len(line))
			st.ckptLast = checkpoint.HashOf(line[:len(line)-1])
		}
		st.ckptHash, st.ckptPrefix = h, checkpoint.SumOf(h)
		return true
	}
	if info.Size() < st.ckptBytes {
		return resetToEnd("the checkpoint file shrank")
	}
	if full || st.ckptHash == nil {
		h := sha256.New()
		if _, err := io.CopyN(h, f, st.ckptBytes); err != nil || (st.ckptBytes > 0 && checkpoint.SumOf(h) != st.ckptPrefix) {
			return resetToEnd("the checkpoint file was rewritten")
		}
		st.ckptHash = h
	} else if _, err := f.Seek(st.ckptBytes, io.SeekStart); err != nil {
		return false
	}
	moved := false
	keys := func(kid string, at time.Time) ([]byte, error) { return w.keys.Key(kid, at, t.now) }
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := readLine(r)
		if err != nil {
			break
		}
		content := line[:len(line)-1]
		rec, perr := checkpoint.ParseRecord(content)
		if perr == nil && rec.Count > st.lines {
			// Ahead of the stream as read: the stream's line is on its way.
			break
		}
		prev := st.ckptLast
		if prev == "" {
			prev = checkpoint.Genesis
		}
		switch {
		case perr != nil:
			t.find(CheckpointInvalid, false, map[string]any{"stream": name, "count": int64(0), "reason": perr.Error()})
		case rec.Stream != name:
			t.find(CheckpointInvalid, false, map[string]any{"stream": name, "count": rec.Count, "reason": "the record names another stream"})
		default:
			status, reason := checkpoint.Verify(rec, prev, view, keys)
			switch status {
			case checkpoint.Accepted:
				at, _ := view.At(rec.Count)
				st.kept = append(st.kept, kept{count: rec.Count, end: at.End, prefix: rec.Prefix, kind: rec.Kind})
				t.entries = append(t.entries, wlog.Entry{Kind: "checkpoint", SeenAt: t.now.Unix(), Stream: name, Count: rec.Count, End: at.End,
					Prefix: rec.Prefix, CkptKind: rec.Kind, Record: rec.Hash()})
			case checkpoint.Unsigned:
				t.find(CheckpointUnsign, false, map[string]any{"stream": name, "count": rec.Count, "reason": rec.UnsignedReason})
			default:
				t.find(CheckpointInvalid, false, map[string]any{"stream": name, "count": rec.Count, "reason": reason})
			}
		}
		st.ckptHash.Write(line)
		st.ckptBytes += int64(len(line))
		st.ckptLast = checkpoint.HashOf(content)
		moved = true
	}
	st.ckptPrefix = checkpoint.SumOf(st.ckptHash)
	return moved
}

func (w *Witness) root(t *tick, tn Tenant, total int64) error {
	store, err := trailryx.ReadStore(tn.Dir)
	if err != nil {
		t.find(RootEquivocated, false, map[string]any{"tenant": tn.Name, "reason": "the record directory does not read as sealed segments"})
		return nil
	}
	rs := w.roots[tn.Name]
	if rs != nil {
		for _, seen := range rs.shards {
			var cur *trailryx.Shard
			for i := range store.Shards {
				if store.Shards[i].Shard == seen.Shard {
					cur = &store.Shards[i]
				}
			}
			ok := cur != nil && cur.Segments >= seen.Segments
			if ok {
				r := trailryx.ShardRootOf(cur.Manifests[:seen.Segments])
				ok = hex.EncodeToString(r[:]) == seen.Root
			}
			if !ok {
				t.find(RootEquivocated, false, map[string]any{"tenant": tn.Name, "shard": int64(seen.Shard), "segments": int64(seen.Segments),
					"root_seen": clip(rs.root), "root_now": clip(hex.EncodeToString(store.Root[:]))})
				rs = nil
				break
			}
		}
	}
	rootHex := hex.EncodeToString(store.Root[:])
	if store.Segments > 0 && (rs == nil || rs.root != rootHex) {
		if err := w.attest(tn, store, t.now); err != nil {
			return err
		}
		var shards []wlog.ShardSeen
		for _, s := range store.Shards {
			shards = append(shards, wlog.ShardSeen{Shard: s.Shard, Segments: s.Segments, Root: hex.EncodeToString(s.Root[:])})
		}
		w.roots[tn.Name] = &rootState{shards: shards, root: rootHex, segments: store.Segments}
		w.lastRootAt[tn.Name], w.linesAtRoot[tn.Name], w.missing[tn.Name] = t.now, total, false
		t.entries = append(t.entries, wlog.Entry{Kind: "root", SeenAt: t.now.Unix(), Tenant: tn.Name, StoreRoot: rootHex, Segments: store.Segments,
			Shards: shards, LinesTotal: total})
		return nil
	}
	if rs == nil {
		return nil
	}
	since := t.now.Sub(w.lastRootAt[tn.Name])
	if !w.missing[tn.Name] && total-w.linesAtRoot[tn.Name] > w.cfg.SealLines && since > 2*w.cfg.SealEvery {
		t.find(RootMissing, false, map[string]any{"tenant": tn.Name, "segments": int64(rs.segments), "lines_since": total - w.linesAtRoot[tn.Name],
			"since_s": int64(since / time.Second)})
		w.missing[tn.Name] = true
	}
	return nil
}

var errRotated = errors.New("witness: the witness key rotated while signing")

// attest signs trailryx-sign's witness statement for a new store root with the
// witness key's ES384 half, the one trailryx-verify checks.
func (w *Witness) attest(tn Tenant, store trailryx.Store, now time.Time) error {
	rec, ok := w.signer.Active(wlog.KeyES384)
	if !ok {
		return errors.New("witness: the witness key has no active ES384 half")
	}
	seen := uint64(now.UnixNano()) // #nosec G115 -- a time after 1970
	stmt := trailryx.WitnessStatement(w.cfg.Name, store.Root, seen, "es384", rec.Public)
	sig, err := w.signer.SignInput(wlog.KeyES384, func(alg policy.Alg, kid string) ([]byte, error) {
		if kid != rec.Kid {
			return nil, errRotated
		}
		return stmt, nil
	})
	if err != nil {
		return err
	}
	if w.cfg.Attestations == "" {
		return nil
	}
	a := Attestation{Witness: w.cfg.Name, Tenant: tn.Name, StoreRoot: hex.EncodeToString(store.Root[:]), Segments: store.Segments, SeenAt: seen,
		Algorithm: "es384", PublicKey: base64.RawURLEncoding.EncodeToString(rec.Public), Signature: base64.RawURLEncoding.EncodeToString(sig.Sig)}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	dir := filepath.Join(w.cfg.Attestations, tn.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, a.StoreRoot+".json"))
}

// EventAlerter writes findings as agent-events into keyryx.ndjson.
type EventAlerter struct {
	w   *event.ChainedWriter
	now func() time.Time
}

// NewEventAlerter opens the alert stream.
func NewEventAlerter(path string, now func() time.Time) (*EventAlerter, error) {
	w, err := event.NewChainedWriter(path)
	if err != nil {
		return nil, err
	}
	return &EventAlerter{w: w, now: now}, nil
}

// Alert writes one finding as a v1.0 event from keyryx under the witness's
// own subject.
func (e *EventAlerter) Alert(f Finding) error {
	return e.w.Write(event.Event{Schema: event.SchemaV10, TS: e.now().UTC().Format("2006-01-02T15:04:05.000Z"), Source: "keyryx",
		Type: f.Type, AgentID: Subject, Severity: f.Severity, Data: f.Data})
}
