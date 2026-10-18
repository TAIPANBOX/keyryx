package witness

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/gowebpki/jcs"

	"github.com/TAIPANBOX/keyryx/internal/checkpoint"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/trailryx"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// The witness exists to disagree when somebody rewrote the record. A rewrite
// it does not report is the failure, and nothing else in the stack would say.

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

const marker = "SECRET-CONTENT-MARKER"

type recorder struct{ got []Finding }

func (r *recorder) Alert(f Finding) error { r.got = append(r.got, f); return nil }

type fakeKeys struct {
	pub     map[string][]byte
	name    map[string]string
	revoked map[string]bool
}

func (f *fakeKeys) Key(kid string, at, seen time.Time) (Certified, error) {
	if f.revoked[kid] {
		return Certified{}, errors.New("the key was revoked before the witness saw this record")
	}
	p, ok := f.pub[kid]
	if !ok {
		return Certified{}, errors.New("no statement certifies that key")
	}
	return Certified{Public: p, Name: f.name[kid], Owner: "test"}, nil
}

type stand struct {
	t       *testing.T
	events  string
	ckpts   string
	records string
	attest  string
	wdata   string
	now     time.Time
	cfg     Config
	signKey *ecdsa.PrivateKey
	signKid string
	custody Keys
	store   *keystore.Store
	log     *wlog.Log
	w       *Witness
	alerts  *recorder
	key     *ecdsa.PrivateKey
	kid     string
	keys    *fakeKeys
	keysDir string
	writers map[string]*event.ChainedWriter
}

func newStand(t *testing.T, edit func(*Config)) *stand {
	t.Helper()
	base := t.TempDir()
	s := &stand{t: t, now: t0, alerts: &recorder{}, writers: map[string]*event.ChainedWriter{}}
	s.events, s.ckpts, s.records = filepath.Join(base, "events"), filepath.Join(base, "checkpoints"), filepath.Join(base, "records")
	s.attest, s.wdata, s.keysDir = filepath.Join(base, "attestations"), filepath.Join(base, "witness"), filepath.Join(base, "keys")
	for _, d := range []string{s.events, s.ckpts, s.records, s.attest, s.wdata} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(s.keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.key = k
	s.kid, _ = delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	pub, _ := k.PublicKey.Bytes()
	s.keys = &fakeKeys{pub: map[string][]byte{s.kid: pub}, name: map[string]string{s.kid: "wardryx-stream"}, revoked: map[string]bool{}}
	s.signKey, s.signKid = s.key, s.kid
	s.cfg = Config{Events: s.events, Checkpoints: s.ckpts, Records: []Tenant{{Name: "acme", Dir: s.records}}, Attestations: s.attest,
		FullBytes: 1 << 30, FullInterval: time.Hour, SealEvery: 15 * time.Minute, SealLines: 4096, Name: "keyryx-witness",
		StreamKeys: map[string]string{"wardryx.ndjson": "wardryx-stream", "garbage.ndjson": "garbage-stream"}}
	if edit != nil {
		edit(&s.cfg)
	}
	store, err := keystore.Open(s.keysDir, [32]byte{6, 6, 6}, wlog.Keys, s.clock)
	if err != nil {
		t.Fatal(err)
	}
	s.store = store
	s.restart()
	return s
}

func (s *stand) clock() time.Time { return s.now }

// restart is the witness process starting again over the same directories.
func (s *stand) restart() {
	s.t.Helper()
	l, err := wlog.Open(s.wdata, statement.StoreKeys(s.store, wlog.KeyES384, wlog.KeyMLDSA), s.clock)
	if err != nil {
		s.t.Fatalf("wlog.Open: %v", err)
	}
	var keys Keys = s.keys
	if s.custody != nil {
		keys = s.custody
	}
	w, err := New(s.cfg, l, s.store, keys, s.alerts, s.clock)
	if err != nil {
		s.t.Fatalf("New: %v", err)
	}
	s.log, s.w = l, w
}

func (s *stand) tick() []Finding {
	s.t.Helper()
	s.now = s.now.Add(time.Minute)
	before := len(s.alerts.got)
	got, err := s.w.Tick()
	if err != nil {
		s.t.Fatalf("Tick: %v", err)
	}
	if len(s.alerts.got)-before != len(got) {
		s.t.Fatalf("Tick returned %d findings and alerted %d", len(got), len(s.alerts.got)-before)
	}
	return got
}

func (s *stand) streamPath(name string) string { return filepath.Join(s.events, name) }

// emit appends n chained events to a stream, each carrying the marker.
func (s *stand) emit(name string, n int) {
	s.t.Helper()
	w := s.writers[name]
	if w == nil {
		var err error
		w, err = event.NewChainedWriter(s.streamPath(name))
		if err != nil {
			s.t.Fatal(err)
		}
		s.writers[name] = w
	}
	for i := 0; i < n; i++ {
		if err := w.Write(event.Event{Schema: event.SchemaV10, TS: s.now.Format(time.RFC3339Nano), Source: "wardryx", Type: "policy_allow",
			AgentID: "agent://acme.example/one", Severity: "info", Data: map[string]any{"note": marker, "n": i}}); err != nil {
			s.t.Fatal(err)
		}
	}
}

func (s *stand) lines(name string) []string {
	raw, _ := os.ReadFile(s.streamPath(name))
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func (s *stand) rewrite(name string, ls []string) {
	s.t.Helper()
	if err := os.WriteFile(s.streamPath(name), []byte(strings.Join(ls, "\n")+"\n"), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func relinked(t *testing.T, ls []string, i int, edit func(map[string]any)) []string {
	t.Helper()
	out := append([]string(nil), ls...)
	var m map[string]any
	_ = json.Unmarshal([]byte(out[i]), &m)
	edit(m)
	b, _ := json.Marshal(m)
	out[i] = string(b)
	if i+1 < len(out) {
		h, _ := event.ChainHashRaw([]byte(out[i]))
		var next map[string]any
		_ = json.Unmarshal([]byte(out[i+1]), &next)
		next["prev_hash"] = h
		nb, _ := json.Marshal(next)
		out[i+1] = string(nb)
	}
	return out
}

// checkpoint writes a record over the stream as it stands, the way a
// producer would; mutate edits the record before it is signed.
func (s *stand) checkpoint(name, kind string, signed bool, mutate func(map[string]any)) {
	s.t.Helper()
	raw, _ := os.ReadFile(s.streamPath(name))
	count := int64(bytes.Count(raw, []byte("\n")))
	end := bytes.LastIndexByte(raw, '\n') + 1
	ls := s.lines(name)
	head, _ := event.ChainHashRaw([]byte(ls[count-1]))
	sum := sha256.Sum256(raw[:end])
	path := filepath.Join(s.ckpts, name+".ckpt.ndjson")
	prev := checkpoint.Genesis
	if old, err := os.ReadFile(path); err == nil && len(old) > 0 {
		recs := strings.Split(strings.TrimRight(string(old), "\n"), "\n")
		p := sha256.Sum256([]byte(recs[len(recs)-1]))
		prev = "sha256:" + hex.EncodeToString(p[:])
	}
	rec := map[string]any{"v": 1, "kind": kind, "stream": name, "count": count, "head": head,
		"prefix": "sha256:" + hex.EncodeToString(sum[:]), "at": s.now.UTC().Format("2006-01-02T15:04:05.000Z"), "prev": prev}
	if signed {
		rec["alg"], rec["kid"] = "ES256", s.signKid
	} else {
		rec["unsigned_reason"] = "key_expired"
	}
	if mutate != nil {
		mutate(rec)
	}
	if signed {
		in := canon(s.t, rec)
		d := sha256.Sum256(in)
		r, ss, err := ecdsa.Sign(rand.Reader, s.signKey, d[:])
		if err != nil {
			s.t.Fatal(err)
		}
		if _, set := rec["sig"]; !set {
			rec["sig"] = base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...))
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		s.t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.Write(append(canon(s.t, rec), '\n'))
}

func canon(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, _ := json.Marshal(m)
	c, err := jcs.Transform(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func types(fs []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.Type] = f
	}
	return out
}

func TestAnHonestStreamIsWitnessedAndRaisesNothing(t *testing.T) {
	s := newStand(t, nil)
	for round := 0; round < 4; round++ {
		s.emit("wardryx.ndjson", 5)
		s.emit("vouchryx.ndjson", 2)
		s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
		if got := s.tick(); len(got) != 0 {
			t.Fatalf("round %d: an honest stack raised %+v", round, got)
		}
	}
	kinds := map[string]int{}
	for _, e := range s.log.Entries() {
		kinds[e.Kind]++
	}
	if kinds["stream"] == 0 || kinds["checkpoint"] != 4 {
		t.Fatalf("the log holds %v, want stream observations and the four checkpoints", kinds)
	}
	if h, ok := s.log.Latest(); !ok || h.Size != s.log.Size() {
		t.Fatalf("the latest head %+v does not cover the log of %d", h, s.log.Size())
	}
	if rep := wlog.VerifyDir(s.wdata, statement.StoreKeys(s.store, wlog.KeyES384, wlog.KeyMLDSA)); rep.Broken || !rep.Measured {
		t.Fatalf("the witness's own log does not verify: %+v", rep)
	}
}

func TestARewriteOfAnyByteItSawIsCaught(t *testing.T) {
	for what, edit := range map[string]func(t *testing.T, ls []string) []string{
		"one byte of an earlier line": func(t *testing.T, ls []string) []string {
			out := append([]string(nil), ls...)
			out[1] = strings.Replace(out[1], "policy_allow", "policy_alloy", 1)
			return out
		},
		"a line rewritten and the next re-linked, which the chain accepts": func(t *testing.T, ls []string) []string {
			out := relinked(t, ls, 1, func(m map[string]any) { m["type"] = "policy_deny" })
			if rep, _ := event.VerifyChain(strings.NewReader(strings.Join(out, "\n") + "\n")); !rep.Ok() {
				t.Fatal("the re-linked rewrite does not pass the chain, so it tests nothing")
			}
			return out
		},
		"whitespace only, which no chain hash sees": func(t *testing.T, ls []string) []string {
			out := append([]string(nil), ls...)
			out[0] = strings.Replace(out[0], `":`, `": `, 1)
			return out
		},
	} {
		s := newStand(t, nil)
		s.emit("wardryx.ndjson", 4)
		s.tick()
		s.emit("wardryx.ndjson", 2)
		s.rewrite("wardryx.ndjson", edit(t, s.lines("wardryx.ndjson")))
		got := types(s.tick())
		f, ok := got["witness_stream_rewritten"]
		if !ok || f.Severity != "high" || f.Data["stream"] != "wardryx.ndjson" {
			t.Errorf("%s: %+v", what, got)
		}
	}
}

func TestAStreamThatShrankIsCaught(t *testing.T) {
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 4)
	s.tick()
	ls := s.lines("wardryx.ndjson")
	s.rewrite("wardryx.ndjson", ls[:2])
	got := types(s.tick())
	if f, ok := got["witness_stream_truncated"]; !ok || f.Severity != "high" || f.Data["lines_seen"] != int64(4) {
		t.Fatalf("a stream cut from 4 lines to 2: %+v", got)
	}
}

func TestARestartIsMediumWhenAResumeExplainsItAndHighWhenNothingDoes(t *testing.T) {
	for _, explained := range []bool{true, false} {
		s := newStand(t, nil)
		s.emit("wardryx.ndjson", 3)
		s.tick()
		// A writer that could not chain from the tail starts a new chain.
		if explained {
			s.checkpoint("wardryx.ndjson", "resume", true, nil)
		}
		f, _ := os.OpenFile(s.streamPath("wardryx.ndjson"), os.O_APPEND|os.O_WRONLY, 0o644)
		_, _ = f.WriteString(`{"agent_id":"agent://acme.example/one","schema":"taipanbox.dev/agent-event/v1.0","source":"wardryx","ts":"2026-10-18T12:05:00Z","type":"policy_allow"}` + "\n")
		_ = f.Close()
		got := types(s.tick())
		f2, ok := got["witness_chain_restarted"]
		want := "high"
		if explained {
			want = "medium"
		}
		if !ok || f2.Severity != want || f2.Data["line"] != int64(4) || f2.Data["explained"] != explained {
			t.Errorf("explained=%v: %+v", explained, got)
		}
	}
}

func TestAKeptCheckpointCatchesARewriteTheProducerSignedAfter(t *testing.T) {
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 2)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	s.emit("wardryx.ndjson", 2)
	s.tick()
	// The producer, holding its own key, rewrites line 1, re-links line 2 and
	// signs a fresh checkpoint over the result.
	s.rewrite("wardryx.ndjson", relinked(t, s.lines("wardryx.ndjson"), 0, func(m map[string]any) { m["type"] = "policy_deny" }))
	s.emit("wardryx.ndjson", 1)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	got := types(s.tick())
	f, ok := got["witness_stream_rewritten"]
	if !ok || f.Data["checkpoint_count"] != int64(2) {
		t.Fatalf("the rewrite contradicts the checkpoint of 2 lines the producer signed before: %+v", got)
	}
}

func TestACheckpointThatDoesNotHoldIsInvalidAndAnUnsignedOneSaysSo(t *testing.T) {
	for what, c := range map[string]struct {
		signed bool
		mutate func(m map[string]any)
		before func(s *stand)
		want   string
	}{
		"a prefix over other bytes": {true, func(m map[string]any) { m["prefix"] = "sha256:" + strings.Repeat("0", 64) }, nil, "witness_checkpoint_invalid"},
		"a head of another line":    {true, func(m map[string]any) { m["head"] = "sha256:" + strings.Repeat("1", 64) }, nil, "witness_checkpoint_invalid"},
		"a signature by nobody": {true, func(m map[string]any) {
			m["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		}, nil, "witness_checkpoint_invalid"},
		"a kid no statement certifies":            {true, func(m map[string]any) { m["kid"] = strings.Repeat("A", 43) }, nil, "witness_checkpoint_invalid"},
		"a key revoked before the witness saw it": {true, nil, func(s *stand) { s.keys.revoked[s.kid] = true }, "witness_checkpoint_invalid"},
		"a prev that does not chain":              {true, func(m map[string]any) { m["prev"] = "sha256:" + strings.Repeat("2", 64) }, nil, "witness_checkpoint_invalid"},
		"an unsigned record":                      {false, nil, nil, "witness_checkpoint_unsigned"},
	} {
		s := newStand(t, nil)
		s.emit("wardryx.ndjson", 3)
		if c.before != nil {
			c.before(s)
		}
		s.checkpoint("wardryx.ndjson", "checkpoint", c.signed, c.mutate)
		got := types(s.tick())
		f, ok := got[c.want]
		if !ok || f.Data["stream"] != "wardryx.ndjson" || f.Data["count"] != int64(3) {
			t.Errorf("%s: %+v, want %s", what, got, c.want)
		}
		if c.want == "witness_checkpoint_invalid" && f.Severity != "high" || c.want == "witness_checkpoint_unsigned" && f.Severity != "medium" {
			t.Errorf("%s: severity %s", what, f.Severity)
		}
	}
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 1)
	_ = os.WriteFile(filepath.Join(s.ckpts, "wardryx.ndjson.ckpt.ndjson"), []byte("not a record\n"), 0o644)
	if _, ok := types(s.tick())["witness_checkpoint_invalid"]; !ok {
		t.Fatal("a line that is not a record raised nothing")
	}
}

func TestACheckpointAheadOfTheStreamWaits(t *testing.T) {
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 3)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	// The stream as the witness reads it is one line short of the record: a
	// writer flushed its checkpoint before the witness read the line.
	ls := s.lines("wardryx.ndjson")
	full, _ := os.ReadFile(s.streamPath("wardryx.ndjson"))
	s.rewrite("wardryx.ndjson", ls[:2])
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("a record ahead of the stream raised %+v", got)
	}
	_ = os.WriteFile(s.streamPath("wardryx.ndjson"), full, 0o644)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("once the line arrived: %+v", got)
	}
	n := 0
	for _, e := range s.log.Entries() {
		if e.Kind == "checkpoint" && e.Count == 3 {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the waiting record was accepted %d times", n)
	}
}

func TestAForwardIntervalReadsOnlyNewBytesAndAFullOneReadsAll(t *testing.T) {
	s := newStand(t, func(c *Config) { c.FullBytes = 1; c.FullInterval = time.Hour })
	s.emit("wardryx.ndjson", 4)
	s.tick() // the first read of a stream is always full
	s.rewrite("wardryx.ndjson", relinked(t, s.lines("wardryx.ndjson"), 0, func(m map[string]any) { m["type"] = "policy_deny" }))
	s.emit("wardryx.ndjson", 1)
	if got := types(s.tick()); len(got) != 0 {
		t.Fatalf("a forward interval read bytes it had already hashed: %+v", got)
	}
	modes := map[string]bool{}
	for _, e := range s.log.Entries() {
		if e.Kind == "stream" {
			modes[e.Mode] = true
		}
	}
	if !modes["full"] || !modes["forward"] {
		t.Fatalf("the log does not say which reads were full and which forward: %v", modes)
	}
	s.now = s.now.Add(time.Hour)
	if _, ok := types(s.tick())["witness_stream_rewritten"]; !ok {
		t.Fatal("the full read an hour later did not catch the rewrite")
	}
}

func TestTheWitnessSurvivesARestartAndCatchesARewriteMadeWhileItWasDown(t *testing.T) {
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 4)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	s.tick()
	// The same length, so the stream reads as rewritten and not as shrunk.
	s.rewrite("wardryx.ndjson", relinked(t, s.lines("wardryx.ndjson"), 2, func(m map[string]any) { m["type"] = "policy_alloy" }))
	s.restart()
	got := types(s.tick())
	if f, ok := got["witness_stream_rewritten"]; !ok || f.Data["checkpoint_count"] != int64(4) {
		t.Fatalf("after a restart: %+v", got)
	}
}

func writeManifest(t *testing.T, dir string, shard uint16, seg uint64, edit func(*trailryx.Manifest)) {
	t.Helper()
	m := trailryx.Manifest{FormatVersion: 1, Segment: seg, Shard: shard, Records: seg * 3,
		IndexRoots:      []trailryx.IndexRoot{{Name: "id"}, {Name: "recorded_at"}, {Name: "agent_id"}, {Name: "run_id"}, {Name: "event_type"}},
		FirstRecordedAt: seg, LastRecordedAt: seg + 1, Algorithms: [3]byte{1, 4, 1}}
	m.HistoryRoot[0] = byte(seg)
	if edit != nil {
		edit(&m)
	}
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("s%d-%06d.mf", shard, seg)), trailryx.EncodeManifest(m), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAStoreRootIsAttestedAndAnEquivocationIsCaught(t *testing.T) {
	s := newStand(t, nil)
	writeManifest(t, s.records, 0, 1, nil)
	writeManifest(t, s.records, 0, 2, nil)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("an honest store raised %+v", got)
	}
	st, _ := trailryx.ReadStore(s.records)
	checkAttestation(t, s, st)
	writeManifest(t, s.records, 0, 3, nil)
	s.tick()
	st3, _ := trailryx.ReadStore(s.records)
	checkAttestation(t, s, st3)
	for what, edit := range map[string]func(){
		"a sealed segment's manifest rewritten": func() {
			writeManifest(t, s.records, 0, 2, func(m *trailryx.Manifest) { m.Records = 99 })
		},
		"a sealed segment's manifest removed": func() { _ = os.Remove(filepath.Join(s.records, "s0-000003.mf")) },
	} {
		edit()
		got := types(s.tick())
		if f, ok := got["witness_root_equivocated"]; !ok || f.Severity != "high" || f.Data["tenant"] != "acme" {
			t.Errorf("%s: %+v", what, got)
		}
	}
}

func checkAttestation(t *testing.T, s *stand, st trailryx.Store) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.attest, "acme", hex.EncodeToString(st.Root[:])+".json"))
	if err != nil {
		t.Fatalf("no attestation for store root %x: %v", st.Root[:8], err)
	}
	var a Attestation
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.RawURLEncoding.DecodeString(a.PublicKey)
	sig, _ := base64.RawURLEncoding.DecodeString(a.Signature)
	rec, _ := s.store.Active(wlog.KeyES384)
	if a.Witness != "keyryx-witness" || a.Algorithm != "es384" || !bytes.Equal(pub, rec.Public) || len(sig) != 96 || a.Segments != st.Segments {
		t.Fatalf("attestation %+v", a)
	}
	stmt := trailryx.WitnessStatement(a.Witness, st.Root, a.SeenAt, a.Algorithm, pub)
	if err := keystore.Verify(policy.ES384, pub, stmt, sig); err != nil {
		t.Fatalf("the attestation does not verify as trailryx-verify checks one: %v", err)
	}
}

func TestAMissingRootIsReported(t *testing.T) {
	s := newStand(t, func(c *Config) { c.SealLines = 5; c.SealEvery = time.Minute })
	writeManifest(t, s.records, 0, 1, nil)
	s.tick()
	s.emit("wardryx.ndjson", 10)
	s.now = s.now.Add(3 * time.Minute)
	got := types(s.tick())
	if f, ok := got["witness_root_missing"]; !ok || f.Severity != "medium" || f.Data["tenant"] != "acme" {
		t.Fatalf("ten lines and three minutes with no new root: %+v", got)
	}
	if _, again := types(s.tick())["witness_root_missing"]; again {
		t.Fatal("a missing root was reported again before a root appeared")
	}
	writeManifest(t, s.records, 0, 2, nil)
	if got := types(s.tick()); len(got) != 0 {
		t.Fatalf("once a root appeared: %+v", got)
	}
}

func TestEveryFindingIsAnAgentEventInKeyryxNdjson(t *testing.T) {
	s := newStand(t, nil)
	alerts := filepath.Join(t.TempDir(), "keyryx.ndjson")
	ea, err := NewEventAlerter(alerts, s.clock)
	if err != nil {
		t.Fatal(err)
	}
	s.alerts = &recorder{}
	l, _ := wlog.Open(s.wdata, statement.StoreKeys(s.store, wlog.KeyES384, wlog.KeyMLDSA), s.clock)
	s.w, _ = New(s.cfg, l, s.store, s.keys, ea, s.clock)
	s.emit("wardryx.ndjson", 4)
	s.now = s.now.Add(time.Minute)
	if _, err := s.w.Tick(); err != nil {
		t.Fatal(err)
	}
	s.rewrite("wardryx.ndjson", relinked(t, s.lines("wardryx.ndjson"), 1, func(m map[string]any) { m["type"] = "policy_deny" }))
	s.checkpoint("wardryx.ndjson", "checkpoint", false, nil)
	s.now = s.now.Add(time.Minute)
	if _, err := s.w.Tick(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(alerts)
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("record content reached the alert stream")
	}
	evs, err := event.ReadFile(alerts)
	if err != nil || len(evs) < 2 {
		t.Fatalf("the alert stream: %d events, %v", len(evs), err)
	}
	registered := map[string]string{"witness_stream_rewritten": "high", "witness_stream_truncated": "high", "witness_checkpoint_invalid": "high",
		"witness_checkpoint_unsigned": "medium", "witness_root_missing": "medium", "witness_root_equivocated": "high"}
	for _, e := range evs {
		if e.Schema != event.SchemaV10 || e.Source != "keyryx" || e.AgentID != "agent://keyryx.internal/witness" || e.Data["stream"] == nil {
			t.Fatalf("event %+v", e)
		}
		if want, ok := registered[e.Type]; ok && e.Severity != want {
			t.Fatalf("%s at %s, the registry says %s", e.Type, e.Severity, want)
		} else if !ok && e.Type != "witness_chain_restarted" {
			t.Fatalf("%s is not a type SPEC 6.2 registers for keyryx", e.Type)
		}
	}
	if rep, err := event.VerifyChain(bytes.NewReader(raw)); err != nil || !rep.Ok() || rep.Chained != len(evs)-1 {
		t.Fatalf("the alert stream is not one chain: %+v %v", rep, err)
	}
}

func TestHostileStreamsNeverPanic(t *testing.T) {
	s := newStand(t, nil)
	r := mrand.New(mrand.NewPCG(20261018, 61))
	alphabet := []byte(`{}[]",:prev_hash0123456789 ` + "\x00\xff\n")
	for i := 0; i < 60; i++ {
		var b []byte
		for k := 0; k < r.IntN(400); k++ {
			b = append(b, alphabet[r.IntN(len(alphabet))])
		}
		f, _ := os.OpenFile(s.streamPath("garbage.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		_, _ = f.Write(b)
		_ = f.Close()
		g, _ := os.OpenFile(filepath.Join(s.ckpts, "garbage.ndjson.ckpt.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		_, _ = g.Write(b)
		_ = g.Close()
		if r.IntN(5) == 0 {
			_ = os.WriteFile(filepath.Join(s.records, fmt.Sprintf("s0-%06d.mf", 1+r.IntN(3))), b, 0o644)
		}
		s.now = s.now.Add(time.Minute)
		if _, err := s.w.Tick(); err != nil {
			t.Fatalf("round %d: a hostile stream stopped the witness: %v", i, err)
		}
	}
}

// A line whose prev_hash names something other than the line before it is a
// chain restarted there, even though every byte before it is untouched.
func TestALineLinkedElsewhereIsARestart(t *testing.T) {
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 3)
	s.tick()
	f, _ := os.OpenFile(s.streamPath("wardryx.ndjson"), os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString(`{"agent_id":"agent://acme.example/one","prev_hash":"sha256:` + strings.Repeat("ab", 32) + `","schema":"taipanbox.dev/agent-event/v1.0","source":"wardryx","ts":"2026-10-18T12:05:00Z","type":"policy_allow"}` + "\n")
	_ = f.Close()
	got := types(s.tick())
	if f, ok := got["witness_chain_restarted"]; !ok || f.Data["line"] != int64(4) || f.Severity != "high" {
		t.Fatalf("a line linked to a line that is not its predecessor: %+v", got)
	}
	if _, ok := got["witness_stream_rewritten"]; ok {
		t.Fatal("an append was reported as a rewrite")
	}
}

// The checkpoint file is append-only too: a record the witness already read,
// edited afterwards, is reported, though nothing re-verifies the old record.
func TestACheckpointFileRewrittenIsReported(t *testing.T) {
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 2)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	s.emit("wardryx.ndjson", 2)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("control: %+v", got)
	}
	path := filepath.Join(s.ckpts, "wardryx.ndjson.ckpt.ndjson")
	raw, _ := os.ReadFile(path)
	_ = os.WriteFile(path, bytes.Replace(raw, []byte(`"count":2`), []byte(`"count":1`), 1), 0o644)
	got := types(s.tick())
	if f, ok := got["witness_checkpoint_invalid"]; !ok || !strings.Contains(fmt.Sprint(f.Data["reason"]), "rewritten") {
		t.Fatalf("an accepted checkpoint edited afterwards: %+v", got)
	}
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("one rewrite was reported again: %+v", got)
	}
}

// A checkpoint is the producer's word about its own stream, so only the key
// certified for that stream may sign it: another producer's key, or the
// delegation service's working key, is certified and valid and still not this
// stream's (CLAUDE.md invariant 32).
func TestACheckpointSignedByAnotherProducersKeyIsInvalid(t *testing.T) {
	s := newStand(t, nil)
	s.emit("wardryx.ndjson", 3)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	if got := s.tick(); len(got) != 0 {
		t.Fatalf("control: the stream's own key: %+v", got)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	okid, _ := delegation.Thumbprint(delegation.FromPublic(&other.PublicKey, ""))
	opub, _ := other.PublicKey.Bytes()
	s.keys.pub[okid], s.keys.name[okid] = opub, "vouchryx-token"
	s.signKey, s.signKid = other, okid
	s.emit("wardryx.ndjson", 1)
	s.checkpoint("wardryx.ndjson", "checkpoint", true, nil)
	got := types(s.tick())
	f, ok := got["witness_checkpoint_invalid"]
	if !ok || !strings.Contains(fmt.Sprint(f.Data["reason"]), "vouchryx-token") || f.Data["count"] != int64(4) {
		t.Fatalf("a checkpoint signed by a key certified for another name: %+v", got)
	}
	// A stream no key is bound to: no signature is its producer's.
	s.signKey, s.signKid = s.key, s.kid
	s.emit("tokenfuse.ndjson", 2)
	s.checkpoint("tokenfuse.ndjson", "checkpoint", true, nil)
	got = types(s.tick())
	if f, ok := got["witness_checkpoint_invalid"]; !ok || f.Data["stream"] != "tokenfuse.ndjson" || !strings.Contains(fmt.Sprint(f.Data["reason"]), "no key") {
		t.Fatalf("a checkpoint for a stream no key is bound to: %+v", got)
	}
	// Checkpoints read with no stream bound at all refuse the start.
	cfg := s.cfg
	cfg.StreamKeys = nil
	if _, err := New(cfg, s.log, s.store, s.keys, s.alerts, s.clock); err == nil {
		t.Fatal("a witness that reads checkpoints with no stream bound to a key started")
	}
}
