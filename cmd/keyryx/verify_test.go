package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// keyryx verify is what an auditor runs offline, with only files. It says
// [ok], [weak] or [broken] per check, and never OK about nothing.

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func keySetFile(t *testing.T, s *keystore.Store, names ...string) string {
	t.Helper()
	var keys []map[string]any
	for _, n := range names {
		recs, _ := s.Published(n)
		for _, r := range recs {
			keys = append(keys, keystore.JWK(r))
		}
	}
	b, _ := json.Marshal(map[string]any{"keys": keys})
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func witnessLog(t *testing.T, root byte) (*keystore.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "witness")
	_ = os.Mkdir(dir, 0o700)
	now := t0
	store, err := keystore.Open(dir, [32]byte{root, 2}, wlog.Keys, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	l, err := wlog.Open(dir, statement.StoreKeys(store, wlog.KeyES384, wlog.KeyMLDSA), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = l.Append(wlog.Entry{Kind: "stream", SeenAt: now.Unix(), Stream: "wardryx.ndjson", Lines: int64(i + 1)})
		now = now.Add(time.Minute)
		if _, err := l.Sign(store); err != nil {
			t.Fatal(err)
		}
	}
	return store, dir
}

func TestVerifyLogChecksAWitnessLog(t *testing.T) {
	store, dir := witnessLog(t, 1)
	keys := keySetFile(t, store, wlog.KeyES384, wlog.KeyMLDSA)
	code, out, _ := call("verify", "log", "--dir", dir, "--keys", keys)
	if code != 0 || !strings.Contains(out, "[ok]") || !strings.Contains(out, "VERIFIED") || strings.Contains(out, "NOT VERIFIED") {
		t.Fatalf("an honest log: exit %d\n%s", code, out)
	}
	other, _ := witnessLog(t, 2)
	if code, out, _ := call("verify", "log", "--dir", dir, "--keys", keySetFile(t, other, wlog.KeyES384, wlog.KeyMLDSA)); code != 1 || !strings.Contains(out, "NOT VERIFIED") {
		t.Fatalf("a log checked against another witness's keys: exit %d\n%s", code, out)
	}
	p := filepath.Join(dir, wlog.LogFile)
	raw, _ := os.ReadFile(p)
	_ = os.WriteFile(p, bytes.Replace(raw, []byte(`"lines":2`), []byte(`"lines":7`), 1), 0o600)
	if code, out, _ := call("verify", "log", "--dir", dir, "--keys", keys); code != 1 || !strings.Contains(out, "[broken]") {
		t.Fatalf("an edited log: exit %d\n%s", code, out)
	}
}

func TestVerifyRefusesToSayOKAboutNothing(t *testing.T) {
	store, _ := witnessLog(t, 1)
	keys := keySetFile(t, store, wlog.KeyES384, wlog.KeyMLDSA)
	if code, out, _ := call("verify", "log", "--dir", t.TempDir(), "--keys", keys); code != 1 || !strings.Contains(out, "measured nothing") {
		t.Fatalf("an empty directory: exit %d\n%s", code, out)
	}
	empty := t.TempDir()
	if code, out, _ := call("verify", "streams", "--events", empty, "--checkpoints", empty, "--statements", empty, "--roots", keys, "--stream-keys", "wardryx.ndjson|wardryx-stream"); code != 1 || !strings.Contains(out, "measured nothing") {
		t.Fatalf("no stream with checkpoints: exit %d\n%s", code, out)
	}
	for _, args := range [][]string{{"verify"}, {"verify", "log"}, {"verify", "log", "--dir", empty}, {"verify", "sideways"},
		{"verify", "streams", "--events", empty, "--checkpoints", empty, "--statements", empty, "--roots", keys}} {
		if code, _, errOut := call(args...); code != exitRefused || !strings.Contains(errOut, "usage") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
}

type producer struct {
	key *ecdsa.PrivateKey
	kid string
	jwk statement.JWK
}

func newProducer(t *testing.T) producer {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := json.Marshal(delegation.FromPublic(&k.PublicKey, ""))
	j, _, err := statement.ParseJWK(b, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	return producer{key: k, kid: j.Kid, jwk: j}
}

func canonical(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, _ := json.Marshal(m)
	c, err := jcs.Transform(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (p producer) record(t *testing.T, stream []byte, name, prev string, at time.Time) []byte {
	t.Helper()
	count := bytes.Count(stream, []byte("\n"))
	lines := strings.Split(strings.TrimRight(string(stream), "\n"), "\n")
	head, _ := event.ChainHashRaw([]byte(lines[count-1]))
	sum := sha256.Sum256(stream)
	rec := map[string]any{"v": 1, "kind": "checkpoint", "stream": name, "count": count, "head": head, "prefix": "sha256:" + hex.EncodeToString(sum[:]),
		"at": at.UTC().Format("2006-01-02T15:04:05.000Z"), "prev": prev, "alg": "ES256", "kid": p.kid}
	d := sha256.Sum256(canonical(t, rec))
	r, s, _ := ecdsa.Sign(rand.Reader, p.key, d[:])
	rec["sig"] = base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
	return canonical(t, rec)
}

func TestVerifyStreamsChecksCheckpointsAgainstTheirStatements(t *testing.T) {
	base := t.TempDir()
	events, ckpts, stmts := filepath.Join(base, "events"), filepath.Join(base, "checkpoints"), filepath.Join(base, "statements")
	for _, d := range []string{events, ckpts, stmts} {
		_ = os.Mkdir(d, 0o755)
	}
	cdir := filepath.Join(base, "custody")
	_ = os.Mkdir(cdir, 0o700)
	custody, err := keystore.Open(cdir, [32]byte{9, 9}, statement.RootKeys, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	p := newProducer(t)
	raw, err := statement.Sign(statement.Statement{V: 1, Iss: statement.Issuer, Name: "wardryx-stream", Owner: "wardryx", Kid: p.kid, JWK: p.jwk,
		NotBefore: t0.Unix(), NotAfter: t0.Add(24 * time.Hour).Unix(), IssuedAt: t0.Unix(), JTI: "jti-verify-0123456789"}, custody)
	if err != nil {
		t.Fatal(err)
	}
	writeStatement := func(revoked int64) {
		b, _ := json.Marshal(map[string]any{"statement": json.RawMessage(raw), "revoked_at": revoked})
		_ = os.WriteFile(filepath.Join(stmts, p.kid+".json"), b, 0o644)
	}
	writeStatement(0)
	roots := keySetFile(t, custody, statement.RootES384, statement.RootMLDSA)
	w, _ := event.NewChainedWriter(filepath.Join(events, "wardryx.ndjson"))
	for i := 0; i < 3; i++ {
		_ = w.Write(event.Event{Schema: event.SchemaV10, TS: "2026-10-18T12:00:00Z", Source: "wardryx", Type: "policy_allow", AgentID: "agent://acme.example/one", Severity: "info"})
	}
	stream, _ := os.ReadFile(filepath.Join(events, "wardryx.ndjson"))
	_ = os.WriteFile(filepath.Join(ckpts, "wardryx.ndjson.ckpt.ndjson"), append(p.record(t, stream, "wardryx.ndjson", checkpoint.Genesis, t0.Add(time.Hour)), '\n'), 0o644)
	args := []string{"verify", "streams", "--events", events, "--checkpoints", ckpts, "--statements", stmts, "--stream-keys", "wardryx.ndjson|wardryx-stream", "--roots", roots}
	if code, out, _ := call(args...); code != 0 || !strings.Contains(out, "[ok]") || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("an honest stream: exit %d\n%s", code, out)
	}
	// The stream bound to another key name: a valid statement, and not this
	// stream's producer's.
	other := append([]string(nil), args...)
	other[9] = "wardryx.ndjson|vouchryx-token"
	if code, out, _ := call(other...); code != 1 || !strings.Contains(out, "vouchryx-token") {
		t.Fatalf("a checkpoint signed by a key certified for another name: exit %d\n%s", code, out)
	}
	writeStatement(t0.Add(30 * time.Minute).Unix())
	if code, out, _ := call(args...); code != 1 || !strings.Contains(out, "[broken]") {
		t.Fatalf("a checkpoint signed after its key was revoked: exit %d\n%s", code, out)
	}
	writeStatement(0)
	_ = os.WriteFile(filepath.Join(events, "wardryx.ndjson"), bytes.Replace(stream, []byte("policy_allow"), []byte("policy_alloy"), 1), 0o644)
	if code, out, _ := call(args...); code != 1 || !strings.Contains(out, "prefix does not match") {
		t.Fatalf("an edited stream: exit %d\n%s", code, out)
	}
	_ = os.WriteFile(filepath.Join(events, "wardryx.ndjson"), stream, 0o644)
	odir := filepath.Join(base, "other")
	_ = os.Mkdir(odir, 0o700)
	otherRoot, err := keystore.Open(odir, [32]byte{8}, statement.RootKeys, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := call(append(args[:len(args)-1], keySetFile(t, otherRoot, statement.RootES384, statement.RootMLDSA))...); code != 1 {
		t.Fatalf("statements checked against another custody's root verified")
	}
}
