package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"

	"github.com/TAIPANBOX/keyryx/internal/checkpoint"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// What the auditor names that cannot be read is [broken] and NOT VERIFIED,
// never skipped into an OK; what is malformed on the command line is the
// usage.

func TestVerifyRefusesMalformedArguments(t *testing.T) {
	empty := t.TempDir()
	for name, args := range map[string][]string{
		"an unknown flag":         {"verify", "log", "--dir", empty, "--keys", "k", "--sideways"},
		"a stray argument":        {"verify", "log", "--dir", empty, "--keys", "k", "extra"},
		"streams with no events":  {"verify", "streams", "--checkpoints", empty, "--statements", empty, "--roots", "r", "--stream-keys", "a.ndjson|b"},
		"a malformed stream-keys": {"verify", "streams", "--events", empty, "--checkpoints", empty, "--statements", empty, "--roots", "r", "--stream-keys", "no-bar"},
	} {
		code, out, errOut := call(args...)
		if code != exitRefused || out != "" || !strings.Contains(errOut, "usage: keyryx verify") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, out, errOut)
		}
		if name == "a malformed stream-keys" && !strings.Contains(errOut, "--stream-keys") {
			t.Errorf("a malformed --stream-keys is not named: %q", errOut)
		}
	}
}

func TestVerifySaysBrokenAboutAFileItCannotRead(t *testing.T) {
	empty := t.TempDir()
	missing := filepath.Join(empty, "nope.json")
	code, out, _ := call("verify", "log", "--dir", empty, "--keys", missing)
	if code != 1 || !strings.Contains(out, "[broken] keys:") || !strings.Contains(out, "NOT VERIFIED") {
		t.Fatalf("a key set that is not there: exit %d\n%s", code, out)
	}
	code, out, _ = call("verify", "streams", "--events", empty, "--checkpoints", empty, "--statements", empty, "--roots", missing, "--stream-keys", "a.ndjson|b")
	if code != 1 || !strings.Contains(out, "[broken] roots:") || !strings.Contains(out, "NOT VERIFIED") {
		t.Fatalf("a root key set that is not there: exit %d\n%s", code, out)
	}
	bad := filepath.Join(empty, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"keys":"no"}`), 0o600)
	if code, out, _ := call("verify", "log", "--dir", empty, "--keys", bad); code != 1 || !strings.Contains(out, "[broken] keys:") {
		t.Fatalf("a key set that does not parse: exit %d\n%s", code, out)
	}
}

// streamsFixture is an events directory holding one stream with one signed
// checkpoint, an empty statements directory, and a root key set file.
func streamsFixture(t *testing.T) (events, ckpts, stmts, roots string, p producer) {
	t.Helper()
	base := t.TempDir()
	events, ckpts, stmts = filepath.Join(base, "events"), filepath.Join(base, "checkpoints"), filepath.Join(base, "statements")
	for _, d := range []string{events, ckpts, stmts} {
		_ = os.Mkdir(d, 0o755)
	}
	cdir := filepath.Join(base, "custody")
	_ = os.Mkdir(cdir, 0o700)
	custody, err := keystore.Open(cdir, [32]byte{5, 5}, statement.RootKeys, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	roots = keySetFile(t, custody, statement.RootES384, statement.RootMLDSA)
	p = newProducer(t)
	w, _ := event.NewChainedWriter(filepath.Join(events, "wardryx.ndjson"))
	_ = w.Write(event.Event{Schema: event.SchemaV10, TS: "2026-10-18T12:00:00Z", Source: "wardryx", Type: "policy_allow", AgentID: "agent://acme.example/one", Severity: "info"})
	stream, _ := os.ReadFile(filepath.Join(events, "wardryx.ndjson"))
	_ = os.WriteFile(filepath.Join(ckpts, "wardryx.ndjson.ckpt.ndjson"), append(p.record(t, stream, "wardryx.ndjson", checkpoint.Genesis, t0.Add(time.Hour)), '\n'), 0o644)
	return events, ckpts, stmts, roots, p
}

func TestVerifyStreamsSaysBrokenWhenAKeyHasNoStatementThatHolds(t *testing.T) {
	events, ckpts, stmts, roots, p := streamsFixture(t)
	// A stream with no checkpoint file beside it is not this check's subject.
	_ = os.WriteFile(filepath.Join(events, "quiet.ndjson"), []byte("{}\n"), 0o644)
	args := []string{"verify", "streams", "--events", events, "--checkpoints", ckpts, "--statements", stmts, "--stream-keys", "wardryx.ndjson|wardryx-stream", "--roots", roots}
	code, out, _ := call(args...)
	if code != 1 || !strings.Contains(out, "[broken] wardryx.ndjson record 1") || !strings.Contains(out, "no statement certifies that key") {
		t.Fatalf("a key with no statement: exit %d\n%s", code, out)
	}
	if strings.Contains(out, "quiet.ndjson") {
		t.Fatalf("a stream with no checkpoints was reported: %s", out)
	}
	_ = os.WriteFile(filepath.Join(stmts, p.kid+".json"), []byte(`{"statement":"not a jws","revoked_at":0}`), 0o644)
	if code, out, _ := call(args...); code != 1 || !strings.Contains(out, "[broken] wardryx.ndjson record 1") || strings.Contains(out, "no statement certifies") {
		t.Fatalf("a statement that does not verify: exit %d\n%s", code, out)
	}
	_ = os.WriteFile(filepath.Join(stmts, p.kid+".json"), []byte(`{"statement":`), 0o644)
	if code, out, _ := call(args...); code != 1 || !strings.Contains(out, "[broken] wardryx.ndjson record 1") || strings.Contains(out, "no statement certifies") {
		t.Fatalf("a statement answer that is not JSON: exit %d\n%s", code, out)
	}
}

func TestVerifyStreamsSaysBrokenAboutWhatItCannotRead(t *testing.T) {
	events, ckpts, stmts, roots, _ := streamsFixture(t)
	gone := filepath.Join(events, "gone")
	code, out, _ := call("verify", "streams", "--events", gone, "--checkpoints", ckpts, "--statements", stmts, "--stream-keys", "wardryx.ndjson|wardryx-stream", "--roots", roots)
	if code != 1 || !strings.Contains(out, "[broken] streams:") || !strings.Contains(out, "NOT VERIFIED") {
		t.Fatalf("an events directory that is not there: exit %d\n%s", code, out)
	}
	// A checkpoint path that is not a file is broken, not skipped.
	_ = os.Mkdir(filepath.Join(ckpts, "other.ndjson.ckpt.ndjson"), 0o755)
	_ = os.WriteFile(filepath.Join(events, "other.ndjson"), []byte("{}\n"), 0o644)
	code, out, _ = call("verify", "streams", "--events", events, "--checkpoints", ckpts, "--statements", stmts, "--stream-keys", "wardryx.ndjson|wardryx-stream", "--roots", roots)
	if code != 1 || !strings.Contains(out, "[broken] other.ndjson:") {
		t.Fatalf("an unreadable checkpoint file: exit %d\n%s", code, out)
	}
}
