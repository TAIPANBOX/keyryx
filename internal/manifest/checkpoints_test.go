package manifest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/agent-stack-go/v2/keyclient"
)

// delegatedSigner signs checkpoint records with a key custody certified,
// through agent-stack-go's keyclient, as a Go producer would.
type delegatedSigner struct{ d *keyclient.Delegated }

func (s delegatedSigner) KeyID() string {
	k, err := s.d.Current()
	if err != nil {
		return ""
	}
	return k.Kid
}

func (s delegatedSigner) Sign(input []byte) ([]byte, error) {
	sig, err := s.d.Sign(input)
	if errors.Is(err, keyclient.ErrNoValidKey) {
		return nil, event.ErrCheckpointKeyExpired
	}
	return sig.Sig, err
}

// The whole chain, each part the real one: the built custody certifies a
// producer's checkpoint key, the producer writes its stream and its signed
// checkpoints with agent-stack-go's writer, the built witness fetches the key's
// statement from custody, checks every record against the stream and logs it
// as accepted, raises nothing on the honest stream, and raises a high finding
// once a covered line is rewritten and re-linked (SPEC 6.5.1, invariants 26,
// 31, 32).
func TestARealProducersCheckpointsVerifyThroughARealCustodyAndWitness(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	_, r := load(t)
	bin := buildBinary(t, r)

	// Custody, with one delegated checkpoint key name for the producer.
	dir := shortDir(t)
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.key")
	if err := os.WriteFile(rootFile, []byte(strings.Repeat("4e", 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(consumerSecret))
	pol := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pol, []byte(`{"version":1,
 "keys":[{"name":"wardryx-checkpoint","alg":"ES256","mode":"delegated","max_lifetime":"24h"}],
 "consumers":[{"name":"wardryx","auth":{"key_digest":"sha256:`+hex.EncodeToString(sum[:])+`"},"grants":{"wardryx-checkpoint":["delegate"]}}]}`), 0o400); err != nil {
		t.Fatal(err)
	}
	caddr := freeAddr(t)
	custody := exec.Command(bin, "custody")
	custody.Env = envList(map[string]string{"KEYRYX_DATA": data, "KEYRYX_ROOT_KEY_FILE": rootFile, "KEYRYX_POLICY": pol,
		"KEYRYX_ADDR": caddr, "KEYRYX_EVENTS": filepath.Join(dir, "keyryx-custody.ndjson")})
	var cerr lockedBuffer
	custody.Stderr = &cerr
	if err := custody.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = custody.Process.Kill(); _ = custody.Wait() }()
	if !waitFor(caddr, 10*time.Second) {
		t.Fatalf("custody never listened: %s", cerr.String())
	}

	// The producer: its key certified by custody, its stream and checkpoints
	// written by agent-stack-go.
	bearer := filepath.Join(dir, "wardryx.bearer")
	if err := os.WriteFile(bearer, []byte(consumerSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	var way keyclient.Credential
	way.BearerFile = bearer
	kc, err := keyclient.New(keyclient.Config{BaseURL: "http://" + caddr, Consumer: "wardryx", Credential: way})
	if err != nil {
		t.Fatal(err)
	}
	d, err := kc.Delegated("wardryx-checkpoint", "ES256", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewIfDue(context.Background()); err != nil {
		t.Fatalf("custody did not certify the producer's checkpoint key: %v\n%s", err, cerr.String())
	}
	env, waddr := witnessEnv(t)
	ckpts := filepath.Join(filepath.Dir(env["KEYRYX_WITNESS_EVENTS"]), "checkpoints")
	if err := os.Mkdir(ckpts, 0o750); err != nil {
		t.Fatal(err)
	}
	stream := filepath.Join(env["KEYRYX_WITNESS_EVENTS"], "wardryx.ndjson")
	w, err := event.NewChainedWriterWithCheckpoints(stream, event.CheckpointConfig{Dir: ckpts, Signer: delegatedSigner{d}, Every: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Write(event.Event{Schema: event.SchemaV10, TS: "2026-11-23T12:00:00.000Z", Source: "wardryx", Type: "policy_allow",
			AgentID: "agent://acme.example/one", Severity: "info"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sidecar, _ := os.ReadFile(filepath.Join(ckpts, event.CheckpointFileName("wardryx.ndjson")))
	if n := bytes.Count(sidecar, []byte(`"sig":`)); n < 2 {
		t.Fatalf("the producer wrote %d signed records: %s", n, sidecar)
	}

	// The witness, reading the stream, its checkpoints and custody.
	alerts := filepath.Join(dir, "keyryx.ndjson")
	env["KEYRYX_WITNESS_CHECKPOINTS"] = ckpts
	env["KEYRYX_WITNESS_CUSTODY_URL"] = "http://" + caddr
	env["KEYRYX_WITNESS_STREAM_KEYS"] = "wardryx.ndjson|wardryx-checkpoint"
	env["KEYRYX_WITNESS_ALERTS"] = alerts
	witness := exec.Command(bin, "witness")
	witness.Env = envList(env)
	var werr lockedBuffer
	witness.Stderr = &werr
	if err := witness.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = witness.Process.Kill(); _ = witness.Wait() }()
	if !waitFor(waddr, 10*time.Second) {
		t.Fatalf("the witness never listened: %s", werr.String())
	}
	logPath := filepath.Join(env["KEYRYX_WITNESS_DATA"], "log.ndjson")
	records := bytes.Count(sidecar, []byte("\n"))
	accepted := 0
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && accepted < records; time.Sleep(200 * time.Millisecond) {
		raw, _ := os.ReadFile(logPath)
		accepted = 0
		for _, l := range bytes.Split(raw, []byte("\n")) {
			var e map[string]any
			if json.Unmarshal(l, &e) == nil && e["kind"] == "checkpoint" && e["stream"] == "wardryx.ndjson" {
				accepted++
			}
		}
	}
	if accepted < records {
		t.Fatalf("the witness accepted %d of the producer's %d checkpoints: %s", accepted, records, werr.String())
	}
	findings := func() []event.Event {
		evs, _ := event.ReadFile(alerts)
		return evs
	}
	for _, e := range findings() {
		t.Fatalf("the honest stream raised %s: %v", e.Type, e.Data)
	}

	// A covered line rewritten and the next one re-linked: the chain alone
	// accepts it, the producer's checkpoints do not.
	raw, _ := os.ReadFile(stream)
	ls := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var m map[string]any
	_ = json.Unmarshal([]byte(ls[0]), &m)
	m["type"] = "policy_alloy"
	b, _ := json.Marshal(m)
	ls[0] = string(b)
	h, _ := event.ChainHashRaw(b)
	var next map[string]any
	_ = json.Unmarshal([]byte(ls[1]), &next)
	next["prev_hash"] = h
	nb, _ := json.Marshal(next)
	ls[1] = string(nb)
	if rep, err := event.VerifyChain(strings.NewReader(strings.Join(ls, "\n") + "\n")); err != nil || !rep.Ok() {
		t.Fatalf("control: the rewritten stream does not pass the chain alone: %v %+v", err, rep)
	}
	if err := os.WriteFile(stream, []byte(strings.Join(ls, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	caught := ""
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && caught == ""; time.Sleep(200 * time.Millisecond) {
		for _, e := range findings() {
			if (e.Type == "witness_checkpoint_invalid" || e.Type == "witness_stream_rewritten") && e.Severity == "high" {
				caught = e.Type
			}
		}
	}
	if caught == "" {
		t.Fatalf("the rewrite of a checkpointed line raised nothing: %s", werr.String())
	}
}
