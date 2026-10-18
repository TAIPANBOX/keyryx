package wconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What the witness believes about its own environment. A witness that came up
// reading nothing would sign tree heads over nothing, which reads as a record
// nobody rewrote; one sharing custody's directory or key could be rewritten
// by custody.

var all = []string{"KEYRYX_WITNESS_DATA", "KEYRYX_WITNESS_ROOT_KEY_FILE", "KEYRYX_WITNESS_EVENTS", "KEYRYX_WITNESS_CHECKPOINTS",
	"KEYRYX_WITNESS_CUSTODY_URL", "KEYRYX_WITNESS_ALERTS", "KEYRYX_WITNESS_RECORDS", "KEYRYX_WITNESS_ADDR", "KEYRYX_WITNESS_INTERVAL",
	"KEYRYX_WITNESS_FULL_BYTES", "KEYRYX_WITNESS_FULL_INTERVAL", "KEYRYX_WITNESS_SEAL_EVERY", "KEYRYX_WITNESS_SEAL_LINES",
	"KEYRYX_WITNESS_NAME", "KEYRYX_WITNESS_TSA_URL", "KEYRYX_WITNESS_TSA_CA", "KEYRYX_WITNESS_TSA_EVERY", "KEYRYX_DATA", "KEYRYX_ROOT_KEY_FILE",
	"KEYRYX_WITNESS_STREAM_KEYS", "KEYRYX_WITNESS_DELEGATION_ROOT_PIN"}

var (
	esKid = strings.Repeat("E", 43)
	mlKid = "mldsa65:" + strings.Repeat("M", 43)
)

func file(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, mode)
	return p
}

func caPEM(t *testing.T, dir string) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a TSA root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	return file(t, dir, "tsa-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
}

func base(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "witness")
	events := filepath.Join(dir, "events")
	_ = os.Mkdir(data, 0o700)
	_ = os.Mkdir(events, 0o750)
	return map[string]string{
		"KEYRYX_WITNESS_DATA":          data,
		"KEYRYX_WITNESS_ROOT_KEY_FILE": file(t, dir, "witness.key", strings.Repeat("cd", 32), 0o400),
		"KEYRYX_WITNESS_EVENTS":        events,
	}
}

func withEnv(t *testing.T, env map[string]string) (Config, error) {
	t.Helper()
	for _, k := range all {
		t.Setenv(k, env[k])
	}
	return FromEnv()
}

func TestAFullWitnessConfigComesUp(t *testing.T) {
	env := base(t)
	if c, err := withEnv(t, env); err != nil || c.Addr != DefaultAddr || c.Interval != time.Minute || c.Witness.FullBytes != 256<<20 ||
		c.Witness.FullInterval != time.Hour || c.Witness.Name != "keyryx-witness" || c.Alerts != filepath.Join(env["KEYRYX_WITNESS_EVENTS"], "keyryx.ndjson") || c.TSA != nil {
		t.Fatalf("the minimal environment: %+v %v", c, err)
	}
	if DefaultAddr != "127.0.0.1:4341" {
		t.Fatalf("the default address is %s; 4341 is beside custody's 4340", DefaultAddr)
	}
	dir := t.TempDir()
	records := filepath.Join(dir, "records")
	ckpts := filepath.Join(dir, "ckpts")
	_ = os.Mkdir(records, 0o750)
	_ = os.Mkdir(ckpts, 0o750)
	env["KEYRYX_WITNESS_CHECKPOINTS"] = ckpts
	env["KEYRYX_WITNESS_CUSTODY_URL"] = "http://127.0.0.1:4340"
	env["KEYRYX_WITNESS_STREAM_KEYS"] = "wardryx.ndjson|wardryx-stream,tokenfuse.ndjson|tokenfuse-stream"
	env["KEYRYX_WITNESS_DELEGATION_ROOT_PIN"] = esKid + "," + mlKid
	env["KEYRYX_WITNESS_RECORDS"] = "acme|" + records
	env["KEYRYX_WITNESS_INTERVAL"] = "30s"
	env["KEYRYX_WITNESS_TSA_URL"] = "https://tsa.example/tsr"
	env["KEYRYX_WITNESS_TSA_CA"] = caPEM(t, dir)
	c, err := withEnv(t, env)
	if err != nil || len(c.Witness.Records) != 1 || c.Witness.Records[0].Name != "acme" || c.TSA == nil || c.TSA.Every != time.Hour || c.CustodyURL == "" {
		t.Fatalf("the full environment: %+v %v", c, err)
	}
	if c.Witness.StreamKeys["wardryx.ndjson"] != "wardryx-stream" || c.Witness.StreamKeys["tokenfuse.ndjson"] != "tokenfuse-stream" || len(c.Witness.StreamKeys) != 2 {
		t.Fatalf("the stream keys: %v", c.Witness.StreamKeys)
	}
	if len(c.Witness.RootPin) != 2 || c.Witness.RootPin[0] != esKid || c.Witness.RootPin[1] != mlKid {
		t.Fatalf("the root pin: %v", c.Witness.RootPin)
	}
}

func TestEachRequiredWitnessVariableIsNamedWhenMissing(t *testing.T) {
	if _, err := withEnv(t, base(t)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, v := range []string{"KEYRYX_WITNESS_DATA", "KEYRYX_WITNESS_ROOT_KEY_FILE", "KEYRYX_WITNESS_EVENTS"} {
		env := base(t)
		env[v] = ""
		if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), v) {
			t.Errorf("%s unset: %v", v, err)
		}
	}
	env := base(t)
	env["KEYRYX_WITNESS_CHECKPOINTS"] = t.TempDir()
	env["KEYRYX_WITNESS_STREAM_KEYS"] = "wardryx.ndjson|wardryx-stream"
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "KEYRYX_WITNESS_CUSTODY_URL") {
		t.Errorf("checkpoints with no custody to ask for their statements: %v", err)
	}
	env = base(t)
	env["KEYRYX_WITNESS_CHECKPOINTS"] = t.TempDir()
	env["KEYRYX_WITNESS_CUSTODY_URL"] = "http://127.0.0.1:4340"
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "KEYRYX_WITNESS_STREAM_KEYS") {
		t.Errorf("checkpoints with no stream bound to its key: %v", err)
	}
	env = base(t)
	env["KEYRYX_WITNESS_TSA_URL"] = "https://tsa.example/tsr"
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "KEYRYX_WITNESS_TSA_CA") {
		t.Errorf("a TSA with no certificate to check its answers against: %v", err)
	}
}

func TestTheWitnessNeverSharesCustodysDataOrRootKey(t *testing.T) {
	env := base(t)
	env["KEYRYX_DATA"] = env["KEYRYX_WITNESS_DATA"]
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "KEYRYX_DATA") {
		t.Errorf("the witness in custody's data directory: %v", err)
	}
	env = base(t)
	env["KEYRYX_ROOT_KEY_FILE"] = env["KEYRYX_WITNESS_ROOT_KEY_FILE"]
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "KEYRYX_ROOT_KEY_FILE") {
		t.Errorf("the witness under custody's root key file: %v", err)
	}
	env = base(t)
	env["KEYRYX_ROOT_KEY_FILE"] = file(t, t.TempDir(), "custody.key", strings.Repeat("cd", 32), 0o400)
	if _, err := withEnv(t, env); err == nil || !strings.Contains(err.Error(), "same root key") {
		t.Errorf("the witness under a copy of custody's root key: %v", err)
	}
	env = base(t)
	env["KEYRYX_DATA"] = filepath.Join(env["KEYRYX_WITNESS_DATA"], "..", filepath.Base(env["KEYRYX_WITNESS_DATA"]))
	if _, err := withEnv(t, env); err == nil {
		t.Error("the same directory spelt another way was accepted")
	}
	env = base(t)
	env["KEYRYX_DATA"] = t.TempDir()
	env["KEYRYX_ROOT_KEY_FILE"] = file(t, t.TempDir(), "custody.key", strings.Repeat("ab", 32), 0o400)
	if _, err := withEnv(t, env); err != nil {
		t.Errorf("control: custody's own directory and key beside the witness's: %v", err)
	}
}

func TestMalformedWitnessValuesRefuseTheStart(t *testing.T) {
	if _, err := withEnv(t, base(t)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, edit := range map[string]func(map[string]string){
		"an interval that is not a duration": func(e map[string]string) { e["KEYRYX_WITNESS_INTERVAL"] = "often" },
		"an interval under a second":         func(e map[string]string) { e["KEYRYX_WITNESS_INTERVAL"] = "100ms" },
		"an interval over an hour":           func(e map[string]string) { e["KEYRYX_WITNESS_INTERVAL"] = "2h" },
		"full bytes that are not a number":   func(e map[string]string) { e["KEYRYX_WITNESS_FULL_BYTES"] = "lots" },
		"negative full bytes":                func(e map[string]string) { e["KEYRYX_WITNESS_FULL_BYTES"] = "-1" },
		"a full interval under a minute":     func(e map[string]string) { e["KEYRYX_WITNESS_FULL_INTERVAL"] = "10s" },
		"seal lines of zero":                 func(e map[string]string) { e["KEYRYX_WITNESS_SEAL_LINES"] = "0" },
		"a witness name with a space":        func(e map[string]string) { e["KEYRYX_WITNESS_NAME"] = "a witness" },
		"a records entry with no directory":  func(e map[string]string) { e["KEYRYX_WITNESS_RECORDS"] = "acme" },
		"a records tenant outside the grammar": func(e map[string]string) {
			e["KEYRYX_WITNESS_RECORDS"] = "../acme|" + t.TempDir()
		},
		"two records entries for one tenant": func(e map[string]string) {
			d := t.TempDir()
			e["KEYRYX_WITNESS_RECORDS"] = "acme|" + d + ",acme|" + d
		},
		"a custody URL that is not one":  func(e map[string]string) { e["KEYRYX_WITNESS_CUSTODY_URL"] = "custody" },
		"a stream key entry with no key": func(e map[string]string) { e["KEYRYX_WITNESS_STREAM_KEYS"] = "wardryx.ndjson" },
		"a stream key for a file that is no stream": func(e map[string]string) {
			e["KEYRYX_WITNESS_STREAM_KEYS"] = "../wardryx.ndjson|wardryx-stream"
		},
		"a stream key name outside the grammar": func(e map[string]string) { e["KEYRYX_WITNESS_STREAM_KEYS"] = "wardryx.ndjson|Wardryx Stream" },
		"one stream bound to two keys": func(e map[string]string) {
			e["KEYRYX_WITNESS_STREAM_KEYS"] = "wardryx.ndjson|a-stream,wardryx.ndjson|b-stream"
		},
		"a pinned kid that is not one": func(e map[string]string) { e["KEYRYX_WITNESS_DELEGATION_ROOT_PIN"] = "chosen," + mlKid },
		"a pin with no ML-DSA half":    func(e map[string]string) { e["KEYRYX_WITNESS_DELEGATION_ROOT_PIN"] = esKid },
		"a pin with no ES384 half":     func(e map[string]string) { e["KEYRYX_WITNESS_DELEGATION_ROOT_PIN"] = mlKid },
		"a TSA over plain HTTP": func(e map[string]string) {
			e["KEYRYX_WITNESS_TSA_URL"] = "http://tsa.example/tsr"
			e["KEYRYX_WITNESS_TSA_CA"] = caPEM(t, t.TempDir())
		},
		"a TSA certificate file that is not PEM": func(e map[string]string) {
			e["KEYRYX_WITNESS_TSA_URL"] = "https://tsa.example/tsr"
			e["KEYRYX_WITNESS_TSA_CA"] = file(t, t.TempDir(), "x.pem", "not pem", 0o644)
		},
		"a TSA every ten seconds": func(e map[string]string) {
			e["KEYRYX_WITNESS_TSA_URL"] = "https://tsa.example/tsr"
			e["KEYRYX_WITNESS_TSA_CA"] = caPEM(t, t.TempDir())
			e["KEYRYX_WITNESS_TSA_EVERY"] = "10s"
		},
		"a data directory open to the group": func(e map[string]string) { _ = os.Chmod(e["KEYRYX_WITNESS_DATA"], 0o750) },
		"a root key readable by the group": func(e map[string]string) {
			e["KEYRYX_WITNESS_ROOT_KEY_FILE"] = file(t, t.TempDir(), "k", strings.Repeat("cd", 32), 0o440)
		},
		"an events directory that is not there": func(e map[string]string) { e["KEYRYX_WITNESS_EVENTS"] = filepath.Join(t.TempDir(), "absent") },
		"an address that is not one":            func(e map[string]string) { e["KEYRYX_WITNESS_ADDR"] = "witness" },
	} {
		env := base(t)
		edit(env)
		if _, err := withEnv(t, env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
