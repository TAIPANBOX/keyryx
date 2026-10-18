package witness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// The witness takes a checkpoint key on custody's word, so that word must be
// a statement both halves of the delegation root signed, for that kid, valid
// then, and not revoked before the witness saw the record.

func TestTheCustodyClientTakesAKeyOnlyOnAStatementThatHolds(t *testing.T) {
	cdir := filepath.Join(t.TempDir(), "custody")
	_ = os.Mkdir(cdir, 0o700)
	custody, err := keystore.Open(cdir, [32]byte{7, 1}, statement.RootKeys, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := json.Marshal(delegation.FromPublic(&k.PublicKey, ""))
	jwk, pub, _ := statement.ParseJWK(b, "ES256")
	raw, err := statement.Sign(statement.Statement{V: 1, Iss: statement.Issuer, Name: "wardryx-stream", Owner: "wardryx", Kid: jwk.Kid, JWK: jwk,
		NotBefore: t0.Unix(), NotAfter: t0.Add(time.Hour).Unix(), IssuedAt: t0.Unix(), JTI: "jti-custody-0123456789"}, custody)
	if err != nil {
		t.Fatal(err)
	}
	var revoked int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/jwks/"+statement.RootName:
			var keys []map[string]any
			for _, n := range []string{statement.RootES384, statement.RootMLDSA} {
				recs, _ := custody.Published(n)
				for _, rec := range recs {
					keys = append(keys, keystore.JWK(rec))
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		case r.URL.Path == "/v1/statements/"+jwk.Kid:
			_ = json.NewEncoder(w).Encode(map[string]any{"statement": json.RawMessage(raw), "revoked_at": revoked})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &CustodyKeys{Base: srv.URL, HTTP: srv.Client(), TTL: time.Nanosecond}
	got, err := c.Key(jwk.Kid, t0.Add(time.Minute), t0.Add(2*time.Minute))
	if err != nil || string(got) != string(pub) {
		t.Fatalf("an honest statement: %v", err)
	}
	for what, call := range map[string]func() error{
		"a kid no statement certifies": func() error { _, err := c.Key(strings.Repeat("B", 43), t0, t0); return err },
		"a record before not_before":   func() error { _, err := c.Key(jwk.Kid, t0.Add(-time.Second), t0); return err },
		"a record after not_after":     func() error { _, err := c.Key(jwk.Kid, t0.Add(2*time.Hour), t0.Add(2*time.Hour)); return err },
		"a key revoked before the witness saw the record": func() error {
			revoked = t0.Add(30 * time.Minute).Unix()
			_, err := c.Key(jwk.Kid, t0.Add(time.Minute), t0.Add(40*time.Minute))
			return err
		},
	} {
		revoked = 0
		if call() == nil {
			t.Errorf("%s: a key was taken", what)
		}
	}
	revoked = t0.Add(30 * time.Minute).Unix()
	if _, err := c.Key(jwk.Kid, t0.Add(time.Minute), t0.Add(10*time.Minute)); err != nil {
		t.Fatalf("a record seen before its key was revoked: %v", err)
	}
	// Another custody's root: the statement does not verify.
	odir := filepath.Join(t.TempDir(), "other")
	_ = os.Mkdir(odir, 0o700)
	other, _ := keystore.Open(odir, [32]byte{7, 2}, statement.RootKeys, func() time.Time { return t0 })
	custody = other
	c2 := &CustodyKeys{Base: srv.URL, HTTP: srv.Client()}
	revoked = 0
	if _, err := c2.Key(jwk.Kid, t0.Add(time.Minute), t0.Add(time.Minute)); err == nil {
		t.Fatal("a statement under another custody's root was taken")
	}
}
