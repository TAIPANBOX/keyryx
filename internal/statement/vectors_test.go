package statement

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// The statement vectors: what a verifier in another repository (heraldyx's
// checkpoint gate) checks its own reading of a key statement against, so that
// a second implementation cannot drift from this one unnoticed. The file is
// written by this package and committed; KEYRYX_WRITE_STATEMENT_VECTORS=1
// rewrites it. Every run checks that the committed file still means what it
// says: each valid statement verifies here under the root it carries, and
// each variant is refused.

const vectorsPath = "testdata/statement-vectors.json"

type vectorFile struct {
	Comment  string          `json:"comment"`
	RootJWKS json.RawMessage `json:"root_jwks"`
	Pin      []string        `json:"pin"`
	Valid    []vectorValid   `json:"valid"`
	Refused  []vectorRefused `json:"refused"`
}

type vectorValid struct {
	Statement json.RawMessage `json:"statement"`
	Name      string          `json:"name"`
	Kid       string          `json:"kid"`
	NotBefore int64           `json:"not_before"`
	NotAfter  int64           `json:"not_after"`
	// Point is the certified key's uncompressed P-256 point, base64url, as
	// heraldyx's pinned-key file carries one.
	Point string `json:"point"`
}

type vectorRefused struct {
	Why       string          `json:"why"`
	Statement json.RawMessage `json:"statement"`
}

func buildVectors(t *testing.T) vectorFile {
	s := rootStore(t, 9)
	var keys []map[string]any
	var pin []string
	for _, name := range []string{RootES384, RootMLDSA} {
		rs, _ := s.Published(name)
		for _, r := range rs {
			keys = append(keys, keystore.JWK(r))
			pin = append(pin, r.Kid)
		}
	}
	jwks, _ := json.Marshal(map[string]any{"keys": keys})
	var v vectorFile
	v.Comment = "Written by keyryx internal/statement TestTheStatementVectorsHold; KEYRYX_WRITE_STATEMENT_VECTORS=1 rewrites it."
	v.RootJWKS, v.Pin = jwks, pin
	var good []byte
	for i, name := range []string{"tokenfuse-checkpoint", "wardryx-checkpoint"} {
		k := ecKey(t, elliptic.P256())
		st := aStatement(t, k)
		st.Name, st.Owner = name, "producer"
		st.NotBefore = t0.Add(time.Duration(i) * time.Hour).Unix()
		st.NotAfter = st.NotBefore + int64(6*time.Hour/time.Second)
		st.IssuedAt = st.NotBefore
		raw := signed(t, s, st)
		point, err := k.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		v.Valid = append(v.Valid, vectorValid{Statement: raw, Name: name, Kid: st.Kid, NotBefore: st.NotBefore, NotAfter: st.NotAfter,
			Point: base64.RawURLEncoding.EncodeToString(point)})
		good = raw
	}
	j := decode(t, good)
	mutate := func(why string, f func(*jws)) {
		c := j
		c.Signatures = append(c.Signatures[:0:0], j.Signatures...)
		f(&c)
		v.Refused = append(v.Refused, vectorRefused{Why: why, Statement: encode(t, c)})
	}
	mutate("the ML-DSA-65 half is missing", func(c *jws) { c.Signatures = c.Signatures[:1] })
	mutate("the ES384 half is missing", func(c *jws) { c.Signatures = c.Signatures[1:] })
	mutate("a third signature", func(c *jws) { c.Signatures = append(c.Signatures, c.Signatures[0]) })
	mutate("the halves are in the wrong order", func(c *jws) { c.Signatures[0], c.Signatures[1] = c.Signatures[1], c.Signatures[0] })
	mutate("the ES384 signature is another's", func(c *jws) {
		sig, _ := base64.RawURLEncoding.DecodeString(c.Signatures[0].Signature)
		sig[5] ^= 1
		c.Signatures[0].Signature = base64.RawURLEncoding.EncodeToString(sig)
	})
	mutate("the ML-DSA-65 signature is another's", func(c *jws) {
		sig, _ := base64.RawURLEncoding.DecodeString(c.Signatures[1].Signature)
		sig[7] ^= 1
		c.Signatures[1].Signature = base64.RawURLEncoding.EncodeToString(sig)
	})
	payload := func(edit func(map[string]any)) string {
		raw, _ := base64.RawURLEncoding.DecodeString(j.Payload)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		edit(m)
		b, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	mutate("the payload names another key name, signatures unchanged", func(c *jws) {
		c.Payload = payload(func(m map[string]any) { m["name"] = "tokenfuse-checkpoint" })
	})
	mutate("the payload carries a claim the format does not list", func(c *jws) {
		c.Payload = payload(func(m map[string]any) { m["scope"] = "everything" })
	})
	// Signed by another root: a whole valid statement under a root nobody pinned.
	other := rootStore(t, 10)
	st := aStatement(t, ecKey(t, elliptic.P256()))
	st.Name = "wardryx-checkpoint"
	v.Refused = append(v.Refused, vectorRefused{Why: "signed by a root that is not the pinned one", Statement: signed(t, other, st)})
	return v
}

func TestTheStatementVectorsHold(t *testing.T) {
	if os.Getenv("KEYRYX_WRITE_STATEMENT_VECTORS") == "1" {
		b, err := json.MarshalIndent(buildVectors(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("the committed vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Valid) == 0 || len(v.Refused) == 0 {
		t.Fatal("the vectors hold no statement, so this test measured nothing")
	}
	roots, err := KeysFromJWKS(v.RootJWKS)
	if err != nil {
		t.Fatalf("the vectors' root key set: %v", err)
	}
	pinned := func(kid string) bool {
		for _, p := range v.Pin {
			if p == kid {
				return true
			}
		}
		return false
	}
	look := func(kid string) (policy.Alg, []byte, bool) {
		if !pinned(kid) {
			return "", nil, false
		}
		return roots(kid)
	}
	for i, g := range v.Valid {
		st, err := Verify(g.Statement, look)
		if err != nil {
			t.Fatalf("valid %d does not verify: %v", i, err)
		}
		if st.Name != g.Name || st.Kid != g.Kid || st.NotBefore != g.NotBefore || st.NotAfter != g.NotAfter {
			t.Fatalf("valid %d says %s %s %d %d", i, st.Name, st.Kid, st.NotBefore, st.NotAfter)
		}
		point, _ := base64.RawURLEncoding.DecodeString(g.Point)
		_, want, _ := ParseJWK(mustJSON(t, st.JWK), policy.ES256)
		if !bytes.Equal(point, want) {
			t.Fatalf("valid %d: the point is not the certified key", i)
		}
	}
	for _, r := range v.Refused {
		if _, err := Verify(r.Statement, look); err == nil {
			t.Errorf("%s: verified", r.Why)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
