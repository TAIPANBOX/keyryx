package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// Which consumer is asking. A wrong answer here signs with somebody else's key.

const (
	clusterIss = "https://k3s.acme.example"
	clusterAud = "keyryx"
	cloudSA    = "system:serviceaccount:agent-stack:tokenfuse-cloud"
	sealSecret = "record-seal-consumer-key-0123456789"
)

var at = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`{"version":1,
 "keys":[{"name":"trailryx-root","alg":"ES384"},{"name":"cloud-audit","alg":"ES256"}],
 "consumers":[
  {"name":"record-seal","auth":{"key_digest":"` + digest(sealSecret) + `"},"grants":{"trailryx-root":["sign"]}},
  {"name":"tokenfuse-cloud","auth":{"k8s":{"issuer":"` + clusterIss + `","subject":"` + cloudSA + `"}},"grants":{"cloud-audit":["sign"]}}
 ]}`))
	if err != nil {
		t.Fatalf("the test policy did not parse: %v", err)
	}
	return p
}

type cluster struct{ key *rsa.PrivateKey }

func newCluster(t *testing.T) *cluster {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &cluster{key: k}
}

func (c *cluster) issuer() Issuer {
	return Issuer{Iss: clusterIss, Aud: clusterAud, Keys: delegation.Set{Keys: []delegation.JWK{{
		Kty: "RSA", Kid: "sa-1",
		N: base64.RawURLEncoding.EncodeToString(c.key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(c.key.E)).Bytes()),
	}}}}
}

func (c *cluster) token(t *testing.T, over map[string]any, hdr map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": "RS256", "kid": "sa-1"}
	for k, v := range hdr {
		h[k] = v
	}
	claims := map[string]any{"iss": clusterIss, "sub": cloudSA, "aud": []string{clusterAud},
		"iat": at.Unix(), "exp": at.Add(10 * time.Minute).Unix()}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func verifier(t *testing.T, c *cluster) *Verifier {
	return &Verifier{Policy: testPolicy(t), Issuers: []Issuer{c.issuer()}, Now: func() time.Time { return at }}
}

func TestAKeyBearerResolvesToItsConsumer(t *testing.T) {
	v := verifier(t, newCluster(t))
	name, via, ok := v.FromBearer("Bearer " + sealSecret)
	if !ok || name != "record-seal" || via != "key" {
		t.Fatalf("got %q %q %v", name, via, ok)
	}
	for _, h := range []string{"", sealSecret, "Basic " + sealSecret, "Bearer " + sealSecret + "x", "Bearer ", "bearer" + sealSecret, "Bearer " + digest(sealSecret)} {
		if n, _, ok := v.FromBearer(h); ok {
			t.Errorf("%q resolved to %s", h, n)
		}
	}
}

func TestAProjectedTokenResolvesToItsBoundConsumer(t *testing.T) {
	c := newCluster(t)
	v := verifier(t, c)
	name, via, ok := v.FromBearer("Bearer " + c.token(t, nil, nil))
	if !ok || name != "tokenfuse-cloud" || via != "k8s" {
		t.Fatalf("got %q %q %v", name, via, ok)
	}
	if n, _, ok := v.FromBearer("Bearer " + c.token(t, map[string]any{"aud": clusterAud}, nil)); !ok || n != "tokenfuse-cloud" {
		t.Fatal("aud as a plain string was refused")
	}
}

func TestAHostileOrWrongProjectedTokenResolvesNobody(t *testing.T) {
	c := newCluster(t)
	v := verifier(t, c)
	if _, _, ok := v.FromBearer("Bearer " + c.token(t, nil, nil)); !ok {
		t.Fatal("control: the honest token was refused")
	}
	other := newCluster(t)
	parts := strings.Split(c.token(t, nil, nil), ".")
	for name, tok := range map[string]string{
		"another issuer":         c.token(t, map[string]any{"iss": "https://k3s.evil.example"}, nil),
		"signed by another key":  other.token(t, nil, nil),
		"for the API server":     c.token(t, map[string]any{"aud": []string{"https://kubernetes.default.svc"}}, nil),
		"two audiences":          c.token(t, map[string]any{"aud": []string{clusterAud, "other"}}, nil),
		"an unbound account":     c.token(t, map[string]any{"sub": "system:serviceaccount:agent-stack:intruder"}, nil),
		"expired":                c.token(t, map[string]any{"iat": at.Add(-time.Hour).Unix(), "exp": at.Add(-time.Minute).Unix()}, nil),
		"from the future":        c.token(t, map[string]any{"iat": at.Add(5 * time.Minute).Unix(), "exp": at.Add(20 * time.Minute).Unix()}, nil),
		"living over an hour":    c.token(t, map[string]any{"exp": at.Add(2 * time.Hour).Unix()}, nil),
		"no sub":                 c.token(t, map[string]any{"sub": nil}, nil),
		"no exp":                 c.token(t, map[string]any{"exp": nil}, nil),
		"no iat":                 c.token(t, map[string]any{"iat": nil}, nil),
		"alg none":               base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"sa-1"}`)) + "." + parts[1] + ".",
		"alg HS256":              c.token(t, nil, map[string]any{"alg": "HS256"}),
		"no kid":                 c.token(t, nil, map[string]any{"kid": ""}),
		"a forged signature":     parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"two parts":              parts[0] + "." + parts[1],
		"garbage":                "a.b.c",
		"a payload that is junk": parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("{")) + "." + parts[2],
	} {
		if n, _, ok := v.FromBearer("Bearer " + tok); ok {
			t.Errorf("%s: resolved to %s", name, n)
		}
	}
}

func TestIssuersParseStrictly(t *testing.T) {
	c := newCluster(t)
	set, _ := json.Marshal(c.issuer().Keys)
	dir := t.TempDir()
	jwks := filepath.Join(dir, "jwks.json")
	_ = os.WriteFile(jwks, set, 0o600)
	read := os.ReadFile
	got, err := ParseIssuers(clusterIss+"|"+clusterAud+"|"+jwks, read)
	if err != nil || len(got) != 1 || got[0].Iss != clusterIss || got[0].Aud != clusterAud || len(got[0].Keys.Keys) != 1 {
		t.Fatalf("a well-formed issuer: %+v %v", got, err)
	}
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"keys":[]}`), 0o600)
	nokid := filepath.Join(dir, "nokid.json")
	_ = os.WriteFile(nokid, []byte(`{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]}`), 0o600)
	nokty := filepath.Join(dir, "nokty.json")
	_ = os.WriteFile(nokty, []byte(`{"keys":[{"kid":"x","n":"AQAB","e":"AQAB"}]}`), 0o600)
	for name, spec := range map[string]string{
		"two fields":        clusterIss + "|" + clusterAud,
		"an empty audience": clusterIss + "||" + jwks,
		"not a URL":         "k3s|" + clusterAud + "|" + jwks,
		"a missing JWKS":    clusterIss + "|" + clusterAud + "|" + filepath.Join(dir, "absent.json"),
		"an empty JWKS":     clusterIss + "|" + clusterAud + "|" + empty,
		"a key with no kid": clusterIss + "|" + clusterAud + "|" + nokid,
		"a key with no kty": clusterIss + "|" + clusterAud + "|" + nokty,
		"a duplicate":       clusterIss + "|" + clusterAud + "|" + jwks + "\n" + clusterIss + "|" + clusterAud + "|" + jwks,
	} {
		if _, err := ParseIssuers(spec, read); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAdminKeysAreDigestsComparedInConstantTime(t *testing.T) {
	keys, err := ParseAdminKeys(digest("admin-key-one-0123456789") + ", " + digest("admin-key-two-0123456789"))
	if err != nil || len(keys) != 2 {
		t.Fatalf("well-formed admin keys: %v %v", keys, err)
	}
	if fp, ok := Admin(keys, "Bearer admin-key-two-0123456789"); !ok || fp == "" || strings.Contains(fp, "admin-key") {
		t.Fatalf("the second admin key: %q %v (a fingerprint, never the key)", fp, ok)
	}
	for _, h := range []string{"", "Bearer ", "Bearer admin-key-one", "admin-key-one-0123456789", "Bearer " + digest("admin-key-one-0123456789")} {
		if _, ok := Admin(keys, h); ok {
			t.Errorf("%q was an admin", h)
		}
	}
	if _, ok := Admin(nil, "Bearer admin-key-one-0123456789"); ok {
		t.Error("with no admin keys configured somebody was an admin")
	}
	for name, spec := range map[string]string{
		"plaintext":   "admin-key-one-0123456789",
		"short":       "sha256:abcd",
		"not hex":     "sha256:" + strings.Repeat("z", 64),
		"a duplicate": digest("a") + "," + digest("a"),
	} {
		if _, err := ParseAdminKeys(spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if keys, err := ParseAdminKeys(""); err != nil || len(keys) != 0 {
		t.Errorf("unset: %v %v", keys, err)
	}
}
