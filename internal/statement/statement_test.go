package statement

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// A key statement is what every verifier of a delegated key trusts: a
// statement that verifies when it should not certifies a key nobody
// certified, and nothing downstream can tell.

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func rootStore(t *testing.T, root byte) *keystore.Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := keystore.Open(dir, [32]byte{root, 1, 2, 3}, RootKeys, func() time.Time { return t0 })
	if err != nil {
		t.Fatalf("the root store did not open: %v", err)
	}
	return s
}

func ecKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwkOf(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := json.Marshal(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func aStatement(t *testing.T, k *ecdsa.PrivateKey) Statement {
	t.Helper()
	j, _, err := ParseJWK(jwkOf(t, k), policy.ES256)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	return Statement{V: 1, Iss: Issuer, Name: "vouchryx-token", Owner: "vouchryx", Kid: j.Kid, JWK: j,
		NotBefore: t0.Unix(), NotAfter: t0.Add(72 * time.Hour).Unix(), IssuedAt: t0.Unix(), JTI: "jti-0123456789abcdef"}
}

func signed(t *testing.T, s *keystore.Store, st Statement) []byte {
	t.Helper()
	raw, err := Sign(st, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return raw
}

type jws struct {
	Payload    string `json:"payload"`
	Signatures []struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	} `json:"signatures"`
}

func decode(t *testing.T, raw []byte) jws {
	t.Helper()
	var j jws
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("the statement is not JWS JSON: %v", err)
	}
	return j
}

func encode(t *testing.T, j any) []byte {
	t.Helper()
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAStatementVerifiesOnlyWithBothHalvesOfItsRoot(t *testing.T) {
	s := rootStore(t, 1)
	k := ecKey(t, elliptic.P256())
	st := aStatement(t, k)
	raw := signed(t, s, st)
	got, err := Verify(raw, StoreRoots(s))
	if err != nil {
		t.Fatalf("the statement does not verify under its own root: %v", err)
	}
	if got.Kid != st.Kid || got.Name != st.Name || got.Owner != st.Owner || got.NotAfter != st.NotAfter || got.JWK.X != st.JWK.X {
		t.Fatalf("verified %+v, signed %+v", got, st)
	}
	es, _ := s.Active(RootES384)
	ml, _ := s.Active(RootMLDSA)
	if got.Roots.ES384 != es.Kid || got.Roots.MLDSA65 != ml.Kid {
		t.Fatalf("the statement names roots %+v, the store's are %s and %s", got.Roots, es.Kid, ml.Kid)
	}
	j := decode(t, raw)
	if len(j.Signatures) != 2 {
		t.Fatalf("%d signatures, want the two halves", len(j.Signatures))
	}
	one := j
	one.Signatures = j.Signatures[:1]
	other := j
	other.Signatures = j.Signatures[1:]
	swapped := j
	swapped.Signatures = append(append(swapped.Signatures[:0:0], j.Signatures[1]), j.Signatures[0])
	payload, _ := base64.RawURLEncoding.DecodeString(j.Payload)
	edited := j
	edited.Payload = base64.RawURLEncoding.EncodeToString(bytes.Replace(payload, []byte(`"owner":"vouchryx"`), []byte(`"owner":"vouchryy"`), 1))
	if edited.Payload == j.Payload {
		t.Fatal("the payload edit did not apply")
	}
	// The ML-DSA half of another statement under the same root: the ES384
	// half still verifies, so only checking the second half refuses it.
	st2 := aStatement(t, ecKey(t, elliptic.P256()))
	j2 := decode(t, signed(t, s, st2))
	mixed := j
	mixed.Signatures = append(append(mixed.Signatures[:0:0], j.Signatures[0]), j2.Signatures[1])
	for name, bad := range map[string][]byte{
		"the ML-DSA half of another statement": encode(t, mixed),
		"the classical half alone":             encode(t, one),
		"the ML-DSA half alone":                encode(t, other),
		"the halves swapped":                   encode(t, swapped),
		"one byte of the payload":              encode(t, edited),
	} {
		if _, err := Verify(bad, StoreRoots(s)); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := Verify(raw, StoreRoots(rootStore(t, 2))); err == nil {
		t.Error("the statement verified under another root")
	}
}

func TestTheStatementsClassicalHalfVerifiesWithAgentStackGo(t *testing.T) {
	s := rootStore(t, 1)
	k := ecKey(t, elliptic.P256())
	st := aStatement(t, k)
	raw := signed(t, s, st)
	compact, err := Compact(raw, policy.ES384)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	recs, _ := s.Published(RootES384)
	var set delegation.Set
	for _, r := range recs {
		b, _ := json.Marshal(keystore.JWK(r))
		var j delegation.JWK
		if err := json.Unmarshal(b, &j); err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, j)
	}
	claims, err := delegation.VerifyToken(compact, set)
	if err != nil {
		t.Fatalf("agent-stack-go refused the classical half: %v", err)
	}
	if claims["kid"] != st.Kid || claims["name"] != st.Name || claims["owner"] != st.Owner || claims["iss"] != Issuer ||
		claims["not_after"] != float64(st.NotAfter) {
		t.Fatalf("claims %v, statement %+v", claims, st)
	}
	if _, err := delegation.VerifyToken(compact, delegation.Set{}); err == nil {
		t.Fatal("the classical half verified under a key set without the root")
	}
	other := rootStore(t, 3)
	orecs, _ := other.Published(RootES384)
	b, _ := json.Marshal(keystore.JWK(orecs[0]))
	var oj delegation.JWK
	_ = json.Unmarshal(b, &oj)
	oj.Kid = set.Keys[0].Kid // the right kid over another root's key
	if _, err := delegation.VerifyToken(compact, delegation.Set{Keys: []delegation.JWK{oj}}); err == nil {
		t.Fatal("the classical half verified under another root's key published with its kid")
	}
	if _, err := Compact(raw, policy.ES256); err == nil {
		t.Fatal("a statement has no ES256 half and Compact made one")
	}
}

func TestHostileStatementsNeverParseAndNeverPanic(t *testing.T) {
	s := rootStore(t, 1)
	k := ecKey(t, elliptic.P256())
	st := aStatement(t, k)
	raw := signed(t, s, st)
	if _, err := Verify(raw, StoreRoots(s)); err != nil {
		t.Fatalf("control: %v", err)
	}
	j := decode(t, raw)
	payload, _ := base64.RawURLEncoding.DecodeString(j.Payload)
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	reSign := func(edit func(map[string]any)) []byte {
		// A statement whose payload is edited and re-signed by the right root:
		// the signatures hold, so only the parser can refuse it.
		// A fresh copy each time: the jwk member is itself a map, and an edit
		// to it must not reach the cases after it.
		var c map[string]any
		if err := json.Unmarshal(payload, &c); err != nil {
			t.Fatal(err)
		}
		edit(c)
		b, _ := json.Marshal(c)
		out, err := signRaw(b, s)
		if err != nil {
			t.Fatalf("re-signing: %v", err)
		}
		return out
	}
	hdr := func(i int, h string) []byte {
		c := decode(t, raw)
		c.Signatures[i].Protected = base64.RawURLEncoding.EncodeToString([]byte(h))
		return encode(t, c)
	}
	cases := map[string][]byte{
		"empty":                       nil,
		"not JSON":                    []byte("{"),
		"an array":                    []byte("[]"),
		"trailing data":               append(append([]byte(nil), raw...), []byte(" {}")...),
		"an unknown top member":       bytes.Replace(raw, []byte(`{"payload"`), []byte(`{"header":{},"payload"`), 1),
		"no signatures":               encode(t, map[string]any{"payload": j.Payload, "signatures": []any{}}),
		"three signatures":            encode(t, map[string]any{"payload": j.Payload, "signatures": []any{j.Signatures[0], j.Signatures[1], j.Signatures[1]}}),
		"the classical half twice":    encode(t, map[string]any{"payload": j.Payload, "signatures": []any{j.Signatures[0], j.Signatures[0]}}),
		"a payload not base64url":     bytes.Replace(raw, []byte(j.Payload[:8]), []byte("!!!!!!!!"), 1),
		"a header of alg none":        hdr(0, `{"alg":"none","kid":"`+claimsRoot(claims, "ES384")+`","typ":"`+Typ+`"}`),
		"a header with no kid":        hdr(0, `{"alg":"ES384","typ":"`+Typ+`"}`),
		"a header with another typ":   hdr(0, `{"alg":"ES384","kid":"`+claimsRoot(claims, "ES384")+`","typ":"JWT"}`),
		"a header with a member more": hdr(0, `{"alg":"ES384","kid":"`+claimsRoot(claims, "ES384")+`","typ":"`+Typ+`","jku":"https://evil.example"}`),
		"a header kid that is not the payload's root": hdr(0, `{"alg":"ES384","kid":"another","typ":"`+Typ+`"}`),
		"version 2":                  reSign(func(c map[string]any) { c["v"] = 2 }),
		"another issuer":             reSign(func(c map[string]any) { c["iss"] = "elsewhere" }),
		"no owner":                   reSign(func(c map[string]any) { delete(c, "owner") }),
		"an unknown claim":           reSign(func(c map[string]any) { c["scope"] = "everything" }),
		"a name outside the grammar": reSign(func(c map[string]any) { c["name"] = "../keys" }),
		"not_after before not_before": reSign(func(c map[string]any) {
			c["not_after"] = c["not_before"].(float64) - 1
		}),
		"a time as a string":          reSign(func(c map[string]any) { c["not_after"] = "soon" }),
		"a kid that is not the key's": reSign(func(c map[string]any) { c["kid"] = "not-the-thumbprint" }),
		"a key with a private member": reSign(func(c map[string]any) {
			jk := c["jwk"].(map[string]any)
			jk["d"] = base64.RawURLEncoding.EncodeToString(rawPrivate(t, k))
		}),
		"a key off the curve": reSign(func(c map[string]any) {
			jk := c["jwk"].(map[string]any)
			jk["y"] = jk["x"]
		}),
		"roots naming other keys": reSign(func(c map[string]any) { c["roots"] = map[string]any{"ES384": "a", "ML-DSA-65": "b"} }),
		"over the size cap":       append(bytes.Repeat([]byte(" "), MaxBytes), raw...),
	}
	for name, bad := range cases {
		if _, err := Verify(bad, StoreRoots(s)); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	r := mrand.New(mrand.NewPCG(20261018, 3))
	alphabet := []byte(`{}[]",:=-_ABCabc019 ` + "\x00\xff")
	for i := 0; i < 1500; i++ {
		b := append([]byte(nil), raw...)
		for n := 0; n <= r.IntN(4); n++ {
			b[r.IntN(len(b))] = alphabet[r.IntN(len(alphabet))]
		}
		got, err := Verify(b, StoreRoots(s))
		if err == nil && (got.Kid != st.Kid || got.Owner != st.Owner || got.NotAfter != st.NotAfter || got.JWK.X != st.JWK.X || got.JWK.Y != st.JWK.Y) {
			t.Fatalf("case %d: an edit verified as something that was never signed: %+v", i, got)
		}
	}
}

func claimsRoot(c map[string]any, alg string) string {
	r, _ := c["roots"].(map[string]any)
	s, _ := r[alg].(string)
	return s
}

func TestHostileKeysAreRefused(t *testing.T) {
	k := ecKey(t, elliptic.P256())
	honest := delegation.FromPublic(&k.PublicKey, "")
	tp, _ := delegation.Thumbprint(honest)
	j, pub, err := ParseJWK(jwkOf(t, k), policy.ES256)
	if err != nil || j.Kid != tp || j.Alg != "ES256" || j.Use != "sig" || len(pub) != 65 || pub[0] != 4 {
		t.Fatalf("the honest key: %+v %d %v", j, len(pub), err)
	}
	if _, _, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-256","x":"`+honest.X+`","y":"`+honest.Y+`","kid":"`+tp+`","alg":"ES256","use":"sig"}`), policy.ES256); err != nil {
		t.Fatalf("the honest key with its own kid, alg and use: %v", err)
	}
	k384 := ecKey(t, elliptic.P384())
	j384, _, err := ParseJWK(jwkOf(t, k384), policy.ES384)
	if err != nil || j384.Crv != "P-384" {
		t.Fatalf("an honest P-384 key for ES384: %+v %v", j384, err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	on := func(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
	base := func() map[string]any {
		return map[string]any{"kty": "EC", "crv": "P-256", "x": honest.X, "y": honest.Y}
	}
	with := func(k string, v any) []byte { m := base(); m[k] = v; return on(m) }
	without := func(k string) []byte { m := base(); delete(m, k); return on(m) }
	cases := map[string]struct {
		raw []byte
		alg policy.Alg
	}{
		"a private member":                 {with("d", b64(rawPrivate(t, k))), policy.ES256},
		"an unknown member":                {with("x5u", "https://evil.example/cert"), policy.ES256},
		"an RSA type":                      {with("kty", "RSA"), policy.ES256},
		"a symmetric type":                 {on(map[string]any{"kty": "oct", "k": b64([]byte("secret"))}), policy.ES256},
		"P-384 for ES256":                  {jwkOf(t, k384), policy.ES256},
		"P-256 for ES384":                  {jwkOf(t, k), policy.ES384},
		"an ML-DSA algorithm":              {jwkOf(t, k), policy.MLDSA65},
		"a point off the curve":            {with("y", honest.X), policy.ES256},
		"a short coordinate":               {with("x", b64(make([]byte, 31))), policy.ES256},
		"a coordinate with padding":        {with("x", honest.X+"="), policy.ES256},
		"no y":                             {without("y"), policy.ES256},
		"a kid that is not its thumbprint": {with("kid", "chosen-by-the-caller"), policy.ES256},
		"another alg":                      {with("alg", "ES384"), policy.ES256},
		"a use for encryption":             {with("use", "enc"), policy.ES256},
		"a number for x":                   {with("x", 5), policy.ES256},
		"not JSON":                         {[]byte(`{`), policy.ES256},
		"trailing data":                    {append(jwkOf(t, k), []byte(` {}`)...), policy.ES256},
		"over a kilobyte":                  {with("crv", strings.Repeat("P", 2048)), policy.ES256},
		"the zero point":                   {with("x", b64(make([]byte, 32))), policy.ES256},
	}
	for name, c := range cases {
		if _, _, err := ParseJWK(c.raw, c.alg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := ParseJWK(with("y", b64(new(big.Int).Add(k.Y, big.NewInt(1)).FillBytes(make([]byte, 32)))), policy.ES256); err == nil {
		t.Error("a y one off its curve point was accepted")
	}
}

func TestAProofBindsTheKeyTheNameTheConsumerAndTheChallenge(t *testing.T) {
	k := ecKey(t, elliptic.P256())
	other := ecKey(t, elliptic.P256())
	j, pub, err := ParseJWK(jwkOf(t, k), policy.ES256)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, _ := ParseJWK(jwkOf(t, other), policy.ES256)
	prove := func(key *ecdsa.PrivateKey, in []byte) []byte {
		d := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
		if err != nil {
			t.Fatal(err)
		}
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	in := ProofInput("vouchryx-token", "vouchryx", j.Kid, "challenge-one")
	proof := prove(k, in)
	if err := keystore.Verify(policy.ES256, pub, in, proof); err != nil {
		t.Fatalf("the honest proof: %v", err)
	}
	for name, alt := range map[string][]byte{
		"another name":      ProofInput("wardryx-stream", "vouchryx", j.Kid, "challenge-one"),
		"another consumer":  ProofInput("vouchryx-token", "wardryx", j.Kid, "challenge-one"),
		"another kid":       ProofInput("vouchryx-token", "vouchryx", "another-kid", "challenge-one"),
		"another challenge": ProofInput("vouchryx-token", "vouchryx", j.Kid, "challenge-two"),
		"a shifted field":   ProofInput("vouchryx-token", "vouchryx", j.Kid+"c", "hallenge-one"),
	} {
		if bytes.Equal(alt, in) {
			t.Fatalf("%s: the proof input did not change", name)
		}
		if keystore.Verify(policy.ES256, pub, alt, proof) == nil {
			t.Errorf("%s: the proof verified", name)
		}
	}
	if keystore.Verify(policy.ES256, otherPub, in, proof) == nil {
		t.Error("the proof verified under another key")
	}
	if !bytes.HasPrefix(in, []byte("keyryx/delegate/v1\x00")) {
		t.Errorf("the proof input carries no domain separator: %q", in[:20])
	}
}

// rawPrivate is the private scalar, fixed width, as a JWK's d would carry it.
func rawPrivate(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
