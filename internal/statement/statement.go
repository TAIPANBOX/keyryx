// Package statement is the key statement: what custody says when it
// certifies a key its consumer holds (CLAUDE.md invariant 24).
//
// # The format
//
// A statement is a JWS in the General JSON Serialization (RFC 7515 section
// 7.2.1) with exactly two signatures over one payload, the two halves of the
// delegation root, in this order:
//
//	{"payload":"<b64url claims>","signatures":[
//	  {"protected":"<b64url {"alg":"ES384","kid":...,"typ":"keyryx-statement+jwt"}>","signature":"<b64url R||S>"},
//	  {"protected":"<b64url {"alg":"ML-DSA-65","kid":...,"typ":"keyryx-statement+jwt"}>","signature":"<b64url FIPS 204>"}]}
//
// Each half's signing input is the JWS one, ASCII(protected "." payload), so
// the classical half is also a compact JWS (Compact) that any ES384 verifier
// checks, the estate's shared one included; the ML-DSA-65 half keeps the
// statement verifying after classical signatures are retired. The payload
// names both halves' key ids (roots), so a strict verifier knows which pair
// must have signed and a half from another statement cannot be swapped in.
//
// The claims: v (1), iss ("keyryx"), name (the delegated key's name), owner
// (the consumer it was certified for), kid (the key's RFC 7638 thumbprint),
// jwk (the public key, EC only, no private member), not_before, not_after,
// issued_at (Unix seconds), jti (random), roots. Every one is required and no
// other is accepted.
package statement

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

const (
	// RootName is the delegation root, two keys in the store's reserved
	// space: RootES384 and RootMLDSA.
	RootName  = "keyryx.delegation-root"
	RootES384 = RootName + ".es384"
	RootMLDSA = RootName + ".ml-dsa-65"
	// Typ is every half's protected typ.
	Typ = "keyryx-statement+jwt"
	// Issuer is the iss claim.
	Issuer = "keyryx"
	// MaxBytes bounds a statement.
	MaxBytes = 16 << 10
	// MaxJWK bounds a key offered for certification.
	MaxJWK = 1 << 10
)

// RootKeys are the delegation root's two halves, held by the store.
var RootKeys = []policy.Key{
	{Name: RootES384, Alg: policy.ES384, Mode: policy.Held},
	{Name: RootMLDSA, Alg: policy.MLDSA65, Mode: policy.Held},
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	jtiRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	b64    = base64.RawURLEncoding.Strict()
)

// JWK is a public EC key in the one form a statement carries it.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// Roots names the two halves that signed.
type Roots struct {
	ES384   string `json:"ES384"`
	MLDSA65 string `json:"ML-DSA-65"`
}

// Statement is what custody certifies.
type Statement struct {
	V         int    `json:"v"`
	Iss       string `json:"iss"`
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	Kid       string `json:"kid"`
	JWK       JWK    `json:"jwk"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	IssuedAt  int64  `json:"issued_at"`
	JTI       string `json:"jti"`
	Roots     Roots  `json:"roots"`
}

// ValidAt reports whether the statement certifies its key at t: from
// not_before, up to and not including not_after.
func (st Statement) ValidAt(t time.Time) bool {
	return t.Unix() >= st.NotBefore && t.Unix() < st.NotAfter
}

// Signer is what signs a statement: the key store.
type Signer interface {
	Active(name string) (keystore.Record, bool)
	SignInput(name string, build func(alg policy.Alg, kid string) ([]byte, error)) (keystore.Signature, error)
}

// RootKey finds a root key by kid: its algorithm and public key.
type RootKey func(kid string) (policy.Alg, []byte, bool)

// StoreRoots finds root keys in a store, in any state: a statement signed by
// a root since retired or revoked still verifies as signed by it; whether it
// is still published is the registry's decision.
func StoreRoots(s *keystore.Store) RootKey {
	return StoreKeys(s, RootES384, RootMLDSA)
}

// StoreKeys finds the keys of names in a store, in any state, by kid.
func StoreKeys(s *keystore.Store, names ...string) RootKey {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	return func(kid string) (policy.Alg, []byte, bool) {
		for _, r := range s.Inventory() {
			if want[r.Name] && r.Kid == kid {
				return r.Alg, r.Public, true
			}
		}
		return "", nil, false
	}
}

// MaxKeySet bounds a key set read back.
const MaxKeySet = 1 << 20

// KeysFromJWKS reads a key set this service published (keystore.JWK's form:
// EC keys, and ML-DSA-65 keys in the AKP form) back into keys by kid. Every
// kid is recomputed from its key, a private member or an algorithm the key is
// not refuses the set, and nothing else is accepted.
func KeysFromJWKS(raw []byte) (RootKey, error) {
	if len(raw) > MaxKeySet {
		return nil, errors.New("statement: the key set is over its size cap")
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := strict(raw, &set); err != nil {
		return nil, fmt.Errorf("statement: not a key set: %w", err)
	}
	type key struct {
		alg policy.Alg
		pub []byte
	}
	keys := map[string]key{}
	for i, k := range set.Keys {
		var head struct {
			Kty string `json:"kty"`
		}
		_ = json.Unmarshal(k, &head)
		var kid string
		var alg policy.Alg
		var pub []byte
		switch head.Kty {
		case "EC":
			var in struct {
				Alg string `json:"alg"`
			}
			_ = json.Unmarshal(k, &in)
			j, point, err := ParseJWK(k, policy.Alg(in.Alg))
			if err != nil {
				return nil, fmt.Errorf("statement: key %d: %w", i, err)
			}
			var given struct {
				Kid *string `json:"kid"`
			}
			_ = json.Unmarshal(k, &given)
			if given.Kid == nil {
				return nil, fmt.Errorf("statement: key %d names no kid", i)
			}
			kid, alg, pub = j.Kid, policy.Alg(j.Alg), point
		case "AKP":
			var in struct {
				Kty string `json:"kty"`
				Alg string `json:"alg"`
				Pub string `json:"pub"`
				Kid string `json:"kid"`
				Use string `json:"use"`
			}
			if err := strict(k, &in); err != nil || in.Alg != string(policy.MLDSA65) || in.Use != "sig" {
				return nil, fmt.Errorf("statement: key %d is not an ML-DSA-65 key in the AKP form", i)
			}
			p, err := b64.DecodeString(in.Pub)
			if err != nil {
				return nil, fmt.Errorf("statement: key %d: pub is not base64url", i)
			}
			if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), p); err != nil {
				return nil, fmt.Errorf("statement: key %d is not an ML-DSA-65 public key", i)
			}
			sum := sha256.Sum256(p)
			if in.Kid != "mldsa65:"+base64.RawURLEncoding.EncodeToString(sum[:]) {
				return nil, fmt.Errorf("statement: key %d names a kid that is not its own", i)
			}
			kid, alg, pub = in.Kid, policy.MLDSA65, p
		default:
			return nil, fmt.Errorf("statement: key %d has a key type this service never publishes", i)
		}
		if _, dup := keys[kid]; dup {
			return nil, fmt.Errorf("statement: two keys share kid %s", kid)
		}
		keys[kid] = key{alg, pub}
	}
	return func(kid string) (policy.Alg, []byte, bool) {
		k, ok := keys[kid]
		return k.alg, k.pub, ok
	}, nil
}

func strict(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the object")
	}
	return nil
}

func curveFor(alg policy.Alg) (elliptic.Curve, string, int, error) {
	switch alg {
	case policy.ES256:
		return elliptic.P256(), "P-256", 32, nil
	case policy.ES384:
		return elliptic.P384(), "P-384", 48, nil
	}
	return nil, "", 0, fmt.Errorf("a delegated key is ES256 or ES384, not %q", alg)
}

// ParseJWK reads a public key offered for certification as alg. It returns
// the key in the one form a statement carries (kid the RFC 7638 thumbprint,
// alg, use "sig") and the uncompressed point. A private member, an unknown
// member, a key off its curve or of the wrong curve for alg is refused; the
// private member is never kept, even to say what it was.
func ParseJWK(raw []byte, alg policy.Alg) (JWK, []byte, error) {
	if len(raw) > MaxJWK {
		return JWK{}, nil, errors.New("the key is over its size cap")
	}
	var in struct {
		Kty *string         `json:"kty"`
		Crv *string         `json:"crv"`
		X   *string         `json:"x"`
		Y   *string         `json:"y"`
		Kid *string         `json:"kid"`
		Alg *string         `json:"alg"`
		Use *string         `json:"use"`
		D   json.RawMessage `json:"d"`
	}
	if err := strict(raw, &in); err != nil {
		return JWK{}, nil, fmt.Errorf("the key is not a JWK of the known shape: %w", err)
	}
	if in.D != nil {
		return JWK{}, nil, errors.New("the key carries a private member; custody certifies a key without ever holding it")
	}
	curve, crv, size, err := curveFor(alg)
	if err != nil {
		return JWK{}, nil, err
	}
	if in.Kty == nil || *in.Kty != "EC" || in.Crv == nil || *in.Crv != crv || in.X == nil || in.Y == nil {
		return JWK{}, nil, fmt.Errorf("the key is not an EC %s key", crv)
	}
	x, errX := b64.DecodeString(*in.X)
	y, errY := b64.DecodeString(*in.Y)
	if errX != nil || errY != nil || len(x) != size || len(y) != size {
		return JWK{}, nil, fmt.Errorf("the key's coordinates are not %d bytes of unpadded base64url", size)
	}
	point := append(append([]byte{4}, x...), y...)
	pk, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return JWK{}, nil, fmt.Errorf("the key is not a point on %s: %w", crv, err)
	}
	kid, err := delegation.Thumbprint(delegation.FromPublic(pk, ""))
	if err != nil {
		return JWK{}, nil, err
	}
	if in.Kid != nil && *in.Kid != kid {
		return JWK{}, nil, errors.New("the key names a kid that is not its RFC 7638 thumbprint")
	}
	if in.Alg != nil && *in.Alg != string(alg) {
		return JWK{}, nil, fmt.Errorf("the key names alg %q, and it is offered as %s", *in.Alg, alg)
	}
	if in.Use != nil && *in.Use != "sig" {
		return JWK{}, nil, errors.New(`the key names a use other than "sig"`)
	}
	return JWK{Kty: "EC", Crv: crv, X: *in.X, Y: *in.Y, Kid: kid, Alg: string(alg), Use: "sig"}, point, nil
}

// ProofInput is what the key being certified signs to prove it is held: a
// domain separator, then the key's name, the consumer, the key's own kid and
// the challenge custody issued, each ended by a NUL so no field can borrow
// from its neighbour.
func ProofInput(name, consumer, kid, challenge string) []byte {
	return []byte("keyryx/delegate/v1\x00" + name + "\x00" + consumer + "\x00" + kid + "\x00" + challenge)
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type sigWire struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

type jwsWire struct {
	Payload    string    `json:"payload"`
	Signatures []sigWire `json:"signatures"`
}

var errRotated = errors.New("statement: the root rotated while signing")

// halves are the two signatures, in their order.
var halves = []struct {
	name string
	alg  policy.Alg
}{{RootES384, policy.ES384}, {RootMLDSA, policy.MLDSA65}}

// Sign fills in the statement's roots and signs it with both halves of the
// delegation root.
func Sign(st Statement, s Signer) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		es, ok1 := s.Active(RootES384)
		ml, ok2 := s.Active(RootMLDSA)
		if !ok1 || !ok2 {
			return nil, errors.New("statement: the delegation root has no active key")
		}
		st.Roots = Roots{ES384: es.Kid, MLDSA65: ml.Kid}
		payload, err := json.Marshal(st)
		if err != nil {
			return nil, err
		}
		out, err := signWith(payload, s, []string{es.Kid, ml.Kid})
		if errors.Is(err, errRotated) {
			continue
		}
		return out, err
	}
	return nil, errRotated
}

// signRaw signs a payload as it is, with the root's active halves. Tests use
// it to sign payloads Sign would never build.
func signRaw(payload []byte, s Signer) ([]byte, error) {
	es, _ := s.Active(RootES384)
	ml, _ := s.Active(RootMLDSA)
	return signWith(payload, s, []string{es.Kid, ml.Kid})
}

func signWith(payload []byte, s Signer, kids []string) ([]byte, error) {
	p := base64.RawURLEncoding.EncodeToString(payload)
	out := jwsWire{Payload: p}
	for i, half := range halves {
		var protected string
		sig, err := s.SignInput(half.name, func(alg policy.Alg, kid string) ([]byte, error) {
			if alg != half.alg || kid != kids[i] {
				return nil, errRotated
			}
			h, err := json.Marshal(header{Alg: string(alg), Kid: kid, Typ: Typ})
			if err != nil {
				return nil, err
			}
			protected = base64.RawURLEncoding.EncodeToString(h)
			return []byte(protected + "." + p), nil
		})
		if err != nil {
			return nil, err
		}
		out.Signatures = append(out.Signatures, sigWire{Protected: protected, Signature: base64.RawURLEncoding.EncodeToString(sig.Sig)})
	}
	return json.Marshal(out)
}

type parsed struct {
	wire    jwsWire
	headers []header
	payload []byte
}

func parse(raw []byte) (parsed, error) {
	var p parsed
	if len(raw) > MaxBytes {
		return p, errors.New("statement: over its size cap")
	}
	if err := strict(raw, &p.wire); err != nil {
		return p, fmt.Errorf("statement: not a JWS of the known shape: %w", err)
	}
	if len(p.wire.Signatures) != len(halves) {
		return p, fmt.Errorf("statement: %d signatures; a statement carries exactly the two halves of its root", len(p.wire.Signatures))
	}
	for i, sw := range p.wire.Signatures {
		hb, err := b64.DecodeString(sw.Protected)
		if err != nil {
			return p, errors.New("statement: a protected header is not base64url")
		}
		var h header
		if err := strict(hb, &h); err != nil || h.Kid == "" || h.Typ != Typ || h.Alg != string(halves[i].alg) {
			return p, fmt.Errorf("statement: signature %d is not the %s half", i+1, halves[i].alg)
		}
		p.headers = append(p.headers, h)
	}
	payload, err := b64.DecodeString(p.wire.Payload)
	if err != nil {
		return p, errors.New("statement: the payload is not base64url")
	}
	p.payload = payload
	return p, nil
}

// Compact returns the half signed with alg as a compact JWS. Only the ES384
// half has a compact form an existing verifier reads; the ML-DSA-65 one is
// returned for completeness.
func Compact(raw []byte, alg policy.Alg) (string, error) {
	p, err := parse(raw)
	if err != nil {
		return "", err
	}
	for i, h := range p.headers {
		if h.Alg == string(alg) {
			return p.wire.Signatures[i].Protected + "." + p.wire.Payload + "." + p.wire.Signatures[i].Signature, nil
		}
	}
	return "", fmt.Errorf("statement: no %s half", alg)
}

// Verify parses a statement, checks every claim, and verifies both halves
// under roots. Validity in time is a separate question: ValidAt.
func Verify(raw []byte, roots RootKey) (Statement, error) {
	p, err := parse(raw)
	if err != nil {
		return Statement{}, err
	}
	st, err := claims(p.payload)
	if err != nil {
		return Statement{}, err
	}
	if p.headers[0].Kid != st.Roots.ES384 || p.headers[1].Kid != st.Roots.MLDSA65 {
		return Statement{}, errors.New("statement: a half was signed by a key the payload does not name")
	}
	for i, h := range p.headers {
		alg, pub, ok := roots(h.Kid)
		if !ok || alg != halves[i].alg {
			return Statement{}, fmt.Errorf("statement: the %s half names a root key this verifier does not hold", halves[i].alg)
		}
		sig, err := b64.DecodeString(p.wire.Signatures[i].Signature)
		if err != nil {
			return Statement{}, errors.New("statement: a signature is not base64url")
		}
		if err := keystore.Verify(alg, pub, []byte(p.wire.Signatures[i].Protected+"."+p.wire.Payload), sig); err != nil {
			return Statement{}, fmt.Errorf("statement: the %s half does not verify", halves[i].alg)
		}
	}
	return st, nil
}

func claims(payload []byte) (Statement, error) {
	var w struct {
		V         *int            `json:"v"`
		Iss       *string         `json:"iss"`
		Name      *string         `json:"name"`
		Owner     *string         `json:"owner"`
		Kid       *string         `json:"kid"`
		JWK       json.RawMessage `json:"jwk"`
		NotBefore *int64          `json:"not_before"`
		NotAfter  *int64          `json:"not_after"`
		IssuedAt  *int64          `json:"issued_at"`
		JTI       *string         `json:"jti"`
		Roots     *Roots          `json:"roots"`
	}
	if err := strict(payload, &w); err != nil {
		return Statement{}, fmt.Errorf("statement: the claims are not of the known shape: %w", err)
	}
	if w.V == nil || w.Iss == nil || w.Name == nil || w.Owner == nil || w.Kid == nil || w.JWK == nil ||
		w.NotBefore == nil || w.NotAfter == nil || w.IssuedAt == nil || w.JTI == nil || w.Roots == nil {
		return Statement{}, errors.New("statement: a required claim is missing")
	}
	switch {
	case *w.V != 1:
		return Statement{}, fmt.Errorf("statement: version %d; this verifier reads version 1", *w.V)
	case *w.Iss != Issuer:
		return Statement{}, errors.New("statement: another issuer")
	case !nameRe.MatchString(*w.Name) || policy.Reserved(*w.Name), !nameRe.MatchString(*w.Owner):
		return Statement{}, errors.New("statement: a name or owner outside the grammar")
	case *w.NotBefore <= 0 || *w.IssuedAt <= 0 || *w.NotAfter <= *w.NotBefore || *w.IssuedAt > *w.NotBefore:
		return Statement{}, errors.New("statement: its times are not issued_at <= not_before < not_after")
	case !jtiRe.MatchString(*w.JTI):
		return Statement{}, errors.New("statement: a jti outside the grammar")
	case w.Roots.ES384 == "" || w.Roots.MLDSA65 == "":
		return Statement{}, errors.New("statement: the roots are not named")
	}
	var alg struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal(w.JWK, &alg)
	jwk, _, err := ParseJWK(w.JWK, policy.Alg(alg.Alg))
	if err != nil {
		return Statement{}, fmt.Errorf("statement: its key: %w", err)
	}
	var given JWK
	if err := json.Unmarshal(w.JWK, &given); err != nil || given != jwk {
		return Statement{}, errors.New("statement: its key is not in the one form a statement carries")
	}
	if *w.Kid != jwk.Kid {
		return Statement{}, errors.New("statement: its kid is not its key's thumbprint")
	}
	return Statement{V: *w.V, Iss: *w.Iss, Name: *w.Name, Owner: *w.Owner, Kid: *w.Kid, JWK: jwk,
		NotBefore: *w.NotBefore, NotAfter: *w.NotAfter, IssuedAt: *w.IssuedAt, JTI: *w.JTI, Roots: *w.Roots}, nil
}
