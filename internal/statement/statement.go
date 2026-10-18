// Package statement is the key statement format. Scaffold.
package statement

import (
	"errors"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

const (
	RootName  = "keyryx.delegation-root"
	RootES384 = RootName + ".es384"
	RootMLDSA = RootName + ".ml-dsa-65"
	Typ       = "keyryx-statement+jwt"
	Issuer    = "keyryx"
	MaxBytes  = 16 << 10
)

// RootKeys are the delegation root's two halves.
var RootKeys = []policy.Key{{Name: RootES384, Alg: policy.ES384, Mode: policy.Held}, {Name: RootMLDSA, Alg: policy.MLDSA65, Mode: policy.Held}}

// JWK is a public EC key.
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

// Signer is what signs a statement: the key store.
type Signer interface {
	Active(name string) (keystore.Record, bool)
	SignInput(name string, build func(alg policy.Alg, kid string) ([]byte, error)) (keystore.Signature, error)
}

// RootKey finds a root key by kid.
type RootKey func(kid string) (policy.Alg, []byte, bool)

var errScaffold = errors.New("statement: not implemented")

// ParseJWK reads a public key offered for certification. Scaffold.
func ParseJWK(raw []byte, alg policy.Alg) (JWK, []byte, error) { return JWK{}, nil, errScaffold }

// Sign signs a statement with both halves of the root. Scaffold.
func Sign(st Statement, s Signer) ([]byte, error) { return nil, errScaffold }

func signRaw(payload []byte, s Signer) ([]byte, error) { return nil, errScaffold }

// Verify parses and verifies a statement. Scaffold.
func Verify(raw []byte, roots RootKey) (Statement, error) { return Statement{}, errScaffold }

// Compact returns one half as a compact JWS. Scaffold.
func Compact(raw []byte, alg policy.Alg) (string, error) { return "", errScaffold }

// ValidAt reports whether the statement certifies its key at t. Scaffold.
func (st Statement) ValidAt(t time.Time) bool { return false }

// ProofInput is what a proof of possession signs. Scaffold.
func ProofInput(name, consumer, kid, challenge string) []byte { return nil }

// StoreRoots finds root keys in a store. Scaffold.
func StoreRoots(s *keystore.Store) RootKey {
	return func(string) (policy.Alg, []byte, bool) { return "", nil, false }
}
