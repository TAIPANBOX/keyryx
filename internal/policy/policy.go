// Package policy reads KEYRYX_POLICY: which keys exist and which consumer may
// use which. Scaffold: the types and signatures the tests name.
package policy

import "errors"

// Alg names a signature algorithm a key is created for.
type Alg string

const (
	ES256    Alg = "ES256"
	ES384    Alg = "ES384"
	MLDSA65  Alg = "ML-DSA-65"
	OpSign       = "sign"
	MaxBytes     = 1 << 20
)

// Key is one declared key.
type Key struct {
	Name string
	Alg  Alg
}

// Consumer is one declared consumer and how it authenticates.
type Consumer struct {
	Name         string
	Socket       string
	KeyDigest    [32]byte
	HasKeyDigest bool
	K8sIssuer    string
	K8sSubject   string
}

// Policy is the parsed file.
type Policy struct {
	Keys      []Key
	Consumers []Consumer
}

// Parse reads a policy file. Scaffold: refuses.
func Parse(data []byte) (*Policy, error) { return nil, errors.New("policy: not implemented") }

func (p *Policy) Key(name string) (Key, bool)                   { return Key{}, false }
func (p *Policy) Allowed(consumer, key, op string) bool         { return false }
func (p *Policy) SocketConsumers() []Consumer                   { return nil }
func (p *Policy) ByKeySecret(secret string) (Consumer, bool)    { return Consumer{}, false }
func (p *Policy) ByK8s(issuer, subject string) (Consumer, bool) { return Consumer{}, false }
func (p *Policy) K8sIssuers() []string                          { return nil }
