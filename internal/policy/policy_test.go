package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
)

// The policy says which consumer may use which key. A policy read wrongly is a
// consumer signing with a key it was never given, and nothing downstream can
// tell that apart from a key it was.

func digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

const wardryxSecret = "wardryx-consumer-key-0123456789"

func goodPolicy() string {
	return `{
  "version": 1,
  "keys": [
    {"name": "wardryx-approval", "alg": "ES256"},
    {"name": "trailryx-root", "alg": "ES384"},
    {"name": "cloud-audit", "alg": "ES256"},
    {"name": "witness-test", "alg": "ML-DSA-65"}
  ],
  "consumers": [
    {"name": "wardryx", "auth": {"socket": "wardryx"}, "grants": {"wardryx-approval": ["sign"]}},
    {"name": "record-seal", "auth": {"key_digest": "` + digest(wardryxSecret+"-seal") + `"}, "grants": {"trailryx-root": ["sign"]}},
    {"name": "tokenfuse-cloud", "auth": {"k8s": {"issuer": "https://k3s.acme.example", "subject": "system:serviceaccount:agent-stack:tokenfuse-cloud"}}, "grants": {"cloud-audit": ["sign"]}}
  ]
}`
}

func TestAWellFormedPolicyParses(t *testing.T) {
	p, err := Parse([]byte(goodPolicy()))
	if err != nil {
		t.Fatalf("a well-formed policy was refused: %v", err)
	}
	if len(p.Keys) != 4 || len(p.Consumers) != 3 {
		t.Fatalf("keys %d, consumers %d", len(p.Keys), len(p.Consumers))
	}
	if k, ok := p.Key("trailryx-root"); !ok || k.Alg != ES384 {
		t.Fatalf("Key(trailryx-root) = %+v %v", k, ok)
	}
	if k, ok := p.Key("witness-test"); !ok || k.Alg != MLDSA65 {
		t.Fatalf("Key(witness-test) = %+v %v", k, ok)
	}
	if s := p.SocketConsumers(); len(s) != 1 || s[0].Name != "wardryx" || s[0].Socket != "wardryx" {
		t.Fatalf("SocketConsumers = %+v", s)
	}
	if c, ok := p.ByKeySecret(wardryxSecret + "-seal"); !ok || c.Name != "record-seal" {
		t.Fatalf("ByKeySecret = %+v %v", c, ok)
	}
	if c, ok := p.ByK8s("https://k3s.acme.example", "system:serviceaccount:agent-stack:tokenfuse-cloud"); !ok || c.Name != "tokenfuse-cloud" {
		t.Fatalf("ByK8s = %+v %v", c, ok)
	}
	if got := p.K8sIssuers(); len(got) != 1 || got[0] != "https://k3s.acme.example" {
		t.Fatalf("K8sIssuers = %v", got)
	}
}

func TestAConsumerMayUseOnlyTheKeysItWasGranted(t *testing.T) {
	p, err := Parse([]byte(goodPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed("wardryx", "wardryx-approval", OpSign) {
		t.Fatal("control: the granted key was refused")
	}
	for _, c := range [][3]string{
		{"wardryx", "trailryx-root", OpSign},
		{"wardryx", "cloud-audit", OpSign},
		{"wardryx", "wardryx-approval", "delegate"},
		{"wardryx", "wardryx-approval", ""},
		{"record-seal", "wardryx-approval", OpSign},
		{"nobody", "wardryx-approval", OpSign},
		{"", "wardryx-approval", OpSign},
		{"wardryx", "no-such-key", OpSign},
	} {
		if p.Allowed(c[0], c[1], c[2]) {
			t.Errorf("Allowed(%q, %q, %q) = true", c[0], c[1], c[2])
		}
	}
}

func TestAKeySecretIsComparedByDigestAndMatchesOnlyItsConsumer(t *testing.T) {
	p, err := Parse([]byte(goodPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.ByKeySecret(wardryxSecret + "-seal"); !ok {
		t.Fatal("control: the right secret matched nobody")
	}
	for _, s := range []string{"", wardryxSecret, wardryxSecret + "-seal ", digest(wardryxSecret + "-seal"), "wardryx"} {
		if c, ok := p.ByKeySecret(s); ok {
			t.Errorf("%q matched %s", s, c.Name)
		}
	}
}

func TestAMalformedPolicyIsRefused(t *testing.T) {
	if _, err := Parse([]byte(goodPolicy())); err != nil {
		t.Fatalf("control: %v", err)
	}
	g := goodPolicy()
	cases := map[string]string{
		"not JSON":                     "{",
		"an array":                     "[]",
		"no version":                   strings.Replace(g, `"version": 1,`, ``, 1),
		"version 2":                    strings.Replace(g, `"version": 1`, `"version": 2`, 1),
		"an unknown field":             strings.Replace(g, `"version": 1,`, `"version": 1, "extra": true,`, 1),
		"an unknown field in a key":    strings.Replace(g, `{"name": "cloud-audit", "alg": "ES256"}`, `{"name": "cloud-audit", "alg": "ES256", "curve": "P-256"}`, 1),
		"trailing data":                g + `{}`,
		"no keys":                      `{"version": 1, "keys": [], "consumers": []}`,
		"a duplicate key":              strings.Replace(g, `{"name": "cloud-audit", "alg": "ES256"}`, `{"name": "trailryx-root", "alg": "ES256"}`, 1),
		"an unknown algorithm":         strings.Replace(g, `"alg": "ES384"`, `"alg": "RS256"`, 1),
		"a key name with a slash":      strings.Replace(g, `"name": "cloud-audit"`, `"name": "cloud/audit"`, 1),
		"a key name climbing up":       strings.Replace(g, `"name": "cloud-audit"`, `"name": ".."`, 1),
		"a key name in capitals":       strings.Replace(g, `"name": "cloud-audit"`, `"name": "Cloud-Audit"`, 1),
		"an empty key name":            strings.Replace(g, `"name": "cloud-audit"`, `"name": ""`, 1),
		"a duplicate consumer":         strings.Replace(g, `"name": "record-seal"`, `"name": "wardryx"`, 1),
		"a consumer with no auth":      strings.Replace(g, `"auth": {"socket": "wardryx"}, `, ``, 1),
		"a consumer with two auths":    strings.Replace(g, `{"socket": "wardryx"}`, `{"socket": "wardryx", "key_digest": "`+digest("x")+`"}`, 1),
		"an empty auth":                strings.Replace(g, `{"socket": "wardryx"}`, `{}`, 1),
		"a socket name with a slash":   strings.Replace(g, `{"socket": "wardryx"}`, `{"socket": "a/b"}`, 1),
		"a socket name climbing up":    strings.Replace(g, `{"socket": "wardryx"}`, `{"socket": ".."}`, 1),
		"a short digest":               strings.Replace(g, digest(wardryxSecret+"-seal"), "sha256:abcd", 1),
		"a digest that is not hex":     strings.Replace(g, digest(wardryxSecret+"-seal"), "sha256:"+strings.Repeat("z", 64), 1),
		"a digest of another scheme":   strings.Replace(g, digest(wardryxSecret+"-seal"), "md5:"+strings.Repeat("a", 64), 1),
		"a k8s issuer that is no URL":  strings.Replace(g, `"issuer": "https://k3s.acme.example"`, `"issuer": "k3s"`, 1),
		"a k8s subject empty":          strings.Replace(g, `"subject": "system:serviceaccount:agent-stack:tokenfuse-cloud"`, `"subject": ""`, 1),
		"a grant of an undeclared key": strings.Replace(g, `"grants": {"wardryx-approval": ["sign"]}`, `"grants": {"nope": ["sign"]}`, 1),
		"an unknown operation":         strings.Replace(g, `"grants": {"wardryx-approval": ["sign"]}`, `"grants": {"wardryx-approval": ["delegate"]}`, 1),
		"an empty operation list":      strings.Replace(g, `"grants": {"wardryx-approval": ["sign"]}`, `"grants": {"wardryx-approval": []}`, 1),
		"a repeated operation":         strings.Replace(g, `"grants": {"wardryx-approval": ["sign"]}`, `"grants": {"wardryx-approval": ["sign", "sign"]}`, 1),
		"a consumer with no grants":    strings.Replace(g, `, "grants": {"wardryx-approval": ["sign"]}`, ``, 1),
		"two consumers on one socket":  strings.Replace(g, `"auth": {"key_digest": "`+digest(wardryxSecret+"-seal")+`"}`, `"auth": {"socket": "wardryx"}`, 1),
		"two consumers on one digest":  strings.Replace(g, `{"k8s": {"issuer": "https://k3s.acme.example", "subject": "system:serviceaccount:agent-stack:tokenfuse-cloud"}}`, `{"key_digest": "`+digest(wardryxSecret+"-seal")+`"}`, 1),
		"over one MiB":                 strings.Replace(g, `"version": 1,`, `"version": 1, "pad": "`+strings.Repeat("a", MaxBytes)+`",`, 1),
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Random damage to a good policy either parses into a policy whose every grant
// names a declared key, or is refused; nothing panics.
func TestHostilePolicyFilesNeverPanicAndNeverGrantAnUndeclaredKey(t *testing.T) {
	base := []byte(goodPolicy())
	if _, err := Parse(base); err != nil {
		t.Fatalf("control: the undamaged policy was refused: %v", err)
	}
	r := rand.New(rand.NewPCG(20261018, 2))
	alphabet := []byte(`{}[]",:0123456789abcdefghijklmnopqrstuvwxyz -_./\` + "\x00\xff\n")
	for i := 0; i < 3000; i++ {
		b := append([]byte(nil), base...)
		for k := 0; k <= r.IntN(6); k++ {
			switch op := r.IntN(3); {
			case op == 0 && len(b) > 0:
				b[r.IntN(len(b))] = alphabet[r.IntN(len(alphabet))]
			case op == 1 && len(b) > 0:
				j := r.IntN(len(b))
				b = append(b[:j], b[j+1:]...)
			default:
				j := r.IntN(len(b) + 1)
				b = append(b[:j], append([]byte{alphabet[r.IntN(len(alphabet))]}, b[j:]...)...)
			}
		}
		p, err := Parse(b)
		if err != nil {
			continue
		}
		declared := map[string]bool{}
		for _, k := range p.Keys {
			declared[k.Name] = true
		}
		for _, c := range p.Consumers {
			for _, k := range []string{"wardryx-approval", "trailryx-root", "cloud-audit", "witness-test", "nope"} {
				if p.Allowed(c.Name, k, OpSign) && !declared[k] {
					t.Fatalf("case %d: %s may sign with %s, which no key declares:\n%s", i, c.Name, k, b)
				}
			}
		}
	}
}
