package policy

import (
	"strings"
	"testing"
	"time"
)

// Delegated keys: custody never holds them, so a policy that let a consumer
// "sign" with one, or "delegate" a held one, would be a policy nobody could
// carry out, and one that let a consumer reach the service's own root would
// let it sign key statements.

func delegationPolicy() string {
	return `{
  "version": 1,
  "keys": [
    {"name": "wardryx-approval", "alg": "ES256"},
    {"name": "vouchryx-token", "alg": "ES256", "mode": "delegated", "max_lifetime": "72h", "overlap": "10m"},
    {"name": "wardryx-stream", "alg": "ES256", "mode": "delegated", "max_lifetime": "24h"},
    {"name": "record-stream", "alg": "ES384", "mode": "delegated", "max_lifetime": "24h"}
  ],
  "consumers": [
    {"name": "wardryx", "auth": {"socket": "wardryx"}, "grants": {"wardryx-approval": ["sign"], "wardryx-stream": ["delegate"]}},
    {"name": "vouchryx", "auth": {"key_digest": "` + digest("vouchryx-consumer-key-0123456789") + `"}, "grants": {"vouchryx-token": ["delegate"]}}
  ]
}`
}

func TestDelegatedKeysParse(t *testing.T) {
	p, err := Parse([]byte(delegationPolicy()))
	if err != nil {
		t.Fatalf("a well-formed delegation policy was refused: %v", err)
	}
	k, ok := p.Key("vouchryx-token")
	if !ok || k.Mode != Delegated || k.Alg != ES256 || k.MaxLifetime != 72*time.Hour || k.Overlap != 10*time.Minute {
		t.Fatalf("vouchryx-token: %+v", k)
	}
	if k, _ := p.Key("wardryx-stream"); k.Overlap != DefaultOverlap || k.MaxLifetime != 24*time.Hour {
		t.Fatalf("an unstated overlap is the default: %+v", k)
	}
	if k, _ := p.Key("wardryx-approval"); k.Mode != Held || k.MaxLifetime != 0 {
		t.Fatalf("a key with no mode is held: %+v", k)
	}
	for _, c := range []struct {
		consumer, key, op string
		want              bool
	}{
		{"vouchryx", "vouchryx-token", OpDelegate, true},
		{"vouchryx", "vouchryx-token", OpSign, false},
		{"wardryx", "wardryx-stream", OpDelegate, true},
		{"wardryx", "wardryx-approval", OpDelegate, false},
		{"wardryx", "vouchryx-token", OpDelegate, false},
	} {
		if got := p.Allowed(c.consumer, c.key, c.op); got != c.want {
			t.Errorf("Allowed(%s, %s, %s) = %v", c.consumer, c.key, c.op, got)
		}
	}
	held := p.HeldKeys()
	if len(held) != 1 || held[0].Name != "wardryx-approval" {
		t.Fatalf("only held keys go to the store, got %+v", held)
	}
	if !Reserved("keyryx.delegation-root") || !Reserved("keyryx.x") || Reserved("keyryx-approval") || Reserved("vouchryx-token") {
		t.Fatal("the reserved space is the names starting keyryx. and only those")
	}
}

func TestAMalformedDelegationPolicyIsRefused(t *testing.T) {
	g := delegationPolicy()
	if _, err := Parse([]byte(g)); err != nil {
		t.Fatalf("control: %v", err)
	}
	vt := `{"name": "vouchryx-token", "alg": "ES256", "mode": "delegated", "max_lifetime": "72h", "overlap": "10m"}`
	for name, bad := range map[string]string{
		"a sign grant on a delegated key": strings.Replace(g, `"vouchryx-token": ["delegate"]`, `"vouchryx-token": ["sign"]`, 1),
		"both grants on a delegated key":  strings.Replace(g, `"vouchryx-token": ["delegate"]`, `"vouchryx-token": ["delegate", "sign"]`, 1),
		"a delegate grant on a held key":  strings.Replace(g, `"wardryx-approval": ["sign"]`, `"wardryx-approval": ["delegate"]`, 1),
		"a delegated ML-DSA key":          strings.Replace(g, vt, `{"name": "vouchryx-token", "alg": "ML-DSA-65", "mode": "delegated", "max_lifetime": "72h"}`, 1),
		"an unknown mode":                 strings.Replace(g, vt, `{"name": "vouchryx-token", "alg": "ES256", "mode": "borrowed", "max_lifetime": "72h"}`, 1),
		"a delegated key with no life":    strings.Replace(g, vt, `{"name": "vouchryx-token", "alg": "ES256", "mode": "delegated"}`, 1),
		"a life that is not a duration":   strings.Replace(g, `"max_lifetime": "72h"`, `"max_lifetime": "three days"`, 1),
		"a life under ten minutes":        strings.Replace(g, `"max_lifetime": "72h"`, `"max_lifetime": "5m"`, 1),
		"a life over a week":              strings.Replace(g, `"max_lifetime": "72h"`, `"max_lifetime": "200h"`, 1),
		"an overlap under a minute":       strings.Replace(g, `"overlap": "10m"`, `"overlap": "10s"`, 1),
		"an overlap over a day":           strings.Replace(g, `"overlap": "10m"`, `"overlap": "25h"`, 1),
		"a held key with a life": strings.Replace(g, `{"name": "wardryx-approval", "alg": "ES256"}`,
			`{"name": "wardryx-approval", "alg": "ES256", "max_lifetime": "1h"}`, 1),
		"a held key with an overlap": strings.Replace(g, `{"name": "wardryx-approval", "alg": "ES256"}`,
			`{"name": "wardryx-approval", "alg": "ES256", "overlap": "1h"}`, 1),
		"a held key named held explicitly, with a life": strings.Replace(g, `{"name": "wardryx-approval", "alg": "ES256"}`,
			`{"name": "wardryx-approval", "alg": "ES256", "mode": "held", "max_lifetime": "1h"}`, 1),
		"a key in the reserved space": strings.Replace(g, `{"name": "wardryx-approval", "alg": "ES256"}`,
			`{"name": "wardryx-approval", "alg": "ES256"}, {"name": "keyryx.delegation-root.es384", "alg": "ES384"}`, 1),
		"a grant of the root": strings.Replace(g, `"wardryx-approval": ["sign"],`, `"wardryx-approval": ["sign"], "keyryx.delegation-root.es384": ["sign"],`, 1),
	} {
		if bad == g {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if p, err := Parse([]byte(strings.Replace(g, `{"name": "wardryx-approval", "alg": "ES256"}`, `{"name": "wardryx-approval", "alg": "ES256", "mode": "held"}`, 1))); err != nil {
		t.Errorf("control: a key named held explicitly: %v", err)
	} else if k, _ := p.Key("wardryx-approval"); k.Mode != Held {
		t.Errorf("control: %+v", k)
	}
}
