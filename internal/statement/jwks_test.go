package statement

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// A verifier offline holds only the key set it was given. Reading it back
// wrongly is a verifier that checks a signature against a key nobody
// published, or under an algorithm the key is not.

func TestAKeySetReadsBackAsKeysByKid(t *testing.T) {
	s := rootStore(t, 1)
	var keys []map[string]any
	var recs []keystore.Record
	for _, name := range []string{RootES384, RootMLDSA} {
		rs, _ := s.Published(name)
		for _, r := range rs {
			keys = append(keys, keystore.JWK(r))
			recs = append(recs, r)
		}
	}
	raw, _ := json.Marshal(map[string]any{"keys": keys})
	look, err := KeysFromJWKS(raw)
	if err != nil {
		t.Fatalf("a key set custody published: %v", err)
	}
	for _, r := range recs {
		alg, pub, ok := look(r.Kid)
		if !ok || alg != r.Alg || !bytes.Equal(pub, r.Public) {
			t.Fatalf("%s: %v %s, want %s", r.Kid, ok, alg, r.Alg)
		}
		salg, spub, sok := StoreKeys(s, RootES384, RootMLDSA)(r.Kid)
		if !sok || salg != r.Alg || !bytes.Equal(spub, r.Public) {
			t.Fatalf("StoreKeys %s: %v %s", r.Kid, sok, salg)
		}
	}
	if _, _, ok := look("no-such-kid"); ok {
		t.Fatal("an unknown kid was found")
	}
	if _, _, ok := StoreKeys(s, RootES384)(recs[1].Kid); ok {
		t.Fatal("StoreKeys found a key of a name it was not asked for")
	}
	es, ml := keys[0], keys[1]
	edit := func(k map[string]any, member string, v any) []byte {
		c := map[string]any{}
		for kk, vv := range k {
			c[kk] = vv
		}
		if v == nil {
			delete(c, member)
		} else {
			c[member] = v
		}
		b, _ := json.Marshal(map[string]any{"keys": []any{c}})
		return b
	}
	for name, bad := range map[string][]byte{
		"an EC key with a private member":    edit(es, "d", "AAAA"),
		"an EC key whose kid is not its own": edit(es, "kid", "chosen"),
		"an EC key with another alg":         edit(es, "alg", "ES256"),
		"an ML-DSA key cut short":            edit(ml, "pub", ml["pub"].(string)[:100]),
		"an ML-DSA key whose kid is another": edit(ml, "kid", es["kid"]),
		"an unknown key type":                edit(es, "kty", "oct"),
		"no kid":                             edit(es, "kid", nil),
		"not a key set":                      []byte(`{"keys":`),
		"an unknown member":                  []byte(strings.Replace(string(edit(es, "kid", es["kid"])), `{"keys"`, `{"jku":"x","keys"`, 1)),
	} {
		if _, err := KeysFromJWKS(bad); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	_ = policy.ES384
}
