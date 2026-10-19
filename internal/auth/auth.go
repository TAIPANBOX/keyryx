// Package auth tells which consumer is asking (CLAUDE.md invariant 22).
//
// Three ways in, one per consumer, each fixed by the policy:
//
//   - a unix socket of its own, whose directory only that consumer's group can
//     enter; the listener names the consumer and nothing the client sends can
//     change it (internal/api, WithSocketConsumer);
//   - a key, presented as a bearer and compared by its SHA-256 digest in
//     constant time; the service never holds the key itself;
//   - a Kubernetes projected service-account token, verified against the
//     cluster's published keys with the algorithm taken from the key type,
//     for exactly one audience, and bound to one service account.
//
// A credential that resolves to nobody is nobody: there is no fallback from
// one way to another and no default consumer.
package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// Skew is the clock difference tolerated on a token's issue time.
const Skew = 60 * time.Second

// MaxTokenLife bounds exp - iat. A projected token is renewed by the kubelet
// long before an hour; one that lives longer was not minted for this.
const MaxTokenLife = time.Hour

// Issuer is a cluster whose projected service-account tokens prove a consumer.
type Issuer struct {
	Iss  string
	Aud  string
	Keys delegation.Set
}

// Verifier resolves a bearer credential to a consumer.
type Verifier struct {
	Policy  *policy.Policy
	Issuers []Issuer
	Now     func() time.Time
}

func bearer(header string) (string, bool) {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || tok == "" || strings.ContainsAny(tok, " \t\r\n") {
		return "", false
	}
	return tok, true
}

// FromBearer resolves an Authorization header to a consumer name and the way
// it came in ("key" or "k8s").
func (v *Verifier) FromBearer(header string) (consumer, via string, ok bool) {
	tok, ok := bearer(header)
	if !ok || v == nil || v.Policy == nil {
		return "", "", false
	}
	if c, ok := v.Policy.ByKeySecret(tok); ok {
		return c.Name, "key", true
	}
	if c, ok := v.fromProjected(tok); ok {
		return c, "k8s", true
	}
	return "", "", false
}

func (v *Verifier) fromProjected(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(v.Issuers) == 0 {
		return "", false
	}
	// The issuer is read from the unverified payload only to choose whose
	// keys to verify with; it is checked again on the verified claims. A
	// token never verifies against another cluster's keys.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var peek struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &peek) != nil {
		return "", false
	}
	var is *Issuer
	for i := range v.Issuers {
		if v.Issuers[i].Iss == peek.Iss {
			is = &v.Issuers[i]
		}
	}
	if is == nil {
		return "", false
	}
	claims, err := delegation.VerifyToken(tok, is.Keys)
	if err != nil {
		return "", false
	}
	if iss, _ := claims["iss"].(string); iss != is.Iss {
		return "", false
	}
	if !oneAudience(claims["aud"], is.Aud) {
		return "", false
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", false
	}
	iat, ok1 := seconds(claims["iat"])
	exp, ok2 := seconds(claims["exp"])
	if !ok1 || !ok2 || exp <= iat || time.Duration(exp-iat)*time.Second > MaxTokenLife {
		return "", false
	}
	now := v.now()
	if now.Unix() >= exp || time.Unix(iat, 0).After(now.Add(Skew)) {
		return "", false
	}
	if nbf, present := claims["nbf"]; present {
		n, ok := seconds(nbf)
		if !ok || time.Unix(n, 0).After(now.Add(Skew)) {
			return "", false
		}
	}
	c, ok := v.Policy.ByK8s(is.Iss, sub)
	if !ok {
		return "", false
	}
	return c.Name, true
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// oneAudience holds when aud is exactly want: the string itself or a one-element
// array of it. A token for the API server and this service at once is a token
// the API server could replay here.
func oneAudience(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		if len(a) != 1 {
			return false
		}
		s, _ := a[0].(string)
		return s == want
	}
	return false
}

func seconds(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int64(f)) || f <= 0 {
		return 0, false
	}
	return int64(f), true
}

// ParseIssuers reads KEYRYX_K8S_ISSUERS: one `issuer|audience|jwks-file` per
// line (or comma-separated), the JWKS file being the cluster's published
// service-account keys. read is os.ReadFile outside tests.
func ParseIssuers(spec string, read func(string) ([]byte, error)) ([]Issuer, error) {
	var out []Issuer
	seen := map[string]bool{}
	for _, item := range splitList(spec) {
		f := strings.Split(item, "|")
		if len(f) != 3 {
			return nil, fmt.Errorf("issuer %q is not issuer|audience|jwks-file", item)
		}
		iss, aud, path := strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.TrimSpace(f[2])
		u, err := url.Parse(iss)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("issuer %q is not an absolute http or https URL", iss)
		}
		if aud == "" || path == "" {
			return nil, fmt.Errorf("issuer %s names no audience or no key file", iss)
		}
		if seen[iss] {
			return nil, fmt.Errorf("issuer %s is configured twice", iss)
		}
		seen[iss] = true
		raw, err := read(path)
		if err != nil {
			return nil, fmt.Errorf("issuer %s: reading its keys: %w", iss, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		var set delegation.Set
		if err := dec.Decode(&set); err != nil {
			return nil, fmt.Errorf("issuer %s: its key file is not a JWKS: %w", iss, err)
		}
		if len(set.Keys) == 0 {
			return nil, fmt.Errorf("issuer %s: its key file holds no key", iss)
		}
		for _, k := range set.Keys {
			if k.Kid == "" || k.Kty == "" {
				return nil, fmt.Errorf("issuer %s: a key in its file has no kid or no kty", iss)
			}
		}
		out = append(out, Issuer{Iss: iss, Aud: aud, Keys: set})
	}
	return out, nil
}

func splitList(spec string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(spec, func(r rune) bool { return r == '\n' || r == ',' }) {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ParseAdminKeys reads KEYRYX_ADMIN_KEYS: comma-separated `sha256:<64 hex>`
// digests of the admin bearer keys. Never a key in the clear.
func ParseAdminKeys(spec string) ([][32]byte, error) {
	var out [][32]byte
	seen := map[[32]byte]bool{}
	for _, item := range splitList(spec) {
		hexPart, ok := strings.CutPrefix(item, "sha256:")
		var d [32]byte
		if !ok || len(hexPart) != 64 {
			return nil, errors.New("an admin key is not sha256:<64 hex>; the service takes the digest, never the key")
		}
		if _, err := hex.Decode(d[:], []byte(hexPart)); err != nil {
			return nil, errors.New("an admin key digest is not hex")
		}
		if seen[d] {
			return nil, errors.New("an admin key digest is listed twice")
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// Admin resolves an admin bearer to a fingerprint for the use log: the first
// eight bytes of the key's digest, never the key. Every configured digest is
// compared in constant time.
func Admin(keys [][32]byte, header string) (string, bool) {
	tok, ok := bearer(header)
	if !ok || len(keys) == 0 {
		return "", false
	}
	sum := sha256.Sum256([]byte(tok))
	hit := 0
	for _, k := range keys {
		hit += subtle.ConstantTimeCompare(sum[:], k[:])
	}
	if hit != 1 {
		return "", false
	}
	return "sha256:" + hex.EncodeToString(sum[:8]), true
}
