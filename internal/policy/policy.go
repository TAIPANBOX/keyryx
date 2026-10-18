// Package policy reads KEYRYX_POLICY: which keys exist, whether custody holds
// each or certifies one its consumer holds, which consumers exist, how each
// consumer proves who it is, and which keys each may use for what (CLAUDE.md
// invariants 17 and 25).
//
// The file is read in full or refused. An unknown field, a duplicate, a grant
// of a key nobody declared or a consumer with two ways in is a policy that
// says something other than what its author meant, and a key service that
// guessed which reading was intended would sign for somebody nobody granted.
package policy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Alg names a signature algorithm a key is created for.
type Alg string

const (
	ES256   Alg = "ES256"
	ES384   Alg = "ES384"
	MLDSA65 Alg = "ML-DSA-65"
	// OpSign is the one operation this version grants.
	OpSign = "sign"
	// MaxBytes bounds the policy file.
	MaxBytes = 1 << 20
)

func (a Alg) valid() bool { return a == ES256 || a == ES384 || a == MLDSA65 }

// name is the grammar of every key, consumer and socket name: a path segment
// that cannot climb, hide or carry a separator.
var name = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Mode says whether custody holds a key or certifies one its consumer holds.
type Mode string

const (
	Held      Mode = "held"
	Delegated Mode = "delegated"
	// OpDelegate is the grant to have a key of a delegated name certified.
	OpDelegate = "delegate"
	// DefaultOverlap is how long a delegated key stays published after its
	// not_after when the policy states no overlap.
	DefaultOverlap = 10 * time.Minute
	// ReservedPrefix is the service's own name space (the delegation root).
	ReservedPrefix = "keyryx."
)

// Key is one declared key.
type Key struct {
	Name        string
	Alg         Alg
	Mode        Mode
	MaxLifetime time.Duration
	Overlap     time.Duration
}

// HeldKeys lists the keys custody holds, the ones that go to the key store.
// A delegated key is never among them: its private half stays with its
// consumer.
func (p *Policy) HeldKeys() []Key {
	var out []Key
	for _, k := range p.Keys {
		if k.Mode == Held {
			out = append(out, k)
		}
	}
	return out
}

// Reserved reports whether name is in the service's own name space, where
// the delegation root lives. No policy declares or grants such a name, and
// the store signs no request with one.
func Reserved(name string) bool { return strings.HasPrefix(name, ReservedPrefix) }

// Life bounds of a delegated key, and of its overlap.
const (
	MinLifetime = 10 * time.Minute
	MaxLifetime = 7 * 24 * time.Hour
	MinOverlap  = time.Minute
	MaxOverlap  = 24 * time.Hour
)

// Consumer is one declared consumer and how it authenticates. Exactly one of
// Socket, HasKeyDigest and K8sIssuer is set.
type Consumer struct {
	Name         string
	Socket       string
	KeyDigest    [32]byte
	HasKeyDigest bool
	K8sIssuer    string
	K8sSubject   string
	grants       map[string]map[string]bool
}

// Policy is the parsed file.
type Policy struct {
	Keys      []Key
	Consumers []Consumer
}

type fileKey struct {
	Name        string  `json:"name"`
	Alg         string  `json:"alg"`
	Mode        *string `json:"mode"`
	MaxLifetime *string `json:"max_lifetime"`
	Overlap     *string `json:"overlap"`
}

type fileK8s struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type fileAuth struct {
	Socket    *string  `json:"socket"`
	KeyDigest *string  `json:"key_digest"`
	K8s       *fileK8s `json:"k8s"`
}

type fileConsumer struct {
	Name   string              `json:"name"`
	Auth   *fileAuth           `json:"auth"`
	Grants map[string][]string `json:"grants"`
}

type file struct {
	Version   *int           `json:"version"`
	Keys      []fileKey      `json:"keys"`
	Consumers []fileConsumer `json:"consumers"`
}

// Parse reads a policy file.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("the policy is %d bytes, over the %d-byte cap", len(data), MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f file
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the policy is not one JSON object of the known shape: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the policy carries data after its object")
	}
	if f.Version == nil || *f.Version != 1 {
		return nil, errors.New(`the policy must say "version": 1`)
	}
	p := &Policy{}
	keys := map[string]Mode{}
	if len(f.Keys) == 0 {
		return nil, errors.New("the policy declares no key, so custody would hold nothing")
	}
	for _, k := range f.Keys {
		if !name.MatchString(k.Name) {
			return nil, fmt.Errorf("key name %q is not 1 to 64 of a-z 0-9 . _ - starting with a letter or digit", k.Name)
		}
		if Reserved(k.Name) {
			return nil, fmt.Errorf("key name %s is in the service's own %q name space", k.Name, ReservedPrefix)
		}
		if _, dup := keys[k.Name]; dup {
			return nil, fmt.Errorf("the policy declares key %s twice", k.Name)
		}
		alg := Alg(k.Alg)
		if !alg.valid() {
			return nil, fmt.Errorf("key %s has algorithm %q; this version creates ES256, ES384 and ML-DSA-65 keys", k.Name, k.Alg)
		}
		key, err := keyMode(k, alg)
		if err != nil {
			return nil, err
		}
		keys[k.Name] = key.Mode
		p.Keys = append(p.Keys, key)
	}
	consumers, sockets, digests, subjects := map[string]bool{}, map[string]bool{}, map[[32]byte]bool{}, map[string]bool{}
	for _, fc := range f.Consumers {
		if !name.MatchString(fc.Name) {
			return nil, fmt.Errorf("consumer name %q is not 1 to 64 of a-z 0-9 . _ - starting with a letter or digit", fc.Name)
		}
		if consumers[fc.Name] {
			return nil, fmt.Errorf("the policy declares consumer %s twice", fc.Name)
		}
		consumers[fc.Name] = true
		c := Consumer{Name: fc.Name, grants: map[string]map[string]bool{}}
		if fc.Auth == nil {
			return nil, fmt.Errorf("consumer %s says nothing about how it authenticates", fc.Name)
		}
		ways := 0
		if fc.Auth.Socket != nil {
			ways++
			if !name.MatchString(*fc.Auth.Socket) {
				return nil, fmt.Errorf("consumer %s names socket %q, which is not a plain directory name", fc.Name, *fc.Auth.Socket)
			}
			if sockets[*fc.Auth.Socket] {
				return nil, fmt.Errorf("two consumers share socket %s, so neither could be told from the other", *fc.Auth.Socket)
			}
			sockets[*fc.Auth.Socket] = true
			c.Socket = *fc.Auth.Socket
		}
		if fc.Auth.KeyDigest != nil {
			ways++
			d, err := parseDigest(*fc.Auth.KeyDigest)
			if err != nil {
				return nil, fmt.Errorf("consumer %s: %w", fc.Name, err)
			}
			if digests[d] {
				return nil, fmt.Errorf("two consumers share one key digest, so neither could be told from the other")
			}
			digests[d] = true
			c.KeyDigest, c.HasKeyDigest = d, true
		}
		if fc.Auth.K8s != nil {
			ways++
			if err := absoluteURL(fc.Auth.K8s.Issuer); err != nil {
				return nil, fmt.Errorf("consumer %s: the cluster issuer %q %w", fc.Name, fc.Auth.K8s.Issuer, err)
			}
			if fc.Auth.K8s.Subject == "" || len(fc.Auth.K8s.Subject) > 256 {
				return nil, fmt.Errorf("consumer %s names no service-account subject", fc.Name)
			}
			bound := fc.Auth.K8s.Issuer + "#" + fc.Auth.K8s.Subject
			if subjects[bound] {
				return nil, fmt.Errorf("two consumers are bound to one service account, so neither could be told from the other")
			}
			subjects[bound] = true
			c.K8sIssuer, c.K8sSubject = fc.Auth.K8s.Issuer, fc.Auth.K8s.Subject
		}
		if ways != 1 {
			return nil, fmt.Errorf("consumer %s must authenticate exactly one way (socket, key_digest or k8s), and names %d", fc.Name, ways)
		}
		if len(fc.Grants) == 0 {
			return nil, fmt.Errorf("consumer %s is granted nothing", fc.Name)
		}
		for key, ops := range fc.Grants {
			mode, declared := keys[key]
			if !declared {
				return nil, fmt.Errorf("consumer %s is granted key %s, which the policy does not declare", fc.Name, key)
			}
			if len(ops) == 0 {
				return nil, fmt.Errorf("consumer %s is granted key %s for no operation", fc.Name, key)
			}
			set := map[string]bool{}
			for _, op := range ops {
				// Custody signs only with a key it holds, and certifies only a
				// key it does not: each operation belongs to one mode.
				switch {
				case op == OpSign && mode == Held, op == OpDelegate && mode == Delegated:
				case op == OpSign || op == OpDelegate:
					return nil, fmt.Errorf("consumer %s is granted %q on %s, a %s key; %q is for held keys and %q for delegated ones", fc.Name, op, key, mode, OpSign, OpDelegate)
				default:
					return nil, fmt.Errorf("consumer %s is granted %q on %s; this version grants only %q and %q", fc.Name, op, key, OpSign, OpDelegate)
				}
				if set[op] {
					return nil, fmt.Errorf("consumer %s is granted %q on %s twice", fc.Name, op, key)
				}
				set[op] = true
			}
			c.grants[key] = set
		}
		p.Consumers = append(p.Consumers, c)
	}
	return p, nil
}

// keyMode reads a key's mode and, for a delegated key, its life and overlap.
func keyMode(k fileKey, alg Alg) (Key, error) {
	key := Key{Name: k.Name, Alg: alg, Mode: Held}
	if k.Mode != nil {
		switch Mode(*k.Mode) {
		case Held, Delegated:
			key.Mode = Mode(*k.Mode)
		default:
			return Key{}, fmt.Errorf("key %s has mode %q; a key is held or delegated", k.Name, *k.Mode)
		}
	}
	if key.Mode == Held {
		if k.MaxLifetime != nil || k.Overlap != nil {
			return Key{}, fmt.Errorf("key %s is held, and a held key has no max_lifetime or overlap: it lives until it is rotated", k.Name)
		}
		return key, nil
	}
	if alg != ES256 && alg != ES384 {
		return Key{}, fmt.Errorf("key %s is delegated as %s; a delegated key is ES256 or ES384 in this version", k.Name, alg)
	}
	if k.MaxLifetime == nil {
		return Key{}, fmt.Errorf("key %s is delegated and names no max_lifetime", k.Name)
	}
	life, err := time.ParseDuration(*k.MaxLifetime)
	if err != nil || life < MinLifetime || life > MaxLifetime {
		return Key{}, fmt.Errorf("key %s has max_lifetime %q; it must be a duration from %s to %s", k.Name, *k.MaxLifetime, MinLifetime, MaxLifetime)
	}
	key.MaxLifetime, key.Overlap = life, DefaultOverlap
	if k.Overlap != nil {
		o, err := time.ParseDuration(*k.Overlap)
		if err != nil || o < MinOverlap || o > MaxOverlap {
			return Key{}, fmt.Errorf("key %s has overlap %q; it must be a duration from %s to %s", k.Name, *k.Overlap, MinOverlap, MaxOverlap)
		}
		key.Overlap = o
	}
	return key, nil
}

func parseDigest(s string) ([32]byte, error) {
	var out [32]byte
	hexPart, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(hexPart) != 64 {
		return out, fmt.Errorf("key_digest %q is not sha256:<64 hex>", s)
	}
	if _, err := hex.Decode(out[:], []byte(hexPart)); err != nil {
		return out, fmt.Errorf("key_digest %q is not hex", s)
	}
	return out, nil
}

func absoluteURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("is not an absolute http or https URL with no query, fragment or userinfo")
	}
	return nil
}

// Key returns the declared key with this name.
func (p *Policy) Key(n string) (Key, bool) {
	for _, k := range p.Keys {
		if k.Name == n {
			return k, true
		}
	}
	return Key{}, false
}

// Allowed reports whether consumer may perform op with key. Every unknown is
// a no: an unknown consumer, key or operation grants nothing.
func (p *Policy) Allowed(consumer, key, op string) bool {
	for _, c := range p.Consumers {
		if c.Name == consumer {
			return c.grants[key][op]
		}
	}
	return false
}

// SocketConsumers lists the consumers that authenticate by socket, sorted.
func (p *Policy) SocketConsumers() []Consumer {
	var out []Consumer
	for _, c := range p.Consumers {
		if c.Socket != "" {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ByKeySecret finds the consumer whose key digest is the SHA-256 of secret.
// Every configured digest is compared, in constant time, so the time taken
// does not say which consumer came closest; the secret is never kept.
func (p *Policy) ByKeySecret(secret string) (Consumer, bool) {
	if secret == "" {
		return Consumer{}, false
	}
	sum := sha256.Sum256([]byte(secret))
	found, hit := Consumer{}, 0
	for _, c := range p.Consumers {
		if !c.HasKeyDigest {
			continue
		}
		if subtle.ConstantTimeCompare(sum[:], c.KeyDigest[:]) == 1 {
			found, hit = c, hit+1
		}
	}
	return found, hit == 1
}

// ByK8s finds the consumer bound to a cluster's service account.
func (p *Policy) ByK8s(issuer, subject string) (Consumer, bool) {
	for _, c := range p.Consumers {
		if c.K8sIssuer != "" && c.K8sIssuer == issuer && c.K8sSubject == subject {
			return c, true
		}
	}
	return Consumer{}, false
}

// K8sIssuers lists the distinct cluster issuers the policy binds a consumer
// to, sorted, so internal/config can refuse one nobody configured.
func (p *Policy) K8sIssuers() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range p.Consumers {
		if c.K8sIssuer != "" && !seen[c.K8sIssuer] {
			seen[c.K8sIssuer] = true
			out = append(out, c.K8sIssuer)
		}
	}
	sort.Strings(out)
	return out
}
