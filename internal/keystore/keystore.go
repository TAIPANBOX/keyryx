// Package keystore holds the custody role's keys, wrapped under the root key.
//
// # What is on disk
//
// One file per key, `<data>/keys/<name>/<kid file>.json`, holding the public
// key and the key's life (created, activated, retired, revoked) in the clear
// and the private key wrapped with AES-256-GCM. The wrapping key is derived
// with HKDF-SHA-384 from the root key and the key's name, id and algorithm,
// and the same three are the GCM additional data, so a record moved under
// another name, or edited to claim another id or algorithm, does not open
// (CLAUDE.md invariant 19). Every record is checked whole at start: its id
// is recomputed from its public key and its private key must be the public
// key's other half; one record that does not hold refuses the start.
//
// # What never leaves
//
// No private member is ever returned, logged or written outside the wrap
// (invariant 5). The private keys live in unexported fields of an unexported
// type, and `scripts/private-keys-stay-in-the-store.sh` holds that every
// reference to a private-key type in this repository is in this package.
//
// # Life of a key
//
// active signs; next is published and does not sign until its activation time
// (rotation with overlap, invariant 20); retired is published and never signs
// again, so what it signed keeps verifying; revoked is never published and
// never signs (invariant 21). Revoking the active key promotes the next one at
// once, or makes a fresh one, so a revocation is never a reason to sign with a
// revoked key.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// State is where a key is in its life.
type State string

const (
	Active  State = "active"
	Next    State = "next"
	Retired State = "retired"
	Revoked State = "revoked"
)

func (s State) valid() bool { return s == Active || s == Next || s == Retired || s == Revoked }

// Record is the public view of one stored key. It carries no private member.
type Record struct {
	Name       string
	Kid        string
	Alg        policy.Alg
	State      State
	Created    int64
	ActivateAt int64
	Retired    int64
	Revoked    int64
	// Public is the uncompressed EC point (0x04 || X || Y) or the ML-DSA
	// public key encoding.
	Public []byte
}

// Signature is what Sign returns.
type Signature struct {
	Alg    policy.Alg
	Kid    string
	Sig    []byte
	Public []byte
}

var (
	ErrUnknownKey         = errors.New("keystore: no key with that name is declared")
	ErrUnknownKid         = errors.New("keystore: no key has that id")
	ErrRotationInProgress = errors.New("keystore: a rotation of that key is already in progress")
	ErrStatementTooLarge  = errors.New("keystore: the statement is over the size cap")
	ErrEmptyStatement     = errors.New("keystore: the statement is empty")
)

// MaxStatement bounds what may be signed on request. A larger artefact is
// signed by its digest, which the consumer computes.
const MaxStatement = 4096

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// held is one key with its private half. Unexported, never serialised.
type held struct {
	rec Record
	ec  *ecdsa.PrivateKey
	ml  *mldsa.PrivateKey
}

// Store is the key store. Safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	dir      string
	root     [32]byte
	now      func() time.Time
	declared map[string]policy.Alg
	keys     map[string][]*held
}

// Open reads every stored key, checks each whole, and creates an active key
// for every declared key that has none. Anything it cannot vouch for refuses
// the open (CLAUDE.md invariant 6).
func Open(dir string, root [32]byte, keys []policy.Key, now func() time.Time) (*Store, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("the data directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("the data directory %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("the data directory %s is open to group or other (mode %o); it must be 0700", dir, info.Mode().Perm())
	}
	if root == ([32]byte{}) {
		return nil, errors.New("the root key is all zero")
	}
	s := &Store{dir: dir, root: root, now: now, declared: map[string]policy.Alg{}, keys: map[string][]*held{}}
	for _, k := range keys {
		s.declared[k.Name] = k.Alg
	}
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", keysDir, err)
	}
	names, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", keysDir, err)
	}
	for _, n := range names {
		if !n.IsDir() || !nameRe.MatchString(n.Name()) {
			return nil, fmt.Errorf("%s holds %q, which is not a key directory this service writes", keysDir, n.Name())
		}
		files, err := os.ReadDir(filepath.Join(keysDir, n.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".tmp-") {
				continue // a write that died before its rename; never a record
			}
			h, err := s.load(n.Name(), f.Name())
			if err != nil {
				return nil, err
			}
			s.keys[n.Name()] = append(s.keys[n.Name()], h)
		}
	}
	for name, hs := range s.keys {
		active, next := 0, 0
		for _, h := range hs {
			if alg, ok := s.declared[name]; ok && h.rec.Alg != alg {
				return nil, fmt.Errorf("the policy declares %s as %s and the store holds a %s key for it", name, alg, h.rec.Alg)
			}
			switch h.rec.State {
			case Active:
				active++
			case Next:
				next++
			}
		}
		if active > 1 || next > 1 {
			return nil, fmt.Errorf("the store holds %d active and %d next keys for %s; at most one of each is ever written", active, next, name)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.tick(); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if s.activeLocked(k.Name) == nil {
			if _, err := s.generateLocked(k.Name, k.Alg, Active, 0); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

type recordFile struct {
	V          int    `json:"v"`
	Name       string `json:"name"`
	Kid        string `json:"kid"`
	Alg        string `json:"alg"`
	State      string `json:"state"`
	Created    int64  `json:"created"`
	ActivateAt int64  `json:"activate_at"`
	Retired    int64  `json:"retired"`
	Revoked    int64  `json:"revoked"`
	Public     string `json:"public"`
	Nonce      string `json:"nonce"`
	Wrapped    string `json:"wrapped"`
}

func fileName(kid string) string { return strings.ReplaceAll(kid, ":", "_") + ".json" }

func (s *Store) load(dirName, file string) (*held, error) {
	path := filepath.Join(s.dir, "keys", dirName, file)
	raw, err := os.ReadFile(path) // #nosec G304 -- a file in this service's own data directory
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	refuse := func(why string) (*held, error) {
		return nil, fmt.Errorf("the key record %s %s; this service never writes one", path, why)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var f recordFile
	if err := dec.Decode(&f); err != nil {
		return refuse("is not a record: " + err.Error())
	}
	if dec.More() {
		return refuse("carries data after its record")
	}
	alg := policy.Alg(f.Alg)
	state := State(f.State)
	switch {
	case f.V != 1:
		return refuse("is not version 1")
	case f.Name != dirName:
		return refuse("names another key than the directory it is in")
	case alg != policy.ES256 && alg != policy.ES384 && alg != policy.MLDSA65:
		return refuse("names an unknown algorithm")
	case !state.valid():
		return refuse("is in an unknown state")
	case f.Created <= 0:
		return refuse("has no creation time")
	case f.Kid == "" || fileName(f.Kid) != file:
		return refuse("names another key id than its file")
	}
	pub, err := base64.RawURLEncoding.DecodeString(f.Public)
	if err != nil {
		return refuse("has a public key that is not base64url")
	}
	kid, err := kidFor(alg, pub)
	if err != nil {
		return refuse("has a public key that does not parse: " + err.Error())
	}
	if kid != f.Kid {
		return refuse("names a key id that is not its public key's")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(f.Nonce)
	if err != nil || len(nonce) != 12 {
		return refuse("has no usable nonce")
	}
	wrapped, err := base64.RawURLEncoding.DecodeString(f.Wrapped)
	if err != nil || len(wrapped) == 0 {
		return refuse("has no wrapped key")
	}
	priv, err := s.unwrap(f.Name, f.Kid, alg, nonce, wrapped)
	if err != nil {
		return refuse("does not open under this root key and this name")
	}
	h := &held{rec: Record{Name: f.Name, Kid: f.Kid, Alg: alg, State: state, Created: f.Created,
		ActivateAt: f.ActivateAt, Retired: f.Retired, Revoked: f.Revoked, Public: pub}}
	if err := h.setPrivate(priv); err != nil {
		return refuse("holds a private key that does not parse")
	}
	if !equalBytes(h.publicBytes(), pub) {
		return refuse("holds a private key that is not its public key's other half")
	}
	return h, nil
}

func equalBytes(a, b []byte) bool { return string(a) == string(b) }

// --- wrapping -----------------------------------------------------------------

func (s *Store) aead(name, kid string, alg policy.Alg) (cipher.AEAD, []byte, error) {
	info := name + "\x00" + kid + "\x00" + string(alg)
	k, err := hkdf.Key(sha512.New384, s.root[:], []byte("keyryx/wrap/v1"), info, 32)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return gcm, []byte("keyryx/key/v1\x00" + info), nil
}

func (s *Store) wrap(name, kid string, alg policy.Alg, priv []byte) (nonce, wrapped []byte, err error) {
	gcm, aad, err := s.aead(name, kid, alg)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, priv, aad), nil
}

func (s *Store) unwrap(name, kid string, alg policy.Alg, nonce, wrapped []byte) ([]byte, error) {
	gcm, aad, err := s.aead(name, kid, alg)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, wrapped, aad)
}

// --- keys -----------------------------------------------------------------------

func curve(alg policy.Alg) elliptic.Curve {
	if alg == policy.ES384 {
		return elliptic.P384()
	}
	return elliptic.P256()
}

func (h *held) setPrivate(priv []byte) error {
	switch h.rec.Alg {
	case policy.MLDSA65:
		k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), priv)
		if err != nil {
			return err
		}
		h.ml = k
	default:
		parsed, err := x509.ParsePKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		k, ok := parsed.(*ecdsa.PrivateKey)
		if !ok || k.Curve != curve(h.rec.Alg) {
			return errors.New("not an EC key on the record's curve")
		}
		h.ec = k
	}
	return nil
}

func (h *held) privateBytes() ([]byte, error) {
	if h.ml != nil {
		return h.ml.Bytes(), nil
	}
	return x509.MarshalPKCS8PrivateKey(h.ec)
}

func (h *held) publicBytes() []byte {
	if h.ml != nil {
		return h.ml.PublicKey().Bytes()
	}
	b, err := h.ec.PublicKey.Bytes()
	if err != nil {
		return nil
	}
	return b
}

// ecPublic decodes an uncompressed EC point on the algorithm's curve.
func ecPublic(alg policy.Alg, b []byte) (*ecdsa.PublicKey, error) {
	if alg != policy.ES256 && alg != policy.ES384 {
		return nil, errors.New("not an EC algorithm")
	}
	return ecdsa.ParseUncompressedPublicKey(curve(alg), b)
}

func kidFor(alg policy.Alg, pub []byte) (string, error) {
	if alg == policy.MLDSA65 {
		if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub); err != nil {
			return "", err
		}
		sum := sha256.Sum256(pub)
		return "mldsa65:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
	}
	k, err := ecPublic(alg, pub)
	if err != nil {
		return "", err
	}
	return delegation.Thumbprint(delegation.FromPublic(k, ""))
}

func (s *Store) generateLocked(name string, alg policy.Alg, state State, activateAt int64) (*held, error) {
	h := &held{rec: Record{Name: name, Alg: alg, State: state, Created: s.now().Unix(), ActivateAt: activateAt}}
	switch alg {
	case policy.MLDSA65:
		k, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return nil, err
		}
		h.ml = k
	case policy.ES256, policy.ES384:
		k, err := ecdsa.GenerateKey(curve(alg), rand.Reader)
		if err != nil {
			return nil, err
		}
		h.ec = k
	default:
		return nil, fmt.Errorf("cannot create a %s key", alg)
	}
	h.rec.Public = h.publicBytes()
	kid, err := kidFor(alg, h.rec.Public)
	if err != nil {
		return nil, err
	}
	h.rec.Kid = kid
	if err := s.persist(h); err != nil {
		return nil, err
	}
	s.keys[name] = append(s.keys[name], h)
	return h, nil
}

// persist writes a record atomically: a temporary file, synced, renamed over
// the record, the directory synced, so a crash leaves the old record or the
// new one and never half of either.
func (s *Store) persist(h *held) error {
	priv, err := h.privateBytes()
	if err != nil {
		return err
	}
	nonce, wrapped, err := s.wrap(h.rec.Name, h.rec.Kid, h.rec.Alg, priv)
	clear(priv)
	if err != nil {
		return err
	}
	f := recordFile{V: 1, Name: h.rec.Name, Kid: h.rec.Kid, Alg: string(h.rec.Alg), State: string(h.rec.State),
		Created: h.rec.Created, ActivateAt: h.rec.ActivateAt, Retired: h.rec.Retired, Revoked: h.rec.Revoked,
		Public:  base64.RawURLEncoding.EncodeToString(h.rec.Public),
		Nonce:   base64.RawURLEncoding.EncodeToString(nonce),
		Wrapped: base64.RawURLEncoding.EncodeToString(wrapped)}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.dir, "keys", h.rec.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, fileName(h.rec.Kid))); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- this service's own key directory
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// --- life of a key --------------------------------------------------------------

func (s *Store) activeLocked(name string) *held {
	for _, h := range s.keys[name] {
		if h.rec.State == Active {
			return h
		}
	}
	return nil
}

func (s *Store) nextLocked(name string) *held {
	for _, h := range s.keys[name] {
		if h.rec.State == Next {
			return h
		}
	}
	return nil
}

// tick promotes every next key whose activation time has come.
func (s *Store) tick() error {
	now := s.now().Unix()
	for name := range s.keys {
		n := s.nextLocked(name)
		if n == nil || n.rec.ActivateAt > now {
			continue
		}
		if err := s.promoteLocked(name, n, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) promoteLocked(name string, n *held, now int64) error {
	if a := s.activeLocked(name); a != nil {
		a.rec.State, a.rec.Retired = Retired, now
		if err := s.persist(a); err != nil {
			return err
		}
	}
	n.rec.State, n.rec.ActivateAt = Active, now
	return s.persist(n)
}

// Sign signs statement with the active key of name.
func (s *Store) Sign(name string, statement []byte) (Signature, error) {
	if len(statement) == 0 {
		return Signature{}, ErrEmptyStatement
	}
	if len(statement) > MaxStatement {
		return Signature{}, ErrStatementTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.declared[name]; !ok {
		return Signature{}, ErrUnknownKey
	}
	if err := s.tick(); err != nil {
		return Signature{}, err
	}
	h := s.activeLocked(name)
	if h == nil {
		return Signature{}, fmt.Errorf("keystore: %s has no active key", name)
	}
	sig, err := h.sign(statement)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Alg: h.rec.Alg, Kid: h.rec.Kid, Sig: sig, Public: append([]byte(nil), h.rec.Public...)}, nil
}

func (h *held) sign(statement []byte) ([]byte, error) {
	switch h.rec.Alg {
	case policy.MLDSA65:
		return h.ml.Sign(rand.Reader, statement, &mldsa.Options{})
	case policy.ES384:
		d := sha512.Sum384(statement)
		return ecSign(h.ec, d[:], 48)
	default:
		d := sha256.Sum256(statement)
		return ecSign(h.ec, d[:], 32)
	}
}

func ecSign(k *ecdsa.PrivateKey, digest []byte, size int) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out, nil
}

// Verify checks a signature: fixed-width R||S over SHA-256 or SHA-384 for
// ECDSA, FIPS 204 for ML-DSA-65, with the public key in the encoding Record
// carries.
func Verify(alg policy.Alg, public, statement, sig []byte) error {
	switch alg {
	case policy.MLDSA65:
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), public)
		if err != nil {
			return err
		}
		return mldsa.Verify(pk, statement, sig, &mldsa.Options{})
	case policy.ES256, policy.ES384:
		pk, err := ecPublic(alg, public)
		if err != nil {
			return err
		}
		size := 32
		var digest []byte
		if alg == policy.ES384 {
			size = 48
			d := sha512.Sum384(statement)
			digest = d[:]
		} else {
			d := sha256.Sum256(statement)
			digest = d[:]
		}
		if len(sig) != 2*size {
			return errors.New("keystore: the signature is the wrong size")
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(pk, digest, r, s) {
			return errors.New("keystore: the signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("keystore: unknown algorithm %q", alg)
}

// Published returns the records a verifier may use for name: every key not
// revoked, active first. False when no key of that name exists.
func (s *Store) Published(name string) ([]Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.tick()
	hs, ok := s.keys[name]
	if !ok {
		return nil, false
	}
	var out []Record
	for _, h := range hs {
		if h.rec.State != Revoked {
			out = append(out, h.rec)
		}
	}
	order := map[State]int{Active: 0, Next: 1, Retired: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].State] != order[out[j].State] {
			return order[out[i].State] < order[out[j].State]
		}
		return out[i].Created > out[j].Created
	})
	return out, true
}

// Inventory returns every record, revoked ones included, by name then age.
func (s *Store) Inventory() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.tick()
	var out []Record
	for _, hs := range s.keys {
		for _, h := range hs {
			out = append(out, h.rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Created != out[j].Created {
			return out[i].Created < out[j].Created
		}
		return out[i].Kid < out[j].Kid
	})
	return out
}

// Rotate creates the next key of name, published now and signing after ahead.
func (s *Store) Rotate(name string, ahead time.Duration) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alg, ok := s.declared[name]
	if !ok {
		return Record{}, ErrUnknownKey
	}
	if err := s.tick(); err != nil {
		return Record{}, err
	}
	if s.nextLocked(name) != nil {
		return Record{}, ErrRotationInProgress
	}
	h, err := s.generateLocked(name, alg, Next, s.now().Add(ahead).Unix())
	if err != nil {
		return Record{}, err
	}
	return h.rec, nil
}

// Revoke takes kid out of every key set for good. Revoking the active key
// promotes the next one at once, or creates a fresh active key for a declared
// name, so signing never falls back to a revoked key.
func (s *Store) Revoke(kid string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, hs := range s.keys {
		for _, h := range hs {
			if h.rec.Kid != kid {
				continue
			}
			if h.rec.State == Revoked {
				return h.rec, nil
			}
			wasActive := h.rec.State == Active
			now := s.now().Unix()
			h.rec.State, h.rec.Revoked = Revoked, now
			if err := s.persist(h); err != nil {
				return Record{}, err
			}
			if wasActive {
				if n := s.nextLocked(name); n != nil {
					if err := s.promoteLocked(name, n, now); err != nil {
						return Record{}, err
					}
				} else if alg, ok := s.declared[name]; ok {
					if _, err := s.generateLocked(name, alg, Active, 0); err != nil {
						return Record{}, err
					}
				}
			}
			return h.rec, nil
		}
	}
	return Record{}, ErrUnknownKid
}

// JWK renders a record's public key as a JWK: kty, crv, x, y for EC, and for
// ML-DSA the AKP form (kty AKP, alg ML-DSA-65, pub) of the JOSE ML-DSA
// specification; kid, alg and use always. Nothing private exists to render.
func JWK(r Record) map[string]any {
	out := map[string]any{"kid": r.Kid, "alg": string(r.Alg), "use": "sig"}
	if r.Alg == policy.MLDSA65 {
		out["kty"] = "AKP"
		out["pub"] = base64.RawURLEncoding.EncodeToString(r.Public)
		return out
	}
	pk, err := ecPublic(r.Alg, r.Public)
	if err != nil {
		return nil
	}
	j := delegation.FromPublic(pk, r.Kid)
	out["kty"], out["crv"], out["x"], out["y"] = j.Kty, j.Crv, j.X, j.Y
	return out
}

// privateMaterial lists every private encoding the store holds, for the
// tests that prove none of them reaches a disk in the clear or an answer.
// Unexported; reachable from outside this package only through
// export_test.go, which no binary compiles.
func (s *Store) privateMaterial() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, hs := range s.keys {
		for _, h := range hs {
			if b, err := h.privateBytes(); err == nil {
				out = append(out, b)
			}
			if h.ec != nil {
				if raw, err := h.ec.Bytes(); err == nil {
					out = append(out, raw)
				}
			}
		}
	}
	return out
}
