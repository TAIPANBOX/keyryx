// Package keystore holds keys wrapped under the root key. Scaffold.
package keystore

import (
	"crypto/ecdsa"
	"errors"
	"time"

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

// Record is the public view of one stored key.
type Record struct {
	Name       string
	Kid        string
	Alg        policy.Alg
	State      State
	Created    int64
	ActivateAt int64
	Retired    int64
	Revoked    int64
	Public     []byte
}

// Signature is what Sign returns.
type Signature struct {
	Alg    policy.Alg
	Kid    string
	Sig    []byte
	Public []byte
}

var (
	ErrUnknownKey         = errors.New("keystore: no such key")
	ErrUnknownKid         = errors.New("keystore: no such key id")
	ErrRotationInProgress = errors.New("keystore: a rotation is already in progress")
	ErrStatementTooLarge  = errors.New("keystore: statement too large")
	errScaffold           = errors.New("keystore: not implemented")
)

// MaxStatement bounds what may be signed.
const MaxStatement = 4096

// Store is the key store.
type Store struct{}

func Open(dir string, root [32]byte, keys []policy.Key, now func() time.Time) (*Store, error) {
	return nil, errScaffold
}
func (s *Store) Sign(name string, statement []byte) (Signature, error) {
	return Signature{}, errScaffold
}
func (s *Store) Published(name string) ([]Record, bool) { return nil, false }
func (s *Store) Inventory() []Record                    { return nil }
func (s *Store) Rotate(name string, ahead time.Duration) (Record, error) {
	return Record{}, errScaffold
}
func (s *Store) Revoke(kid string) (Record, error) { return Record{}, errScaffold }

// JWK renders a record's public key. Scaffold.
func JWK(r Record) map[string]any { return nil }

// Verify checks a signature. Scaffold: refuses.
func Verify(alg policy.Alg, public, statement, sig []byte) error { return errScaffold }

// ecPublic decodes an uncompressed EC point. Scaffold.
func ecPublic(alg policy.Alg, b []byte) (*ecdsa.PublicKey, error) { return nil, errScaffold }

// privateMaterial lists every private encoding the store holds, for the test
// that proves none of them reaches the disk in the clear. Scaffold: none.
func (s *Store) privateMaterial() [][]byte { return nil }
