// Package certify issues key statements for delegated keys. Scaffold.
package certify

import (
	"errors"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

const (
	ChallengeTTL = time.Minute
	MaxLive      = 4
	MinLifetime  = 10 * time.Minute
)

var (
	ErrNotDelegated = errors.New("certify: no delegated key with that name is declared")
	ErrNoChallenge  = errors.New("certify: no such challenge")
	ErrBadProof     = errors.New("certify: the proof does not verify")
	ErrKidKnown     = errors.New("certify: that key is already certified")
	ErrKidRevoked   = errors.New("certify: that key was revoked")
	ErrLifetime     = errors.New("certify: the life asked is out of range")
	ErrTooManyLive  = errors.New("certify: the name holds too many live keys")
	ErrUnknownKid   = errors.New("certify: no statement has that key id")
	errScaffold     = errors.New("certify: not implemented")
)

// Request is a delegate request.
type Request struct {
	JWK       []byte
	Challenge string
	Proof     []byte
	Lifetime  time.Duration
}

// Entry is one statement in the inventory.
type Entry struct {
	Statement statement.Statement
	Revoked   int64
}

// Registry holds the issued statements.
type Registry struct{}

// Open reads the issued statements. Scaffold.
func Open(dir string, store *keystore.Store, p *policy.Policy, ahead time.Duration, now func() time.Time) (*Registry, error) {
	return &Registry{}, nil
}

// Challenge issues a challenge. Scaffold.
func (r *Registry) Challenge(consumer, name string) (string, int64, error) { return "", 0, errScaffold }

// Delegate certifies a key. Scaffold.
func (r *Registry) Delegate(consumer, name string, req Request, record func(statement.Statement, []byte) error) (statement.Statement, []byte, error) {
	return statement.Statement{}, nil, errScaffold
}

// Published lists the key set of a delegated name. Scaffold.
func (r *Registry) Published(name string) ([]map[string]any, bool) { return nil, false }

// Statement returns an issued statement. Scaffold.
func (r *Registry) Statement(kid string) ([]byte, int64, bool) { return nil, 0, false }

// Revoke revokes a delegated key. Scaffold.
func (r *Registry) Revoke(kid string) (statement.Statement, error) {
	return statement.Statement{}, ErrUnknownKid
}

// Inventory lists every statement. Scaffold.
func (r *Registry) Inventory() []Entry { return nil }
