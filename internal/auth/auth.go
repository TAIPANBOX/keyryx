// Package auth tells which consumer is asking. Scaffold.
package auth

import (
	"errors"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

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

// FromBearer resolves an Authorization header. Scaffold: nobody.
func (v *Verifier) FromBearer(header string) (string, string, bool) { return "", "", false }

// ParseIssuers reads KEYRYX_K8S_ISSUERS. Scaffold.
func ParseIssuers(spec string, read func(string) ([]byte, error)) ([]Issuer, error) {
	return nil, errors.New("auth: not implemented")
}

// ParseAdminKeys reads KEYRYX_ADMIN_KEYS. Scaffold.
func ParseAdminKeys(spec string) ([][32]byte, error) { return nil, errors.New("auth: not implemented") }

// Admin resolves an admin bearer. Scaffold: nobody.
func Admin(keys [][32]byte, header string) (string, bool) { return "", false }
