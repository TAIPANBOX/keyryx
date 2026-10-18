// Package config reads the custody role's environment. Scaffold.
package config

import (
	"errors"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// DefaultAddr is where custody listens when nothing says otherwise.
const DefaultAddr = "127.0.0.1:4340"

// Config is everything custody needs.
type Config struct {
	Addr         string
	DataDir      string
	Root         [32]byte
	Policy       *policy.Policy
	SocketDir    string
	AdminKeys    [][32]byte
	Issuers      []auth.Issuer
	PublishAhead time.Duration
}

// FromEnv builds a config or says what is wrong. Scaffold: refuses.
func FromEnv() (Config, error) { return Config{}, errors.New("config: not implemented") }
