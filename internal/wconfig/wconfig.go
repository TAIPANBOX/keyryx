// Package wconfig reads the witness role's environment. Scaffold.
package wconfig

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/witness"
)

// DefaultAddr is where the witness listens when nothing says otherwise.
const DefaultAddr = "127.0.0.1:4341"

// TSA is the opt-in time-stamping authority.
type TSA struct {
	URL   string
	Roots *x509.CertPool
	Every time.Duration
}

// Config is everything the witness needs.
type Config struct {
	Addr, DataDir, Alerts, CustodyURL string
	Root                              [32]byte
	Interval                          time.Duration
	Witness                           witness.Config
	TSA                               *TSA
}

// FromEnv builds a config or says what is wrong. Scaffold: refuses.
func FromEnv() (Config, error) { return Config{}, errors.New("wconfig: not implemented") }
