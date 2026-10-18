// Package witness is the witness role's observer. Scaffold.
package witness

import (
	"errors"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// Tenant is one trailryx data directory.
type Tenant struct{ Name, Dir string }

// Config is what the witness reads and how often it reads it in full.
type Config struct {
	Events, Checkpoints, Attestations string
	Records                           []Tenant
	FullBytes                         int64
	FullInterval, SealEvery           time.Duration
	SealLines                         int64
	Name                              string
}

// Keys answers which public key certifies a checkpoint's kid.
type Keys interface {
	Key(kid string, at, seen time.Time) ([]byte, error)
}

// Finding is one thing the witness disagrees with.
type Finding struct {
	Type, Severity string
	Data           map[string]any
}

// Alerter is where findings go.
type Alerter interface{ Alert(Finding) error }

// Attestation is a trailryx witness attestation.
type Attestation struct {
	Witness   string `json:"witness"`
	Tenant    string `json:"tenant"`
	StoreRoot string `json:"store_root"`
	Segments  uint64 `json:"segments"`
	SeenAt    uint64 `json:"seen_at"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// Witness is the observer.
type Witness struct{}

var errScaffold = errors.New("witness: not implemented")

// New rebuilds the witness's state from its log. Scaffold.
func New(cfg Config, log *wlog.Log, signer statement.Signer, keys Keys, alerts Alerter, now func() time.Time) (*Witness, error) {
	return nil, errScaffold
}

// Tick observes once. Scaffold.
func (w *Witness) Tick() ([]Finding, error) { return nil, errScaffold }

// EventAlerter writes findings as agent-events.
type EventAlerter struct{}

// NewEventAlerter opens the alert stream. Scaffold.
func NewEventAlerter(path string, now func() time.Time) (*EventAlerter, error) {
	return nil, errScaffold
}

// Alert writes one finding. Scaffold.
func (e *EventAlerter) Alert(f Finding) error { return errScaffold }
