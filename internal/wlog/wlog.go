// Package wlog is the witness's own append-only log. Scaffold.
package wlog

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/merkle"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

const (
	KeyES384  = "keyryx.witness.es384"
	KeyMLDSA  = "keyryx.witness.ml-dsa-65"
	LogFile   = "log.ndjson"
	HeadsFile = "heads.ndjson"
)

// Keys are the witness key's two halves.
var Keys = []policy.Key{{Name: KeyES384, Alg: policy.ES384, Mode: policy.Held}, {Name: KeyMLDSA, Alg: policy.MLDSA65, Mode: policy.Held}}

// ShardSeen is one trailryx shard as witnessed.
type ShardSeen struct {
	Shard    uint16 `json:"shard"`
	Segments uint64 `json:"segments"`
	Root     string `json:"root"`
}

// Entry is one observation.
type Entry struct {
	Kind       string      `json:"kind"`
	SeenAt     int64       `json:"seen_at"`
	Stream     string      `json:"stream,omitempty"`
	Tenant     string      `json:"tenant,omitempty"`
	Lines      int64       `json:"lines,omitempty"`
	Bytes      int64       `json:"bytes,omitempty"`
	Prefix     string      `json:"prefix,omitempty"`
	Head       string      `json:"head,omitempty"`
	Mode       string      `json:"mode,omitempty"`
	CkptBytes  int64       `json:"checkpoint_bytes,omitempty"`
	CkptPrefix string      `json:"checkpoint_prefix,omitempty"`
	CkptLast   string      `json:"checkpoint_last,omitempty"`
	Count      int64       `json:"count,omitempty"`
	End        int64       `json:"end,omitempty"`
	CkptKind   string      `json:"checkpoint_kind,omitempty"`
	Record     string      `json:"record,omitempty"`
	StoreRoot  string      `json:"store_root,omitempty"`
	Segments   uint64      `json:"segments,omitempty"`
	Shards     []ShardSeen `json:"shards,omitempty"`
	LinesTotal int64       `json:"lines_total,omitempty"`
	Type       string      `json:"type,omitempty"`
	Severity   string      `json:"severity,omitempty"`
	Size       int64       `json:"size,omitempty"`
	Token      string      `json:"token,omitempty"`
	GenTime    int64       `json:"gen_time,omitempty"`
}

// Sig is one half of a head's signature.
type Sig struct {
	Kid string `json:"kid"`
	Sig string `json:"sig"`
}

// Head is a signed tree head.
type Head struct {
	Size    int64  `json:"size"`
	Root    string `json:"root"`
	At      int64  `json:"at"`
	ES384   Sig    `json:"es384"`
	MLDSA65 Sig    `json:"ml_dsa_65"`
}

// Report is what VerifyDir found.
type Report struct {
	Lines    []string
	Broken   bool
	Measured bool
}

// Log is the open log.
type Log struct{}

var errScaffold = errors.New("wlog: not implemented")

func HeadInput(size int64, root merkle.Hash, at int64) []byte { return nil }
func Open(dir string, keys statement.RootKey, now func() time.Time) (*Log, error) {
	return nil, errScaffold
}
func (l *Log) Append(es ...Entry) error                   { return errScaffold }
func (l *Log) Sign(s statement.Signer) (Head, error)      { return Head{}, errScaffold }
func (l *Log) Size() int64                                { return 0 }
func (l *Log) Leaves() []merkle.Hash                      { return nil }
func (l *Log) Entries() []Entry                           { return nil }
func (l *Log) Heads() []Head                              { return nil }
func (l *Log) Latest() (Head, bool)                       { return Head{}, false }
func (l *Log) Close() error                               { return nil }
func VerifyDir(dir string, keys statement.RootKey) Report { return Report{} }
func decodeB64(s string) ([]byte, error)                  { return base64.RawURLEncoding.DecodeString(s) }
