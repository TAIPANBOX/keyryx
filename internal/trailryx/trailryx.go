// Package trailryx reads trailryx-node's sealed manifests. Scaffold.
package trailryx

import "errors"

// Hash is a SHA-384 digest.
type Hash = [48]byte

// IndexRoot is one dimension's index root.
type IndexRoot struct {
	Name string
	Root Hash
}

// Manifest is one sealed segment's manifest.
type Manifest struct {
	FormatVersion                        uint16
	Segment                              uint64
	Shard                                uint16
	Records                              uint64
	HistoryRoot, ChainBefore, ChainAfter Hash
	IndexRoots                           []IndexRoot
	FirstRecordedAt, LastRecordedAt      uint64
	Algorithms                           [3]byte
}

// Shard is one shard's sealed segments.
type Shard struct {
	Shard    uint16
	Segments uint64
	Root     Hash
}

// Store is a data directory's sealed state.
type Store struct {
	Shards   []Shard
	Segments uint64
	Root     Hash
}

var errScaffold = errors.New("trailryx: not implemented")

func EncodeManifest(m Manifest) []byte          { return nil }
func DecodeManifest(b []byte) (Manifest, error) { return Manifest{}, errScaffold }
func (m Manifest) Root() Hash                   { return Hash{} }
func ReadStore(dir string) (Store, error)       { return Store{}, errScaffold }
func CheckWitnessName(name string) error        { return nil }
func WitnessStatement(witness string, storeRoot Hash, seenAt uint64, alg string, pub []byte) []byte {
	return nil
}
