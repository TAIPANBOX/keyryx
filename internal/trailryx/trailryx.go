// Package trailryx reads what trailryx-node seals, so the witness can attest
// to the store root trailryx-verify derives (CLAUDE.md invariant 34).
//
// Every layout here is trailryx's, rebuilt from its source at 92dd4b6 rather
// than shared with it, the way trailryx-verify rebuilds the store's: the
// manifest bytes are crates/trailryx-store/src/evidence.rs encode_manifest
// and decode_manifest; the manifest root, the shard leaf and the store root
// are crates/trailryx-verify/src/verify.rs manifest_root and shard_leaf over
// crates/trailryx-verify/src/merkle.rs; the witness statement is
// crates/trailryx-sign/src/lib.rs witness_statement; a data directory holds
// `s{shard}-{segment:06}.mf` per sealed segment, as
// crates/trailryx-node/src/plane.rs names them, and a manifest filed under
// another segment's or shard's name is refused as plane.rs refuses it.
package trailryx

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/TAIPANBOX/keyryx/internal/merkle"
)

// Hash is a SHA-384 digest.
type Hash = [48]byte

// Dimensions are trailryx-index's Dimension::ALL names.
var Dimensions = []string{"id", "recorded_at", "agent_id", "run_id", "event_type"}

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

// MaxManifest bounds a manifest file.
const MaxManifest = 64 << 10

// EncodeManifest is encode_manifest.
func EncodeManifest(m Manifest) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, m.FormatVersion)
	b = binary.BigEndian.AppendUint64(b, m.Segment)
	b = binary.BigEndian.AppendUint16(b, m.Shard)
	b = binary.BigEndian.AppendUint64(b, m.Records)
	b = append(b, m.HistoryRoot[:]...)
	b = append(b, m.ChainBefore[:]...)
	b = append(b, m.ChainAfter[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(m.IndexRoots)))
	for _, r := range m.IndexRoots {
		b = binary.BigEndian.AppendUint32(b, uint32(len(r.Name)))
		b = append(b, r.Name...)
		b = append(b, r.Root[:]...)
	}
	b = binary.BigEndian.AppendUint64(b, m.FirstRecordedAt)
	b = binary.BigEndian.AppendUint64(b, m.LastRecordedAt)
	return append(b, m.Algorithms[:]...)
}

type reader struct {
	b  []byte
	at int
}

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || len(r.b)-r.at < n {
		return nil, false
	}
	out := r.b[r.at : r.at+n]
	r.at += n
	return out, true
}

func (r *reader) u16() (uint16, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (r *reader) u32() (uint32, bool) {
	b, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

func (r *reader) u64() (uint64, bool) {
	b, ok := r.take(8)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint64(b), true
}

func (r *reader) hash() (Hash, bool) {
	var h Hash
	b, ok := r.take(48)
	if !ok {
		return h, false
	}
	copy(h[:], b)
	return h, true
}

var errManifest = errors.New("trailryx: this is not a segment manifest")

// DecodeManifest is decode_manifest: every read bounded before it happens, a
// dimension or an algorithm code trailryx does not define refused, and nothing
// after the last field.
func DecodeManifest(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > MaxManifest {
		return m, errManifest
	}
	r := &reader{b: b}
	var ok [8]bool
	m.FormatVersion, ok[0] = r.u16()
	m.Segment, ok[1] = r.u64()
	m.Shard, ok[2] = r.u16()
	m.Records, ok[3] = r.u64()
	m.HistoryRoot, ok[4] = r.hash()
	m.ChainBefore, ok[5] = r.hash()
	m.ChainAfter, ok[6] = r.hash()
	var count uint64
	count, ok[7] = r.u64()
	for _, o := range ok {
		if !o {
			return Manifest{}, errManifest
		}
	}
	// Bounded by what is left rather than by what was declared: each entry
	// costs at least four bytes of length and forty-eight of root.
	if count > uint64(len(b))/52 {
		return Manifest{}, errManifest
	}
	for i := uint64(0); i < count; i++ {
		n, ok := r.u32()
		if !ok {
			return Manifest{}, errManifest
		}
		name, ok := r.take(int(n))
		if !ok || !known(string(name)) {
			return Manifest{}, errManifest
		}
		root, ok := r.hash()
		if !ok {
			return Manifest{}, errManifest
		}
		m.IndexRoots = append(m.IndexRoots, IndexRoot{Name: string(name), Root: root})
	}
	var ok1, ok2 bool
	m.FirstRecordedAt, ok1 = r.u64()
	m.LastRecordedAt, ok2 = r.u64()
	alg, ok3 := r.take(3)
	if !ok1 || !ok2 || !ok3 || r.at != len(b) {
		return Manifest{}, errManifest
	}
	copy(m.Algorithms[:], alg)
	// hash: sha384 (1); signature: es256 (1), ml-dsa-65 (2), slh-dsa (3), es384 (4); kem: x25519-ml-kem-768 (1).
	if m.Algorithms[0] != 1 || m.Algorithms[1] < 1 || m.Algorithms[1] > 4 || m.Algorithms[2] != 1 {
		return Manifest{}, errManifest
	}
	return m, nil
}

func known(name string) bool {
	for _, d := range Dimensions {
		if d == name {
			return true
		}
	}
	return false
}

// Root is manifest_root: the manifest's fields under trailryx's domain, the
// dimension names length-prefixed with eight bytes rather than the four the
// encoding uses.
func (m Manifest) Root() Hash {
	var b []byte
	b = append(b, "trailryx/segment-manifest/v1\x00"...)
	b = binary.BigEndian.AppendUint16(b, m.FormatVersion)
	b = binary.BigEndian.AppendUint64(b, m.Segment)
	b = binary.BigEndian.AppendUint16(b, m.Shard)
	b = binary.BigEndian.AppendUint64(b, m.Records)
	b = append(b, m.HistoryRoot[:]...)
	b = append(b, m.ChainBefore[:]...)
	b = append(b, m.ChainAfter[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(m.IndexRoots)))
	for _, r := range m.IndexRoots {
		b = binary.BigEndian.AppendUint64(b, uint64(len(r.Name)))
		b = append(b, r.Name...)
		b = append(b, r.Root[:]...)
	}
	b = binary.BigEndian.AppendUint64(b, m.FirstRecordedAt)
	b = binary.BigEndian.AppendUint64(b, m.LastRecordedAt)
	b = append(b, m.Algorithms[:]...)
	return sha512.Sum384(b)
}

// Shard is one shard's sealed segments, in order.
type Shard struct {
	Shard     uint16
	Segments  uint64
	Root      Hash
	Manifests []Hash
}

// ShardRootOf is the root over the first k manifest roots of a shard.
func ShardRootOf(manifests []Hash) Hash {
	leaves := make([]merkle.Hash, len(manifests))
	for i, m := range manifests {
		leaves[i] = merkle.LeafHash(m[:])
	}
	return merkle.Root(leaves)
}

// shardLeaf is shard_leaf.
func shardLeaf(shard uint16, segments uint64, root Hash) merkle.Hash {
	var b []byte
	b = append(b, "trailryx/store-leaf/v1\x00"...)
	b = binary.BigEndian.AppendUint16(b, shard)
	b = binary.BigEndian.AppendUint64(b, segments)
	b = append(b, root[:]...)
	inner := sha512.Sum384(b)
	return merkle.LeafHash(inner[:])
}

// Store is a data directory's sealed state.
type Store struct {
	Shards   []Shard
	Segments uint64
	Root     Hash
}

// StoreRoot is the store root over shards in shard order.
func StoreRoot(shards []Shard) Hash {
	leaves := make([]merkle.Hash, len(shards))
	for i, s := range shards {
		leaves[i] = shardLeaf(s.Shard, s.Segments, s.Root)
	}
	return merkle.Root(leaves)
}

var manifestName = regexp.MustCompile(`^s([0-9]{1,5})-([0-9]{6,20})\.mf$`)

// ReadStore reads every sealed segment of every shard in dir, in order. A
// directory that does not exist holds no sealed segments; a manifest that is
// not one, or that describes another segment or shard than its name, refuses.
func ReadStore(dir string) (Store, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return Store{Root: StoreRoot(nil)}, nil
	}
	if err != nil {
		return Store{}, err
	}
	type seg struct {
		n    uint64
		root Hash
	}
	shards := map[uint16][]seg{}
	for _, e := range entries {
		mm := manifestName.FindStringSubmatch(e.Name())
		if mm == nil || !e.Type().IsRegular() {
			continue
		}
		shard, err1 := strconv.ParseUint(mm[1], 10, 16)
		segment, err2 := strconv.ParseUint(mm[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path) // #nosec G304 -- a file in a trailryx data directory the operator named
		if err != nil {
			return Store{}, err
		}
		m, err := DecodeManifest(raw)
		if err != nil {
			return Store{}, fmt.Errorf("%s: %w", path, err)
		}
		if m.Segment != segment || m.Shard != uint16(shard) {
			return Store{}, fmt.Errorf("%s: the manifest inside describes segment %d of shard %d", path, m.Segment, m.Shard)
		}
		shards[uint16(shard)] = append(shards[uint16(shard)], seg{segment, m.Root()})
	}
	var st Store
	for shard, segs := range shards {
		sort.Slice(segs, func(i, j int) bool { return segs[i].n < segs[j].n })
		s := Shard{Shard: shard, Segments: uint64(len(segs))}
		for _, sg := range segs {
			s.Manifests = append(s.Manifests, sg.root)
		}
		s.Root = ShardRootOf(s.Manifests)
		st.Shards = append(st.Shards, s)
		st.Segments += s.Segments
	}
	sort.Slice(st.Shards, func(i, j int) bool { return st.Shards[i].Shard < st.Shards[j].Shard })
	st.Root = StoreRoot(st.Shards)
	return st, nil
}

// MaxWitnessName bounds a witness name, as trailryx-sign does.
const MaxWitnessName = 64

var witnessName = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// CheckWitnessName is check_witness_name: a bounded token, never free text.
func CheckWitnessName(name string) error {
	if !witnessName.MatchString(name) {
		return errors.New("trailryx: a witness name is 1 to 64 of a-z 0-9 . _ -")
	}
	return nil
}

func field(b, v []byte) []byte {
	return append(binary.BigEndian.AppendUint64(b, uint64(len(v))), v...)
}

// WitnessStatement is witness_statement: what one witness asserts, that this
// root existed and it saw it then.
func WitnessStatement(witness string, storeRoot Hash, seenAt uint64, alg string, pub []byte) []byte {
	b := []byte("trailryx/witness/v1\x00")
	b = field(b, []byte(witness))
	b = field(b, storeRoot[:])
	b = binary.BigEndian.AppendUint64(b, seenAt)
	b = field(b, []byte(alg))
	return field(b, pub)
}
