package trailryx

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The witness attests to trailryx's store root, so it has to compute the root
// trailryx-verify computes, from the manifests trailryx-node writes, byte for
// byte. These tests rebuild every byte layout by hand from the Rust source
// (trailryx 92dd4b6: crates/trailryx-store/src/evidence.rs encode_manifest,
// crates/trailryx-verify/src/verify.rs manifest_root and shard_leaf,
// crates/trailryx-verify/src/merkle.rs, crates/trailryx-sign/src/lib.rs
// witness_statement), independently of this package's code.

func h(b byte) Hash {
	var x Hash
	for i := range x {
		x[i] = b + byte(i)
	}
	return x
}

func aManifest(shard uint16, segment uint64) Manifest {
	return Manifest{FormatVersion: 1, Segment: segment, Shard: shard, Records: 10 * segment,
		HistoryRoot: h(1), ChainBefore: h(2), ChainAfter: h(3),
		IndexRoots:      []IndexRoot{{"id", h(4)}, {"recorded_at", h(5)}, {"agent_id", h(6)}, {"run_id", h(7)}, {"event_type", h(8)}},
		FirstRecordedAt: 1_792_000_000_000_000_000 + segment, LastRecordedAt: 1_792_000_000_500_000_000 + segment, Algorithms: [3]byte{1, 4, 1}}
}

// byHand is encode_manifest written out from the Rust, not from Encode.
func byHand(m Manifest) []byte {
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

func TestAManifestDecodesAsTrailryxEncodesIt(t *testing.T) {
	m := aManifest(0, 3)
	raw := byHand(m)
	got, err := DecodeManifest(raw)
	if err != nil {
		t.Fatalf("a manifest laid out as trailryx writes it: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint(m) {
		t.Fatalf("decoded %+v, wrote %+v", got, m)
	}
	if !bytes.Equal(EncodeManifest(m), raw) {
		t.Fatal("EncodeManifest does not write what trailryx writes")
	}
}

func TestHostileManifestsNeverDecodeAndNeverPanic(t *testing.T) {
	raw := byHand(aManifest(0, 1))
	if _, err := DecodeManifest(raw); err != nil {
		t.Fatalf("control: %v", err)
	}
	for n := 0; n < len(raw); n++ {
		if _, err := DecodeManifest(raw[:n]); err == nil {
			t.Fatalf("a manifest cut to %d of %d bytes decoded", n, len(raw))
		}
	}
	at := func(m Manifest) int { return 2 + 8 + 2 + 8 + 48*3 } // the index count
	edit := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), raw...)) }
	for name, b := range map[string][]byte{
		"a byte after the end": append(append([]byte(nil), raw...), 0),
		"a count past what the bytes hold": edit(func(b []byte) []byte {
			binary.BigEndian.PutUint64(b[at(Manifest{}):], 1<<40)
			return b
		}),
		"an unknown dimension": bytes.Replace(raw, []byte("run_id"), []byte("run_ix"), 1),
		"an unknown hash":      edit(func(b []byte) []byte { b[len(b)-3] = 2; return b }),
		"an unknown signature": edit(func(b []byte) []byte { b[len(b)-2] = 9; return b }),
		"an unknown kem":       edit(func(b []byte) []byte { b[len(b)-1] = 0; return b }),
		"a name longer than the bytes": edit(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[at(Manifest{})+8:], 1<<30)
			return b
		}),
	} {
		if _, err := DecodeManifest(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	r := mrand.New(mrand.NewPCG(20261018, 31))
	for i := 0; i < 3000; i++ {
		b := append([]byte(nil), raw...)
		for k := 0; k <= r.IntN(3); k++ {
			b[r.IntN(len(b))] = byte(r.IntN(256))
		}
		if m, err := DecodeManifest(b); err == nil && !bytes.Equal(EncodeManifest(m), b) {
			t.Fatalf("case %d: decoded into something that does not encode back to its bytes", i)
		}
	}
}

// The reference construction, written from trailryx-verify's source.
func refManifestRoot(m Manifest) Hash {
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

func refLeaf(d []byte) Hash { return sha512.Sum384(append([]byte{0}, d...)) }

func refNode(a, b Hash) Hash { return sha512.Sum384(append(append([]byte{1}, a[:]...), b[:]...)) }

func refRoot(ls []Hash) Hash {
	switch len(ls) {
	case 0:
		return sha512.Sum384(nil)
	case 1:
		return ls[0]
	}
	k := 1
	for k<<1 < len(ls) {
		k <<= 1
	}
	return refNode(refRoot(ls[:k]), refRoot(ls[k:]))
}

func refShardLeaf(shard uint16, segments uint64, root Hash) Hash {
	var b []byte
	b = append(b, "trailryx/store-leaf/v1\x00"...)
	b = binary.BigEndian.AppendUint16(b, shard)
	b = binary.BigEndian.AppendUint64(b, segments)
	b = append(b, root[:]...)
	inner := sha512.Sum384(b)
	return refLeaf(inner[:])
}

func writeStore(t *testing.T, dir string, shards map[uint16]uint64) map[uint16][]Manifest {
	t.Helper()
	out := map[uint16][]Manifest{}
	for shard, n := range shards {
		for seg := uint64(1); seg <= n; seg++ {
			m := aManifest(shard, seg)
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("s%d-%06d.mf", shard, seg)), byHand(m), 0o600); err != nil {
				t.Fatal(err)
			}
			out[shard] = append(out[shard], m)
		}
	}
	return out
}

func TestTheStoreRootIsTrailryxVerifysConstruction(t *testing.T) {
	dir := t.TempDir()
	written := writeStore(t, dir, map[uint16]uint64{0: 3, 1: 1})
	// Files a trailryx data directory also holds, which are not manifests.
	for _, f := range []string{"s0-000004.trlx", "s0-000004.mf.part", "s0-9f3a.cur", "notes.txt"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600)
	}
	st, err := ReadStore(dir)
	if err != nil {
		t.Fatalf("ReadStore: %v", err)
	}
	var storeLeaves []Hash
	for _, shard := range []uint16{0, 1} {
		var ls []Hash
		for _, m := range written[shard] {
			if m.Root() != refManifestRoot(m) {
				t.Fatalf("shard %d segment %d: the manifest root is not trailryx-verify's", shard, m.Segment)
			}
			ls = append(ls, refLeaf(func() []byte { r := refManifestRoot(m); return r[:] }()))
		}
		storeLeaves = append(storeLeaves, refShardLeaf(shard, uint64(len(ls)), refRoot(ls)))
	}
	if st.Root != refRoot(storeLeaves) {
		t.Fatal("the store root is not the one trailryx-verify derives from the same manifests")
	}
	if st.Segments != 4 || len(st.Shards) != 2 || st.Shards[0].Segments != 3 {
		t.Fatalf("store %+v", st)
	}
}

func TestAStoreDirectoryIsReadAsTrailryxNodeReadsIt(t *testing.T) {
	dir := t.TempDir()
	writeStore(t, dir, map[uint16]uint64{0: 2})
	if _, err := ReadStore(dir); err != nil {
		t.Fatalf("control: %v", err)
	}
	// A manifest filed under another segment's name: trailryx-node refuses it.
	moved := t.TempDir()
	m := aManifest(0, 2)
	_ = os.WriteFile(filepath.Join(moved, "s0-000001.mf"), byHand(m), 0o600)
	if _, err := ReadStore(moved); err == nil || !strings.Contains(err.Error(), "describes") {
		t.Fatalf("a manifest under another segment's name: %v", err)
	}
	other := t.TempDir()
	_ = os.WriteFile(filepath.Join(other, "s3-000001.mf"), byHand(aManifest(0, 1)), 0o600)
	if _, err := ReadStore(other); err == nil {
		t.Fatal("a manifest under another shard's name was read")
	}
	garbage := t.TempDir()
	_ = os.WriteFile(filepath.Join(garbage, "s0-000001.mf"), []byte("not a manifest"), 0o600)
	if _, err := ReadStore(garbage); err == nil {
		t.Fatal("a file that is not a manifest was read as one")
	}
	if st, err := ReadStore(filepath.Join(t.TempDir(), "absent")); err != nil || st.Segments != 0 {
		t.Fatalf("a directory that does not exist yet holds no sealed segments: %+v %v", st, err)
	}
}

func TestTheWitnessStatementIsTrailryxSignsBytes(t *testing.T) {
	root := h(9)
	pub := append([]byte{4}, bytes.Repeat([]byte{7}, 96)...)
	got := WitnessStatement("keyryx-witness", root, 1_792_000_000_123_456_789, "es384", pub)
	field := func(b []byte) []byte { return append(binary.BigEndian.AppendUint64(nil, uint64(len(b))), b...) }
	var want []byte
	want = append(want, "trailryx/witness/v1\x00"...)
	want = append(want, field([]byte("keyryx-witness"))...)
	want = append(want, field(root[:])...)
	want = binary.BigEndian.AppendUint64(want, 1_792_000_000_123_456_789)
	want = append(want, field([]byte("es384"))...)
	want = append(want, field(pub)...)
	if !bytes.Equal(got, want) {
		t.Fatal("the witness statement is not trailryx-sign's bytes")
	}
	if bytes.Equal(WitnessStatement("ab", Hash{}, 1, "es384", []byte("c")), WitnessStatement("a", Hash{}, 1, "es384", []byte("bc"))) {
		t.Fatal("two fields ran into one")
	}
	if err := CheckWitnessName("keyryx-witness.a_1"); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, bad := range []string{"", "Keyryx", "a b", "a\nb", strings.Repeat("a", 65), "kpmg.example\n[note] root-signature"} {
		if CheckWitnessName(bad) == nil {
			t.Errorf("the witness name %q was accepted", bad)
		}
	}
}
