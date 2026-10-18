package merkle

import (
	"crypto/sha512"
	"fmt"
	mrand "math/rand/v2"
	"testing"
)

// The witness's own log is a Merkle tree so that a verifier holding an old
// tree head can prove the log only grew. A proof that verifies when it should
// not is a witness that rewrote its own history and got away with it.

func leaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = LeafHash([]byte(fmt.Sprintf("entry %d", i)))
	}
	return out
}

func TestTheRootsRFC9162Specifies(t *testing.T) {
	if EmptyRoot() != Hash(sha512.Sum384(nil)) {
		t.Fatal("the empty tree's root is not the hash of the empty string")
	}
	if Root(nil) != EmptyRoot() {
		t.Fatal("Root of no leaves is not the empty root")
	}
	a, b, c := LeafHash([]byte("a")), LeafHash([]byte("b")), LeafHash([]byte("c"))
	want := sha512.Sum384(append([]byte{0}, 'a'))
	if a != Hash(want) {
		t.Fatal("a leaf is not SHA-384 over 0x00 and its data")
	}
	if Root([]Hash{a}) != a {
		t.Fatal("one leaf is its own root")
	}
	n := sha512.Sum384(append(append([]byte{1}, a[:]...), b[:]...))
	if Root([]Hash{a, b}) != Hash(n) || NodeHash(a, b) != Hash(n) {
		t.Fatal("a node is not SHA-384 over 0x01 and its children")
	}
	// Three leaves split 2 + 1: the largest power of two strictly below n.
	if Root([]Hash{a, b, c}) != NodeHash(NodeHash(a, b), c) {
		t.Fatal("three leaves do not split 2 + 1")
	}
	if LeafHash(append(a[:], b[:]...)) == NodeHash(a, b) {
		t.Fatal("a leaf can stand in for a node")
	}
}

func TestEveryInclusionProofVerifiesAndNoOtherDoes(t *testing.T) {
	for n := 1; n <= 33; n++ {
		ls := leaves(n)
		root := Root(ls)
		for i := 0; i < n; i++ {
			p, err := InclusionProof(ls, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(ls[i], i, n, p, root) {
				t.Fatalf("n=%d i=%d: the honest proof does not verify", n, i)
			}
			if VerifyInclusion(LeafHash([]byte("not in the tree")), i, n, p, root) {
				t.Fatalf("n=%d i=%d: another leaf verified", n, i)
			}
			if n > 1 && VerifyInclusion(ls[i], (i+1)%n, n, p, root) {
				t.Fatalf("n=%d i=%d: the proof verified at another index", n, i)
			}
			// A proof is for one (size, root) pair, which a signed head binds
			// together: in the tree one leaf larger, it does not verify.
			bigger := append(append([]Hash(nil), ls...), LeafHash([]byte("one more")))
			if VerifyInclusion(ls[i], i, n+1, p, Root(bigger)) {
				t.Fatalf("n=%d i=%d: the proof verified in the tree one leaf larger", n, i)
			}
			if len(p) > 0 {
				bad := append([]Hash(nil), p...)
				bad[len(bad)-1][0] ^= 1
				if VerifyInclusion(ls[i], i, n, bad, root) {
					t.Fatalf("n=%d i=%d: an edited proof verified", n, i)
				}
				if VerifyInclusion(ls[i], i, n, append(p, p[0]), root) {
					t.Fatalf("n=%d i=%d: a proof with a node more verified", n, i)
				}
			}
		}
		if _, err := InclusionProof(ls, n); err == nil {
			t.Fatalf("n=%d: a proof for an index past the tree", n)
		}
	}
}

func TestEveryConsistencyProofVerifiesAndNoOtherDoes(t *testing.T) {
	for n := 1; n <= 33; n++ {
		ls := leaves(n)
		newRoot := Root(ls)
		for m := 1; m <= n; m++ {
			oldRoot := Root(ls[:m])
			p, err := ConsistencyProof(ls, m)
			if err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			if !VerifyConsistency(m, n, p, oldRoot, newRoot) {
				t.Fatalf("m=%d n=%d: the honest proof does not verify", m, n)
			}
			forged := oldRoot
			forged[0] ^= 1
			if VerifyConsistency(m, n, p, forged, newRoot) {
				t.Fatalf("m=%d n=%d: the proof verified from another old root", m, n)
			}
			// A rewritten history: the same size, one earlier leaf changed.
			other := append([]Hash(nil), ls...)
			other[0] = LeafHash([]byte("rewritten"))
			if m < n && VerifyConsistency(m, n, p, oldRoot, Root(other)) {
				t.Fatalf("m=%d n=%d: a rewritten tree verified as an extension", m, n)
			}
			if len(p) > 0 {
				bad := append([]Hash(nil), p...)
				bad[0][3] ^= 1
				if VerifyConsistency(m, n, bad, oldRoot, newRoot) {
					t.Fatalf("m=%d n=%d: an edited proof verified", m, n)
				}
			}
		}
		if _, err := ConsistencyProof(ls, 0); err == nil {
			t.Fatalf("n=%d: a consistency proof from an empty tree", n)
		}
		if _, err := ConsistencyProof(ls, n+1); err == nil {
			t.Fatalf("n=%d: a consistency proof to a larger tree", n)
		}
	}
}

func TestHostileProofsNeverVerifyAndNeverPanic(t *testing.T) {
	ls := leaves(21)
	root := Root(ls)
	// Control: the honest proofs verify, so a verifier that says no to
	// everything does not pass this test.
	if p, err := InclusionProof(ls, 5); err != nil || !VerifyInclusion(ls[5], 5, 21, p, root) {
		t.Fatalf("control: an honest inclusion proof: %v", err)
	}
	if p, err := ConsistencyProof(ls, 8); err != nil || !VerifyConsistency(8, 21, p, Root(ls[:8]), root) {
		t.Fatalf("control: an honest consistency proof: %v", err)
	}
	r := mrand.New(mrand.NewPCG(20261018, 21))
	random := func() []Hash {
		p := make([]Hash, r.IntN(9))
		for i := range p {
			for j := range p[i] {
				p[i][j] = byte(r.IntN(256))
			}
		}
		return p
	}
	for i := 0; i < 3000; i++ {
		idx, size := r.IntN(30)-3, r.IntN(30)-3
		if VerifyInclusion(ls[i%21], idx, size, random(), root) {
			t.Fatalf("case %d: a random inclusion proof verified", i)
		}
		m, n := r.IntN(30)-3, r.IntN(30)-3
		// Equal sizes and equal roots with an empty proof is the one honest
		// answer a random draw can produce.
		if VerifyConsistency(m, n, random(), Root(ls[:1+i%21]), root) && !(m == n && m > 0 && 1+i%21 == 21) {
			t.Fatalf("case %d: a random consistency proof verified (m=%d n=%d)", i, m, n)
		}
	}
}

func TestTheFrontierRootIsTheTreeRoot(t *testing.T) {
	var f Frontier
	if f.Root() != EmptyRoot() {
		t.Fatal("an empty frontier is not the empty tree")
	}
	ls := leaves(130)
	for n := 1; n <= len(ls); n++ {
		f.Add(ls[n-1])
		if f.Size() != n || f.Root() != Root(ls[:n]) {
			t.Fatalf("after %d leaves the frontier's root is not the tree's", n)
		}
	}
}
