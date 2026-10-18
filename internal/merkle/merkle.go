// Package merkle is RFC 9162's Merkle tree (sections 2.1.1 to 2.1.4) with
// SHA-384 in place of SHA-256, the hash trailryx's own trees and the
// witness's P-384 half use.
//
// A leaf hashes with a 0x00 prefix and a node with 0x01, so a leaf can never
// stand in for a node; the split point of n leaves is the largest power of two
// strictly below n. The proofs and their verification are RFC 9162's
// algorithms step for step: a witness whose log only grew can prove it to
// anyone holding an earlier tree head, and one that rewrote its log cannot.
package merkle

import (
	"crypto/sha512"
	"errors"
)

// Hash is a SHA-384 digest.
type Hash [48]byte

// EmptyRoot is the root of the empty tree: the hash of the empty string.
func EmptyRoot() Hash { return sha512.Sum384(nil) }

// LeafHash hashes one entry as a leaf.
func LeafHash(data []byte) Hash {
	return sha512.Sum384(append([]byte{0}, data...))
}

// NodeHash hashes two children into their parent.
func NodeHash(left, right Hash) Hash {
	b := make([]byte, 0, 1+2*len(left))
	b = append(b, 1)
	b = append(b, left[:]...)
	b = append(b, right[:]...)
	return sha512.Sum384(b)
}

// split is the largest power of two strictly below n, for n > 1.
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root is the tree root over leaves that are already leaf hashes.
func Root(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot()
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return NodeHash(Root(leaves[:k]), Root(leaves[k:]))
}

// InclusionProof is PATH(index, leaves), RFC 9162 section 2.1.3.1.
func InclusionProof(leaves []Hash, index int) ([]Hash, error) {
	if index < 0 || index >= len(leaves) {
		return nil, errors.New("merkle: the index is not a leaf of the tree")
	}
	return path(index, leaves), nil
}

func path(m int, d []Hash) []Hash {
	if len(d) <= 1 {
		return nil
	}
	k := split(len(d))
	if m < k {
		return append(path(m, d[:k]), Root(d[k:]))
	}
	return append(path(m-k, d[k:]), Root(d[:k]))
}

// VerifyInclusion is RFC 9162 section 2.1.3.2.
func VerifyInclusion(leaf Hash, index, size int, proof []Hash, root Hash) bool {
	if index < 0 || size <= 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// ConsistencyProof is PROOF(m, leaves), RFC 9162 section 2.1.4.1, from the
// tree of the first m leaves to the tree of all of them.
func ConsistencyProof(leaves []Hash, m int) ([]Hash, error) {
	if m <= 0 || m > len(leaves) {
		return nil, errors.New("merkle: the first size is not between one and the tree's size")
	}
	return subproof(m, leaves, true), nil
}

func subproof(m int, d []Hash, b bool) []Hash {
	n := len(d)
	if m == n {
		if b {
			return nil
		}
		return []Hash{Root(d)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(m, d[:k], b), Root(d[k:]))
	}
	return append(subproof(m-k, d[k:], false), Root(d[:k]))
}

// VerifyConsistency is RFC 9162 section 2.1.4.2: the tree of size n whose
// root is newRoot extends the tree of size m whose root is oldRoot.
func VerifyConsistency(m, n int, proof []Hash, oldRoot, newRoot Hash) bool {
	if m <= 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && oldRoot == newRoot
	}
	if m&(m-1) == 0 {
		proof = append([]Hash{oldRoot}, proof...)
	}
	if len(proof) == 0 {
		return false
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return fr == oldRoot && sr == newRoot && sn == 0
}

// Frontier is a tree's right edge: the roots of its perfect subtrees, largest
// first. It gives the root of a growing tree in O(log n) per leaf, without
// keeping the leaves.
type Frontier struct {
	nodes []Hash
	sizes []int
	n     int
}

// Add appends one leaf hash.
func (f *Frontier) Add(leaf Hash) {
	f.nodes, f.sizes = append(f.nodes, leaf), append(f.sizes, 1)
	f.n++
	for k := len(f.nodes); k >= 2 && f.sizes[k-1] == f.sizes[k-2]; k = len(f.nodes) {
		parent := NodeHash(f.nodes[k-2], f.nodes[k-1])
		f.nodes, f.sizes = append(f.nodes[:k-2], parent), append(f.sizes[:k-2], 2*f.sizes[k-2])
	}
}

// Size is the number of leaves added.
func (f *Frontier) Size() int { return f.n }

// Root is the root of the tree of every leaf added: the perfect subtrees
// folded from the right, which is the left-perfect split RFC 9162 defines.
func (f *Frontier) Root() Hash {
	if len(f.nodes) == 0 {
		return EmptyRoot()
	}
	r := f.nodes[len(f.nodes)-1]
	for i := len(f.nodes) - 2; i >= 0; i-- {
		r = NodeHash(f.nodes[i], r)
	}
	return r
}
