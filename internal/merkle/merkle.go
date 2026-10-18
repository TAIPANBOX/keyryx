// Package merkle is RFC 9162's Merkle tree with SHA-384. Scaffold.
package merkle

import "errors"

// Hash is a SHA-384 digest.
type Hash [48]byte

var errScaffold = errors.New("merkle: not implemented")

func EmptyRoot() Hash                                                          { return Hash{} }
func LeafHash(data []byte) Hash                                                { return Hash{} }
func NodeHash(left, right Hash) Hash                                           { return Hash{} }
func Root(leaves []Hash) Hash                                                  { return Hash{} }
func InclusionProof(leaves []Hash, index int) ([]Hash, error)                  { return nil, errScaffold }
func VerifyInclusion(leaf Hash, index, size int, proof []Hash, root Hash) bool { return false }
func ConsistencyProof(leaves []Hash, m int) ([]Hash, error)                    { return nil, errScaffold }
func VerifyConsistency(m, n int, proof []Hash, oldRoot, newRoot Hash) bool     { return false }
