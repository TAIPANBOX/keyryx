// Package rootkey reads the root key every stored key is wrapped under.
// Scaffold: the signature the tests name, refusing everything.
package rootkey

import "errors"

// Size is the root key's length in bytes.
const Size = 32

// Load reads the root key file. Scaffold: refuses.
func Load(path string) ([Size]byte, error) {
	return [Size]byte{}, errors.New("rootkey: not implemented")
}
