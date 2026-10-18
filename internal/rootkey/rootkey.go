// Package rootkey reads the root key every stored key is wrapped under.
//
// One file, sixty-four hex characters (an optional single newline after
// them), readable by its owner and nobody else. Anything else refuses the
// start: a key service that accepted a root key its group could read would
// come up looking exactly like one that did not, and every key it wrapped
// would be as safe as the file's least careful reader (CLAUDE.md invariant 16).
package rootkey

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// Size is the root key's length in bytes.
const Size = 32

// Load reads the root key file at path.
//
// The file must be a regular file (a symlink is followed, because a
// Kubernetes Secret mounts as one), carry no permission for group or other,
// and hold exactly sixty-four hex characters, optionally followed by one
// newline. An all-zero key is refused: it is the value an empty or
// uninitialised secret decodes to.
func Load(path string) ([Size]byte, error) {
	var key [Size]byte
	if path == "" {
		return key, errors.New("no root key file is named")
	}
	info, err := os.Stat(path)
	if err != nil {
		return key, fmt.Errorf("the root key file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return key, fmt.Errorf("the root key file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return key, fmt.Errorf("the root key file %s is readable by group or other (mode %o); it must be 0400 or 0600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path, read once at startup
	if err != nil {
		return key, fmt.Errorf("reading the root key file %s: %w", path, err)
	}
	if len(raw) == 2*Size+1 && raw[2*Size] == '\n' {
		raw = raw[:2*Size]
	}
	if len(raw) != 2*Size {
		return key, fmt.Errorf("the root key file %s does not hold exactly %d hex characters", path, 2*Size)
	}
	n, err := hex.Decode(key[:], raw)
	if err != nil || n != Size {
		return [Size]byte{}, fmt.Errorf("the root key file %s is not hex", path)
	}
	if key == ([Size]byte{}) {
		return key, fmt.Errorf("the root key file %s holds an all-zero key", path)
	}
	return key, nil
}
