//go:build linux

package announce

import (
	"os"
	"strconv"
)

// fdPath names an open file by its descriptor: opening it opens that file,
// not whatever is at the name it was opened by.
func fdPath(f *os.File) string { return "/proc/self/fd/" + strconv.Itoa(int(f.Fd())) }
