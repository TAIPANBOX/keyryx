package announce

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// OpenBus opens custody's stream on the bus for the delivery loop. The bus
// directory is shared, and a plane that can write it could put a link at
// custody's name pointing at a file custody can write (its use log, a key
// record), so that custody appends its announcements there, or swap one in
// while custody opens the file. So custody opens the name itself, never
// following a link (O_NOFOLLOW; it creates the file, O_EXCL, when it is not
// there), checks the file it holds, not the name: a regular file with one
// link, owned by uid, custody's own; and hands the writer that very file
// through the descriptor's own path, which names the open file whatever is at
// the name by then. A file another plane made is not custody's, whatever its
// name.
func OpenBus(path string, uid int) (Emitter, error) {
	const flags = os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	f, err := os.OpenFile(path, flags, 0) // #nosec G304 -- the operator's KEYRYX_EVENTS, held to custody's own file below
	if errors.Is(err, fs.ErrNotExist) {
		f, err = os.OpenFile(path, flags|os.O_CREATE|os.O_EXCL, 0o640) // #nosec G304 -- as above
		if err == nil {
			err = f.Chmod(0o640)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s does not open as custody's own file: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := ownStream(path, info, uid); err != nil {
		return nil, err
	}
	beforeTheWriterOpens(path)
	w, err := event.NewChainedWriter(fdPath(f))
	if err != nil {
		return nil, err
	}
	return w, nil
}

// beforeTheWriterOpens runs between the checks and the writer's open. A test
// swaps the name there, as a plane racing custody would; nothing else sets it.
var beforeTheWriterOpens = func(string) {}

func ownStream(path string, info fs.FileInfo, uid int) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (%s), so custody does not write its announcements there", path, info.Mode().Type())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: its owner cannot be read on this platform", path)
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("%s belongs to uid %d, not to custody's uid %d, so another plane made it", path, st.Uid, uid)
	}
	if uint64(st.Nlink) != 1 {
		return fmt.Errorf("%s has %d links, so it is also another file", path, st.Nlink)
	}
	return nil
}
