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
// record), so that custody appends its announcements there. The stream is
// therefore refused unless it is a regular file with one link, owned by uid,
// custody's own, and the same file before and after the writer opens it. A
// file another plane made is not custody's, whatever its name. When the
// stream is not there yet, the writer creates it only in a directory custody
// owns (agent-stack-go's rule), and the same checks hold for what it made.
func OpenBus(path string, uid int) (Emitter, error) {
	before, err := os.Lstat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := ownStream(path, before, uid); err != nil {
			return nil, err
		}
	}
	w, err := event.NewChainedWriter(path)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err == nil {
		err = ownStream(path, after, uid)
	}
	if err == nil && before != nil && !os.SameFile(before, after) {
		err = fmt.Errorf("%s was replaced while it was opened", path)
	}
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

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
