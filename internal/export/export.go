// Package export writes public copies of what custody certified into a
// directory a reader on the same machine mounts read only: the delegation
// root's key set and, for every delegated key, its statement and when it was
// revoked. heraldyx reads them there rather than over the network, because a
// reader that may open no connection (its "one way out") can still read a file
// (CLAUDE.md invariant 44).
//
// What is written is public and nothing else: the same bytes custody serves on
// GET /v1/jwks/keyryx.delegation-root and GET /v1/statements/{kid}. The
// exporter is handed bytes, never the store.
//
// Every write is of the registry's state as it stands when the write is made,
// never a payload queued earlier, so an older state can never land after a
// newer one: a key's file is marked dirty, and whoever writes it next reads the
// current state. A write that fails stays dirty and is tried again by Run; a
// revocation and a change of the root are also written at once by the admin
// route that made them, which says 503 (the change stands) when that write
// failed, as it does for the use log.
package export

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RootFile is the delegation root's key set in the directory.
const RootFile = "delegation-root.jwks.json"

const tmpPrefix = ".tmp-"

// KidRe is what a delegated key's kid is: an RFC 7638 thumbprint, 43
// characters of base64url. Its file is <kid>.json.
var KidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Source is what the exporter writes from: custody's current state.
type Source interface {
	// RootSet is the delegation root's key set as custody publishes it.
	RootSet() ([]byte, error)
	// Statement is a delegated key's statement and when it was revoked (0
	// when it was not); false for a kid custody never certified.
	Statement(kid string) (raw []byte, revokedAt int64, ok bool)
	// Kids is every kid custody certified.
	Kids() []string
}

// Exporter is the open directory. Safe for concurrent use.
type Exporter struct {
	root *os.Root
	src  Source
	logf func(string, ...any)

	mu        sync.Mutex // one write at a time, so files land in the order states were read
	dirtyMu   sync.Mutex
	dirty     map[string]bool
	rootDirty bool
	kick      chan struct{}
	retryIn   time.Duration
}

// Check refuses a directory custody must not write: anything but a real
// directory, one owned by another uid, one its group or other users can write,
// and one that is, contains or is inside a directory named in avoid
// (custody's data directory, the directory of its event stream).
func Check(dir string, uid int, avoid []string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("%q is not a clean absolute path", dir)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory (%s)", dir, info.Mode().Type())
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by its group or other users (mode %o); only custody writes it", dir, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid {
		return fmt.Errorf("%s does not belong to custody's uid %d", dir, uid)
	}
	for _, a := range avoid {
		if a == "" {
			continue
		}
		a = filepath.Clean(a)
		if within(dir, a) || within(a, dir) {
			return fmt.Errorf("%s overlaps %s, which is not a directory to publish into", dir, a)
		}
	}
	return nil
}

func within(dir, parent string) bool {
	rel, err := filepath.Rel(parent, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Open opens dir, which Check has passed, and brings it to custody's state:
// a temporary file a write died in is removed, a name custody never writes
// refuses the open, and the root key set and every statement are written.
func Open(dir string, src Source, logf func(string, ...any)) (*Exporter, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	e := &Exporter{root: root, src: src, logf: logf, dirty: map[string]bool{}, kick: make(chan struct{}, 1), retryIn: 5 * time.Second}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	for _, de := range entries {
		name := de.Name()
		switch {
		case strings.HasPrefix(name, tmpPrefix) && de.Type().IsRegular():
			if err := root.Remove(name); err != nil {
				_ = root.Close()
				return nil, err
			}
		case name == RootFile && de.Type().IsRegular():
		case strings.HasSuffix(name, ".json") && KidRe.MatchString(strings.TrimSuffix(name, ".json")) && de.Type().IsRegular():
		default:
			_ = root.Close()
			return nil, fmt.Errorf("%s holds %q, which custody never writes; it publishes into a directory of its own", dir, name)
		}
	}
	if err := e.Root(); err != nil {
		_ = root.Close()
		return nil, err
	}
	for _, kid := range src.Kids() {
		if err := e.Kid(kid); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	return e, nil
}

// Root writes the root key set now. On failure it stays to be written by Run.
func (e *Exporter) Root() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dirtyMu.Lock()
	e.rootDirty = false
	e.dirtyMu.Unlock()
	raw, err := e.src.RootSet()
	if err == nil {
		err = e.write(RootFile, raw)
	}
	if err != nil {
		e.dirtyMu.Lock()
		e.rootDirty = true
		e.dirtyMu.Unlock()
		return fmt.Errorf("export: the root key set: %w", err)
	}
	return nil
}

// Kid writes a delegated key's file now, from custody's state as it stands.
// On failure it stays to be written by Run.
func (e *Exporter) Kid(kid string) error {
	if !KidRe.MatchString(kid) {
		return fmt.Errorf("export: %q is not a kid", kid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dirtyMu.Lock()
	delete(e.dirty, kid)
	e.dirtyMu.Unlock()
	raw, revoked, ok := e.src.Statement(kid)
	var err error
	if !ok {
		// Nothing to copy, now or later: not kept to be tried again.
		return fmt.Errorf("export: %s: custody holds no statement for it", kid)
	}
	{
		var body []byte
		body, err = json.Marshal(struct {
			Statement json.RawMessage `json:"statement"`
			RevokedAt int64           `json:"revoked_at"`
		}{raw, revoked})
		if err == nil {
			err = e.write(kid+".json", body)
		}
	}
	if err != nil {
		e.dirtyMu.Lock()
		e.dirty[kid] = true
		e.dirtyMu.Unlock()
		return fmt.Errorf("export: %s: %w", kid, err)
	}
	return nil
}

// Mark asks for a key's file to be written by Run, soon.
func (e *Exporter) Mark(kid string) {
	e.dirtyMu.Lock()
	e.dirty[kid] = true
	e.dirtyMu.Unlock()
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Unexported is how many files wait to be written.
func (e *Exporter) Unexported() int {
	e.dirtyMu.Lock()
	defer e.dirtyMu.Unlock()
	n := len(e.dirty)
	if e.rootDirty {
		n++
	}
	return n
}

// Flush writes everything that waits, once.
func (e *Exporter) Flush() {
	e.dirtyMu.Lock()
	root := e.rootDirty
	var kids []string
	for k := range e.dirty {
		kids = append(kids, k)
	}
	e.dirtyMu.Unlock()
	if root {
		if err := e.Root(); err != nil {
			e.logf("keyryx: %v; tried again in %s", err, e.retryIn)
		}
	}
	for _, k := range kids {
		if err := e.Kid(k); err != nil {
			e.logf("keyryx: %v; tried again in %s", err, e.retryIn)
		}
	}
}

// Run writes what waits until stop is closed: after each Mark, and every
// retry interval while anything waits.
func (e *Exporter) Run(stop <-chan struct{}) {
	t := time.NewTicker(e.retryIn)
	defer t.Stop()
	for {
		e.Flush()
		select {
		case <-stop:
			return
		case <-e.kick:
		case <-t.C:
		}
	}
}

// write replaces name in the directory with data, atomically: a new file of
// its own, synced, given mode 0644, renamed over the old one, and the
// directory synced. Everything goes through the open directory, so no name
// can lead outside it.
func (e *Exporter) write(name string, data []byte) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	f, err := e.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if werr == nil {
		werr = f.Chmod(0o644) // #nosec G302 -- a public copy of a public statement, read by another uid
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = e.root.Remove(tmp)
		return werr
	}
	if err := e.root.Rename(tmp, name); err != nil {
		_ = e.root.Remove(tmp)
		return err
	}
	d, err := e.root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Close closes the directory.
func (e *Exporter) Close() error { return e.root.Close() }
