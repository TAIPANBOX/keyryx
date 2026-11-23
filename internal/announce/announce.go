// Package announce tells the bus what an admin did to custody's keys.
//
// A rotation and a revocation are each announced as an agent-event (SPEC 6.2:
// KeyRotated, info, and KeyRevoked, high, from source keyryx under the
// custody's own subject), so the people who read the bus hear of a key change
// they did not make. The announcement goes through an outbox in custody's data
// directory: the admin action changes the key, writes its use-log line, puts
// the announcement in the outbox (fsynced) and answers; a delivery loop writes
// the outbox to the bus in order and records how far it got.
//
// Why an outbox and not a write in the handler (CLAUDE.md invariant 43):
//
//   - The bus file is locked with flock(2) by every writer, and the bus
//     directory is shared. A write in the handler would let anything that can
//     open the file hold the lock and stall a revocation, which is the
//     emergency action.
//   - A write that fails after the key changed would be lost: the retry is a
//     second rotation (refused while one is pending) or a revocation of a kid
//     that is already revoked. The outbox keeps it until the bus takes it,
//     across a restart too.
//
// Delivery is at least once: a death between the bus write and the cursor
// write repeats one announcement after the restart. `Pending` says how many
// are waiting, and custody's state route shows it.
//
// The bus stream is opened by the delivery loop, not at the start: its writer
// takes the stream's lock when it opens, and a lock held by someone else must
// not keep custody, and so its admin socket, from coming up.
//
// The outbox keeps every announcement it ever took, so a retried admin action
// can ask whether its change was announced (Has, Count) and announce it when a
// failure in between left it out.
package announce

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// Subject is custody's own subject on the bus (SPEC 6.2's keyryx bullet).
const Subject = "agent://keyryx.internal/custody"

// The two types custody announces, and the band SPEC 6.2 gives each.
const (
	KeyRotated = "key_rotated"
	KeyRevoked = "key_revoked"
)

var severity = map[string]string{
	KeyRotated: event.SeverityInfo,
	KeyRevoked: event.SeverityHigh,
}

// The outbox and its cursor, inside custody's data directory.
const (
	OutboxName = "announce.ndjson"
	CursorName = "announce.done"
)

// FinalWait bounds the last delivery when custody stops.
const FinalWait = 3 * time.Second

// maxLine bounds one outbox line. An announcement is four short strings.
const maxLine = 4 << 10

// Emitter is where announcements go: the bus file's chained writer.
type Emitter interface {
	Write(event.Event) error
}

// Rotated is a key_rotated announcement: name is the key name, kid the new
// key, previous the key it replaces ("" when there was none) and alg its
// algorithm.
func Rotated(name, kid, previous, alg string) Announcement {
	return Announcement{Type: KeyRotated, Data: map[string]string{"name": name, "kid": kid, "previous_kid": previous, "alg": alg}}
}

// Revoked is a key_revoked announcement.
func Revoked(name, kid, alg string) Announcement {
	return Announcement{Type: KeyRevoked, Data: map[string]string{"name": name, "kid": kid, "alg": alg}}
}

// Announcement is one event waiting for the bus.
type Announcement struct {
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}

// event is the agent-event an announcement made at ts becomes on the bus.
func (a Announcement) event(ts time.Time) event.Event {
	data := make(map[string]any, len(a.Data))
	for k, v := range a.Data {
		data[k] = v
	}
	return event.Event{Schema: event.SchemaV10, TS: ts.UTC().Format("2006-01-02T15:04:05.000Z"),
		Source: "keyryx", Type: a.Type, AgentID: Subject, Severity: severity[a.Type], Data: data}
}

type line struct {
	Seq  int64             `json:"seq"`
	At   string            `json:"at"`
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}

// file is what the outbox needs of its file; a test stands in a failing one.
type file interface {
	io.Reader
	io.WriterAt
	Sync() error
	Truncate(int64) error
	Close() error
}

// Outbox is the open outbox. Safe for concurrent use.
type Outbox struct {
	mu      sync.Mutex
	dir     string
	f       file
	size    int64 // the bytes of whole, synced lines: where the next one goes
	broken  error // set when a failed append could not be taken back
	lines   []line
	done    int64
	deliver sync.Mutex // one delivery at a time; it owns emit
	bus     func() (Emitter, error)
	emit    Emitter
	now     func() time.Time
	kick    chan struct{}
	logf    func(string, ...any)
	retryIn time.Duration
}

// Fixed is a bus that is already open.
func Fixed(e Emitter) func() (Emitter, error) {
	return func() (Emitter, error) { return e, nil }
}

// Open reads the outbox in dir and its cursor. A torn last line is dropped (an
// append the process died in); any other line that does not read, or a
// sequence that skips, refuses the open, because an outbox custody did not
// write is not one it should deliver.
func Open(dir string, bus func() (Emitter, error), now func() time.Time, logf func(string, ...any)) (*Outbox, error) {
	if bus == nil {
		return nil, errors.New("announce: no bus to announce to")
	}
	path := filepath.Join(dir, OutboxName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- custody's own data directory
	if err != nil {
		return nil, err
	}
	// A cursor write the process died in leaves its temporary file behind.
	if left, err := filepath.Glob(filepath.Join(dir, CursorName+".*")); err == nil {
		for _, l := range left {
			_ = os.Remove(l)
		}
	}
	o := &Outbox{dir: dir, f: f, bus: bus, now: now, logf: logf, kick: make(chan struct{}, 1), retryIn: 5 * time.Second}
	if err := o.load(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("announce: %s: %w", path, err)
	}
	return o, nil
}

func (o *Outbox) load() error {
	raw, err := io.ReadAll(o.f)
	if err != nil {
		return err
	}
	complete := bytes.LastIndexByte(raw, '\n') + 1
	if complete < len(raw) {
		if err := o.f.Truncate(int64(complete)); err != nil {
			return err
		}
	}
	o.size = int64(complete)
	sc := bufio.NewScanner(bytes.NewReader(raw[:complete]))
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		var l line
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&l); err != nil {
			return fmt.Errorf("line %d does not read: %w", len(o.lines)+1, err)
		}
		if l.Seq != int64(len(o.lines))+1 {
			return fmt.Errorf("line %d carries sequence %d", len(o.lines)+1, l.Seq)
		}
		if err := check(Announcement{Type: l.Type, Data: l.Data}); err != nil {
			return fmt.Errorf("line %d: %w", l.Seq, err)
		}
		if _, err := time.Parse(time.RFC3339Nano, l.At); err != nil {
			return fmt.Errorf("line %d has no time: %w", l.Seq, err)
		}
		o.lines = append(o.lines, l)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	cur, err := os.ReadFile(filepath.Join(o.dir, CursorName)) // #nosec G304 -- custody's own data directory
	switch {
	case errors.Is(err, os.ErrNotExist):
		o.done = 0
	case err != nil:
		return err
	default:
		n, err := strconv.ParseInt(strings.TrimSpace(string(cur)), 10, 64)
		if err != nil || n < 0 || n > int64(len(o.lines)) {
			return fmt.Errorf("the cursor %q is not a count of its lines (%d)", strings.TrimSpace(string(cur)), len(o.lines))
		}
		o.done = n
	}
	return nil
}

// check holds an announcement to the shapes SPEC 6.2 fixes.
func check(a Announcement) error {
	var want []string
	switch a.Type {
	case KeyRotated:
		want = []string{"name", "kid", "previous_kid", "alg"}
	case KeyRevoked:
		want = []string{"name", "kid", "alg"}
	default:
		return fmt.Errorf("type %q is not one custody announces", a.Type)
	}
	if len(a.Data) != len(want) {
		return fmt.Errorf("%s carries %d members, want %v", a.Type, len(a.Data), want)
	}
	for _, k := range want {
		v, ok := a.Data[k]
		if !ok {
			return fmt.Errorf("%s has no %s", a.Type, k)
		}
		if v == "" && k != "previous_kid" {
			return fmt.Errorf("%s has an empty %s", a.Type, k)
		}
	}
	return nil
}

// Enqueue puts an announcement in the outbox and returns once it is on disk.
// It does not wait for the bus.
func (o *Outbox) Enqueue(a Announcement) error {
	if err := check(a); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.broken != nil {
		return o.broken
	}
	l := line{Seq: int64(len(o.lines)) + 1, At: o.now().UTC().Format(time.RFC3339Nano), Type: a.Type, Data: a.Data}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := o.f.WriteAt(b, o.size)
	if err == nil {
		err = o.f.Sync()
	}
	if err != nil {
		// Take back whatever reached the file, so the next line starts
		// where this one did and the outbox still reads at the next start.
		// If even that fails, nothing more is appended: a line glued to a
		// fragment would make the outbox unreadable.
		if terr := o.f.Truncate(o.size); terr != nil {
			o.broken = fmt.Errorf("announce: a failed append could not be taken back, so the outbox takes nothing more until a restart: %w", terr)
		}
		return err
	}
	o.size += int64(n)
	o.lines = append(o.lines, l)
	select {
	case o.kick <- struct{}{}:
	default:
	}
	return nil
}

// Has says whether the outbox holds an announcement of typ for kid, delivered
// or not.
func (o *Outbox) Has(typ, kid string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, l := range o.lines {
		if l.Type == typ && l.Data["kid"] == kid {
			return true
		}
	}
	return false
}

// Count is how many announcements of typ the outbox holds for the key name.
func (o *Outbox) Count(typ, name string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, l := range o.lines {
		if l.Type == typ && l.Data["name"] == name {
			n++
		}
	}
	return n
}

// Pending is how many announcements have not reached the bus yet.
func (o *Outbox) Pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.lines) - int(o.done)
}

// Deliver writes every pending announcement to the bus in order, and records
// each one delivered before it writes the next. It stops at the first that
// the bus does not take and says why.
func (o *Outbox) Deliver() error {
	o.deliver.Lock()
	defer o.deliver.Unlock()
	if o.emit == nil {
		e, err := o.bus()
		if err != nil {
			return fmt.Errorf("announce: the bus stream does not open: %w", err)
		}
		o.emit = e
	}
	for {
		o.mu.Lock()
		if o.done >= int64(len(o.lines)) {
			o.mu.Unlock()
			return nil
		}
		l := o.lines[o.done]
		o.mu.Unlock()
		ts, _ := time.Parse(time.RFC3339Nano, l.At)
		if err := o.emit.Write(Announcement{Type: l.Type, Data: l.Data}.event(ts)); err != nil {
			return fmt.Errorf("announce: the bus did not take %s %d: %w", l.Type, l.Seq, err)
		}
		if err := o.writeCursor(l.Seq); err != nil {
			return fmt.Errorf("announce: %s %d is on the bus and its cursor did not write: %w", l.Type, l.Seq, err)
		}
		o.mu.Lock()
		o.done = l.Seq
		o.mu.Unlock()
	}
}

func (o *Outbox) writeCursor(seq int64) error {
	tmp, err := os.CreateTemp(o.dir, CursorName+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(strconv.FormatInt(seq, 10) + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(o.dir, CursorName)); err != nil {
		return err
	}
	d, err := os.Open(o.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Run delivers until stop is closed: at once, after each Enqueue, and again
// every retry interval while something is pending. On stop it tries once more,
// for up to FinalWait, so a change made just before a shutdown is not left to
// the next start.
func (o *Outbox) Run(stop <-chan struct{}) {
	t := time.NewTicker(o.retryIn)
	defer t.Stop()
	for {
		if err := o.Deliver(); err != nil && o.logf != nil {
			o.logf("keyryx: %v; %d announcements wait for the bus", err, o.Pending())
		}
		select {
		case <-stop:
			done := make(chan struct{})
			go func() { _ = o.Deliver(); close(done) }()
			select {
			case <-done:
			case <-time.After(FinalWait):
			}
			return
		case <-o.kick:
		case <-t.C:
		}
	}
}

// Close closes the outbox file.
func (o *Outbox) Close() error { return o.f.Close() }
