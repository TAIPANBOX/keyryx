package announce

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return t0 }

type sink struct {
	mu   sync.Mutex
	got  []event.Event
	fail error
	gate chan struct{}
}

func (s *sink) Write(e event.Event) error {
	if s.gate != nil {
		<-s.gate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.got = append(s.got, e)
	return nil
}

func dataDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func open(t *testing.T, dir string, e Emitter) *Outbox {
	t.Helper()
	o, err := Open(dir, Fixed(e), clock, nil)
	if err != nil {
		t.Fatalf("the outbox did not open: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func TestAnAnnouncementIsAnAgentEventFromCustodyOnTheChain(t *testing.T) {
	dir := dataDir(t)
	bus := filepath.Join(t.TempDir(), "keyryx-custody.ndjson")
	w, err := event.NewChainedWriter(bus)
	if err != nil {
		t.Fatal(err)
	}
	o := open(t, dir, w)
	for _, a := range []Announcement{Rotated("wardryx-approval", "new", "old", "ES256"), Revoked("wardryx-approval", "old", "ES256"), Rotated("trailryx-root", "first", "", "ES384")} {
		if err := o.Enqueue(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Deliver(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(bus)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := event.VerifyChain(bytes.NewReader(raw))
	if err != nil || !rep.Ok() {
		t.Fatalf("the announcements are not one chain: %v %+v", err, rep)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines on the bus, want 3", len(lines))
	}
	want := []struct {
		typ, sev string
		data     map[string]any
	}{
		{"key_rotated", "info", map[string]any{"name": "wardryx-approval", "kid": "new", "previous_kid": "old", "alg": "ES256"}},
		{"key_revoked", "high", map[string]any{"name": "wardryx-approval", "kid": "old", "alg": "ES256"}},
		{"key_rotated", "info", map[string]any{"name": "trailryx-root", "kid": "first", "previous_kid": "", "alg": "ES384"}},
	}
	for i, l := range lines {
		e, err := event.Unmarshal([]byte(l))
		if err != nil {
			t.Fatalf("line %d is not an agent-event: %v", i+1, err)
		}
		if e.Schema != event.SchemaV10 || e.Source != "keyryx" || e.AgentID != Subject || e.Type != want[i].typ || e.Severity != want[i].sev {
			t.Errorf("line %d: %s %s %s %s %s", i+1, e.Schema, e.Source, e.AgentID, e.Type, e.Severity)
		}
		if e.TS != "2026-11-23T12:00:00.000Z" {
			t.Errorf("line %d is stamped %s, not when the change was made", i+1, e.TS)
		}
		got, _ := json.Marshal(e.Data)
		exp, _ := json.Marshal(want[i].data)
		if string(got) != string(exp) {
			t.Errorf("line %d carries %s, want %s", i+1, got, exp)
		}
	}
	if o.Pending() != 0 {
		t.Fatalf("%d pending after delivery", o.Pending())
	}
}

func TestAnAnnouncementWaitsForTheBusAndSurvivesARestart(t *testing.T) {
	dir := dataDir(t)
	down := &sink{fail: errors.New("the bus is not writable")}
	o := open(t, dir, down)
	if err := o.Enqueue(Rotated("k", "b", "a", "ES256")); err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(Revoked("k", "a", "ES256")); err != nil {
		t.Fatal(err)
	}
	if err := o.Deliver(); err == nil {
		t.Fatal("a bus that refused said nothing")
	}
	if o.Pending() != 2 {
		t.Fatalf("%d pending after the bus refused, want 2", o.Pending())
	}
	_ = o.Close()

	// A restart: the outbox reads both back and delivers them in order.
	up := &sink{}
	o2 := open(t, dir, up)
	if o2.Pending() != 2 {
		t.Fatalf("%d pending after a restart, want 2", o2.Pending())
	}
	if err := o2.Deliver(); err != nil {
		t.Fatal(err)
	}
	if len(up.got) != 2 || up.got[0].Type != KeyRotated || up.got[1].Type != KeyRevoked {
		t.Fatalf("delivered %v", up.got)
	}
	_ = o2.Close()

	// Another restart delivers nothing again.
	again := &sink{}
	o3 := open(t, dir, again)
	if err := o3.Deliver(); err != nil || len(again.got) != 0 || o3.Pending() != 0 {
		t.Fatalf("a delivered announcement was delivered again: %v %v", err, again.got)
	}
}

func TestDeliveryStopsAtTheFirstRefusalAndKeepsTheOrder(t *testing.T) {
	dir := dataDir(t)
	s := &sink{}
	o := open(t, dir, s)
	_ = o.Enqueue(Rotated("k", "b", "a", "ES256"))
	if err := o.Deliver(); err != nil {
		t.Fatal(err)
	}
	s.fail = errors.New("down")
	_ = o.Enqueue(Revoked("k", "a", "ES256"))
	_ = o.Enqueue(Rotated("k", "c", "b", "ES256"))
	if err := o.Deliver(); err == nil || o.Pending() != 2 {
		t.Fatalf("pending %d after a refusal: %v", o.Pending(), err)
	}
	s.fail = nil
	if err := o.Deliver(); err != nil {
		t.Fatal(err)
	}
	if len(s.got) != 3 || s.got[1].Type != KeyRevoked || s.got[2].Data["kid"] != "c" {
		t.Fatalf("delivered out of order: %v", s.got)
	}
}

func TestEnqueueDoesNotWaitForTheBus(t *testing.T) {
	dir := dataDir(t)
	s := &sink{gate: make(chan struct{})}
	o := open(t, dir, s)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { o.Run(stop); close(done) }()
	_ = o.Enqueue(Rotated("k", "b", "a", "ES256"))
	// The delivery loop is now stuck in the bus write; the next enqueue,
	// which is a revocation answering an admin, must not wait for it.
	enq := make(chan error, 1)
	go func() { enq <- o.Enqueue(Revoked("k", "a", "ES256")) }()
	select {
	case err := <-enq:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an enqueue waited for a bus that held its lock")
	}
	close(s.gate)
	deadline := time.Now().Add(5 * time.Second)
	for o.Pending() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-done
	if o.Pending() != 0 || len(s.got) != 2 {
		t.Fatalf("the loop did not deliver both once the bus was free: pending %d, got %d", o.Pending(), len(s.got))
	}
}

func TestATornLastLineIsDroppedAndTheOutboxGoesOn(t *testing.T) {
	dir := dataDir(t)
	o := open(t, dir, &sink{})
	_ = o.Enqueue(Rotated("k", "b", "a", "ES256"))
	_ = o.Close()
	f, _ := os.OpenFile(filepath.Join(dir, OutboxName), os.O_APPEND|os.O_WRONLY, 0o600)
	// A fragment longer than the next line, so a line written over it
	// without the truncation would leave its tail behind.
	_, _ = f.WriteString(`{"seq":2,"at":"2026-11` + strings.Repeat("x", 400))
	_ = f.Close()
	s := &sink{}
	o2 := open(t, dir, s)
	if o2.Pending() != 1 {
		t.Fatalf("%d pending, want the one whole line", o2.Pending())
	}
	if err := o2.Enqueue(Revoked("k", "a", "ES256")); err != nil {
		t.Fatal(err)
	}
	if err := o2.Deliver(); err != nil || len(s.got) != 2 {
		t.Fatalf("after a torn line: %v %v", err, s.got)
	}
	_ = o2.Close()
	o3 := open(t, dir, &sink{})
	if o3.Pending() != 0 || !o3.Has(KeyRevoked, "a") {
		t.Fatalf("the outbox after a torn line and a new one does not read back whole: pending %d", o3.Pending())
	}
}

func TestAnOutboxCustodyDidNotWriteRefusesToOpen(t *testing.T) {
	good := `{"seq":1,"at":"2026-11-23T12:00:00Z","type":"key_revoked","data":{"name":"k","kid":"a","alg":"ES256"}}` + "\n"
	for name, c := range map[string]struct{ outbox, cursor string }{
		"a line that is not JSON":     {"not json\n", ""},
		"a sequence that skips":       {strings.Replace(good, `"seq":1`, `"seq":2`, 1), ""},
		"a type custody never writes": {strings.Replace(good, "key_revoked", "key_stolen", 1), ""},
		"a member SPEC does not list": {strings.Replace(good, `"alg":"ES256"`, `"alg":"ES256","secret":"x"`, 1), ""},
		"a missing member":            {strings.Replace(good, `,"alg":"ES256"`, "", 1), ""},
		"an unknown field":            {strings.Replace(good, `"seq":1,`, `"seq":1,"extra":true,`, 1), ""},
		"no time":                     {strings.Replace(good, `"2026-11-23T12:00:00Z"`, `"yesterday"`, 1), ""},
		"a cursor past its lines":     {good, "2\n"},
		"a cursor that is no count":   {good, "one\n"},
		"a negative cursor":           {good, "-1\n"},
		"a line over the bound":       {`{"seq":1,"at":"` + strings.Repeat("9", 5000) + "\"}\n", ""},
	} {
		dir := dataDir(t)
		if err := os.WriteFile(filepath.Join(dir, OutboxName), []byte(c.outbox), 0o600); err != nil {
			t.Fatal(err)
		}
		if c.cursor != "" {
			_ = os.WriteFile(filepath.Join(dir, CursorName), []byte(c.cursor), 0o600)
		}
		if o, err := Open(dir, Fixed(&sink{}), clock, nil); err == nil {
			_ = o.Close()
			t.Errorf("%s: the outbox opened", name)
		}
	}
	if _, err := Open(dataDir(t), nil, clock, nil); err == nil {
		t.Error("an outbox with no bus opened")
	}
}

func TestOnlyTheShapesSpecFixesAreEnqueued(t *testing.T) {
	o := open(t, dataDir(t), &sink{})
	for name, a := range map[string]Announcement{
		"an unknown type":                   {Type: "key_lost", Data: map[string]string{"name": "k", "kid": "a", "alg": "ES256"}},
		"a rotation with no kid":            Rotated("k", "", "a", "ES256"),
		"a rotation with no name":           Rotated("", "b", "a", "ES256"),
		"a rotation with no alg":            Rotated("k", "b", "a", ""),
		"a revocation with no kid":          Revoked("k", "", "ES256"),
		"an extra member":                   {Type: KeyRevoked, Data: map[string]string{"name": "k", "kid": "a", "alg": "ES256", "d": "x"}},
		"a revocation shaped as a rotation": {Type: KeyRevoked, Data: map[string]string{"name": "k", "kid": "a", "previous_kid": "", "alg": "ES256"}},
	} {
		if err := o.Enqueue(a); err == nil {
			t.Errorf("%s was enqueued", name)
		}
	}
	if o.Pending() != 0 {
		t.Fatalf("%d refused announcements are pending", o.Pending())
	}
	if err := o.Enqueue(Rotated("k", "b", "", "ES256")); err != nil {
		t.Fatalf("a first rotation, with no previous key: %v", err)
	}
}

func TestTheOutboxIsCustodysAlone(t *testing.T) {
	dir := dataDir(t)
	o := open(t, dir, &sink{})
	_ = o.Enqueue(Rotated("k", "b", "a", "ES256"))
	if err := o.Deliver(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{OutboxName, CursorName} {
		info, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %o, open to group or other", n, info.Mode().Perm())
		}
	}
}

// faulty is the outbox's file with failures a test chooses.
type faulty struct {
	*os.File
	halfWrite, failSync, failTruncate bool
}

func (f *faulty) WriteAt(b []byte, off int64) (int, error) {
	if f.halfWrite {
		n, _ := f.File.WriteAt(b[:len(b)/2], off)
		return n, errors.New("no space left on device")
	}
	return f.File.WriteAt(b, off)
}

func (f *faulty) Sync() error {
	if f.failSync {
		return errors.New("sync failed")
	}
	return f.File.Sync()
}

func (f *faulty) Truncate(n int64) error {
	if f.failTruncate {
		return errors.New("truncate failed")
	}
	return f.File.Truncate(n)
}

func TestAFailedAppendIsTakenBackAndTheOutboxStillReads(t *testing.T) {
	for _, c := range []struct {
		name string
		f    faulty
	}{{"a write cut short", faulty{halfWrite: true}}, {"a sync that failed", faulty{failSync: true}}} {
		dir := dataDir(t)
		o := open(t, dir, &sink{})
		_ = o.Enqueue(Rotated("k", "b", "a", "ES256"))
		ff := c.f
		ff.File = o.f.(*os.File)
		o.f = &ff
		if err := o.Enqueue(Revoked("k", "a", "ES256")); err == nil {
			t.Fatalf("%s: the append said nothing", c.name)
		}
		ff.halfWrite, ff.failSync = false, false
		if err := o.Enqueue(Revoked("k", "b", "ES256")); err != nil {
			t.Fatalf("%s: the next append: %v", c.name, err)
		}
		if o.Pending() != 2 || o.Has(KeyRevoked, "a") {
			t.Fatalf("%s: the failed announcement counts: pending %d", c.name, o.Pending())
		}
		_ = o.Close()
		o2, err := Open(dir, Fixed(&sink{}), clock, nil)
		if err != nil {
			t.Fatalf("%s: the outbox does not read after a failed append: %v", c.name, err)
		}
		if o2.Pending() != 2 || !o2.Has(KeyRevoked, "b") {
			t.Fatalf("%s: read back %d pending", c.name, o2.Pending())
		}
		_ = o2.Close()
	}

	// A failed append that cannot be taken back: nothing more is appended.
	dir := dataDir(t)
	o := open(t, dir, &sink{})
	ff := &faulty{File: o.f.(*os.File), halfWrite: true, failTruncate: true}
	o.f = ff
	if err := o.Enqueue(Rotated("k", "b", "a", "ES256")); err == nil {
		t.Fatal("the append said nothing")
	}
	ff.halfWrite, ff.failTruncate = false, false
	if err := o.Enqueue(Rotated("k", "c", "b", "ES256")); err == nil {
		t.Fatal("an outbox with a fragment it could not take back took another line")
	}
}

func TestTheBusIsOpenedByTheDeliveryLoop(t *testing.T) {
	dir := dataDir(t)
	opened := 0
	var bus func() (Emitter, error)
	s := &sink{}
	bus = func() (Emitter, error) {
		opened++
		if opened == 1 {
			return nil, errors.New("the stream is locked")
		}
		return s, nil
	}
	o, err := Open(dir, bus, clock, nil)
	if err != nil {
		t.Fatalf("the outbox did not open while the bus would not: %v", err)
	}
	defer o.Close()
	if opened != 0 {
		t.Fatal("the bus was opened at the start")
	}
	_ = o.Enqueue(Rotated("k", "b", "a", "ES256"))
	if err := o.Deliver(); err == nil || o.Pending() != 1 {
		t.Fatalf("a bus that did not open: %v, pending %d", err, o.Pending())
	}
	if err := o.Deliver(); err != nil || len(s.got) != 1 || opened != 2 {
		t.Fatalf("the second delivery: %v, got %d, opened %d", err, len(s.got), opened)
	}
	_ = o.Deliver()
	if opened != 2 {
		t.Fatalf("the bus was opened again: %d", opened)
	}
}

func TestAChangeMadeJustBeforeAStopIsDelivered(t *testing.T) {
	s := &sink{fail: errors.New("down")}
	o := open(t, dataDir(t), s)
	o.retryIn = time.Hour
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { o.Run(stop); close(done) }()
	_ = o.Enqueue(Revoked("k", "a", "ES256"))
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	s.fail = nil
	s.mu.Unlock()
	close(stop)
	<-done
	if o.Pending() != 0 || len(s.got) != 1 {
		t.Fatalf("a change made before the stop was left: pending %d", o.Pending())
	}
}

func TestHasAndCountReadTheWholeHistory(t *testing.T) {
	o := open(t, dataDir(t), &sink{})
	_ = o.Enqueue(Rotated("r", "b", "a", "ES384"))
	_ = o.Enqueue(Rotated("r", "c", "b", "ES384"))
	_ = o.Enqueue(Revoked("r", "b", "ES384"))
	_ = o.Deliver()
	if !o.Has(KeyRotated, "c") || !o.Has(KeyRevoked, "b") || o.Has(KeyRevoked, "c") || o.Has(KeyRotated, "a") {
		t.Fatal("Has reads the wrong lines")
	}
	if o.Count(KeyRotated, "r") != 2 || o.Count(KeyRevoked, "r") != 1 || o.Count(KeyRotated, "other") != 0 {
		t.Fatalf("Count: %d %d", o.Count(KeyRotated, "r"), o.Count(KeyRevoked, "r"))
	}
}

func TestACursorWriteLeftBehindIsCleared(t *testing.T) {
	dir := dataDir(t)
	left := filepath.Join(dir, CursorName+".123456")
	_ = os.WriteFile(left, []byte("1\n"), 0o600)
	open(t, dir, &sink{})
	if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a cursor write left behind is still there: %v", err)
	}
}
