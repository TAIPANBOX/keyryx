package certify

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
)

// A consumer keeps its key in memory, so a restart makes a new one, and the
// keys of the processes before it stay live to their not_after plus the
// overlap with nobody holding them. Four restarts inside a key's life used to
// fill a name, and the fifth start was left with no key for up to that life.

const life = 72 * time.Hour

// starts has n keys certified for vouchryx, each a gap after the one before,
// as n starts of the same consumer would.
func (s *stand) starts(n int, gap time.Duration) []holder {
	s.t.Helper()
	out := make([]holder, 0, n)
	for i := 0; i < n; i++ {
		if i > 0 {
			s.now = s.now.Add(gap)
		}
		h := newHolder(s.t)
		if _, _, err := s.certify(h, "vouchryx", "vouchryx-token", life); err != nil {
			s.t.Fatalf("start %d of %d: %v", i+1, n, err)
		}
		out = append(out, h)
	}
	return out
}

func TestAStartPastTheCapRetiresTheOldestKeyOfItsOwner(t *testing.T) {
	s := newStand(t)
	held := s.starts(MaxLive, time.Hour)
	s.now = s.now.Add(time.Hour)
	fifth := newHolder(t)
	if _, _, err := s.certify(fifth, "vouchryx", "vouchryx-token", life); err != nil {
		t.Fatalf("the start past the cap got no key: %v", err)
	}
	set := s.published("vouchryx-token")
	if len(set) != MaxLive {
		t.Fatalf("%d keys published, want %d", len(set), MaxLive)
	}
	if set[held[0].kid] {
		t.Fatal("the oldest key is still published")
	}
	if !set[fifth.kid] {
		t.Fatal("the new key is not published")
	}
	for i, h := range held[1:] {
		if !set[h.kid] {
			t.Fatalf("key %d left the set, and only the oldest should", i+2)
		}
	}
}

func TestEveryStartPastTheCapGetsAKey(t *testing.T) {
	s := newStand(t)
	held := s.starts(12, time.Hour)
	set := s.published("vouchryx-token")
	if len(set) != MaxLive {
		t.Fatalf("%d keys published, want %d", len(set), MaxLive)
	}
	for i, h := range held {
		if want := i >= len(held)-MaxLive; set[h.kid] != want {
			t.Fatalf("key %d of %d: published %v, want %v", i+1, len(held), set[h.kid], want)
		}
	}
}

func TestTheOldestKeyStaysWhileATokenItSignedCouldStillLive(t *testing.T) {
	s := newStand(t)
	held := s.starts(MaxLive, time.Minute)
	k, _ := s.pol.Key("vouchryx-token")
	// The second key began to sign a publish-ahead after it was certified, and
	// the oldest key signed nothing after that.
	began := t0.Add(time.Minute).Add(ahead)
	before := s.published("vouchryx-token")

	s.now = began.Add(k.Overlap - time.Second)
	late := newHolder(t)
	if _, _, err := s.certify(late, "vouchryx", "vouchryx-token", life); !errors.Is(err, ErrTooManyLive) {
		t.Fatalf("a second inside the overlap: %v, want ErrTooManyLive", err)
	}
	if after := s.published("vouchryx-token"); !maps.Equal(before, after) {
		t.Fatalf("a refused start changed the key set: %v, was %v", after, before)
	}

	s.now = began.Add(k.Overlap)
	if _, _, err := s.certify(late, "vouchryx", "vouchryx-token", life); err != nil {
		t.Fatalf("the moment the overlap ended: %v", err)
	}
	set := s.published("vouchryx-token")
	if set[held[0].kid] || !set[late.kid] || len(set) != MaxLive {
		t.Fatalf("the moment the overlap ended the set is %v", set)
	}
}

// sharedPolicy declares a name two consumers may have keys certified for.
func sharedPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`{"version":1,
 "keys":[{"name":"shared","alg":"ES256","mode":"delegated","max_lifetime":"72h","overlap":"10m"}],
 "consumers":[
  {"name":"one","auth":{"socket":"one"},"grants":{"shared":["delegate"]}},
  {"name":"two","auth":{"socket":"two"},"grants":{"shared":["delegate"]}}]}`))
	if err != nil {
		t.Fatalf("the shared policy did not parse: %v", err)
	}
	return p
}

func TestAKeyOfAnotherOwnerIsNeverRetired(t *testing.T) {
	s := newStand(t)
	s.pol = sharedPolicy(t)
	s.reopen()
	take := func(consumer string) (holder, error) {
		s.now = s.now.Add(time.Hour)
		h := newHolder(t)
		_, _, err := s.certify(h, consumer, "shared", life)
		return h, err
	}
	var held []holder
	for _, consumer := range []string{"one", "two", "two", "two"} {
		h, err := take(consumer)
		if err != nil {
			t.Fatalf("filling the name, %s: %v", consumer, err)
		}
		held = append(held, h)
	}
	// "one" holds the oldest key of the name and has no second key: nothing of
	// its own can go, and nothing of "two" may.
	if _, err := take("one"); !errors.Is(err, ErrTooManyLive) {
		t.Fatalf("a consumer with one key at a full name: %v, want ErrTooManyLive", err)
	}
	h, err := take("two")
	if err != nil {
		t.Fatalf("a consumer with keys to spare: %v", err)
	}
	set := s.published("shared")
	if !set[held[0].kid] {
		t.Fatal("the oldest key of the name is gone, and it belongs to another consumer")
	}
	if set[held[1].kid] {
		t.Fatal("the consumer's own oldest key is still published")
	}
	if !set[h.kid] || len(set) != MaxLive {
		t.Fatalf("the set is %v", set)
	}
}

func TestNoScheduleOfStartsBreaksTheBoundOrCutsALiveToken(t *testing.T) {
	gaps := []time.Duration{time.Second, 30 * time.Second, 5 * time.Minute, 11 * time.Minute, 30 * time.Minute,
		2 * time.Hour, 40 * time.Hour, 73 * time.Hour}
	for seed := uint64(0); seed < 60; seed++ {
		rng := mrand.New(mrand.NewPCG(seed, 311))
		s := newStand(t)
		k, _ := s.pol.Key("vouchryx-token")
		var keys []statement.Statement
		gone := map[string]bool{}
		for step := 0; step < 24; step++ {
			s.now = s.now.Add(gaps[rng.IntN(len(gaps))])
			before := len(s.published("vouchryx-token"))
			st, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", life)
			switch {
			case err == nil:
				keys = append(keys, st)
			case !errors.Is(err, ErrTooManyLive):
				t.Fatalf("seed %d step %d: %v", seed, step, err)
			case before < MaxLive:
				t.Fatalf("seed %d step %d: refused with %d of %d live", seed, step, before, MaxLive)
			default:
				// A refusal at the cap is right only while the oldest key's tokens
				// could still be alive.
				var live []statement.Statement
				now := s.published("vouchryx-token")
				for _, key := range keys {
					if now[key.Kid] {
						live = append(live, key)
					}
				}
				if !s.now.Before(time.Unix(live[1].NotBefore, 0).Add(k.Overlap)) {
					t.Fatalf("seed %d step %d: refused though the oldest key could have left", seed, step)
				}
			}
			set := s.published("vouchryx-token")
			if len(set) > MaxLive {
				t.Fatalf("seed %d step %d: %d keys published", seed, step, len(set))
			}
			for i, key := range keys {
				natural := s.now.Before(time.Unix(key.NotAfter, 0).Add(k.Overlap))
				if set[key.Kid] || gone[key.Kid] || !natural {
					continue
				}
				gone[key.Kid] = true
				if i+1 >= len(keys) {
					t.Fatalf("seed %d step %d: the newest key left the set", seed, step)
				}
				if s.now.Before(time.Unix(keys[i+1].NotBefore, 0).Add(k.Overlap)) {
					t.Fatalf("seed %d step %d: a key left before its successor signed for the overlap", seed, step)
				}
			}
		}
	}
}

func TestTheOldestKeyIsStillTheOldestAfterARestartOfCustody(t *testing.T) {
	// Custody reads its statements back in the order of their file names, which
	// are key ids and say nothing about age, so this is played a few times.
	for round := 0; round < 8; round++ {
		s := newStand(t)
		held := s.starts(MaxLive, time.Hour)
		s.reopen()
		s.now = s.now.Add(time.Hour)
		if _, _, err := s.certify(newHolder(t), "vouchryx", "vouchryx-token", life); err != nil {
			t.Fatal(err)
		}
		if s.published("vouchryx-token")[held[0].kid] {
			t.Fatalf("round %d: a younger key went and the oldest stayed", round)
		}
	}
}

func TestARetiredKeyIsNotARevokedKey(t *testing.T) {
	s := newStand(t)
	held := s.starts(MaxLive+1, time.Hour)
	old := held[0]
	if s.published("vouchryx-token")[old.kid] {
		t.Fatal("control: the oldest key is still published")
	}
	if _, revoked, ok := s.reg.Statement(old.kid); !ok || revoked != 0 {
		t.Fatalf("the statement of a retired key: found %v, revoked at %d", ok, revoked)
	}
	if _, _, err := s.certify(old, "vouchryx", "vouchryx-token", life); !errors.Is(err, ErrKidKnown) {
		t.Fatalf("a retired key offered again: %v, want ErrKidKnown", err)
	}
	if _, err := s.reg.Revoke(old.kid); err != nil {
		t.Fatalf("revoking a retired key: %v", err)
	}
	if _, revoked, _ := s.reg.Statement(old.kid); revoked == 0 {
		t.Fatal("the revocation of a retired key did not take")
	}
}

func TestARetirementSurvivesARestartOfCustody(t *testing.T) {
	s := newStand(t)
	held := s.starts(MaxLive, time.Hour)
	before := statementBytes(t, s.dir)
	s.now = s.now.Add(time.Hour)
	fifth := newHolder(t)
	if _, _, err := s.certify(fifth, "vouchryx", "vouchryx-token", life); err != nil {
		t.Fatal(err)
	}
	s.reopen()
	set := s.published("vouchryx-token")
	if set[held[0].kid] || !set[fifth.kid] || len(set) != MaxLive {
		t.Fatalf("after the restart the set is %v", set)
	}
	if len(s.reg.Alarms()) != 0 {
		t.Fatalf("alarms after an honest retirement: %v", s.reg.Alarms())
	}
	// An older release of custody reads the same directory after a rollback, so
	// a retirement leaves the statement records in the form it knows.
	after := statementBytes(t, s.dir)
	for path, raw := range before {
		if !bytes.Equal(after[path], raw) {
			t.Fatalf("%s changed on disk", path)
		}
	}
}

func statementBytes(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, f := range statementFiles(t, dir) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = raw
	}
	return out
}

// retirement is the record that says kid retired.
func retirementFile(t *testing.T, dir, kid string) (string, map[string]any) {
	t.Helper()
	path := filepath.Join(dir, "retired", "vouchryx-token", kid+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return path, r
}

func TestAnEditedRetirementIsTreatedAsRevokedAndRaisesAnAlarm(t *testing.T) {
	setup := func() (*stand, []holder) {
		s := newStand(t)
		return s, s.starts(MaxLive+2, time.Hour)
	}
	s, _ := setup()
	s.reopen()
	if len(s.reg.Alarms()) != 0 {
		t.Fatalf("control: alarms %v", s.reg.Alarms())
	}
	for what, edit := range map[string]func(s *stand, other string, r map[string]any){
		"the time moved":  func(_ *stand, _ string, r map[string]any) { r["retired"] = t0.Add(time.Minute).Unix() },
		"the MAC removed": func(_ *stand, _ string, r map[string]any) { delete(r, "mac") },
		"another key's MAC": func(s *stand, other string, r map[string]any) {
			_, o := retirementFile(t, s.dir, other)
			r["mac"] = o["mac"]
		},
	} {
		s, held := setup()
		kid := held[0].kid
		path, r := retirementFile(t, s.dir, kid)
		edit(s, held[1].kid, r)
		writeJSON(t, path, r)
		reg, err := Open(s.dir, s.store, s.pol, ahead, s.clock)
		if err != nil {
			t.Errorf("%s: the registry refused to open (%v); an edited state is an alarm, not an outage", what, err)
			continue
		}
		s.reg = reg
		if s.published("vouchryx-token")[kid] {
			t.Errorf("%s: %s is published", what, kid)
		}
		if !s.alarmFor(kid) {
			t.Errorf("%s: no alarm names %s: %v", what, kid, reg.Alarms())
		}
		if _, rev, _ := reg.Statement(kid); rev == 0 {
			t.Errorf("%s: its statement reads as not revoked", what)
		}
	}
}

func TestAFileCustodyNeverWroteInTheRetiredDirectoryRefusesTheStart(t *testing.T) {
	for what, plant := range map[string]func(t *testing.T, s *stand, kid string){
		"not a record": func(t *testing.T, s *stand, kid string) {
			if err := os.WriteFile(filepath.Join(s.dir, "retired", "vouchryx-token", kid+".json"), []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an unknown member": func(t *testing.T, s *stand, kid string) {
			path, r := retirementFile(t, s.dir, kid)
			r["extra"] = 1
			writeJSON(t, path, r)
		},
		"data after its record": func(t *testing.T, s *stand, kid string) {
			path, _ := retirementFile(t, s.dir, kid)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(raw, raw...), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a version custody does not write": func(t *testing.T, s *stand, kid string) {
			path, r := retirementFile(t, s.dir, kid)
			r["v"] = 2
			writeJSON(t, path, r)
		},
		"a key no statement certifies": func(t *testing.T, s *stand, kid string) {
			path, r := retirementFile(t, s.dir, kid)
			writeJSON(t, filepath.Join(filepath.Dir(path), "no-such-kid.json"), r)
		},
		"a name that is no statement directory": func(t *testing.T, s *stand, kid string) {
			if err := os.Mkdir(filepath.Join(s.dir, "retired", "Not A Name"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"filed under another name": func(t *testing.T, s *stand, kid string) {
			path, r := retirementFile(t, s.dir, kid)
			other := filepath.Join(s.dir, "retired", "wardryx-stream")
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			writeJSON(t, filepath.Join(other, filepath.Base(path)), r)
		},
	} {
		s := newStand(t)
		held := s.starts(MaxLive+1, time.Hour)
		plant(t, s, held[0].kid)
		if _, err := Open(s.dir, s.store, s.pol, ahead, s.clock); err == nil {
			t.Errorf("%s: custody opened", what)
		}
	}
}

func TestRevokingAnAlarmedRetirementAcknowledgesIt(t *testing.T) {
	s := newStand(t)
	kid := s.starts(MaxLive+1, time.Hour)[0].kid
	path, r := retirementFile(t, s.dir, kid)
	delete(r, "mac")
	writeJSON(t, path, r)
	s.reopen()
	if !s.alarmFor(kid) {
		t.Fatal("control: no alarm")
	}
	if _, err := s.reg.Revoke(kid); err != nil {
		t.Fatalf("revoking the alarmed key: %v", err)
	}
	if s.alarmFor(kid) {
		t.Fatal("the alarm survived an operator's revocation")
	}
	s.reopen()
	if s.alarmFor(kid) {
		t.Fatal("the alarm came back after a restart")
	}
	if s.published("vouchryx-token")[kid] {
		t.Fatal("the acknowledged key is published")
	}
}

func TestNoKeyIsRetiredWhenItsLineCouldNotBeLogged(t *testing.T) {
	s := newStand(t)
	held := s.starts(MaxLive, time.Hour)
	s.now = s.now.Add(time.Hour)
	fifth := newHolder(t)
	c, _, err := s.reg.Challenge("vouchryx", "vouchryx-token")
	if err != nil {
		t.Fatal(err)
	}
	closed := errors.New("the use log is closed")
	req := Request{JWK: fifth.jwk, Challenge: c, Proof: fifth.prove(t, "vouchryx-token", "vouchryx", c), Lifetime: life}
	_, _, err = s.reg.Delegate("vouchryx", "vouchryx-token", req, record, func(statement.Statement) error { return closed })
	if !errors.Is(err, closed) {
		t.Fatalf("a retirement that could not be logged: %v", err)
	}
	set := s.published("vouchryx-token")
	if !set[held[0].kid] || set[fifth.kid] || len(set) != MaxLive {
		t.Fatalf("the set is %v", set)
	}
	s.reopen()
	if !s.published("vouchryx-token")[held[0].kid] {
		t.Fatal("after a restart the key that was not retired is gone")
	}
}

func TestNoKeyIsCertifiedWhenTheRetirementCouldNotBeWritten(t *testing.T) {
	s := newStand(t)
	held := s.starts(MaxLive, time.Hour)
	// A file where the directory should be: the write of the retirement fails.
	if err := os.WriteFile(filepath.Join(s.dir, "retired"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.now = s.now.Add(time.Hour)
	fifth := newHolder(t)
	if _, _, err := s.certify(fifth, "vouchryx", "vouchryx-token", life); err == nil {
		t.Fatal("a key was certified with the retirement unwritten")
	}
	set := s.published("vouchryx-token")
	if !set[held[0].kid] || set[fifth.kid] || len(set) != MaxLive {
		t.Fatalf("the set is %v", set)
	}
}

func TestAKeyLeavesOnDiskBeforeItsReplacementArrives(t *testing.T) {
	s := newStand(t)
	held := s.starts(MaxLive, time.Hour)
	s.now = s.now.Add(time.Hour)
	fifth := newHolder(t)
	c, _, err := s.reg.Challenge("vouchryx", "vouchryx-token")
	if err != nil {
		t.Fatal(err)
	}
	req := Request{JWK: fifth.jwk, Challenge: c, Proof: fifth.prove(t, "vouchryx-token", "vouchryx", c), Lifetime: life}
	crash := errors.New("the process died here")
	failed := func(statement.Statement, []byte) error { return crash }
	if _, _, err := s.reg.Delegate("vouchryx", "vouchryx-token", req, failed, recordRetired); !errors.Is(err, crash) {
		t.Fatalf("the failed start: %v", err)
	}
	s.reopen()
	set := s.published("vouchryx-token")
	if set[held[0].kid] || set[fifth.kid] || len(set) != MaxLive-1 {
		t.Fatalf("after the crash the set is %v", set)
	}
}
