package checkpoint

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// A checkpoint is what a producer signs about its own stream. A verifier
// that accepts one that does not hold, or refuses one that does, gives a
// wrong answer about the record nobody would see.

// testdata/checkpoint-vectors.json is agent-passport's
// examples/checkpoint-vectors.json at 9cf83da (SPEC 6.5.1, format v1),
// copied byte for byte.
type vectors struct {
	Key struct {
		Crv, Kty, X, Y, Kid string
	} `json:"key"`
	Stream struct {
		Name  string   `json:"name"`
		Lines []string `json:"lines"`
	} `json:"stream"`
	Checkpoints []struct {
		SigningInput string `json:"signing_input"`
		Record       string `json:"record"`
	} `json:"checkpoints"`
	Negative map[string]struct {
		Lines    []string          `json:"lines"`
		Refused  map[string]string `json:"refused"`
		Accepted []int             `json:"accepted"`
	} `json:"negative_variants"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/checkpoint-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Stream.Lines) == 0 || len(v.Checkpoints) == 0 || len(v.Negative) == 0 {
		t.Fatal("the vectors hold nothing, so this test measured nothing")
	}
	return v
}

func joinLines(lines []string) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// verified runs VerifyFile and refuses to index past what it answered.
func verified(t *testing.T, want int, file, stream []byte, keys KeyFunc) []Result {
	t.Helper()
	res := VerifyFile(file, stream, keys)
	if len(res) != want {
		t.Fatalf("%d results for %d records", len(res), want)
	}
	return res
}

func (v vectors) file() []byte {
	var lines []string
	for _, c := range v.Checkpoints {
		lines = append(lines, c.Record)
	}
	return joinLines(lines)
}

// keys answers with the vectors' key for its kid, at any time.
func (v vectors) keys() KeyFunc {
	return func(kid string, at time.Time) ([]byte, error) {
		if kid != v.Key.Kid {
			return nil, errors.New("no statement certifies that key")
		}
		x, _ := base64.RawURLEncoding.DecodeString(v.Key.X)
		y, _ := base64.RawURLEncoding.DecodeString(v.Key.Y)
		return append(append([]byte{4}, x...), y...), nil
	}
}

func TestTheSpecVectorsVerify(t *testing.T) {
	v := load(t)
	stream := joinLines(v.Stream.Lines)
	results := VerifyFile(v.file(), stream, v.keys())
	if len(results) != len(v.Checkpoints) {
		t.Fatalf("%d results for %d records", len(results), len(v.Checkpoints))
	}
	signed := 0
	for i, r := range results {
		want := Accepted
		if strings.Contains(v.Checkpoints[i].Record, `"unsigned_reason"`) {
			want = Unsigned
		}
		if r.Status != want {
			t.Errorf("record %d: %v (%s), want %v", i, r.Status, r.Reason, want)
		}
		if v.Checkpoints[i].SigningInput != "" {
			signed++
			in, err := SigningInput(r.Record)
			if err != nil || string(in) != v.Checkpoints[i].SigningInput {
				t.Errorf("record %d: signing input %q, the vectors give %q (%v)", i, in, v.Checkpoints[i].SigningInput, err)
			}
		}
	}
	if signed == 0 {
		t.Fatal("no signed record was checked")
	}
	for name, nv := range v.Negative {
		s := joinLines(nv.Lines)
		// Each variant passes the SPEC 6.5 chain on its own, so the chain is
		// not what refuses it.
		rep, err := event.VerifyChain(bytes.NewReader(s))
		if err != nil || !rep.Ok() {
			t.Fatalf("%s: the variant does not chain (%v %+v), so it tests nothing", name, err, rep)
		}
		res := verified(t, len(v.Checkpoints), v.file(), s, v.keys())
		for idx, reason := range nv.Refused {
			i := int(idx[0] - '0')
			if res[i].Status != Refused || !strings.Contains(res[i].Reason, reason) {
				t.Errorf("%s record %d: %v %q, want refused with %q", name, i, res[i].Status, res[i].Reason, reason)
			}
		}
		for _, i := range nv.Accepted {
			if res[i].Status == Refused {
				t.Errorf("%s record %d: refused (%s), the vectors accept it", name, i, res[i].Reason)
			}
		}
	}
}

func TestARecordThatIsNotItsOwnCanonicalFormIsRefused(t *testing.T) {
	v := load(t)
	good := v.Checkpoints[0].Record
	if _, err := ParseRecord([]byte(good)); err != nil {
		t.Fatalf("control: %v", err)
	}
	var obj map[string]any
	_ = json.Unmarshal([]byte(good), &obj)
	with := func(k string, val any) string {
		m := map[string]any{}
		for kk, vv := range obj {
			m[kk] = vv
		}
		if val == nil {
			delete(m, k)
		} else {
			m[k] = val
		}
		b, _ := json.Marshal(m) // Go sorts map keys, which is JCS for this subset
		return string(b)
	}
	cases := map[string]string{
		"a space after a colon":         strings.Replace(good, `"alg":"ES256"`, `"alg": "ES256"`, 1),
		"members out of order":          strings.Replace(strings.Replace(good, `{"alg":"ES256",`, `{`, 1), `"v":1}`, `"v":1,"alg":"ES256"}`, 1),
		"an unknown member":             with("note", "x"),
		"no prefix":                     with("prefix", nil),
		"no prev":                       with("prev", nil),
		"version 2":                     with("v", 2),
		"an unknown kind":               with("kind", "snapshot"),
		"a count of zero":               with("count", 0),
		"a count as a string":           with("count", "2"),
		"a fractional count":            with("count", 2.5),
		"a time without milliseconds":   with("at", "2026-10-18T09:00:10Z"),
		"a time not in UTC":             with("at", "2026-10-18T09:00:10.000+01:00"),
		"a head in upper case":          with("head", strings.ToUpper(obj["head"].(string))),
		"a prefix with no algorithm":    with("prefix", strings.TrimPrefix(obj["prefix"].(string), "sha256:")),
		"another algorithm":             with("alg", "ES384"),
		"a stream with a path":          with("stream", "../wardryx.ndjson"),
		"a stream that is not ndjson":   with("stream", "wardryx.log"),
		"a signature with padding":      with("sig", obj["sig"].(string)+"="),
		"a signature too short":         with("sig", obj["sig"].(string)[:40]),
		"signed and unsigned at once":   with("unsigned_reason", "key_expired"),
		"a kid and no signature":        with("sig", nil),
		"not JSON":                      `{`,
		"an array":                      `[]`,
		"trailing data":                 good + " ",
		"a duplicate member":            strings.Replace(good, `"v":1}`, `"v":1,"v":1}`, 1),
		"non-ASCII escaped differently": with("stream", "wärdryx.ndjson"),
	}
	for name, line := range cases {
		if line == good {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := ParseRecord([]byte(line)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	unsigned := v.Checkpoints[3].Record
	if r, err := ParseRecord([]byte(unsigned)); err != nil || r.Signed || r.UnsignedReason != "key_expired" {
		t.Fatalf("the unsigned vector: %+v %v", r, err)
	}
}

func TestAnUnsignedRecordIsReportedUnsignedNeverValid(t *testing.T) {
	v := load(t)
	stream := joinLines(v.Stream.Lines)
	res := verified(t, len(v.Checkpoints), v.file(), stream, v.keys())
	if res[3].Status != Unsigned {
		t.Fatalf("the unsigned vector: %v", res[3].Status)
	}
	// Another reason is unsigned too, never valid, never an error.
	var obj map[string]any
	_ = json.Unmarshal([]byte(v.Checkpoints[3].Record), &obj)
	obj["unsigned_reason"] = "no_key_yet"
	b, _ := json.Marshal(obj)
	r, err := ParseRecord(b)
	if err != nil || r.Signed {
		t.Fatalf("an unsigned record with another reason: %+v %v", r, err)
	}
	if st, _ := Verify(r, r.Prev, ViewOf(stream), v.keys()); st != Unsigned {
		t.Fatalf("an unsigned record with another reason verified as %v", st)
	}
}

func TestPrevChainsAndADroppedRecordIsRefused(t *testing.T) {
	v := load(t)
	stream := joinLines(v.Stream.Lines)
	var lines []string
	for i, c := range v.Checkpoints {
		if i != 1 {
			lines = append(lines, c.Record)
		}
	}
	res := verified(t, len(lines), joinLines(lines), stream, v.keys())
	if res[0].Status != Accepted {
		t.Fatalf("control: the first record: %v %s", res[0].Status, res[0].Reason)
	}
	if res[1].Status != Refused || !strings.Contains(res[1].Reason, "prev") {
		t.Fatalf("a record whose predecessor was dropped: %v %q", res[1].Status, res[1].Reason)
	}
}

func TestASignatureOrAKeyThatDoesNotHoldIsRefused(t *testing.T) {
	v := load(t)
	stream := joinLines(v.Stream.Lines)
	noKey := func(string, time.Time) ([]byte, error) {
		return nil, errors.New("no statement certifies that key at that time")
	}
	if res := verified(t, len(v.Checkpoints), v.file(), stream, noKey); res[0].Status != Refused || !strings.Contains(res[0].Reason, "no statement") {
		t.Fatalf("a kid no statement certifies: %v %q", res[0].Status, res[0].Reason)
	}
	other := func(string, time.Time) ([]byte, error) {
		// A valid P-256 point that is not the signer: the vectors' own key
		// with y negated.
		x, _ := base64.RawURLEncoding.DecodeString(v.Key.X)
		y, _ := base64.RawURLEncoding.DecodeString(v.Key.Y)
		return append(append([]byte{4}, x...), negY(y)...), nil
	}
	if res := verified(t, len(v.Checkpoints), v.file(), stream, other); res[0].Status != Refused || !strings.Contains(res[0].Reason, "signature") {
		t.Fatalf("a signature under another key: %v %q", res[0].Status, res[0].Reason)
	}
	var at time.Time
	seen := func(kid string, a time.Time) ([]byte, error) { at = a; return v.keys()(kid, a) }
	VerifyFile(v.file(), stream, seen)
	if at.IsZero() || at.UTC().Format("2006-01-02T15:04:05.000Z") == "" {
		t.Fatal("the key was not asked for at the record's own time")
	}
}

func TestATornLastLineIsIgnored(t *testing.T) {
	v := load(t)
	stream := joinLines(v.Stream.Lines)
	file := append(v.file(), []byte(`{"alg":"ES256","at":"2026-10-18T09`)...)
	res := VerifyFile(file, stream, v.keys())
	if len(res) != len(v.Checkpoints) {
		t.Fatalf("a torn last line became a result: %d results", len(res))
	}
	for i, r := range res {
		if r.Status == Refused {
			t.Errorf("record %d refused beside a torn tail: %s", i, r.Reason)
		}
	}
}

func TestHostileCheckpointFilesNeverPanicAndNeverAcceptWhatWasNotSigned(t *testing.T) {
	v := load(t)
	stream := joinLines(v.Stream.Lines)
	file := v.file()
	honest := map[string]bool{}
	for _, r := range VerifyFile(file, stream, v.keys()) {
		if r.Status == Accepted {
			honest[string(r.Record.Raw)] = true
		}
	}
	if len(honest) == 0 {
		t.Fatal("control: nothing accepted")
	}
	r := mrand.New(mrand.NewPCG(20261018, 11))
	alphabet := []byte(`{}[]",:0123456789abcdef-_ ` + "\x00\xff\n")
	for i := 0; i < 1500; i++ {
		b := append([]byte(nil), file...)
		for k := 0; k <= r.IntN(4); k++ {
			j := r.IntN(len(b))
			switch r.IntN(3) {
			case 0:
				b[j] = alphabet[r.IntN(len(alphabet))]
			case 1:
				b = append(b[:j], b[j+1:]...)
			default:
				b = append(b[:j], append([]byte{alphabet[r.IntN(len(alphabet))]}, b[j:]...)...)
			}
		}
		for _, res := range VerifyFile(b, stream, v.keys()) {
			if res.Status == Accepted && !honest[string(res.Record.Raw)] {
				t.Fatalf("case %d: a record nobody signed was accepted: %s", i, res.Record.Raw)
			}
		}
	}
}

// negY is the other point with the same x: a valid key that is not the signer.
func negY(y []byte) []byte {
	p := elliptic.P256().Params().P
	return new(big.Int).Sub(p, new(big.Int).SetBytes(y)).FillBytes(make([]byte, 32))
}
