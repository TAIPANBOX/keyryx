// Package checkpoint reads and verifies checkpoint records, agent-passport
// SPEC 6.5.1 format v1 (CLAUDE.md invariant 32).
//
// A record is the RFC 8785 serialization of its own object and one LF; a line
// that is not exactly that, or that carries a member, type or value v1 does
// not list, is refused. Verification follows the SPEC's steps in order: the
// signature under a key a statement certifies at the record's time, the
// record's prev against the previous record's bytes, then count, head and
// prefix against the stream. Step 5, consistency with earlier records a
// verifier kept, is the caller's: it is a question about records the caller
// held, not about this file (internal/witness checks it as it re-reads).
package checkpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/gowebpki/jcs"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
)

// Genesis is the prev of a file's first record.
const Genesis = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// MaxRecord bounds one record line.
const MaxRecord = 4096

// AtLayout is the one form of `at` v1 allows.
const AtLayout = "2006-01-02T15:04:05.000Z"

// Record is one checkpoint record.
type Record struct {
	V                                     int
	Kind, Stream                          string
	Count                                 int64
	Head, Prefix, At, Prev, Kid, Alg, Sig string
	UnsignedReason                        string
	Signed                                bool
	// Raw is the record's bytes without the LF.
	Raw []byte
}

// Time is the record's at.
func (r Record) Time() time.Time {
	t, _ := time.Parse(AtLayout, r.At)
	return t
}

// Hash is what the next record carries as its prev.
func (r Record) Hash() string { return HashOf(r.Raw) }

// HashOf is the prev a record's bytes give the record after it.
func HashOf(line []byte) string {
	sum := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Status is a record's verdict.
type Status int

const (
	Accepted Status = iota + 1
	Refused
	Unsigned
)

func (s Status) String() string {
	switch s {
	case Accepted:
		return "accepted"
	case Refused:
		return "refused"
	case Unsigned:
		return "unsigned"
	}
	return "unknown"
}

// Result is one record's verdict.
type Result struct {
	Index  int
	Record Record
	Status Status
	Reason string
}

// KeyFunc returns the uncompressed P-256 public key a statement certifies for
// kid at at, or why there is none.
type KeyFunc func(kid string, at time.Time) ([]byte, error)

// LineAt is what a stream holds at one line: Count lines, ending at byte End,
// the SHA-256 of the first End bytes, and the SPEC 6.5 chain hash of the line.
type LineAt struct {
	Count, End   int64
	Prefix, Head string
}

// StreamView answers what a stream holds at a line count; false when it holds
// fewer lines than that.
type StreamView interface {
	At(count int64) (LineAt, bool)
}

var (
	common   = []string{"v", "kind", "stream", "count", "head", "prefix", "at", "prev"}
	signed   = []string{"alg", "kid", "sig"}
	kinds    = map[string]bool{"checkpoint": true, "close": true, "resume": true}
	streamRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.ndjson$`)
	hashRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	atRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	kidRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	reasonRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	b64      = base64.RawURLEncoding.Strict()
)

// ParseRecord reads one record line, without its LF.
func ParseRecord(line []byte) (Record, error) {
	if len(line) == 0 || len(line) > MaxRecord {
		return Record{}, errors.New("not a record: empty or over the size cap")
	}
	canon, err := jcs.Transform(line)
	if err != nil {
		return Record{}, fmt.Errorf("not a record: %v", err)
	}
	if !bytes.Equal(canon, line) {
		return Record{}, errors.New("not canonical: the line is not the RFC 8785 serialization of its own object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(line, &m); err != nil {
		return Record{}, fmt.Errorf("not a record: %v", err)
	}
	want := map[string]bool{}
	for _, k := range common {
		want[k] = true
	}
	_, isUnsigned := m["unsigned_reason"]
	if isUnsigned {
		want["unsigned_reason"] = true
	} else {
		for _, k := range signed {
			want[k] = true
		}
	}
	if len(m) != len(want) {
		return Record{}, errors.New("not a record: its members are not those of a signed or an unsigned v1 record")
	}
	for k := range m {
		if !want[k] {
			return Record{}, fmt.Errorf("not a record: member %q is not a v1 member of this kind of record", k)
		}
	}
	r := Record{Raw: append([]byte(nil), line...), Signed: !isUnsigned}
	str := func(k string) (string, error) {
		var s string
		if err := json.Unmarshal(m[k], &s); err != nil {
			return "", fmt.Errorf("not a record: %s is not a string", k)
		}
		return s, nil
	}
	var errs []error
	get := func(k string) string {
		s, err := str(k)
		errs = append(errs, err)
		return s
	}
	if err := json.Unmarshal(m["v"], &r.V); err != nil || r.V != 1 {
		return Record{}, errors.New("not a record: v is not the integer 1")
	}
	if err := json.Unmarshal(m["count"], &r.Count); err != nil || r.Count < 1 {
		return Record{}, errors.New("not a record: count is not an integer of at least 1")
	}
	r.Kind, r.Stream, r.Head, r.Prefix, r.At, r.Prev = get("kind"), get("stream"), get("head"), get("prefix"), get("at"), get("prev")
	if r.Signed {
		r.Alg, r.Kid, r.Sig = get("alg"), get("kid"), get("sig")
	} else {
		r.UnsignedReason = get("unsigned_reason")
	}
	if err := errors.Join(errs...); err != nil {
		return Record{}, err
	}
	switch {
	case !kinds[r.Kind]:
		return Record{}, fmt.Errorf("not a record: kind %q is not checkpoint, close or resume", r.Kind)
	case !streamRe.MatchString(r.Stream):
		return Record{}, errors.New("not a record: stream is not a file name ending in .ndjson")
	case !hashRe.MatchString(r.Head), !hashRe.MatchString(r.Prefix), !hashRe.MatchString(r.Prev):
		return Record{}, errors.New("not a record: head, prefix and prev are sha256: and 64 lowercase hex digits")
	case !atRe.MatchString(r.At) || r.Time().IsZero():
		return Record{}, errors.New("not a record: at is not YYYY-MM-DDTHH:MM:SS.sssZ")
	}
	if r.Signed {
		sig, err := b64.DecodeString(r.Sig)
		switch {
		case r.Alg != "ES256":
			return Record{}, errors.New("not a record: alg is not ES256")
		case !kidRe.MatchString(r.Kid):
			return Record{}, errors.New("not a record: kid is not an RFC 7638 thumbprint")
		case err != nil || len(sig) != 64:
			return Record{}, errors.New("not a record: sig is not 64 bytes of unpadded base64url")
		}
	} else if !reasonRe.MatchString(r.UnsignedReason) {
		return Record{}, errors.New("not a record: unsigned_reason is not a reason")
	}
	return r, nil
}

// SigningInput is what a signed record's signature covers: the RFC 8785
// serialization of its object with sig removed.
func SigningInput(r Record) ([]byte, error) {
	if !r.Signed {
		return nil, errors.New("an unsigned record has no signing input")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r.Raw, &m); err != nil {
		return nil, err
	}
	delete(m, "sig")
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// Verify judges one parsed record by SPEC 6.5.1's steps 2 to 4, given the
// prev it must carry and a view of the stream.
func Verify(r Record, prev string, view StreamView, keys KeyFunc) (Status, string) {
	if r.Signed {
		pub, err := keys(r.Kid, r.Time())
		if err != nil {
			return Refused, "key: " + err.Error()
		}
		in, err := SigningInput(r)
		if err != nil {
			return Refused, "signing input: " + err.Error()
		}
		sig, _ := b64.DecodeString(r.Sig)
		if err := keystore.Verify(policy.ES256, pub, in, sig); err != nil {
			return Refused, "the signature does not verify under the certified key"
		}
	}
	if r.Prev != prev {
		return Refused, "prev does not chain from the record before it"
	}
	at, ok := view.At(r.Count)
	if !ok {
		return Refused, "the stream is shorter than the record's N bytes: it holds fewer than count lines"
	}
	if at.Head != r.Head {
		return Refused, "head does not match the chain hash of line count"
	}
	if at.Prefix != r.Prefix {
		return Refused, "prefix does not match the stream's first N bytes"
	}
	if !r.Signed {
		return Unsigned, "unsigned: " + r.UnsignedReason
	}
	return Accepted, ""
}

// Lines walks the LF-terminated lines of b, without their LFs; a final line
// with no LF is a torn append and is not walked.
func Lines(b []byte, fn func(line []byte, end int64) bool) {
	var at int64
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return
		}
		at += int64(i + 1)
		if !fn(b[:i], at) {
			return
		}
		b = b[i+1:]
	}
}

// memView is a stream held in memory, indexed by line.
type memView []LineAt

func (v memView) At(count int64) (LineAt, bool) {
	if count < 1 || count > int64(len(v)) {
		return LineAt{}, false
	}
	return v[count-1], true
}

// ViewOf indexes a stream held in memory.
func ViewOf(stream []byte) StreamView {
	h := sha256.New()
	var out memView
	var last int64
	Lines(stream, func(line []byte, end int64) bool {
		h.Write(stream[last:end])
		last = end
		head, _ := event.ChainHashRaw(line)
		out = append(out, LineAt{Count: int64(len(out) + 1), End: end, Prefix: sumOf(h), Head: head})
		return true
	})
	return out
}

func sumOf(h hash.Hash) string { return "sha256:" + hex.EncodeToString(h.Sum(nil)) }

// SumOf is a running hash's prefix value, without finishing the hash.
func SumOf(h hash.Hash) string { return sumOf(h) }

// VerifyFile judges every record of a checkpoint file against a stream held
// in memory, in order, each record's prev against the bytes of the one before.
func VerifyFile(file, stream []byte, keys KeyFunc) []Result {
	view := ViewOf(stream)
	prev := Genesis
	var out []Result
	Lines(file, func(line []byte, _ int64) bool {
		res := Result{Index: len(out)}
		r, err := ParseRecord(line)
		if err != nil {
			res.Record, res.Status, res.Reason = Record{Raw: append([]byte(nil), line...)}, Refused, err.Error()
		} else {
			res.Record = r
			res.Status, res.Reason = Verify(r, prev, view, keys)
		}
		prev = HashOf(line)
		out = append(out, res)
		return true
	})
	return out
}

