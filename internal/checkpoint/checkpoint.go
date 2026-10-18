// Package checkpoint reads and verifies SPEC 6.5.1 checkpoint records. Scaffold.
package checkpoint

import (
	"errors"
	"time"
)

// Genesis is the prev of a file's first record.
const Genesis = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Record is one checkpoint record.
type Record struct {
	V                                     int
	Kind, Stream                          string
	Count                                 int64
	Head, Prefix, At, Prev, Kid, Alg, Sig string
	UnsignedReason                        string
	Signed                                bool
	Raw                                   []byte
}

// Status is a record's verdict.
type Status int

const (
	Accepted Status = iota + 1
	Refused
	Unsigned
)

// Result is one record's verdict.
type Result struct {
	Index  int
	Record Record
	Status Status
	Reason string
}

// KeyFunc returns the uncompressed P-256 public key a statement certifies for
// kid at at.
type KeyFunc func(kid string, at time.Time) ([]byte, error)

// LineAt is what a stream holds at one line.
type LineAt struct {
	Count, End   int64
	Prefix, Head string
}

// StreamView answers what a stream holds at a line count.
type StreamView interface {
	At(count int64) (LineAt, bool)
}

var errScaffold = errors.New("checkpoint: not implemented")

// ParseRecord reads one record. Scaffold.
func ParseRecord(line []byte) (Record, error) { return Record{}, errScaffold }

// SigningInput is what a signed record's signature covers. Scaffold.
func SigningInput(r Record) ([]byte, error) { return nil, errScaffold }

// Verify judges one record. Scaffold.
func Verify(r Record, prev string, view StreamView, keys KeyFunc) (Status, string) {
	return Refused, "not implemented"
}

type noView struct{}

func (noView) At(int64) (LineAt, bool) { return LineAt{}, false }

// ViewOf indexes a stream held in memory. Scaffold.
func ViewOf(stream []byte) StreamView { return noView{} }

// VerifyFile judges every record of a checkpoint file. Scaffold.
func VerifyFile(file, stream []byte, keys KeyFunc) []Result { return nil }
