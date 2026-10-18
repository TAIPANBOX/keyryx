// Package uselog is the append-only log of every use of a key: who, which
// key, which key id, what operation, the digest of what was signed, and when
// (CLAUDE.md invariant 18).
//
// Each line names the SHA-256 of the line before it, so an edit, a removal or
// a reordering in the middle is a break the next start refuses. A signature is
// answered only after its line reached the disk, so "the consumer was handed a
// signature" and "the operator's record holds it" are the same fact.
//
// What it is not: protection against whoever can rewrite the whole file from
// the first line. That is the witness's job, which keeps its own log on its
// own volume under its own uid.
package uselog

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Entry is one use of a key. Never the statement itself, only its digest.
type Entry struct {
	At       int64  `json:"at"`
	Consumer string `json:"consumer"`
	Op       string `json:"op"`
	Key      string `json:"key"`
	Kid      string `json:"kid"`
	Purpose  string `json:"purpose,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Prev     string `json:"prev"`
}

// Log is the open log. Safe for concurrent use.
type Log struct {
	mu     sync.Mutex
	f      *os.File
	last   string
	broken error
	closed bool
}

// Open reads and verifies the log at path, discards a half-written last line
// (a write that died before its sync, which no caller was told about), and
// opens it for appending. A break anywhere else refuses the open.
func Open(path string) (*Log, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's data directory, read once at startup
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading the use log %s: %w", path, err)
	}
	keep := raw
	if i := bytes.LastIndexByte(raw, '\n'); i != len(raw)-1 {
		keep = raw[:i+1] // drop a torn tail (or everything, if no line ended)
	}
	last := ""
	sc := bufio.NewScanner(bytes.NewReader(keep))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("the use log %s line %d is not an entry: %w", path, n, err)
		}
		if e.Prev != last {
			return nil, fmt.Errorf("the use log %s line %d does not follow the line before it", path, n)
		}
		last = hashLine(line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading the use log %s: %w", path, err)
	}
	if len(keep) != len(raw) {
		if err := os.WriteFile(path, keep, 0o600); err != nil {
			return nil, fmt.Errorf("discarding the torn last line of %s: %w", path, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the same path
	if err != nil {
		return nil, fmt.Errorf("opening the use log %s: %w", path, err)
	}
	return &Log{f: f, last: last}, nil
}

func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Append writes one entry and returns only after it reached the disk. After a
// failed write every later append fails too, so a torn line can only be the
// last one, and after Close every append fails.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("the use log is closed")
	}
	if l.broken != nil {
		return l.broken
	}
	e.Prev = l.last
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		l.broken = fmt.Errorf("the use log stopped taking writes after: %w", err)
		return l.broken
	}
	if err := l.f.Sync(); err != nil {
		l.broken = fmt.Errorf("the use log stopped taking writes after: %w", err)
		return l.broken
	}
	l.last = hashLine(b)
	return nil
}

// Close releases the file; every later Append fails.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.f.Close()
}
