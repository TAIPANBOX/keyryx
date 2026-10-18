// Package uselog is the append-only log of every key use. Scaffold.
package uselog

import "errors"

// Entry is one use of a key.
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

// Log is the open log.
type Log struct{}

func Open(path string) (*Log, error) { return nil, errors.New("uselog: not implemented") }
func (l *Log) Append(e Entry) error  { return errors.New("uselog: not implemented") }
func (l *Log) Close() error          { return nil }
