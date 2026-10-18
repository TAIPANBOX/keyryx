// Package tsa is an RFC 3161 time-stamping client. Scaffold.
package tsa

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"time"
)

// MaxResponse bounds a TSA's answer.
const MaxResponse = 64 << 10

// Request is a TimeStampReq.
type Request struct {
	DER    []byte
	Nonce  *big.Int
	Digest []byte
}

// Token is a verified time-stamp token.
type Token struct {
	DER     []byte
	GenTime time.Time
	Serial  *big.Int
	Policy  string
	TSA     string
}

var errScaffold = errors.New("tsa: not implemented")

// NewRequest builds a request for a SHA-384 digest. Scaffold.
func NewRequest(digest []byte) (Request, error) {
	return Request{Digest: digest, Nonce: big.NewInt(0)}, errScaffold
}

// Verify checks a TimeStampResp. Scaffold.
func Verify(resp []byte, req Request, roots *x509.CertPool) (Token, error) {
	return Token{}, errScaffold
}

// Client asks a TSA.
type Client struct {
	URL   string
	HTTP  *http.Client
	Roots *x509.CertPool
}

// Stamp asks for a time-stamp over digest. Scaffold.
func (c Client) Stamp(ctx context.Context, digest []byte) (Token, error) { return Token{}, errScaffold }
