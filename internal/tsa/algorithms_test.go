package tsa

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The signer's algorithms map to exactly the x509 check that holds them, and
// anything else is no algorithm at all; the client says why it has no token.

func TestOnlyTheDigestsANamedHashIsAreKnown(t *testing.T) {
	for _, tc := range []struct {
		oid  asn1.ObjectIdentifier
		want crypto.Hash
		ok   bool
	}{
		{idSHA256, crypto.SHA256, true},
		{idSHA384, crypto.SHA384, true},
		{idSHA512, crypto.SHA512, true},
		{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, 0, false}, // SHA-1
		{idRSA256, 0, false},
		{asn1.ObjectIdentifier{}, 0, false},
	} {
		if got, ok := hashFor(tc.oid); got != tc.want || ok != tc.ok {
			t.Errorf("hashFor(%v) = %v %v, want %v %v", tc.oid, got, ok, tc.want, tc.ok)
		}
	}
}

func TestASignatureAlgorithmIsTheOneItsDigestAndKeyName(t *testing.T) {
	for _, tc := range []struct {
		digest crypto.Hash
		sig    asn1.ObjectIdentifier
		want   x509.SignatureAlgorithm
	}{
		{crypto.SHA384, idRSA256, x509.SHA256WithRSA},
		{crypto.SHA256, idRSA, x509.SHA256WithRSA},
		{crypto.SHA256, idRSA384, x509.SHA384WithRSA},
		{crypto.SHA384, idRSA, x509.SHA384WithRSA},
		{crypto.SHA256, idRSA512, x509.SHA512WithRSA},
		{crypto.SHA512, idRSA, x509.SHA512WithRSA},
		{crypto.SHA384, idECDSA256, x509.ECDSAWithSHA256},
		{crypto.SHA256, idECPublic, x509.ECDSAWithSHA256},
		{crypto.SHA256, idECDSA384, x509.ECDSAWithSHA384},
		{crypto.SHA384, idECPublic, x509.ECDSAWithSHA384},
		{crypto.SHA256, idECDSA512, x509.ECDSAWithSHA512},
		{crypto.SHA512, idECPublic, x509.ECDSAWithSHA512},
	} {
		if got, ok := signatureAlgorithm(tc.digest, tc.sig); !ok || got != tc.want {
			t.Errorf("signatureAlgorithm(%v, %v) = %v %v, want %v", tc.digest, tc.sig, got, ok, tc.want)
		}
	}
	for _, tc := range []struct {
		digest crypto.Hash
		sig    asn1.ObjectIdentifier
	}{
		{crypto.SHA1, idRSA},
		{crypto.SHA1, idECPublic},
		{crypto.SHA256, idSHA256},
		{crypto.SHA384, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}}, // sha1WithRSA
	} {
		if got, ok := signatureAlgorithm(tc.digest, tc.sig); ok || got != x509.UnknownSignatureAlgorithm {
			t.Errorf("signatureAlgorithm(%v, %v) = %v, want none", tc.digest, tc.sig, got)
		}
	}
}

func TestTheClientSaysWhyItHasNoToken(t *testing.T) {
	short := sha256.Sum256([]byte("a head"))
	if _, err := NewRequest(short[:]); err == nil || !strings.Contains(err.Error(), "SHA-384") {
		t.Fatalf("a SHA-256 digest: %v", err)
	}
	var asked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	d := sha512.Sum384([]byte("a head"))
	if _, err := (Client{URL: srv.URL}).Stamp(context.Background(), short[:]); err == nil || asked.Load() != 0 {
		t.Fatalf("a short digest: %v, asked %d times", err, asked.Load())
	}
	// No client named: a default one with a timeout asks.
	if _, err := (Client{URL: srv.URL}).Stamp(context.Background(), d[:]); err == nil || !strings.Contains(err.Error(), "answered 502") || asked.Load() != 1 {
		t.Fatalf("a TSA that answered 502: %v, asked %d times", err, asked.Load())
	}
	if _, err := (Client{URL: "http://tsa.example/\x7f"}).Stamp(context.Background(), d[:]); err == nil {
		t.Fatal("a URL that does not parse asked anyway")
	}
	url := srv.URL
	srv.Close()
	if _, err := (Client{URL: url}).Stamp(context.Background(), d[:]); err == nil || !strings.Contains(err.Error(), "tsa: asking "+url) {
		t.Fatalf("a TSA that is not there: %v", err)
	}
}
