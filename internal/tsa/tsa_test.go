package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A time-stamp says when somebody outside the host saw the witness's tree
// head. A token accepted when it does not hold is a date the witness made up
// and an auditor believes.

var genTime = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

type authority struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	tsaCert *x509.Certificate
	tsaKey  crypto.Signer
	roots   *x509.CertPool
}

func newAuthority(t *testing.T, rsaKey bool, eku []x509.ExtKeyUsage) *authority {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test TSA root"},
		NotBefore: genTime.Add(-24 * time.Hour), NotAfter: genTime.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	var tsaKey crypto.Signer
	if rsaKey {
		tsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		tsaKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test TSA"},
		NotBefore: genTime.Add(-time.Hour), NotAfter: genTime.Add(time.Hour), ExtKeyUsage: eku, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, tsaKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &authority{caCert: ca, caKey: caKey, tsaCert: cert, tsaKey: tsaKey, roots: pool}
}

var (
	oidSHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384t = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidPolicy  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
)

// knobs lets a test build a token that is wrong in exactly one way.
type knobs struct {
	status         int
	hashOID        asn1.ObjectIdentifier
	imprint        []byte
	nonce          *big.Int
	noNonce        bool
	editAfterSign  bool
	signWith       crypto.Signer
	certs          []*x509.Certificate
	noSigningCert  bool
	signingCertFor *x509.Certificate
	contentType    asn1.ObjectIdentifier
	eContentType   asn1.ObjectIdentifier
	trailing       bool
}

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type msgImprint struct {
	HashAlgorithm algID
	HashedMessage []byte
}

type tstInfoOut struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint msgImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int  `asn1:"optional"`
}

func mustMarshal(t *testing.T, v any, params ...string) []byte {
	t.Helper()
	var b []byte
	var err error
	if len(params) > 0 {
		b, err = asn1.MarshalWithParams(v, params[0])
	} else {
		b, err = asn1.Marshal(v)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func set(t *testing.T, elems ...[]byte) []byte {
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: bytes.Join(elems, nil)})
}

func attr(t *testing.T, oid asn1.ObjectIdentifier, value []byte) []byte {
	return mustMarshal(t, struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{oid, asn1.RawValue{FullBytes: set(t, value)}})
}

// respond is a TSA: it answers req with a token, wrong in the ways k says.
func (a *authority) respond(t *testing.T, req Request, k knobs) []byte {
	t.Helper()
	statusInfo := mustMarshal(t, struct{ Status int }{k.status})
	if k.status != 0 && k.status != 1 {
		return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: statusInfo})
	}
	hashOID, imprint, nonce := oidSHA384t, req.Digest, req.Nonce
	if k.hashOID != nil {
		hashOID = k.hashOID
	}
	if k.imprint != nil {
		imprint = k.imprint
	}
	if k.nonce != nil {
		nonce = k.nonce
	}
	if k.noNonce {
		nonce = nil
	}
	tst := mustMarshal(t, tstInfoOut{Version: 1, Policy: oidPolicy, MessageImprint: msgImprint{algID{Algorithm: hashOID}, imprint},
		SerialNumber: big.NewInt(4242), GenTime: genTime, Nonce: nonce})
	signedTST := tst
	if k.editAfterSign {
		tst = mustMarshal(t, tstInfoOut{Version: 1, Policy: oidPolicy, MessageImprint: msgImprint{algID{Algorithm: hashOID}, imprint},
			SerialNumber: big.NewInt(4343), GenTime: genTime, Nonce: nonce})
	}
	digest := sha256.Sum256(signedTST)
	ct := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	if k.contentType != nil {
		ct = k.contentType
	}
	certFor := a.tsaCert
	if k.signingCertFor != nil {
		certFor = k.signingCertFor
	}
	certHash := sha256.Sum256(certFor.Raw)
	essV2 := mustMarshal(t, struct {
		Certs []struct{ CertHash []byte }
	}{[]struct{ CertHash []byte }{{certHash[:]}}})
	attrs := [][]byte{
		attr(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}, mustMarshal(t, ct)),
		attr(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}, mustMarshal(t, digest[:])),
	}
	if !k.noSigningCert {
		attrs = append(attrs, attr(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}, essV2))
	}
	signedAttrs := set(t, attrs...)
	signer := a.tsaKey
	if k.signWith != nil {
		signer = k.signWith
	}
	h := sha256.Sum256(signedAttrs)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sigAlg := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	if _, ok := signer.Public().(*rsa.PublicKey); ok {
		sigAlg = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	}
	implicitAttrs := append([]byte(nil), signedAttrs...)
	implicitAttrs[0] = 0xA0
	sid := mustMarshal(t, struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: a.tsaCert.RawIssuer}, a.tsaCert.SerialNumber})
	signerInfo := mustMarshal(t, struct {
		Version         int
		SID             asn1.RawValue
		DigestAlgorithm algID
		SignedAttrs     asn1.RawValue
		SignatureAlg    algID
		Signature       []byte
	}{1, asn1.RawValue{FullBytes: sid}, algID{Algorithm: oidSHA256}, asn1.RawValue{FullBytes: implicitAttrs}, algID{Algorithm: sigAlg}, sig})
	ect := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	if k.eContentType != nil {
		ect = k.eContentType
	}
	encap := mustMarshal(t, struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{ect, asn1.RawValue{FullBytes: mustMarshal(t, tst)}})
	certs := k.certs
	if certs == nil {
		certs = []*x509.Certificate{a.tsaCert}
	}
	var certBytes []byte
	for _, c := range certs {
		certBytes = append(certBytes, c.Raw...)
	}
	sdFields := [][]byte{
		mustMarshal(t, 3),
		set(t, mustMarshal(t, algID{Algorithm: oidSHA256})),
		encap,
	}
	if len(certs) > 0 {
		sdFields = append(sdFields, mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certBytes}))
	}
	sdFields = append(sdFields, set(t, signerInfo))
	sd := mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(sdFields, nil)})
	token := mustMarshal(t, struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{FullBytes: sd}})
	resp := mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(statusInfo, token...)})
	if k.trailing {
		resp = append(resp, 0)
	}
	return resp
}

func aRequest(t *testing.T) Request {
	t.Helper()
	d := sha512.Sum384([]byte("a tree head"))
	req, err := NewRequest(d[:])
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestTheRequestIsRFC3161(t *testing.T) {
	req := aRequest(t)
	var parsed struct {
		Version        int
		MessageImprint msgImprint
		Nonce          *big.Int `asn1:"optional"`
		CertReq        bool     `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(req.DER, &parsed)
	if err != nil || len(rest) != 0 {
		t.Fatalf("the request is not one DER TimeStampReq: %v", err)
	}
	if parsed.Version != 1 || !parsed.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA384t) ||
		!bytes.Equal(parsed.MessageImprint.HashedMessage, req.Digest) || parsed.Nonce == nil || parsed.Nonce.Cmp(req.Nonce) != 0 || !parsed.CertReq {
		t.Fatalf("request %+v", parsed)
	}
	if aRequest(t).Nonce.Cmp(req.Nonce) == 0 {
		t.Fatal("two requests carry one nonce")
	}
	if _, err := NewRequest(make([]byte, 32)); err == nil {
		t.Fatal("a digest that is not SHA-384's length was accepted")
	}
}

func TestATimestampFromATSAVerifies(t *testing.T) {
	for _, rsaKey := range []bool{false, true} {
		a := newAuthority(t, rsaKey, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
		req := aRequest(t)
		for _, status := range []int{0, 1} {
			tok, err := Verify(a.respond(t, req, knobs{status: status}), req, a.roots)
			if err != nil {
				t.Fatalf("rsa=%v status=%d: an honest token was refused: %v", rsaKey, status, err)
			}
			if !tok.GenTime.Equal(genTime) || tok.Serial.Cmp(big.NewInt(4242)) != 0 || !strings.Contains(tok.TSA, "Test TSA") || len(tok.DER) == 0 {
				t.Fatalf("rsa=%v: token %+v", rsaKey, tok)
			}
		}
	}
}

func TestATimestampThatDoesNotHoldIsRefused(t *testing.T) {
	a := newAuthority(t, false, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	req := aRequest(t)
	if _, err := Verify(a.respond(t, req, knobs{}), req, a.roots); err != nil {
		t.Fatalf("control: %v", err)
	}
	stranger := newAuthority(t, false, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	noEKU := newAuthority(t, false, nil)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, k := range map[string]knobs{
		"a rejection":                              {status: 2},
		"another imprint":                          {imprint: bytes.Repeat([]byte{1}, 48)},
		"another hash algorithm":                   {hashOID: oidSHA256},
		"another nonce":                            {nonce: big.NewInt(7)},
		"no nonce":                                 {noNonce: true},
		"the TSTInfo edited after signing":         {editAfterSign: true},
		"a signature by another key":               {signWith: otherKey},
		"no signing-certificate attribute":         {noSigningCert: true},
		"a signing certificate of another TSA":     {signingCertFor: stranger.tsaCert},
		"a content-type attribute of another kind": {contentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		"an eContentType that is not TSTInfo":      {eContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		"no certificates":                          {certs: []*x509.Certificate{}},
		"a byte after the end":                     {trailing: true},
	} {
		if _, err := Verify(a.respond(t, req, k), req, a.roots); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := Verify(stranger.respond(t, req, knobs{}), req, a.roots); err == nil {
		t.Error("a token from a TSA under another root verified")
	}
	if _, err := Verify(noEKU.respond(t, req, knobs{}), req, noEKU.roots); err == nil {
		t.Error("a token from a certificate without the time-stamping purpose verified")
	}
	if _, err := Verify(a.respond(t, req, knobs{}), aRequest(t), a.roots); err == nil {
		t.Error("a token for another request verified")
	}
}

func TestHostileTimestampResponsesNeverParseAndNeverPanic(t *testing.T) {
	a := newAuthority(t, false, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	req := aRequest(t)
	resp := a.respond(t, req, knobs{})
	honest, err := Verify(resp, req, a.roots)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	for n := 0; n < len(resp); n += 7 {
		if _, err := Verify(resp[:n], req, a.roots); err == nil {
			t.Fatalf("a response cut to %d bytes verified", n)
		}
	}
	r := mrand.New(mrand.NewPCG(20261018, 41))
	for i := 0; i < 3000; i++ {
		b := append([]byte(nil), resp...)
		for k := 0; k <= r.IntN(3); k++ {
			b[r.IntN(len(b))] = byte(r.IntN(256))
		}
		if tok, err := Verify(b, req, a.roots); err == nil && (!tok.GenTime.Equal(honest.GenTime) || tok.Serial.Cmp(honest.Serial) != 0) {
			t.Fatalf("case %d: an edited response verified as another token", i)
		}
	}
}

func TestTheClientPostsAQueryAndVerifiesTheReply(t *testing.T) {
	a := newAuthority(t, false, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	var seen string
	mode := "ok"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		var parsed struct {
			Version        int
			MessageImprint msgImprint
			Nonce          *big.Int `asn1:"optional"`
			CertReq        bool     `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(body, &parsed); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch mode {
		case "fail":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "huge":
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, _ = w.Write(bytes.Repeat([]byte{0}, MaxResponse+1))
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(a.respond(t, Request{DER: body, Nonce: parsed.Nonce, Digest: parsed.MessageImprint.HashedMessage}, knobs{}))
	}))
	defer srv.Close()
	c := Client{URL: srv.URL, HTTP: srv.Client(), Roots: a.roots}
	d := sha512.Sum384([]byte("a head"))
	tok, err := c.Stamp(context.Background(), d[:])
	if err != nil || !tok.GenTime.Equal(genTime) {
		t.Fatalf("Stamp: %+v %v", tok, err)
	}
	if seen != "application/timestamp-query" {
		t.Fatalf("the query was sent as %q", seen)
	}
	for _, m := range []string{"fail", "huge"} {
		mode = m
		if _, err := c.Stamp(context.Background(), d[:]); err == nil {
			t.Errorf("%s: Stamp succeeded", m)
		}
	}
}
