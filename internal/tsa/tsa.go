// Package tsa is an RFC 3161 time-stamping client, standard library only
// (CLAUDE.md invariant 35).
//
// The witness asks an operator-chosen authority, opt-in and off by default,
// to time-stamp the SHA-384 of its latest tree head, so that a rewrite of the
// witness's own log by whoever holds the host cannot be dated before the
// time-stamp. A token is accepted only when every one of these holds:
//
//   - the status is granted or granted with modifications;
//   - the token is CMS SignedData (RFC 5652) whose content is a TSTInfo;
//   - the TSTInfo's imprint is SHA-384 over exactly the digest asked for, and
//     its nonce is the request's;
//   - the signer's signed attributes carry the content type TSTInfo, the
//     digest of the TSTInfo as signed, and a signing-certificate attribute
//     (RFC 5035 v2, or RFC 2634 v1) naming the signer's certificate;
//   - the signature over those attributes verifies under the signer's
//     certificate, and that certificate chains to a root the operator
//     configured, for the time-stamping purpose, at the token's own time.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 2634 ESSCertID names the signer by SHA-1 of its certificate; the hash identifies, it does not sign
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// MaxResponse bounds a TSA's answer.
const MaxResponse = 64 << 10

var (
	idSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	idSHA384     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	idSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	idSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	idTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	idCType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	idMDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	idSigCertV1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	idSigCertV2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	idRSA        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	idRSA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	idRSA384     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	idRSA512     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	idECDSA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	idECDSA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	idECDSA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	idECPublic   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional,default:false"`
}

// Request is a TimeStampReq over a SHA-384 digest.
type Request struct {
	DER    []byte
	Nonce  *big.Int
	Digest []byte
}

// NewRequest builds a request for a SHA-384 digest, with a fresh 128-bit
// nonce, asking for the signer's certificate.
func NewRequest(digest []byte) (Request, error) {
	if len(digest) != sha512.Size384 {
		return Request{}, errors.New("tsa: the digest is not SHA-384's length")
	}
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Request{}, err
	}
	der, err := asn1.Marshal(timeStampReq{Version: 1, MessageImprint: messageImprint{algorithmIdentifier{Algorithm: idSHA384}, digest},
		Nonce: nonce, CertReq: true})
	if err != nil {
		return Request{}, err
	}
	return Request{DER: der, Nonce: nonce, Digest: append([]byte(nil), digest...)}, nil
}

// Token is a verified time-stamp token.
type Token struct {
	DER     []byte
	GenTime time.Time
	Serial  *big.Int
	Policy  string
	TSA     string
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

type essCertID struct {
	CertHash []byte
	Issuer   asn1.RawValue `asn1:"optional"`
}

type signingCertificate struct {
	Certs    []essCertID
	Policies asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	HashAlgorithm algorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	Issuer        asn1.RawValue `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

func unmarshalWhole(b []byte, into any, params string) error {
	rest, err := asn1.UnmarshalWithParams(b, into, params)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}

// elements splits the contents of a SET or an IMPLICIT SET into its elements.
func elements(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(idSHA256):
		return crypto.SHA256, true
	case oid.Equal(idSHA384):
		return crypto.SHA384, true
	case oid.Equal(idSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

// signatureAlgorithm maps a signer's digest and signature algorithms to the
// x509 algorithm that checks them.
func signatureAlgorithm(digest crypto.Hash, sig asn1.ObjectIdentifier) (x509.SignatureAlgorithm, bool) {
	switch {
	case sig.Equal(idRSA256), sig.Equal(idRSA) && digest == crypto.SHA256:
		return x509.SHA256WithRSA, true
	case sig.Equal(idRSA384), sig.Equal(idRSA) && digest == crypto.SHA384:
		return x509.SHA384WithRSA, true
	case sig.Equal(idRSA512), sig.Equal(idRSA) && digest == crypto.SHA512:
		return x509.SHA512WithRSA, true
	case sig.Equal(idECDSA256), sig.Equal(idECPublic) && digest == crypto.SHA256:
		return x509.ECDSAWithSHA256, true
	case sig.Equal(idECDSA384), sig.Equal(idECPublic) && digest == crypto.SHA384:
		return x509.ECDSAWithSHA384, true
	case sig.Equal(idECDSA512), sig.Equal(idECPublic) && digest == crypto.SHA512:
		return x509.ECDSAWithSHA512, true
	}
	return x509.UnknownSignatureAlgorithm, false
}

func refuse(why string) (Token, error) { return Token{}, errors.New("tsa: " + why) }

// Verify checks a TimeStampResp against the request it answers and the roots
// the operator configured.
func Verify(resp []byte, req Request, roots *x509.CertPool) (Token, error) {
	if len(resp) > MaxResponse {
		return refuse("the answer is over its size cap")
	}
	var r timeStampResp
	if err := unmarshalWhole(resp, &r, ""); err != nil {
		return refuse("the answer is not a TimeStampResp: " + err.Error())
	}
	if r.Status.Status != 0 && r.Status.Status != 1 {
		return refuse(fmt.Sprintf("the authority refused, status %d", r.Status.Status))
	}
	if len(r.TimeStampToken.FullBytes) == 0 {
		return refuse("a granted answer carries no token")
	}
	var ci contentInfo
	if err := unmarshalWhole(r.TimeStampToken.FullBytes, &ci, ""); err != nil || !ci.ContentType.Equal(idSignedData) {
		return refuse("the token is not CMS SignedData")
	}
	var sd signedData
	if err := unmarshalWhole(ci.Content.Bytes, &sd, ""); err != nil {
		return refuse("the token's SignedData does not parse: " + err.Error())
	}
	if !sd.EncapContentInfo.EContentType.Equal(idTSTInfo) {
		return refuse("the token's content is not a TSTInfo")
	}
	var eContent []byte
	if err := unmarshalWhole(sd.EncapContentInfo.EContent.Bytes, &eContent, ""); err != nil || len(eContent) == 0 {
		return refuse("the token carries no TSTInfo")
	}
	var info tstInfo
	if err := unmarshalWhole(eContent, &info, ""); err != nil {
		return refuse("the TSTInfo does not parse: " + err.Error())
	}
	if info.Version != 1 || !info.MessageImprint.HashAlgorithm.Algorithm.Equal(idSHA384) || !bytes.Equal(info.MessageImprint.HashedMessage, req.Digest) {
		return refuse("the token time-stamps something other than the SHA-384 digest asked for")
	}
	if info.Nonce == nil || req.Nonce == nil || info.Nonce.Cmp(req.Nonce) != 0 {
		return refuse("the token's nonce is not the request's")
	}
	if info.SerialNumber == nil {
		return refuse("the token has no serial number")
	}
	var certs []*x509.Certificate
	if len(sd.Certificates.Bytes) > 0 {
		els, err := elements(sd.Certificates.Bytes)
		if err != nil {
			return refuse("the token's certificates do not parse")
		}
		for _, e := range els {
			c, err := x509.ParseCertificate(e.FullBytes)
			if err != nil {
				return refuse("a certificate in the token does not parse")
			}
			certs = append(certs, c)
		}
	}
	signers, err := elements(sd.SignerInfos.Bytes)
	if err != nil || len(signers) != 1 {
		return refuse("the token does not have exactly one signer")
	}
	var si signerInfo
	if err := unmarshalWhole(signers[0].FullBytes, &si, ""); err != nil {
		return refuse("the signer does not parse: " + err.Error())
	}
	var sid issuerAndSerial
	if err := unmarshalWhole(si.SID.FullBytes, &sid, ""); err != nil {
		return refuse("the signer is not named by issuer and serial number")
	}
	var signer *x509.Certificate
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, sid.Issuer.FullBytes) && c.SerialNumber.Cmp(sid.Serial) == 0 {
			signer = c
		}
	}
	if signer == nil {
		return refuse("the token does not carry the signer's certificate")
	}
	digestHash, ok := hashFor(si.DigestAlgorithm.Algorithm)
	if !ok {
		return refuse("the signer's digest algorithm is not one this client checks")
	}
	if len(si.SignedAttrs.FullBytes) == 0 {
		return refuse("the signer has no signed attributes")
	}
	attrs, err := elements(si.SignedAttrs.Bytes)
	if err != nil {
		return refuse("the signed attributes do not parse")
	}
	var gotType, gotDigest, gotCert bool
	h := digestHash.New()
	h.Write(eContent)
	contentDigest := h.Sum(nil)
	for _, a := range attrs {
		var at attribute
		if err := unmarshalWhole(a.FullBytes, &at, ""); err != nil {
			return refuse("a signed attribute does not parse")
		}
		vals, err := elements(at.Values.Bytes)
		if err != nil || len(vals) != 1 {
			return refuse("a signed attribute does not carry one value")
		}
		v := vals[0].FullBytes
		switch {
		case at.Type.Equal(idCType):
			var ct asn1.ObjectIdentifier
			if unmarshalWhole(v, &ct, "") != nil || !ct.Equal(idTSTInfo) {
				return refuse("the signed content type is not TSTInfo")
			}
			gotType = true
		case at.Type.Equal(idMDigest):
			var md []byte
			if unmarshalWhole(v, &md, "") != nil || !bytes.Equal(md, contentDigest) {
				return refuse("the signed digest is not the digest of the TSTInfo as it stands")
			}
			gotDigest = true
		case at.Type.Equal(idSigCertV2):
			var sc signingCertificateV2
			if unmarshalWhole(v, &sc, "") != nil || len(sc.Certs) == 0 {
				return refuse("the signing-certificate attribute does not parse")
			}
			hh := crypto.SHA256
			if len(sc.Certs[0].HashAlgorithm.Algorithm) > 0 {
				if hh, ok = hashFor(sc.Certs[0].HashAlgorithm.Algorithm); !ok {
					return refuse("the signing certificate is named by a hash this client does not check")
				}
			}
			ch := hh.New()
			ch.Write(signer.Raw)
			if !bytes.Equal(ch.Sum(nil), sc.Certs[0].CertHash) {
				return refuse("the signing-certificate attribute names another certificate")
			}
			gotCert = true
		case at.Type.Equal(idSigCertV1):
			var sc signingCertificate
			if unmarshalWhole(v, &sc, "") != nil || len(sc.Certs) == 0 {
				return refuse("the signing-certificate attribute does not parse")
			}
			sum := sha1.Sum(signer.Raw) // #nosec G401 -- RFC 2634 ESSCertID is SHA-1 by definition; identification, not a signature
			if !bytes.Equal(sum[:], sc.Certs[0].CertHash) {
				return refuse("the signing-certificate attribute names another certificate")
			}
			gotCert = true
		}
	}
	if !gotType || !gotDigest || !gotCert {
		return refuse("the signed attributes lack the content type, the digest or the signing certificate")
	}
	alg, ok := signatureAlgorithm(digestHash, si.SignatureAlgorithm.Algorithm)
	if !ok {
		return refuse("the signature algorithm is not one this client checks")
	}
	// The signature covers the attributes as a SET, not as the [0] IMPLICIT
	// they are carried in (RFC 5652 section 5.4).
	signedSet := append([]byte(nil), si.SignedAttrs.FullBytes...)
	signedSet[0] = 0x31
	if err := signer.CheckSignature(alg, signedSet, si.Signature); err != nil {
		return refuse("the token's signature does not verify under its signer's certificate")
	}
	// RFC 3161 section 2.3: one critical extended key usage extension naming
	// time-stamping and nothing else. A certificate with no such extension is
	// good for any purpose to x509.Verify, and so not good enough here.
	ekuCritical := false
	for _, e := range signer.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			ekuCritical = e.Critical
		}
	}
	if !ekuCritical || len(signer.ExtKeyUsage) != 1 || signer.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(signer.UnknownExtKeyUsage) != 0 {
		return refuse("the signer's certificate is not marked for time-stamping alone, in a critical extension")
	}
	inter := x509.NewCertPool()
	for _, c := range certs {
		if c != signer {
			inter.AddCert(c)
		}
	}
	if _, err := signer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: info.GenTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
		return refuse("the signer's certificate does not chain to a configured root for time-stamping: " + err.Error())
	}
	return Token{DER: append([]byte(nil), r.TimeStampToken.FullBytes...), GenTime: info.GenTime, Serial: info.SerialNumber,
		Policy: info.Policy.String(), TSA: signer.Subject.String()}, nil
}

// Client asks a TSA.
type Client struct {
	URL   string
	HTTP  *http.Client
	Roots *x509.CertPool
}

// Stamp asks for a time-stamp over a SHA-384 digest and verifies the answer.
func (c Client) Stamp(ctx context.Context, digest []byte) (Token, error) {
	req, err := NewRequest(digest)
	if err != nil {
		return Token{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(req.DER))
	if err != nil {
		return Token{}, err
	}
	hr.Header.Set("Content-Type", "application/timestamp-query")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(hr) // #nosec G107 -- the URL is the operator's configured authority
	if err != nil {
		return Token{}, fmt.Errorf("tsa: asking %s: %w", c.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("tsa: %s answered %d", c.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return Token{}, err
	}
	if len(body) > MaxResponse {
		return Token{}, errors.New("tsa: the answer is over its size cap")
	}
	return Verify(body, req, c.Roots)
}
