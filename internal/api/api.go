// Package api is the custody role's HTTP surface.
//
// Every route is in one table, Routes, and the mux is built from that table
// and nothing else, so the table is the whole surface: a test calls every
// route in it, and a route that is not in it is not served
// (TestTheRouteTableIsTheMux). None of these routes is on a request path
// (CLAUDE.md invariant 1): a sign is asked for at human rate (an approval
// granted) or schedule rate (a seal, a manifest); the key sets are fetched and
// cached by verifiers, which keep verifying when this service is down.
//
// A refusal tells the caller its status and nothing else; the reason goes to
// the operator's log (invariant 23). A signature, and a key statement, is
// answered only once its use is on the use log (invariant 18).
//
// Delegated keys (internal/certify): a consumer granted `delegate` asks for a
// challenge, answers it with a proof made by its own key, and gets a key
// statement; the name's key set then publishes the key. The delegation
// root's own key set, both halves, is `GET /v1/jwks/keyryx.delegation-root`.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/certify"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/uselog"
)

// Route is one entry of the route table. Access is public, consumer (a
// consumer the policy grants the key to) or admin (a KEYRYX_ADMIN_KEYS key).
type Route struct {
	Method, Pattern, Access string
}

var routes = []Route{
	{"GET", "/healthz", "public"},
	{"GET", "/v1/state", "public"},
	{"GET", "/v1/keys", "public"},
	{"GET", "/v1/jwks/{name}", "public"},
	{"POST", "/v1/keys/{name}/sign", "consumer"},
	{"POST", "/v1/keys/{name}/challenge", "consumer"},
	{"POST", "/v1/keys/{name}/delegate", "consumer"},
	{"GET", "/v1/statements/{kid}", "public"},
	{"POST", "/v1/keys/{name}/rotate", "admin"},
	{"POST", "/v1/kids/{kid}/revoke", "admin"},
}

// Routes is the route table: every route this service serves, and only those.
func Routes() []Route { return slices.Clone(routes) }

// Server holds what the handlers need.
type Server struct {
	Policy       *policy.Policy
	Store        *keystore.Store
	Certs        *certify.Registry
	Log          *uselog.Log
	Auth         *auth.Verifier
	AdminKeys    [][32]byte
	PublishAhead time.Duration
	Now          func() time.Time
	Version      string
}

// MaxBody bounds a request body. A sign request is a 4 KiB statement in
// base64 and a short purpose; anything near this is not one.
const MaxBody = 16 << 10

var purposeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type ctxKey struct{}

// WithSocketConsumer marks a connection as arriving on a consumer's own
// socket. Only the socket listener calls it, with the consumer the policy
// binds to that socket; the key is unexported, so nothing a client sends can
// set it.
func WithSocketConsumer(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxKey{}, name)
}

// Handler is the mux, built from the route table.
func (s *Server) Handler() http.Handler {
	h := map[string]http.HandlerFunc{
		"GET /healthz":                   s.healthz,
		"GET /v1/state":                  s.state,
		"GET /v1/keys":                   s.inventory,
		"GET /v1/jwks/{name}":            s.jwks,
		"POST /v1/keys/{name}/sign":      s.sign,
		"POST /v1/keys/{name}/challenge": s.challenge,
		"POST /v1/keys/{name}/delegate":  s.delegate,
		"GET /v1/statements/{kid}":       s.statement,
		"POST /v1/keys/{name}/rotate":    s.rotate,
		"POST /v1/kids/{kid}/revoke":     s.revoke,
	}
	mux := http.NewServeMux()
	for _, r := range routes {
		if f, ok := h[r.Method+" "+r.Pattern]; ok {
			mux.HandleFunc(r.Method+" "+r.Pattern, f)
		}
	}
	return mux
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// refuse answers a status and a word for it. The reason is the operator's,
// logged, and never part of the answer.
func refuse(w http.ResponseWriter, code int, route, reason string, kv ...any) {
	args := append([]any{route, reason}, kv...)
	format := "keyryx: refused %s: reason=%s"
	for i := 0; i+1 < len(kv); i += 2 {
		format += " %s=%q"
	}
	log.Printf(format, args...)
	writeJSON(w, code, map[string]string{"error": http.StatusText(code)})
}

// consumer says who is asking. A request that came in on a consumer's socket
// is that consumer and no other, whatever it carries; a request over TCP is
// whoever its bearer resolves to, and nobody when it resolves to nobody.
func (s *Server) consumer(r *http.Request) (name, via string, ok bool) {
	if sc, isSocket := r.Context().Value(ctxKey{}).(string); isSocket {
		for _, c := range s.Policy.SocketConsumers() {
			if c.Name == sc {
				return c.Name, "socket", true
			}
		}
		return "", "socket", false
	}
	if s.Auth == nil {
		return "", "bearer", false
	}
	n, via, ok := s.Auth.FromBearer(r.Header.Get("Authorization"))
	if via == "" {
		via = "bearer"
	}
	return n, via, ok
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request, route string) (string, bool) {
	if len(s.AdminKeys) == 0 {
		refuse(w, http.StatusForbidden, route, "admin_disabled")
		return "", false
	}
	fp, ok := auth.Admin(s.AdminKeys, r.Header.Get("Authorization"))
	if !ok {
		refuse(w, http.StatusUnauthorized, route, "admin_unknown")
		return "", false
	}
	return fp, true
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) state(w http.ResponseWriter, _ *http.Request) {
	type keyState struct {
		Name        string   `json:"name"`
		Alg         string   `json:"alg"`
		Mode        string   `json:"mode"`
		ActiveKid   string   `json:"active_kid,omitempty"`
		ActiveSince int64    `json:"active_since,omitempty"`
		NextKid     string   `json:"next_kid,omitempty"`
		NextAt      int64    `json:"next_activates_at,omitempty"`
		LiveKids    []string `json:"live_kids,omitempty"`
		RenewDue    bool     `json:"renew_due,omitempty"`
	}
	var keys []keyState
	now := s.now()
	for _, k := range append(append([]policy.Key(nil), s.Policy.Keys...), statement.RootKeys...) {
		ks := keyState{Name: k.Name, Alg: string(k.Alg), Mode: string(k.Mode)}
		if k.Mode == policy.Delegated {
			// A delegated name is due for renewal when no key of it is
			// valid past half its life from now.
			fresh := false
			for _, e := range s.certs() {
				if e.Statement.Name != k.Name || e.Revoked != 0 || !e.Statement.ValidAt(now) {
					continue
				}
				ks.LiveKids = append(ks.LiveKids, e.Statement.Kid)
				half := e.Statement.NotBefore + (e.Statement.NotAfter-e.Statement.NotBefore)/2
				fresh = fresh || now.Unix() < half
			}
			ks.RenewDue = !fresh
			keys = append(keys, ks)
			continue
		}
		recs, _ := s.Store.Published(k.Name)
		for _, r := range recs {
			switch r.State {
			case keystore.Active:
				ks.ActiveKid, ks.ActiveSince = r.Kid, max(r.ActivateAt, r.Created)
			case keystore.Next:
				ks.NextKid, ks.NextAt = r.Kid, r.ActivateAt
			}
		}
		keys = append(keys, ks)
	}
	// A state custody found on disk and could not vouch for: the key it
	// names is treated as revoked, and the alarm stays until an admin
	// revokes that key (CLAUDE.md invariant 30).
	alarms := append(s.Store.Alarms(), s.certAlarms()...)
	if alarms == nil {
		alarms = []keystore.Alarm{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": "custody", "version": s.Version, "root_key": "loaded", "keys": keys, "alarms": alarms})
}

func (s *Server) inventory(w http.ResponseWriter, _ *http.Request) {
	type entry struct {
		Name       string `json:"name"`
		Alg        string `json:"alg"`
		Kid        string `json:"kid"`
		Mode       string `json:"mode"`
		State      string `json:"state"`
		Created    int64  `json:"created"`
		ActivateAt int64  `json:"activate_at,omitempty"`
		Retired    int64  `json:"retired,omitempty"`
		Revoked    int64  `json:"revoked,omitempty"`
		Owner      string `json:"owner,omitempty"`
		NotBefore  int64  `json:"not_before,omitempty"`
		NotAfter   int64  `json:"not_after,omitempty"`
	}
	out := []entry{}
	for _, r := range s.Store.Inventory() {
		out = append(out, entry{Name: r.Name, Alg: string(r.Alg), Kid: r.Kid, Mode: string(policy.Held), State: string(r.State),
			Created: r.Created, ActivateAt: r.ActivateAt, Retired: r.Retired, Revoked: r.Revoked})
	}
	now := s.now()
	for _, e := range s.certs() {
		st := e.Statement
		state := "active"
		switch {
		case e.Revoked != 0:
			state = "revoked"
		case now.Unix() < st.NotBefore:
			state = "pending"
		case now.Unix() >= st.NotAfter:
			state = "expired"
		}
		out = append(out, entry{Name: st.Name, Alg: st.JWK.Alg, Kid: st.Kid, Mode: string(policy.Delegated), State: state,
			Created: st.IssuedAt, Revoked: e.Revoked, Owner: st.Owner, NotBefore: st.NotBefore, NotAfter: st.NotAfter})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// jwks publishes a key's set. Its cache lifetime is at most half the
// publish-ahead time, so a verifier that refreshes on it holds a next key
// before that key signs anything (invariant 20).
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	keys := []map[string]any{}
	found := false
	if s.Certs != nil {
		// A delegated name's set: the keys its statements certify.
		if published, ok := s.Certs.Published(name); ok {
			keys, found = published, true
		}
	}
	if !found {
		names := []string{name}
		if name == statement.RootName {
			names = []string{statement.RootES384, statement.RootMLDSA}
		}
		for _, n := range names {
			recs, ok := s.Store.Published(n)
			found = found || ok
			for _, rec := range recs {
				if j := keystore.JWK(rec); j != nil {
					keys = append(keys, j)
				}
			}
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	age := min(int64(s.PublishAhead/time.Second)/2, 300)
	w.Header().Set("Cache-Control", "public, max-age="+itoa(max(age, 0)))
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

type signRequest struct {
	Statement *string `json:"statement_b64"`
	Purpose   *string `json:"purpose"`
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	const route = "sign"
	name := r.PathValue("name")
	consumer, via, ok := s.consumer(r)
	if !ok {
		refuse(w, http.StatusUnauthorized, route, "consumer_unknown", "via", via, "key", name)
		return
	}
	if !s.Policy.Allowed(consumer, name, policy.OpSign) {
		refuse(w, http.StatusForbidden, route, "key_not_granted", "consumer", consumer, "key", name)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req signRequest
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			refuse(w, http.StatusRequestEntityTooLarge, route, "body_too_large", "consumer", consumer)
			return
		}
		refuse(w, http.StatusBadRequest, route, "body_not_a_request", "consumer", consumer)
		return
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		refuse(w, http.StatusBadRequest, route, "body_has_trailing_data", "consumer", consumer)
		return
	}
	if req.Statement == nil || req.Purpose == nil || !purposeRe.MatchString(*req.Purpose) {
		refuse(w, http.StatusBadRequest, route, "statement_or_purpose_missing", "consumer", consumer)
		return
	}
	stmt, err := base64.StdEncoding.Strict().DecodeString(*req.Statement)
	if err != nil || len(stmt) == 0 {
		refuse(w, http.StatusBadRequest, route, "statement_not_base64", "consumer", consumer)
		return
	}
	if len(stmt) > keystore.MaxStatement {
		refuse(w, http.StatusRequestEntityTooLarge, route, "statement_too_large", "consumer", consumer)
		return
	}
	sig, err := s.Store.Sign(name, stmt)
	if err != nil {
		refuse(w, http.StatusInternalServerError, route, "store_failed", "consumer", consumer, "key", name, "error", err.Error())
		return
	}
	sum := sha256.Sum256(stmt)
	if err := s.Log.Append(uselog.Entry{At: s.now().Unix(), Consumer: consumer, Op: policy.OpSign, Key: name,
		Kid: sig.Kid, Purpose: *req.Purpose, Digest: "sha256:" + hex.EncodeToString(sum[:])}); err != nil {
		// The signature exists only in this process and is dropped: a
		// signature with no record of it is what this service must never hand out.
		refuse(w, http.StatusServiceUnavailable, route, "use_log_failed", "consumer", consumer, "error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"alg":            string(sig.Alg),
		"kid":            sig.Kid,
		"signature_b64":  base64.StdEncoding.EncodeToString(sig.Sig),
		"public_key_b64": base64.StdEncoding.EncodeToString(sig.Public),
	})
}

func publicRecord(r keystore.Record) map[string]any {
	return map[string]any{"name": r.Name, "alg": string(r.Alg), "kid": r.Kid, "state": string(r.State),
		"created": r.Created, "activate_at": r.ActivateAt, "retired": r.Retired, "revoked": r.Revoked}
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	const route = "rotate"
	fp, ok := s.admin(w, r, route)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if name == statement.RootName {
		s.rotateRoot(w, fp)
		return
	}
	rec, err := s.Store.Rotate(name, s.PublishAhead)
	switch {
	case errors.Is(err, keystore.ErrUnknownKey):
		refuse(w, http.StatusNotFound, route, "key_unknown", "key", name)
		return
	case errors.Is(err, keystore.ErrRotationInProgress):
		refuse(w, http.StatusConflict, route, "rotation_in_progress", "key", name)
		return
	case err != nil:
		refuse(w, http.StatusInternalServerError, route, "store_failed", "key", name, "error", err.Error())
		return
	}
	if err := s.Log.Append(uselog.Entry{At: s.now().Unix(), Consumer: "admin:" + fp, Op: "rotate", Key: name, Kid: rec.Kid}); err != nil {
		refuse(w, http.StatusServiceUnavailable, route, "use_log_failed", "key", name, "error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, publicRecord(rec))
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	const route = "revoke"
	fp, ok := s.admin(w, r, route)
	if !ok {
		return
	}
	kid := r.PathValue("kid")
	rec, err := s.Store.Revoke(kid)
	switch {
	case errors.Is(err, keystore.ErrUnknownKid) && s.Certs != nil:
		s.revokeDelegated(w, fp, kid)
		return
	case errors.Is(err, keystore.ErrUnknownKid):
		refuse(w, http.StatusNotFound, route, "kid_unknown", "kid", kid)
		return
	case err != nil:
		refuse(w, http.StatusInternalServerError, route, "store_failed", "kid", kid, "error", err.Error())
		return
	}
	if err := s.Log.Append(uselog.Entry{At: s.now().Unix(), Consumer: "admin:" + fp, Op: "revoke", Key: rec.Name, Kid: rec.Kid}); err != nil {
		refuse(w, http.StatusServiceUnavailable, route, "use_log_failed", "kid", kid, "error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, publicRecord(rec))
}

func (s *Server) certAlarms() []keystore.Alarm {
	if s.Certs == nil {
		return nil
	}
	return s.Certs.Alarms()
}

func (s *Server) certs() []certify.Entry {
	if s.Certs == nil {
		return nil
	}
	return s.Certs.Inventory()
}

// rotateRoot rotates both halves of the delegation root together, so a
// statement is always signed by two halves of one generation.
func (s *Server) rotateRoot(w http.ResponseWriter, fp string) {
	const route = "rotate"
	halves := []string{statement.RootES384, statement.RootMLDSA}
	for _, n := range halves {
		recs, _ := s.Store.Published(n)
		for _, rec := range recs {
			if rec.State == keystore.Next {
				refuse(w, http.StatusConflict, route, "rotation_in_progress", "key", n)
				return
			}
		}
	}
	var out []map[string]any
	for _, n := range halves {
		rec, err := s.Store.Rotate(n, s.PublishAhead)
		if err != nil {
			refuse(w, http.StatusInternalServerError, route, "store_failed", "key", n, "error", err.Error())
			return
		}
		if err := s.Log.Append(uselog.Entry{At: s.now().Unix(), Consumer: "admin:" + fp, Op: "rotate", Key: n, Kid: rec.Kid}); err != nil {
			refuse(w, http.StatusServiceUnavailable, route, "use_log_failed", "key", n, "error", err.Error())
			return
		}
		out = append(out, publicRecord(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) revokeDelegated(w http.ResponseWriter, fp, kid string) {
	const route = "revoke"
	st, err := s.Certs.Revoke(kid)
	switch {
	case errors.Is(err, certify.ErrUnknownKid):
		refuse(w, http.StatusNotFound, route, "kid_unknown", "kid", kid)
		return
	case err != nil:
		refuse(w, http.StatusInternalServerError, route, "registry_failed", "kid", kid, "error", err.Error())
		return
	}
	if err := s.Log.Append(uselog.Entry{At: s.now().Unix(), Consumer: "admin:" + fp, Op: "revoke", Key: st.Name, Kid: st.Kid}); err != nil {
		refuse(w, http.StatusServiceUnavailable, route, "use_log_failed", "kid", kid, "error", err.Error())
		return
	}
	_, revoked, _ := s.Certs.Statement(kid)
	writeJSON(w, http.StatusOK, map[string]any{"name": st.Name, "kid": st.Kid, "mode": string(policy.Delegated), "revoked": revoked})
}

// delegator resolves the consumer and checks its delegate grant on name.
func (s *Server) delegator(w http.ResponseWriter, r *http.Request, route string) (consumer, name string, ok bool) {
	name = r.PathValue("name")
	consumer, via, ok := s.consumer(r)
	if !ok {
		refuse(w, http.StatusUnauthorized, route, "consumer_unknown", "via", via, "key", name)
		return "", "", false
	}
	if !s.Policy.Allowed(consumer, name, policy.OpDelegate) || s.Certs == nil {
		refuse(w, http.StatusForbidden, route, "key_not_granted", "consumer", consumer, "key", name)
		return "", "", false
	}
	return consumer, name, true
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	const route = "challenge"
	consumer, name, ok := s.delegator(w, r, route)
	if !ok {
		return
	}
	c, exp, err := s.Certs.Challenge(consumer, name)
	if err != nil {
		refuse(w, http.StatusForbidden, route, "key_not_delegated", "consumer", consumer, "key", name)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": c, "expires_at": exp})
}

type delegateRequest struct {
	JWK       json.RawMessage `json:"jwk"`
	Challenge *string         `json:"challenge"`
	Proof     *string         `json:"proof_b64"`
	Lifetime  *int64          `json:"lifetime_s"`
}

func (s *Server) delegate(w http.ResponseWriter, r *http.Request) {
	const route = "delegate"
	consumer, name, ok := s.delegator(w, r, route)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req delegateRequest
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			refuse(w, http.StatusRequestEntityTooLarge, route, "body_too_large", "consumer", consumer)
			return
		}
		refuse(w, http.StatusBadRequest, route, "body_not_a_request", "consumer", consumer)
		return
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		refuse(w, http.StatusBadRequest, route, "body_has_trailing_data", "consumer", consumer)
		return
	}
	if req.JWK == nil || req.Challenge == nil || req.Proof == nil || req.Lifetime == nil {
		refuse(w, http.StatusBadRequest, route, "field_missing", "consumer", consumer)
		return
	}
	proof, err := base64.StdEncoding.Strict().DecodeString(*req.Proof)
	if err != nil || *req.Lifetime <= 0 || *req.Lifetime > int64(policy.MaxLifetime/time.Second) {
		refuse(w, http.StatusBadRequest, route, "proof_or_life_malformed", "consumer", consumer)
		return
	}
	var logErr error
	st, raw, err := s.Certs.Delegate(consumer, name, certify.Request{JWK: req.JWK, Challenge: *req.Challenge, Proof: proof,
		Lifetime: time.Duration(*req.Lifetime) * time.Second}, func(st statement.Statement, raw []byte) error {
		sum := sha256.Sum256(raw)
		logErr = s.Log.Append(uselog.Entry{At: s.now().Unix(), Consumer: consumer, Op: policy.OpDelegate, Key: name, Kid: st.Kid,
			Digest: "sha256:" + hex.EncodeToString(sum[:])})
		return logErr
	})
	switch {
	case err == nil:
	case logErr != nil:
		refuse(w, http.StatusServiceUnavailable, route, "use_log_failed", "consumer", consumer, "error", logErr.Error())
		return
	case errors.Is(err, certify.ErrNoChallenge):
		refuse(w, http.StatusForbidden, route, "challenge_unknown", "consumer", consumer, "key", name)
		return
	case errors.Is(err, certify.ErrBadProof):
		refuse(w, http.StatusForbidden, route, "proof_invalid", "consumer", consumer, "key", name)
		return
	case errors.Is(err, certify.ErrKidRevoked):
		refuse(w, http.StatusForbidden, route, "kid_revoked", "consumer", consumer, "key", name)
		return
	case errors.Is(err, certify.ErrBadKey), errors.Is(err, certify.ErrLifetime):
		refuse(w, http.StatusBadRequest, route, "key_or_life_refused", "consumer", consumer, "key", name, "error", err.Error())
		return
	case errors.Is(err, certify.ErrKidKnown):
		refuse(w, http.StatusConflict, route, "kid_already_certified", "consumer", consumer, "key", name)
		return
	case errors.Is(err, certify.ErrTooManyLive):
		refuse(w, http.StatusConflict, route, "too_many_live_keys", "consumer", consumer, "key", name)
		return
	default:
		refuse(w, http.StatusInternalServerError, route, "registry_failed", "consumer", consumer, "key", name, "error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"statement": json.RawMessage(raw), "kid": st.Kid, "not_before": st.NotBefore, "not_after": st.NotAfter})
}

// statement serves the statement that certified a key, and when it was
// revoked, for a verifier checking what a delegated key signed.
func (s *Server) statement(w http.ResponseWriter, r *http.Request) {
	if s.Certs == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	raw, revoked, ok := s.Certs.Statement(r.PathValue("kid"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	age := min(int64(s.PublishAhead/time.Second)/2, 300)
	w.Header().Set("Cache-Control", "public, max-age="+itoa(max(age, 0)))
	writeJSON(w, http.StatusOK, map[string]any{"statement": json.RawMessage(raw), "revoked_at": revoked})
}
