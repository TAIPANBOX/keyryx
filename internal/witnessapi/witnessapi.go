// Package witnessapi is the witness role's HTTP surface: reads only, no
// credential, nothing on a request path (CLAUDE.md invariants 1 and 33).
//
// A verifier that kept a tree head asks two things: is this entry in the log
// (inclusion), and is today's log an extension of the one I saw
// (consistency). Both proofs are RFC 9162's over the witness's own log, and
// the key set they verify under is the witness key's two halves.
package witnessapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/merkle"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// Route is one entry of the route table.
type Route struct{ Method, Pattern string }

var routes = []Route{
	{"GET", "/healthz"},
	{"GET", "/v1/witness/head"},
	{"GET", "/v1/witness/keys"},
	{"GET", "/v1/witness/inclusion"},
	{"GET", "/v1/witness/consistency"},
	{"GET", "/v1/witness/entries"},
}

// Routes is the route table: every route the witness serves, and only those.
func Routes() []Route { return slices.Clone(routes) }

// MaxEntries bounds one entries answer.
const MaxEntries = 1000

// Server holds the log and the witness key store.
type Server struct {
	Log   *wlog.Log
	Store *keystore.Store
}

// Handler is the mux, built from the route table.
func (s *Server) Handler() http.Handler {
	h := map[string]http.HandlerFunc{
		"GET /healthz":                s.healthz,
		"GET /v1/witness/head":        s.head,
		"GET /v1/witness/keys":        s.keys,
		"GET /v1/witness/inclusion":   s.inclusion,
		"GET /v1/witness/consistency": s.consistency,
		"GET /v1/witness/entries":     s.entries,
	}
	mux := http.NewServeMux()
	for _, r := range routes {
		if f, ok := h[r.Method+" "+r.Pattern]; ok {
			mux.HandleFunc(r.Method+" "+r.Pattern, f)
		}
	}
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func bad(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": http.StatusText(http.StatusBadRequest)})
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) head(w http.ResponseWriter, _ *http.Request) {
	h, ok := s.Log.Latest()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	writeJSON(w, http.StatusOK, h)
}

// keys publishes the witness key's two halves, every state but revoked.
func (s *Server) keys(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]any{}
	for _, n := range []string{wlog.KeyES384, wlog.KeyMLDSA} {
		recs, _ := s.Store.Published(n)
		for _, r := range recs {
			if j := keystore.JWK(r); j != nil {
				out = append(out, j)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// param reads a non-negative integer query parameter.
func param(r *http.Request, name string) (int, bool) {
	v := r.URL.Query().Get(name)
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || len(v) > 12 {
		return 0, false
	}
	return n, true
}

func hexes(hs []merkle.Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = hex.EncodeToString(h[:])
	}
	return out
}

func (s *Server) inclusion(w http.ResponseWriter, r *http.Request) {
	index, ok1 := param(r, "index")
	size, ok2 := param(r, "size")
	leaves := s.Log.Leaves()
	if !ok1 || !ok2 || size < 1 || size > len(leaves) || index >= size {
		bad(w)
		return
	}
	p, err := merkle.InclusionProof(leaves[:size], index)
	if err != nil {
		bad(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"index": index, "size": size, "leaf": hex.EncodeToString(leaves[index][:]), "proof": hexes(p)})
}

func (s *Server) consistency(w http.ResponseWriter, r *http.Request) {
	first, ok1 := param(r, "first")
	second, ok2 := param(r, "second")
	leaves := s.Log.Leaves()
	if !ok1 || !ok2 || first < 1 || first > second || second > len(leaves) {
		bad(w)
		return
	}
	p, err := merkle.ConsistencyProof(leaves[:second], first)
	if err != nil {
		bad(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"first": first, "second": second, "proof": hexes(p)})
}

func (s *Server) entries(w http.ResponseWriter, r *http.Request) {
	start, ok1 := param(r, "start")
	end, ok2 := param(r, "end")
	if !ok1 || !ok2 || start >= end || end-start > MaxEntries || int64(end) > s.Log.Size() {
		bad(w)
		return
	}
	out := []json.RawMessage{}
	for _, line := range s.Log.Lines(start, end) {
		out = append(out, json.RawMessage(line))
	}
	writeJSON(w, http.StatusOK, map[string]any{"start": start, "end": end, "entries": out})
}
