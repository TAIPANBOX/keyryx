// Package witnessapi is the witness role's read-only HTTP surface. Scaffold.
package witnessapi

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"

	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// Route is one entry of the route table.
type Route struct{ Method, Pattern string }

// Routes is the route table. Scaffold.
func Routes() []Route { return nil }

// Server holds the log and the witness key store.
type Server struct {
	Log   *wlog.Log
	Store *keystore.Store
}

// Handler is the mux. Scaffold.
func (s *Server) Handler() http.Handler { return http.NewServeMux() }

func hexOrB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return hex.DecodeString(s)
}
