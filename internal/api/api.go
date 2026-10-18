// Package api is the custody role's HTTP surface. Scaffold.
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/uselog"
)

// Route is one entry of the route table.
type Route struct {
	Method, Pattern, Access string
}

// Routes is the route table. Scaffold: none.
func Routes() []Route { return nil }

// Server holds what the handlers need.
type Server struct {
	Policy       *policy.Policy
	Store        *keystore.Store
	Log          *uselog.Log
	Auth         *auth.Verifier
	AdminKeys    [][32]byte
	PublishAhead time.Duration
	Now          func() time.Time
}

// Handler is the mux. Scaffold: every route 404.
func (s *Server) Handler() http.Handler { return http.NewServeMux() }

// WithSocketConsumer marks a connection as arriving on a consumer's socket.
func WithSocketConsumer(ctx context.Context, name string) context.Context { return ctx }
