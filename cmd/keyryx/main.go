// Command keyryx is key custody and an independent witness for the
// agent-governance record.
//
// Two roles, one binary, never one process:
//
//	keyryx custody   holds keys, signs low-rate statements, certifies the
//	                 short-lived keys of high-rate signers, publishes JWKS
//	keyryx witness   reads the record read-only, countersigns what it saw,
//	                 keeps its own append-only log
//	keyryx verify    checks a witness log or streams and their checkpoints
//	                 offline, from files only
//	keyryx version   prints the version this binary was built as
//
// Neither role is on an agent's request path: no enforcement point waits on
// this service to decide anything (CLAUDE.md invariant 1).
//
// Each role refuses to start without what it needs and names the variable it
// is missing (invariant 6); the witness also refuses custody's directory or
// root key as its own (invariant 7).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/api"
	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/certify"
	"github.com/TAIPANBOX/keyryx/internal/config"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/uselog"
)

// version is overridden at build time via -ldflags (see Dockerfile).
var version = "dev"

// exitRefused is the exit code for "refusing to start", the one a launcher
// reads (components.json's missing_required_exit_code).
const exitRefused = 2

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: what each argument list does and which
// code it exits with, so the behaviour is testable without a subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitRefused
	}
	switch args[0] {
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "keyryx %s\n", version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	case "custody":
		return custody(stderr)
	case "witness":
		return witnessRole(stderr)
	case "verify":
		return verify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "keyryx: unknown command %q\n", args[0])
		usage(stderr)
		return exitRefused
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: keyryx <command>

commands:
  custody   hold keys, sign low-rate statements, certify delegated keys, publish key sets
  witness   read the record, say when what it saw is gone, keep a signed log
  verify    log --dir D --keys F
            streams --events D --checkpoints D --statements D --roots F
  version   print the version
`)
}

// SocketName is the file a socket consumer connects to, inside its own
// directory under KEYRYX_SOCKET_DIR.
const SocketName = "keyryx.sock"

// custody runs the custody role until SIGTERM or SIGINT. Everything it needs
// is checked before it listens, and anything missing refuses the start.
func custody(stderr io.Writer) int {
	refuse := func(err error) int {
		fmt.Fprintf(stderr, "keyryx: refusing to start: %v\n", err)
		return exitRefused
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return refuse(err)
	}
	// The store holds the keys custody signs with: the policy's held keys and
	// the two halves of the delegation root. A delegated key is never in it.
	store, err := keystore.Open(cfg.DataDir, cfg.Root, append(cfg.Policy.HeldKeys(), statement.RootKeys...), time.Now)
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_DATA: %w", err))
	}
	certs, err := certify.Open(cfg.DataDir, store, cfg.Policy, cfg.PublishAhead, time.Now)
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_DATA: %w", err))
	}
	ul, err := uselog.Open(filepath.Join(cfg.DataDir, "use.ndjson"))
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_DATA: %w", err))
	}
	defer ul.Close()
	// A state custody could not vouch for is treated as revoked; it is said
	// on stderr and written on the use log at every start until an admin
	// revokes the key it names.
	for _, a := range append(store.Alarms(), certs.Alarms()...) {
		fmt.Fprintf(stderr, "keyryx: ALARM: the %s %s %s has a state custody did not write (%s); it is treated as revoked until an admin revokes it\n", a.Kind, a.Name, a.Kid, a.Reason)
		if err := ul.Append(uselog.Entry{At: time.Now().Unix(), Consumer: "keyryx", Op: "state_alarm", Key: a.Name, Kid: a.Kid, Purpose: a.Reason}); err != nil {
			return refuse(fmt.Errorf("KEYRYX_DATA: the use log does not take the alarm: %w", err))
		}
	}
	srv := &api.Server{
		Policy: cfg.Policy, Store: store, Certs: certs, Log: ul,
		Auth:      &auth.Verifier{Policy: cfg.Policy, Issuers: cfg.Issuers, Now: time.Now},
		AdminKeys: cfg.AdminKeys, PublishAhead: cfg.PublishAhead, Now: time.Now, Version: version,
	}
	handler := srv.Handler()

	tcp, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_ADDR: %w", err))
	}
	type listener struct {
		l   net.Listener
		srv *http.Server
	}
	all := []listener{{tcp, newServer(handler, nil)}}
	for _, c := range cfg.Policy.SocketConsumers() {
		path := filepath.Join(cfg.SocketDir, c.Socket, SocketName)
		l, err := listenSocket(path)
		if err != nil {
			for _, x := range all {
				_ = x.l.Close()
			}
			return refuse(fmt.Errorf("KEYRYX_SOCKET_DIR: consumer %s: %w", c.Name, err))
		}
		name := c.Name
		all = append(all, listener{l, newServer(handler, func(ctx context.Context, _ net.Conn) context.Context {
			return api.WithSocketConsumer(ctx, name)
		})})
	}

	log.SetOutput(stderr)
	log.Printf("keyryx custody %s: listening on %s and %d consumer sockets; %d keys held", version, cfg.Addr, len(all)-1, len(cfg.Policy.Keys))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	failed := make(chan error, len(all))
	for _, x := range all {
		go func() {
			if err := x.srv.Serve(x.l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				failed <- err
			}
		}()
	}
	code := 0
	select {
	case <-ctx.Done():
	case err := <-failed:
		log.Printf("keyryx custody: a listener stopped: %v", err)
		code = 1
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, x := range all {
		_ = x.srv.Shutdown(shut)
	}
	return code
}

func newServer(h http.Handler, conn func(context.Context, net.Conn) context.Context) *http.Server {
	return &http.Server{
		Handler:           h,
		ConnContext:       conn,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// listenSocket listens on a consumer's socket. A socket left by a previous
// run is replaced; anything else at that path refuses, because custody never
// removes a file it did not make. The socket itself is open to every user
// who can reach it: the directory around it, which config checks carries no
// permission for other, is what decides who can.
func listenSocket(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- the consumer's directory is the gate; see listenSocket
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
