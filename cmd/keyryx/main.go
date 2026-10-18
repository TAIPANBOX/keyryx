// Command keyryx is key custody and an independent witness for the
// agent-governance record.
//
// Two roles, one binary, never one process:
//
//	keyryx custody   holds keys, signs low-rate statements, certifies the
//	                 short-lived keys of high-rate signers, publishes JWKS
//	keyryx witness   reads the record read-only, countersigns what it saw,
//	                 keeps its own append-only log
//	keyryx version   prints the version this binary was built as
//
// Neither role is on an agent's request path: no enforcement point waits on
// this service to decide anything (CLAUDE.md invariant 1).
//
// This is the scaffold. Neither role is built yet, and asking for one refuses
// to start rather than starting a service that holds nothing and looks
// healthy (invariant 6).
package main

import (
	"fmt"
	"io"
	"os"
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
	case "custody", "witness":
		// Refusing, not idling: a key service that came up holding nothing
		// would answer its health path and sign nothing, which reads as working.
		fmt.Fprintf(stderr, "keyryx: refusing to start: the %s role is not built in this version\n", args[0])
		return exitRefused
	default:
		fmt.Fprintf(stderr, "keyryx: unknown command %q\n", args[0])
		usage(stderr)
		return exitRefused
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: keyryx <command>

commands:
  custody   hold keys, sign low-rate statements, certify short-lived keys (not built yet)
  witness   countersign what the record holds, keep an append-only log (not built yet)
  version   print the version
`)
}
