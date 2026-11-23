package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/config"
)

// adminArg is what a key name or a kid may be on the command line: the
// policy's name grammar and the base64url of a thumbprint, which may begin
// with `_` or `-`, both fit; a path separator, a leading dot (so no dot
// segment) or a query does not.
var adminArg = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)

// admin asks custody, on its admin socket, to rotate a key or revoke a kid.
// The socket is `$KEYRYX_DATA/admin.sock`, the variable custody itself reads,
// so inside custody's container it needs nothing more. It opens neither the
// store nor the root key: custody does the work and checks who asked, and a
// refusal prints its status only, the reason being in custody's own log
// (invariant 23).
func admin(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || (args[0] != "rotate" && args[0] != "revoke") {
		fmt.Fprint(stderr, "usage: keyryx admin rotate NAME | keyryx admin revoke KID\n")
		return exitRefused
	}
	if !adminArg.MatchString(args[1]) {
		fmt.Fprintf(stderr, "keyryx admin: %q is not a key name or a kid\n", args[1])
		return exitRefused
	}
	dir := os.Getenv("KEYRYX_DATA")
	if dir == "" {
		fmt.Fprint(stderr, "keyryx admin: KEYRYX_DATA is not set: the admin socket is custody's, inside its data directory\n")
		return exitRefused
	}
	sock := filepath.Join(dir, config.AdminSocketName)
	path := "/v1/keys/" + url.PathEscape(args[1]) + "/rotate"
	if args[0] == "revoke" {
		path = "/v1/kids/" + url.PathEscape(args[1]) + "/revoke"
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequest(http.MethodPost, "http://keyryx-admin"+path, nil)
	if err != nil {
		fmt.Fprintf(stderr, "keyryx admin: %v\n", err)
		return 1
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "keyryx admin: custody's admin socket %s did not answer: %v\n", sock, err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "keyryx admin: custody refused the %s: %s; the reason is in custody's log\n", args[0], resp.Status)
		return 1
	}
	_, _ = stdout.Write(body)
	return 0
}
