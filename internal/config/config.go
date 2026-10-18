// Package config reads the custody role's environment.
//
// Every value is a statement about which keys custody holds and who may use
// them, so a missing or malformed one refuses the start and the message names
// the variable (CLAUDE.md invariant 6). Nothing has a default that signs: the
// defaults are a loopback address, a fifteen-minute overlap and no admin key.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/auth"
	"github.com/TAIPANBOX/keyryx/internal/policy"
	"github.com/TAIPANBOX/keyryx/internal/rootkey"
)

// DefaultAddr is where custody listens when nothing says otherwise: loopback,
// on the port the estate's port map reserves for it.
const DefaultAddr = "127.0.0.1:4340"

// DefaultPublishAhead is how long a next key is published before it signs.
const DefaultPublishAhead = 15 * time.Minute

// Config is everything custody needs.
type Config struct {
	Addr         string
	DataDir      string
	Root         [32]byte
	Policy       *policy.Policy
	SocketDir    string
	AdminKeys    [][32]byte
	Issuers      []auth.Issuer
	PublishAhead time.Duration
}

// FromEnv builds a config or says what is wrong.
func FromEnv() (Config, error) {
	var c Config
	c.DataDir = os.Getenv("KEYRYX_DATA")
	if c.DataDir == "" {
		return c, errors.New("KEYRYX_DATA is not set: custody needs a data directory for its wrapped keys and its use log")
	}
	rootPath := os.Getenv("KEYRYX_ROOT_KEY_FILE")
	if rootPath == "" {
		return c, errors.New("KEYRYX_ROOT_KEY_FILE is not set: custody wraps every key under a root key and holds none without it")
	}
	root, err := rootkey.Load(rootPath)
	if err != nil {
		return c, fmt.Errorf("KEYRYX_ROOT_KEY_FILE: %w", err)
	}
	c.Root = root
	polPath := os.Getenv("KEYRYX_POLICY")
	if polPath == "" {
		return c, errors.New("KEYRYX_POLICY is not set: custody signs for nobody without a policy naming its keys and consumers")
	}
	raw, err := readCapped(polPath, policy.MaxBytes)
	if err != nil {
		return c, fmt.Errorf("KEYRYX_POLICY: %w", err)
	}
	if c.Policy, err = policy.Parse(raw); err != nil {
		return c, fmt.Errorf("KEYRYX_POLICY %s: %w", polPath, err)
	}

	c.Addr = os.Getenv("KEYRYX_ADDR")
	if c.Addr == "" {
		c.Addr = DefaultAddr
	}
	if host, port, err := net.SplitHostPort(c.Addr); err != nil || host == "" {
		return c, fmt.Errorf("KEYRYX_ADDR %q is not host:port", c.Addr)
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return c, fmt.Errorf("KEYRYX_ADDR %q has no usable port", c.Addr)
	}

	c.PublishAhead = DefaultPublishAhead
	if v := os.Getenv("KEYRYX_PUBLISH_AHEAD"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("KEYRYX_PUBLISH_AHEAD %q is not a duration", v)
		}
		if d < time.Minute || d > 24*time.Hour {
			return c, fmt.Errorf("KEYRYX_PUBLISH_AHEAD %s is outside one minute to one day", d)
		}
		c.PublishAhead = d
	}

	if c.AdminKeys, err = auth.ParseAdminKeys(os.Getenv("KEYRYX_ADMIN_KEYS")); err != nil {
		return c, fmt.Errorf("KEYRYX_ADMIN_KEYS: %w", err)
	}

	if c.Issuers, err = auth.ParseIssuers(os.Getenv("KEYRYX_K8S_ISSUERS"), readJWKS); err != nil {
		return c, fmt.Errorf("KEYRYX_K8S_ISSUERS: %w", err)
	}
	configured := map[string]bool{}
	for _, is := range c.Issuers {
		configured[is.Iss] = true
	}
	for _, iss := range c.Policy.K8sIssuers() {
		if !configured[iss] {
			return c, fmt.Errorf("KEYRYX_K8S_ISSUERS names no keys for %s, which a consumer in KEYRYX_POLICY authenticates against", iss)
		}
	}

	sockets := c.Policy.SocketConsumers()
	c.SocketDir = os.Getenv("KEYRYX_SOCKET_DIR")
	if len(sockets) > 0 && c.SocketDir == "" {
		return c, fmt.Errorf("KEYRYX_SOCKET_DIR is not set and consumer %s authenticates by socket", sockets[0].Name)
	}
	for _, sc := range sockets {
		if err := socketDir(filepath.Join(c.SocketDir, sc.Socket)); err != nil {
			return c, fmt.Errorf("KEYRYX_SOCKET_DIR: consumer %s: %w", sc.Name, err)
		}
	}
	return c, nil
}

// socketDir checks a consumer's socket directory: a real directory the
// operator made for that consumer, which other users cannot enter. The
// directory is what keeps another local user off the consumer's socket.
func socketDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("its socket directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("its socket directory %s is not a directory", path)
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("its socket directory %s is open to other users (mode %o); it must carry no permission for other", path, info.Mode().Perm())
	}
	return nil
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path, read once at startup
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over the %d-byte cap", path, limit)
	}
	return b, nil
}

func readJWKS(path string) ([]byte, error) { return readCapped(path, 1<<20) }
