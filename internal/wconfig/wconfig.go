// Package wconfig reads the witness role's environment (CLAUDE.md invariants
// 6 and 7).
//
// Anything missing or malformed refuses the start and names the variable. The
// witness never shares custody's data directory, root key file, or root key:
// if KEYRYX_DATA or KEYRYX_ROOT_KEY_FILE is set where the witness starts, it
// must not be the witness's own, nor hold the same key. The uid and the volume
// each role runs under are the launcher's to choose; this is what this
// repository can hold.
package wconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/rootkey"
	"github.com/TAIPANBOX/keyryx/internal/trailryx"
	"github.com/TAIPANBOX/keyryx/internal/witness"
)

// DefaultAddr is where the witness listens when nothing says otherwise:
// loopback, beside custody's 4340.
const DefaultAddr = "127.0.0.1:4341"

// TSA is the opt-in time-stamping authority.
type TSA struct {
	URL   string
	Roots *x509.CertPool
	Every time.Duration
}

// Config is everything the witness needs.
type Config struct {
	Addr, DataDir, Alerts, CustodyURL string
	Root                              [32]byte
	Interval                          time.Duration
	Witness                           witness.Config
	TSA                               *TSA
}

var (
	tenantRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// An ES384 kid is an RFC 7638 thumbprint, an ML-DSA-65 kid the same
	// with its prefix: both 43 base64url characters of SHA-256.
	esKidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	mlKidRe = regexp.MustCompile(`^mldsa65:[A-Za-z0-9_-]{43}$`)
)

// rootPin reads an operator's pin of the delegation root: its kids, at
// least one of each half, since a statement verifies only under both.
func rootPin(v string) ([]string, error) {
	var kids []string
	es, ml := false, false
	for _, k := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' }) {
		k = strings.TrimSpace(k)
		switch {
		case k == "":
			continue
		case esKidRe.MatchString(k):
			es = true
		case mlKidRe.MatchString(k):
			ml = true
		default:
			return nil, fmt.Errorf("KEYRYX_WITNESS_DELEGATION_ROOT_PIN entry %q is not an ES384 or ML-DSA-65 kid", k)
		}
		kids = append(kids, k)
	}
	if !es || !ml {
		return nil, errors.New("KEYRYX_WITNESS_DELEGATION_ROOT_PIN must name at least one ES384 and one ML-DSA-65 kid of the delegation root")
	}
	sort.Strings(kids)
	return kids, nil
}

func duration(name string, def, lo, hi time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a duration", name, v)
	}
	if d < lo || d > hi {
		return 0, fmt.Errorf("%s %s is outside %s to %s", name, d, lo, hi)
	}
	return d, nil
}

func integer(name string, def, lo int64) (int64, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lo {
		return 0, fmt.Errorf("%s %q is not an integer of at least %d", name, v, lo)
	}
	return n, nil
}

func dirExists(name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", name, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %s is not a directory", name, path)
	}
	return nil
}

func same(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}

// FromEnv builds a config or says what is wrong.
func FromEnv() (Config, error) {
	var c Config
	c.DataDir = os.Getenv("KEYRYX_WITNESS_DATA")
	if c.DataDir == "" {
		return c, errors.New("KEYRYX_WITNESS_DATA is not set: the witness needs a directory of its own for its log and its key")
	}
	info, err := os.Stat(c.DataDir)
	if err != nil || !info.IsDir() {
		return c, fmt.Errorf("KEYRYX_WITNESS_DATA %s is not a directory", c.DataDir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return c, fmt.Errorf("KEYRYX_WITNESS_DATA %s is open to group or other (mode %o); it must be 0700", c.DataDir, info.Mode().Perm())
	}
	rootPath := os.Getenv("KEYRYX_WITNESS_ROOT_KEY_FILE")
	if rootPath == "" {
		return c, errors.New("KEYRYX_WITNESS_ROOT_KEY_FILE is not set: the witness key is wrapped under a root key of its own")
	}
	if c.Root, err = rootkey.Load(rootPath); err != nil {
		return c, fmt.Errorf("KEYRYX_WITNESS_ROOT_KEY_FILE: %w", err)
	}
	if v := os.Getenv("KEYRYX_DATA"); v != "" && same(v, c.DataDir) {
		return c, errors.New("KEYRYX_DATA and KEYRYX_WITNESS_DATA name one directory; custody and the witness never share one")
	}
	if v := os.Getenv("KEYRYX_ROOT_KEY_FILE"); v != "" {
		if same(v, rootPath) {
			return c, errors.New("KEYRYX_ROOT_KEY_FILE and KEYRYX_WITNESS_ROOT_KEY_FILE name one file; custody and the witness never share a root key")
		}
		if other, err := rootkey.Load(v); err == nil && bytes.Equal(other[:], c.Root[:]) {
			return c, errors.New("KEYRYX_ROOT_KEY_FILE holds the same root key as KEYRYX_WITNESS_ROOT_KEY_FILE; custody and the witness never share a key")
		}
	}
	c.Witness.Events = os.Getenv("KEYRYX_WITNESS_EVENTS")
	if c.Witness.Events == "" {
		return c, errors.New("KEYRYX_WITNESS_EVENTS is not set: the witness has no streams to read")
	}
	if err := dirExists("KEYRYX_WITNESS_EVENTS", c.Witness.Events); err != nil {
		return c, err
	}
	c.Witness.Checkpoints = os.Getenv("KEYRYX_WITNESS_CHECKPOINTS")
	c.CustodyURL = os.Getenv("KEYRYX_WITNESS_CUSTODY_URL")
	if c.Witness.Checkpoints != "" {
		if err := dirExists("KEYRYX_WITNESS_CHECKPOINTS", c.Witness.Checkpoints); err != nil {
			return c, err
		}
		if c.CustodyURL == "" {
			return c, errors.New("KEYRYX_WITNESS_CUSTODY_URL is not set and KEYRYX_WITNESS_CHECKPOINTS is: a checkpoint is checked against its key's statement, which custody serves")
		}
	}
	if c.Witness.StreamKeys, err = witness.ParseStreamKeys(os.Getenv("KEYRYX_WITNESS_STREAM_KEYS")); err != nil {
		return c, fmt.Errorf("KEYRYX_WITNESS_STREAM_KEYS: %w", err)
	}
	if c.Witness.Checkpoints != "" && len(c.Witness.StreamKeys) == 0 {
		return c, errors.New("KEYRYX_WITNESS_STREAM_KEYS is not set and KEYRYX_WITNESS_CHECKPOINTS is: each stream's checkpoints are taken only under the key its producer is certified for")
	}
	if v := os.Getenv("KEYRYX_WITNESS_DELEGATION_ROOT_PIN"); v != "" {
		if c.Witness.RootPin, err = rootPin(v); err != nil {
			return c, err
		}
	}
	if c.CustodyURL != "" {
		u, err := url.Parse(c.CustodyURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, fmt.Errorf("KEYRYX_WITNESS_CUSTODY_URL %q is not an http or https URL", c.CustodyURL)
		}
	}
	c.Alerts = os.Getenv("KEYRYX_WITNESS_ALERTS")
	if c.Alerts == "" {
		c.Alerts = filepath.Join(c.Witness.Events, "keyryx.ndjson")
	}
	seen := map[string]bool{}
	for _, item := range strings.FieldsFunc(os.Getenv("KEYRYX_WITNESS_RECORDS"), func(r rune) bool { return r == ',' || r == '\n' }) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, dir, ok := strings.Cut(item, "|")
		if !ok || !tenantRe.MatchString(name) || dir == "" {
			return c, fmt.Errorf("KEYRYX_WITNESS_RECORDS entry %q is not tenant|directory", item)
		}
		if seen[name] {
			return c, fmt.Errorf("KEYRYX_WITNESS_RECORDS names tenant %s twice", name)
		}
		seen[name] = true
		c.Witness.Records = append(c.Witness.Records, witness.Tenant{Name: name, Dir: dir})
	}
	c.Addr = os.Getenv("KEYRYX_WITNESS_ADDR")
	if c.Addr == "" {
		c.Addr = DefaultAddr
	}
	if host, port, err := net.SplitHostPort(c.Addr); err != nil || host == "" {
		return c, fmt.Errorf("KEYRYX_WITNESS_ADDR %q is not host:port", c.Addr)
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return c, fmt.Errorf("KEYRYX_WITNESS_ADDR %q has no usable port", c.Addr)
	}
	if c.Interval, err = duration("KEYRYX_WITNESS_INTERVAL", time.Minute, time.Second, time.Hour); err != nil {
		return c, err
	}
	if c.Witness.FullBytes, err = integer("KEYRYX_WITNESS_FULL_BYTES", 256<<20, 0); err != nil {
		return c, err
	}
	if c.Witness.FullInterval, err = duration("KEYRYX_WITNESS_FULL_INTERVAL", time.Hour, time.Minute, 24*time.Hour); err != nil {
		return c, err
	}
	if c.Witness.SealEvery, err = duration("KEYRYX_WITNESS_SEAL_EVERY", 15*time.Minute, time.Minute, 24*time.Hour); err != nil {
		return c, err
	}
	if c.Witness.SealLines, err = integer("KEYRYX_WITNESS_SEAL_LINES", 4096, 1); err != nil {
		return c, err
	}
	c.Witness.Name = os.Getenv("KEYRYX_WITNESS_NAME")
	if c.Witness.Name == "" {
		c.Witness.Name = "keyryx-witness"
	}
	if err := trailryx.CheckWitnessName(c.Witness.Name); err != nil {
		return c, fmt.Errorf("KEYRYX_WITNESS_NAME: %w", err)
	}
	c.Witness.Attestations = filepath.Join(c.DataDir, "attestations")
	if u := os.Getenv("KEYRYX_WITNESS_TSA_URL"); u != "" {
		pu, err := url.Parse(u)
		if err != nil || pu.Scheme != "https" || pu.Host == "" || pu.User != nil {
			return c, fmt.Errorf("KEYRYX_WITNESS_TSA_URL %q is not an https URL", u)
		}
		caPath := os.Getenv("KEYRYX_WITNESS_TSA_CA")
		if caPath == "" {
			return c, errors.New("KEYRYX_WITNESS_TSA_CA is not set and KEYRYX_WITNESS_TSA_URL is: a time-stamp is accepted only from a TSA under a root the operator names")
		}
		raw, err := os.ReadFile(caPath) // #nosec G304 -- operator-supplied path, read once at startup
		if err != nil {
			return c, fmt.Errorf("KEYRYX_WITNESS_TSA_CA: %w", err)
		}
		pool := x509.NewCertPool()
		n := 0
		for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return c, fmt.Errorf("KEYRYX_WITNESS_TSA_CA %s holds a certificate that does not parse", caPath)
			}
			pool.AddCert(cert)
			n++
		}
		if n == 0 {
			return c, fmt.Errorf("KEYRYX_WITNESS_TSA_CA %s holds no PEM certificate", caPath)
		}
		every, err := duration("KEYRYX_WITNESS_TSA_EVERY", time.Hour, 10*time.Minute, 24*time.Hour)
		if err != nil {
			return c, err
		}
		c.TSA = &TSA{URL: u, Roots: pool, Every: every}
	}
	return c, nil
}
