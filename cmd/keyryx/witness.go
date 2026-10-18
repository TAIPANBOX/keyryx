package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/TAIPANBOX/keyryx/internal/checkpoint"
	"github.com/TAIPANBOX/keyryx/internal/keystore"
	"github.com/TAIPANBOX/keyryx/internal/merkle"
	"github.com/TAIPANBOX/keyryx/internal/statement"
	"github.com/TAIPANBOX/keyryx/internal/tsa"
	"github.com/TAIPANBOX/keyryx/internal/wconfig"
	"github.com/TAIPANBOX/keyryx/internal/witness"
	"github.com/TAIPANBOX/keyryx/internal/witnessapi"
	"github.com/TAIPANBOX/keyryx/internal/wlog"
)

// witnessRole runs the witness until SIGTERM or SIGINT: a read of the record
// every interval, a signed tree head after each, and, when an operator named
// one, a time-stamp of the latest head from an RFC 3161 authority.
func witnessRole(stderr io.Writer) int {
	refuse := func(err error) int {
		fmt.Fprintf(stderr, "keyryx: refusing to start: %v\n", err)
		return exitRefused
	}
	cfg, err := wconfig.FromEnv()
	if err != nil {
		return refuse(err)
	}
	store, err := keystore.Open(cfg.DataDir, cfg.Root, wlog.Keys, time.Now)
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_WITNESS_DATA: %w", err))
	}
	for _, a := range store.Alarms() {
		fmt.Fprintf(stderr, "keyryx: ALARM: the witness %s %s %s has a state the witness did not write (%s); it is treated as revoked\n", a.Kind, a.Name, a.Kid, a.Reason)
	}
	wl, err := wlog.Open(cfg.DataDir, statement.StoreKeys(store, wlog.KeyES384, wlog.KeyMLDSA), time.Now)
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_WITNESS_DATA: %w", err))
	}
	defer wl.Close()
	alerts, err := witness.NewEventAlerter(cfg.Alerts, time.Now)
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_WITNESS_ALERTS: %w", err))
	}
	var keys witness.Keys
	if cfg.CustodyURL != "" {
		keys = &witness.CustodyKeys{Base: cfg.CustodyURL, HTTP: &http.Client{Timeout: 10 * time.Second}, TTL: cfg.Interval}
	}
	w, err := witness.New(cfg.Witness, wl, store, keys, alerts, time.Now)
	if err != nil {
		return refuse(err)
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return refuse(fmt.Errorf("KEYRYX_WITNESS_ADDR: %w", err))
	}
	srv := newServer((&witnessapi.Server{Log: wl, Store: store}).Handler(), nil)
	log.SetOutput(stderr)
	log.Printf("keyryx witness %s: listening on %s; reading %s every %s", version, cfg.Addr, cfg.Witness.Events, cfg.Interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	failed := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
	}()
	var stamper *tsa.Client
	if cfg.TSA != nil {
		stamper = &tsa.Client{URL: cfg.TSA.URL, Roots: cfg.TSA.Roots, HTTP: &http.Client{Timeout: 30 * time.Second}}
	}
	var lastAnchor time.Time
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	code := 0
	for {
		if _, err := w.Tick(); err != nil {
			log.Printf("keyryx witness: %v", err)
		}
		if stamper != nil && time.Since(lastAnchor) >= cfg.TSA.Every {
			if err := anchor(ctx, wl, stamper); err != nil {
				log.Printf("keyryx witness: the time-stamp was not taken: %v", err)
			} else {
				lastAnchor = time.Now()
			}
		}
		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
		case err := <-failed:
			log.Printf("keyryx witness: the listener stopped: %v", err)
			code = 1
		}
		break
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shut)
	return code
}

// anchor time-stamps the SHA-384 of the latest tree head's signed input and
// writes the token into the log, so the next head covers it.
func anchor(ctx context.Context, wl *wlog.Log, c *tsa.Client) error {
	h, ok := wl.Latest()
	if !ok {
		return errors.New("no tree head yet")
	}
	root, err := rootOf(h)
	if err != nil {
		return err
	}
	digest := sha512.Sum384(wlog.HeadInput(h.Size, root, h.At))
	tok, err := c.Stamp(ctx, digest[:])
	if err != nil {
		return err
	}
	return wl.Append(wlog.Entry{Kind: "anchor", SeenAt: time.Now().Unix(), Size: h.Size, Token: base64.StdEncoding.EncodeToString(tok.DER),
		GenTime: tok.GenTime.Unix()})
}

func rootOf(h wlog.Head) (merkle.Hash, error) {
	var r merkle.Hash
	b, err := hexDecode(h.Root)
	if err != nil || len(b) != len(r) {
		return r, errors.New("a head's root is not a SHA-384 digest")
	}
	copy(r[:], b)
	return r, nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		var v byte
		for _, c := range []byte(s[2*i : 2*i+2]) {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			default:
				return nil, errors.New("not lowercase hex")
			}
		}
		out[i] = v
	}
	return out, nil
}

func verifyUsage(stderr io.Writer) int {
	fmt.Fprint(stderr, `usage: keyryx verify log --dir <witness data directory> --keys <witness key set file>
       keyryx verify streams --events <dir> --checkpoints <dir> --statements <dir> --stream-keys <stream|key-name,...> --roots <delegation root key set file>
`)
	return exitRefused
}

// verify checks offline, from files only, and prints [ok], [weak] or [broken]
// per check, trailryx-verify's vocabulary. It exits 0 when nothing is broken
// and something was measured, and 1 otherwise: it never says OK about nothing.
func verify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return verifyUsage(stderr)
	}
	fs := flag.NewFlagSet("verify "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	keysFile := fs.String("keys", "", "")
	events := fs.String("events", "", "")
	ckpts := fs.String("checkpoints", "", "")
	stmts := fs.String("statements", "", "")
	rootsFile := fs.String("roots", "", "")
	streamKeys := fs.String("stream-keys", "", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return verifyUsage(stderr)
	}
	var lines []string
	broken, measured := false, false
	switch args[0] {
	case "log":
		if *dir == "" || *keysFile == "" {
			return verifyUsage(stderr)
		}
		keys, err := readKeys(*keysFile)
		if err != nil {
			lines, broken = append(lines, "[broken] keys: "+err.Error()), true
			break
		}
		rep := wlog.VerifyDir(*dir, keys)
		lines, broken, measured = rep.Lines, rep.Broken, rep.Measured
	case "streams":
		if *events == "" || *ckpts == "" || *stmts == "" || *rootsFile == "" || *streamKeys == "" {
			return verifyUsage(stderr)
		}
		bound, err := witness.ParseStreamKeys(*streamKeys)
		if err != nil {
			fmt.Fprintf(stderr, "keyryx verify: --stream-keys: %v\n", err)
			return verifyUsage(stderr)
		}
		roots, err := readKeys(*rootsFile)
		if err != nil {
			lines, broken = append(lines, "[broken] roots: "+err.Error()), true
			break
		}
		lines, broken, measured = verifyStreams(*events, *ckpts, *stmts, bound, roots)
	default:
		return verifyUsage(stderr)
	}
	for _, l := range lines {
		fmt.Fprintln(stdout, l)
	}
	if broken || !measured {
		fmt.Fprintln(stdout, "NOT VERIFIED")
		return 1
	}
	fmt.Fprintln(stdout, "VERIFIED")
	return 0
}

func readKeys(path string) (statement.RootKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- a file the auditor named
	if err != nil {
		return nil, err
	}
	return statement.KeysFromJWKS(raw)
}

// verifyStreams checks every stream that has a checkpoint file, record by
// record, each key against the statement saved under its kid and the key
// name the auditor bound that stream to.
func verifyStreams(events, ckpts, stmts string, bound map[string]string, roots statement.RootKey) ([]string, bool, bool) {
	var lines []string
	broken, measured := false, false
	entries, err := os.ReadDir(events)
	if err != nil {
		return []string{"[broken] streams: " + err.Error()}, true, false
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ndjson") && e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	keysFor := func(stream string) func(string, time.Time) ([]byte, error) {
		return func(kid string, at time.Time) ([]byte, error) {
			raw, err := os.ReadFile(filepath.Join(stmts, filepath.Base(kid)+".json")) // #nosec G304 -- a file in the directory the auditor named
			if err != nil {
				return nil, errors.New("no statement certifies that key in " + stmts)
			}
			st, revoked, err := witness.ParseStatementAnswer(raw)
			if err != nil {
				return nil, err
			}
			// Offline there is no witness clock: a record counts as seen at
			// its own time, so a key revoked before then refuses it.
			c, err := witness.KeyFromStatement(st, revoked, roots, kid, at, at)
			if err != nil {
				return nil, err
			}
			if err := witness.CheckBound(bound, stream, c); err != nil {
				return nil, err
			}
			return c.Public, nil
		}
	}
	for _, name := range names {
		file, err := os.ReadFile(filepath.Join(ckpts, name+".ckpt.ndjson")) // #nosec G304 -- a file in the directory the auditor named
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			lines, broken = append(lines, fmt.Sprintf("[broken] %s: %v", name, err)), true
			continue
		}
		stream, err := os.ReadFile(filepath.Join(events, name)) // #nosec G304 -- a file in the directory the auditor named
		if err != nil {
			lines, broken = append(lines, fmt.Sprintf("[broken] %s: %v", name, err)), true
			continue
		}
		for _, r := range checkpoint.VerifyFile(file, stream, keysFor(name)) {
			measured = true
			switch r.Status {
			case checkpoint.Accepted:
				lines = append(lines, fmt.Sprintf("[ok] %s record %d (%d lines): signed, and the stream still holds what it covers", name, r.Index+1, r.Record.Count))
			case checkpoint.Unsigned:
				lines = append(lines, fmt.Sprintf("[weak] %s record %d (%d lines): unsigned, %s", name, r.Index+1, r.Record.Count, r.Record.UnsignedReason))
			default:
				broken = true
				lines = append(lines, fmt.Sprintf("[broken] %s record %d: %s", name, r.Index+1, r.Reason))
			}
		}
	}
	if !measured && !broken {
		lines = append(lines, "[broken] streams: no stream in "+events+" has a checkpoint file in "+ckpts+", so this check measured nothing")
	}
	return lines, broken, measured
}
