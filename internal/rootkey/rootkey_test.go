package rootkey

import (
	"bytes"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The root key wraps every stored key. A wrong answer here is silent in the
// worst way: a service that accepted a weak or exposed root key would come up
// looking exactly like one that did not.

var good = strings.Repeat("0123456789abcdef", 4)

func write(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestARootKeyOfSixtyFourHexCharactersLoads(t *testing.T) {
	want, _ := hex.DecodeString(good)
	for name, body := range map[string]string{"bare": good, "with a newline": good + "\n", "upper case": strings.ToUpper(good)} {
		got, err := Load(write(t, []byte(body), 0o400))
		if err != nil {
			t.Fatalf("%s: a well-formed root key was refused: %v", name, err)
		}
		if !bytes.Equal(got[:], want) {
			t.Fatalf("%s: the key read is not the key written", name)
		}
	}
	if _, err := Load(write(t, []byte(good), 0o600)); err != nil {
		t.Fatalf("0600 was refused: %v", err)
	}
}

func TestARootKeyReadableByGroupOrOtherIsRefused(t *testing.T) {
	if _, err := Load(write(t, []byte(good), 0o400)); err != nil {
		t.Fatalf("control: 0400 was refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o440, 0o404, 0o640, 0o644, 0o660, 0o606, 0o666, 0o700 | 0o040} {
		if _, err := Load(write(t, []byte(good), mode)); err == nil {
			t.Errorf("a root key with mode %o was accepted", mode)
		} else if !strings.Contains(err.Error(), "group or other") {
			t.Errorf("mode %o: the refusal does not say why: %v", mode, err)
		}
	}
}

func TestAMissingOrMalformedRootKeyIsRefused(t *testing.T) {
	if _, err := Load(write(t, []byte(good), 0o400)); err != nil {
		t.Fatalf("control: a well-formed key was refused: %v", err)
	}
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "absent.key")); err == nil {
		t.Error("a missing file was accepted")
	}
	if _, err := Load(dir); err == nil {
		t.Error("a directory was accepted")
	}
	for name, body := range map[string]string{
		"empty":             "",
		"63 characters":     good[:63],
		"65 characters":     good + "0",
		"not hex":           strings.Repeat("zz", 32),
		"two newlines":      good + "\n\n",
		"a space":           good + " ",
		"leading newline":   "\n" + good,
		"all zero":          strings.Repeat("0", 64),
		"raw 32 bytes":      string(bytes.Repeat([]byte{0x11}, 32)),
		"a carriage return": good + "\r\n",
	} {
		if _, err := Load(write(t, []byte(body), 0o400)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every random file either is a well-formed key or is refused, and none panics.
func TestHostileRootKeyFilesNeverLoadAndNeverPanic(t *testing.T) {
	if _, err := Load(write(t, []byte(good+"\n"), 0o400)); err != nil {
		t.Fatalf("control: a well-formed key was refused: %v", err)
	}
	r := rand.New(rand.NewPCG(20261018, 1))
	for i := 0; i < 2000; i++ {
		n := r.IntN(130)
		body := make([]byte, n)
		for j := range body {
			body[j] = byte(r.IntN(256))
		}
		if i%3 == 0 && n > 0 {
			// Mostly hex, so the sweep spends time near the accepted shape.
			for j := range body {
				body[j] = "0123456789abcdef\n"[r.IntN(17)]
			}
		}
		_, err := Load(write(t, body, 0o400))
		valid := (len(body) == 64 || (len(body) == 65 && body[64] == '\n')) && isHex(body[:min(64, len(body))]) && !allZero(body[:min(64, len(body))])
		if valid && err != nil {
			t.Fatalf("seed case %d: a valid key %q was refused: %v", i, body, err)
		}
		if !valid && err == nil {
			t.Fatalf("seed case %d: %q was accepted", i, body)
		}
	}
}

func isHex(b []byte) bool {
	for _, c := range b {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(c)) {
			return false
		}
	}
	return len(b) > 0
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != '0' {
			return false
		}
	}
	return true
}
