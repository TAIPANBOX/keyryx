package main

import (
	"bytes"
	"strings"
	"testing"
)

func call(args ...string) (code int, stdout, stderr string) {
	var out, errw bytes.Buffer
	code = run(args, &out, &errw)
	return code, out.String(), errw.String()
}

func TestTheVersionIsPrintedAndExitsZero(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-V"} {
		code, out, _ := call(arg)
		if code != 0 || out != "keyryx dev\n" {
			t.Errorf("%s: exit %d, printed %q", arg, code, out)
		}
	}
}

func TestARoleThatIsNotBuiltRefusesToStart(t *testing.T) {
	for _, role := range []string{"witness"} {
		code, out, errOut := call(role)
		if code != exitRefused {
			t.Errorf("%s: exit %d, want %d", role, code, exitRefused)
		}
		if out != "" {
			t.Errorf("%s: printed to stdout %q; a refusal goes to stderr", role, out)
		}
		if !strings.Contains(errOut, "refusing to start") || !strings.Contains(errOut, role) {
			t.Errorf("%s: the refusal does not say what refused: %q", role, errOut)
		}
	}
}

func TestNoCommandOrAnUnknownOneRefusesWithTheUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"serve"}, {"--custody"}} {
		code, _, errOut := call(args...)
		if code != exitRefused || !strings.Contains(errOut, "usage: keyryx") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
	if code, out, _ := call("help"); code != 0 || !strings.Contains(out, "usage: keyryx") {
		t.Errorf("help: exit %d, stdout %q", code, out)
	}
}

// Custody is built now, and refuses to start without what it needs, naming
// the first thing missing (CLAUDE.md invariant 6).
func TestCustodyRefusesToStartWithoutItsConfiguration(t *testing.T) {
	for _, k := range []string{"KEYRYX_DATA", "KEYRYX_ROOT_KEY_FILE", "KEYRYX_POLICY"} {
		t.Setenv(k, "")
	}
	code, out, errOut := call("custody")
	if code != exitRefused {
		t.Fatalf("custody with an empty environment exited %d", code)
	}
	if out != "" || !strings.Contains(errOut, "refusing to start") || !strings.Contains(errOut, "KEYRYX_") {
		t.Fatalf("the refusal does not name what is missing: stdout %q stderr %q", out, errOut)
	}
	if strings.Contains(errOut, "not built in this version") {
		t.Fatalf("custody still says it is not built: %q", errOut)
	}
}
