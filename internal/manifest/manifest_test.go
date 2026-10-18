// The declaration in components.json is only worth reading if this repository
// proves it, and proves it by running rather than by describing.
//
// What is proved here is the `checked` bucket and nothing else. The
// `declared` bucket carries a `why` on every entry and is asserted against
// nothing, on purpose: a test that pretended to verify a sentence about
// purpose would be the failure this design exists to avoid.
package manifest_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type manifest struct {
	Repo       string `json:"repo"`
	Components []struct {
		Name    string `json:"name"`
		Checked struct {
			Package string `json:"package"`
			Env     map[string]struct {
				Required bool `json:"required"`
			} `json:"env"`
			RefusedRoles            []string `json:"refused_roles"`
			MissingRequiredExitCode int      `json:"missing_required_exit_code"`
		} `json:"checked"`
		Declared map[string]struct {
			Why string `json:"why"`
		} `json:"declared"`
	} `json:"components"`
}

func root(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("no go.mod above the test's working directory")
	return ""
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	raw, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("components.json is not JSON this reader understands: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares nothing, so this test measured nothing")
	}
	return m, r
}

// A binary this repository builds and does not declare is invisible from
// outside by construction.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)
	list := exec.Command("go", "list", "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./...")
	list.Dir = r
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			built[line] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package, so this test measured nothing")
	}
	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}
	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// Every KEYRYX_ name in non-test source, against every one declared, by
// string literal rather than by os.Getenv call site, so a name read through a
// helper is not missed. Zero names is a true state for the scaffold; zero
// files read is not, and fails.
func TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)
	name := regexp.MustCompile(`"(KEYRYX_[A-Z0-9_]+)"`)
	read := map[string]bool{}
	files := 0
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.Walk(filepath.Join(r, dir), func(p string, info os.FileInfo, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			files++
			for _, mm := range name.FindAllStringSubmatch(string(b), -1) {
				read[mm[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files == 0 {
		t.Fatal("no non-test Go file was read, so this test measured nothing")
	}
	declared := map[string]bool{}
	for _, c := range m.Components {
		for k := range c.Checked.Env {
			declared[k] = true
		}
	}
	for v := range read {
		if !declared[v] {
			t.Errorf("this repository reads %s and components.json does not declare it", v)
		}
	}
	for v := range declared {
		if !read[v] {
			t.Errorf("components.json declares %s and nothing in this repository reads it", v)
		}
	}
}

// A declared entry with no `why` is a claim wearing the costume of a
// decision.
func TestEveryDeclaredEntryCarriesItsReason(t *testing.T) {
	m, _ := load(t)
	n := 0
	for _, c := range m.Components {
		for k, v := range c.Declared {
			n++
			if strings.TrimSpace(v.Why) == "" {
				t.Errorf("%s: declared entry %q has no why", c.Name, k)
			}
		}
	}
	if n == 0 {
		t.Fatal("no declared entry exists, so this test measured nothing")
	}
}

// The built binary refuses each role this version does not build, with the
// exit code a launcher reads. Started as a process, because a launcher sees a
// process and nothing else.
func TestTheBuiltBinaryRefusesARoleItDoesNotBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the binary")
	}
	m, r := load(t)
	bin := filepath.Join(t.TempDir(), "keyryx")
	build := exec.Command("go", "build", "-o", bin, "./cmd/keyryx")
	build.Dir = r
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}
	c := m.Components[0]
	if len(c.Checked.RefusedRoles) == 0 || c.Checked.MissingRequiredExitCode == 0 {
		t.Fatal("components.json names no refused role or no exit code, so this test measured nothing")
	}
	for _, role := range c.Checked.RefusedRoles {
		cmd := exec.Command(bin, role)
		cmd.Env = []string{}
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != c.Checked.MissingRequiredExitCode {
			t.Errorf("%s: %v, want exit %d (output %q)", role, err, c.Checked.MissingRequiredExitCode, out)
		}
	}
}
