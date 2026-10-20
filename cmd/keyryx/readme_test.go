package main

// The public documents say what the code is and what is published. Each test
// here reads one document or manifest and compares it with the thing it
// describes, so a sentence that drifts from the code or the registry fails the
// suite instead of waiting for a reader to notice.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/TAIPANBOX/keyryx/internal/api"
	"github.com/TAIPANBOX/keyryx/internal/witnessapi"
)

// repoFile reads a file at the repository root. Tests run in their package
// directory, cmd/keyryx, two levels below the root.
func repoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(b)
}

// section returns the text under a level-two heading, up to the next one.
func section(readme, heading string) string {
	i := strings.Index(readme, "\n"+heading+"\n")
	if i < 0 {
		return ""
	}
	rest := readme[i+len(heading)+2:]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		return rest[:j]
	}
	return rest
}

// The latest published tag is named here and moves with each release.
func TestTheReadmeStatesWhatIsPublished(t *testing.T) {
	readme := repoFile(t, "README.md")
	if strings.Contains(readme, "No image has been published") {
		t.Error("README says no image has been published; the registry holds published tags")
	}
	if !strings.Contains(readme, "ghcr.io/taipanbox/keyryx:v0.1.2") {
		t.Error("README does not name the latest published image, ghcr.io/taipanbox/keyryx:v0.1.2")
	}
	var comp struct {
		Distribution string `json:"distribution"`
	}
	if err := json.Unmarshal([]byte(repoFile(t, "components.json")), &comp); err != nil {
		t.Fatalf("components.json: %v", err)
	}
	if strings.Contains(comp.Distribution, "not distributed yet") || !strings.Contains(comp.Distribution, "v0.1.2") {
		t.Errorf("components.json says distribution %q", comp.Distribution)
	}
}

func TestTheReadmeHasTheHouseSections(t *testing.T) {
	readme := repoFile(t, "README.md")
	for _, heading := range []string{
		"## Where this fits in the stack",
		"## Status",
		"## Install",
		"## Verify the image",
		"## Security",
		"## Testing",
		"## NOT PROVEN",
		"## Licence",
	} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(heading) + `$`).MatchString(readme) {
			t.Errorf("README has no %q heading", heading)
		}
	}
	if !strings.Contains(readme, "```mermaid") {
		t.Error("the stack position section has no mermaid diagram")
	}
	if !strings.Contains(section(readme, "## Status"), "- [x] ") {
		t.Error("the status section is not a checklist with a checked item")
	}
	if !strings.Contains(section(readme, "## Verify the image"), "gh attestation verify oci://ghcr.io/taipanbox/keyryx:") {
		t.Error("the verify section does not name the attestation check for a published image")
	}
}

var (
	htmlImage     = regexp.MustCompile(`<img\s[^>]*>`)
	markdownImage = regexp.MustCompile(`!\[([^\]]*)\]\(([^)\s]+)`)
	altAttr       = regexp.MustCompile(`alt="([^"]+)"`)
	srcAttr       = regexp.MustCompile(`src="([^"]+)"`)
)

func TestEveryImageInTheReadmeHasAltText(t *testing.T) {
	readme := repoFile(t, "README.md")
	local := func(name string) {
		if _, err := os.Stat(filepath.Join("..", "..", name)); err != nil {
			t.Errorf("README embeds %s, which is not in the repository", name)
		}
	}
	seen := 0
	for _, tag := range htmlImage.FindAllString(readme, -1) {
		seen++
		src := srcAttr.FindStringSubmatch(tag)
		if altAttr.FindStringSubmatch(tag) == nil {
			t.Errorf("image without alt text: %s", tag)
		}
		if src == nil {
			t.Errorf("image without src: %s", tag)
			continue
		}
		if !strings.HasPrefix(src[1], "http") {
			local(src[1])
		}
	}
	for _, m := range markdownImage.FindAllStringSubmatch(readme, -1) {
		seen++
		if strings.TrimSpace(m[1]) == "" {
			t.Errorf("markdown image without alt text: %s", m[2])
		}
		if !strings.HasPrefix(m[2], "http") {
			local(m[2])
		}
	}
	if seen == 0 {
		t.Fatal("the README embeds no image; this test measured nothing")
	}
}

func TestTheHouseDocumentsExist(t *testing.T) {
	for _, name := range []string{"CONTRIBUTING.md", "VALIDATION.md", "COMPATIBILITY.md"} {
		if got := repoFile(t, name); len(strings.TrimSpace(got)) < 200 {
			t.Errorf("%s is %d bytes; a document that short says nothing", name, len(got))
		}
	}
}

// compare requires the promised paths and the served paths to be one set.
func compare(t *testing.T, kind string, promised, served []string) {
	t.Helper()
	if len(served) == 0 {
		t.Fatalf("%s: the route table is empty; this test measured nothing", kind)
	}
	p := slices.Clone(promised)
	s := slices.Clone(served)
	slices.Sort(p)
	slices.Sort(s)
	if !slices.Equal(p, s) {
		t.Errorf("%s: compat/1.0.json promises %v, the code serves %v", kind, p, s)
	}
}

func TestTheFrozenRoutesAreTheRouteTables(t *testing.T) {
	var m struct {
		Frozen map[string][]string `json:"frozen"`
	}
	if err := json.Unmarshal([]byte(repoFile(t, "compat/1.0.json")), &m); err != nil {
		t.Fatalf("compat/1.0.json: %v", err)
	}
	var custody, witness []string
	for _, r := range api.Routes() {
		custody = append(custody, r.Pattern)
	}
	for _, r := range witnessapi.Routes() {
		witness = append(witness, r.Pattern)
	}
	compare(t, "http.custody.routes", m.Frozen["http.custody.routes"], custody)
	compare(t, "http.witness.routes", m.Frozen["http.witness.routes"], witness)
}
