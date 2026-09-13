package agentskill

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// trackedSource is the canonical skill directory this package mirrors.
const trackedSource = "../../docs/agents/skills/sandcastle"

func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestEmbeddedSkillMatchesTrackedSource fails on any drift between the
// tracked docs/agents/skills/sandcastle and the embedded copy: a file added,
// removed, or changed by a single byte. Fix with `make skill-sync`.
func TestEmbeddedSkillMatchesTrackedSource(t *testing.T) {
	tracked := readTree(t, trackedSource)
	if len(tracked) == 0 {
		t.Fatalf("no files under %s", trackedSource)
	}
	embeddedFiles := map[string][]byte{}
	for _, f := range Files() {
		embeddedFiles[f.Path] = f.Data
	}
	var names []string
	for name := range tracked {
		names = append(names, name)
	}
	for name := range embeddedFiles {
		if _, ok := tracked[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var drift []string
	for _, name := range names {
		want, inTracked := tracked[name]
		got, inEmbedded := embeddedFiles[name]
		switch {
		case !inTracked:
			drift = append(drift, name+": only in the embedded copy")
		case !inEmbedded:
			drift = append(drift, name+": missing from the embedded copy")
		case !bytes.Equal(want, got):
			drift = append(drift, name+": content differs")
		}
	}
	if len(drift) > 0 {
		t.Fatalf("embedded skill drifted from %s; run `make skill-sync`:\n  %s", trackedSource, strings.Join(drift, "\n  "))
	}
}

func TestFilesAndVersion(t *testing.T) {
	files := Files()
	if len(files) < 2 {
		t.Fatalf("expected SKILL.md plus references, got %d files", len(files))
	}
	if !sort.SliceIsSorted(files, func(i, j int) bool { return files[i].Path < files[j].Path }) {
		t.Fatal("Files() is not sorted by path")
	}
	if files[0].Path != "SKILL.md" {
		t.Fatalf("first file %q, want SKILL.md", files[0].Path)
	}
	if !bytes.HasPrefix(SkillMD(), []byte("---\nname: sandcastle\n")) {
		t.Fatalf("SKILL.md frontmatter missing: %q", SkillMD()[:40])
	}
	if v := Version(); len(v) != 12 || v != Version() {
		t.Fatalf("Version() = %q, want stable 12 hex chars", v)
	}
	if Name != "sandcastle" {
		t.Fatalf("Name = %q", Name)
	}
}
