// Package agentskill embeds the Sandcastle agent skill (the model-invoked
// SKILL.md + reference files that teach Claude Code and Codex how to drive
// `sc`/`sc-adm`) and installs it into the agents' skill directories.
//
// The tracked source is docs/agents/skills/sandcastle/. go:embed cannot reach
// outside the package, so a byte-exact copy lives at ./sandcastle and
// TestEmbeddedSkillMatchesTrackedSource fails on any drift. Refresh the copy
// with `make skill-sync` after editing the tracked directory.
package agentskill

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"sync"
)

// Name is the skill's directory name under every agent's skills root.
const Name = "sandcastle"

//go:embed all:sandcastle
var embedded embed.FS

// File is one file of the skill, with Path relative to the skill directory
// (e.g. "SKILL.md", "reference/admin.md") using forward slashes.
type File struct {
	Path string
	Data []byte
}

var (
	filesOnce sync.Once
	files     []File
	version   string
)

func load() {
	filesOnce.Do(func() {
		err := fs.WalkDir(embedded, Name, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			data, err := embedded.ReadFile(path)
			if err != nil {
				return err
			}
			files = append(files, File{Path: path[len(Name)+1:], Data: data})
			return nil
		})
		if err != nil {
			panic(fmt.Sprintf("agentskill: walk embedded skill: %v", err))
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		h := sha256.New()
		for _, f := range files {
			fmt.Fprintf(h, "%s\x00%d\x00", f.Path, len(f.Data))
			h.Write(f.Data)
			h.Write([]byte{0})
		}
		version = hex.EncodeToString(h.Sum(nil))[:12]
	})
}

// Files returns every file of the embedded skill, sorted by path. Callers
// must not mutate the returned data.
func Files() []File {
	load()
	out := make([]File, len(files))
	copy(out, files)
	return out
}

// Version is a short content hash (12 hex chars of SHA-256 over the sorted
// path+data set). Two binaries embedding the same skill files agree on it;
// any byte change in any file changes it.
func Version() string {
	load()
	return version
}

// SkillMD returns the embedded SKILL.md.
func SkillMD() []byte {
	for _, f := range Files() {
		if f.Path == "SKILL.md" {
			return f.Data
		}
	}
	return nil
}
