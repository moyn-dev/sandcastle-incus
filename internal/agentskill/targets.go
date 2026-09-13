package agentskill

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Agent is a supported coding agent.
type Agent string

// Scope is where an agent looks for the skill: the user's home config or the
// current repository.
type Scope string

const (
	AgentClaude Agent = "claude"
	AgentCodex  Agent = "codex"

	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
)

// AllAgents in display order.
var AllAgents = []Agent{AgentClaude, AgentCodex}

// ParseAgents turns the --agent flag value (claude|codex|all, or a
// comma-separated list) into a de-duplicated, ordered list.
func ParseAgents(value string) ([]Agent, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || value == "all" {
		return append([]Agent(nil), AllAgents...), nil
	}
	seen := map[Agent]bool{}
	var out []Agent
	for _, part := range strings.Split(value, ",") {
		a := Agent(strings.TrimSpace(part))
		switch a {
		case AgentClaude, AgentCodex:
		case "all":
			return append([]Agent(nil), AllAgents...), nil
		default:
			return nil, fmt.Errorf("unknown agent %q (want claude, codex, or all)", part)
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return indexOf(out[i]) < indexOf(out[j]) })
	return out, nil
}

func indexOf(a Agent) int {
	for i, x := range AllAgents {
		if x == a {
			return i
		}
	}
	return len(AllAgents)
}

// ParseScope validates the --scope flag value.
func ParseScope(value string) (Scope, error) {
	switch s := Scope(strings.TrimSpace(strings.ToLower(value))); s {
	case "", ScopeUser:
		return ScopeUser, nil
	case ScopeProject:
		return ScopeProject, nil
	default:
		return "", fmt.Errorf("unknown scope %q (want user or project)", value)
	}
}

// Env is the environment target resolution reads. Zero values fall back to
// os.Getenv, os.UserHomeDir and the current directory.
type Env struct {
	Getenv   func(string) string
	Home     string
	RepoRoot string // project-scope base: the git toplevel, else the cwd
}

func (e Env) getenv(key string) string {
	if e.Getenv != nil {
		return e.Getenv(key)
	}
	return os.Getenv(key)
}

func (e Env) home() (string, error) {
	if e.Home != "" {
		return e.Home, nil
	}
	return os.UserHomeDir()
}

// Target is one place the skill can live.
type Target struct {
	Agent Agent
	Scope Scope
	// ConfigDir is the agent's own config directory (~/.claude, ~/.codex or
	// their env overrides). Its existence is how "is this agent installed"
	// is decided; unset for project scope.
	ConfigDir string
	// Root is the skills directory; Dir is Root/<Name>.
	Root string
	Dir  string
}

// Installed reports whether the agent appears to be set up on this machine
// (its ConfigDir exists). Always true for project scope, which has no
// per-machine marker.
func (t Target) Installed() bool {
	if t.ConfigDir == "" {
		return true
	}
	info, err := os.Stat(t.ConfigDir)
	return err == nil && info.IsDir()
}

// ConfigDirHint is the ConfigDir as it appears in messages ("~/.codex").
func (t Target) ConfigDirHint(home string) string {
	return DisplayPath(t.ConfigDir, home)
}

// Resolve returns the target for one agent/scope pair.
//
//   - claude, user:    $CLAUDE_CONFIG_DIR/skills, default ~/.claude/skills
//   - codex,  user:    $CODEX_HOME/skills,        default ~/.codex/skills
//   - claude, project: <repo>/.claude/skills
//   - codex,  project: <repo>/.agents/skills (the repository skill root
//     documented at https://developers.openai.com/codex/skills)
func Resolve(agent Agent, scope Scope, env Env) (Target, error) {
	t := Target{Agent: agent, Scope: scope}
	switch scope {
	case ScopeUser:
		home, err := env.home()
		if err != nil {
			return t, fmt.Errorf("resolve home directory: %w", err)
		}
		switch agent {
		case AgentClaude:
			t.ConfigDir = firstNonEmpty(env.getenv("CLAUDE_CONFIG_DIR"), filepath.Join(home, ".claude"))
		case AgentCodex:
			t.ConfigDir = firstNonEmpty(env.getenv("CODEX_HOME"), filepath.Join(home, ".codex"))
		default:
			return t, fmt.Errorf("unknown agent %q", agent)
		}
		t.Root = filepath.Join(t.ConfigDir, "skills")
	case ScopeProject:
		base := env.RepoRoot
		if base == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return t, err
			}
			base = cwd
		}
		switch agent {
		case AgentClaude:
			t.Root = filepath.Join(base, ".claude", "skills")
		case AgentCodex:
			t.Root = filepath.Join(base, ".agents", "skills")
		default:
			return t, fmt.Errorf("unknown agent %q", agent)
		}
	default:
		return t, fmt.Errorf("unknown scope %q", scope)
	}
	t.Dir = filepath.Join(t.Root, Name)
	return t, nil
}

// Targets resolves every agent in agents for scope.
func Targets(agents []Agent, scope Scope, env Env) ([]Target, error) {
	out := make([]Target, 0, len(agents))
	for _, a := range agents {
		t, err := Resolve(a, scope, env)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// DisplayPath abbreviates home to "~" for messages.
func DisplayPath(path, home string) string {
	if home != "" && (path == home || strings.HasPrefix(path, home+string(filepath.Separator))) {
		return "~" + path[len(home):]
	}
	return path
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
