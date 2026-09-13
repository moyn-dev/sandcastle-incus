package agentskill

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MarkerFile is written into an installed skill directory so later runs can
// tell a managed copy (safe to refresh or remove) from a hand-placed one.
const MarkerFile = ".sc-skill-version"

// State of one install location.
type State string

const (
	StateMissing   State = "missing"    // the skill directory does not exist
	StateUpToDate  State = "up to date" // managed copy at the embedded version
	StateOutdated  State = "outdated"   // managed copy at another version
	StateUnmanaged State = "unmanaged"  // directory exists without a marker
)

// Status describes the skill directory at Dir (…/<root>/sandcastle).
type Status struct {
	Dir              string
	State            State
	InstalledVersion string // content version from the marker ("" unless managed)
	InstalledCLI     string // CLI version from the marker ("" unless managed)
}

// Marker is the parsed content of MarkerFile.
type Marker struct {
	Version string // skill content version
	CLI     string // CLI version that wrote the copy
}

func (m Marker) encode() []byte {
	return []byte("# written by `sc skill install`; do not edit\nversion=" + m.Version + "\ncli=" + m.CLI + "\n")
}

// ReadMarker parses the marker file in dir; ok is false when there is none.
func ReadMarker(dir string) (m Marker, ok bool, err error) {
	f, err := os.Open(filepath.Join(dir, MarkerFile))
	if errors.Is(err, os.ErrNotExist) {
		return Marker{}, false, nil
	}
	if err != nil {
		return Marker{}, false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "version":
			m.Version = strings.TrimSpace(value)
		case "cli":
			m.CLI = strings.TrimSpace(value)
		}
	}
	return m, true, sc.Err()
}

// Inspect reports the state of the skill directory dir.
func Inspect(dir string) (Status, error) {
	st := Status{Dir: dir, State: StateMissing}
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if !info.IsDir() {
		st.State = StateUnmanaged
		return st, nil
	}
	m, ok, err := ReadMarker(dir)
	if err != nil {
		return st, err
	}
	if !ok {
		st.State = StateUnmanaged
		return st, nil
	}
	st.InstalledVersion, st.InstalledCLI = m.Version, m.CLI
	if m.Version == Version() {
		st.State = StateUpToDate
	} else {
		st.State = StateOutdated
	}
	return st, nil
}

// Action is what Install/Uninstall did (or, with DryRun, would do).
type Action string

const (
	ActionInstalled Action = "installed"
	ActionUpdated   Action = "updated"
	ActionUpToDate  Action = "up to date"
	ActionRemoved   Action = "removed"
	ActionMissing   Action = "missing"
	ActionSkipped   Action = "skipped"
)

// Result of one Install/Uninstall.
type Result struct {
	Dir    string
	Action Action
	Before Status
	DryRun bool
}

// InstallOptions tune Install.
type InstallOptions struct {
	// CLIVersion is recorded in the marker.
	CLIVersion string
	// Force replaces an unmanaged (marker-less) directory.
	Force bool
	// DryRun reports the action without touching the filesystem.
	DryRun bool
}

// ErrUnmanaged is returned when dir exists without a marker and Force is off.
var ErrUnmanaged = errors.New("directory exists and is not managed by sc (no " + MarkerFile + "); pass --force to replace it")

// Install writes the embedded skill to dir (…/<root>/sandcastle) atomically:
// the new tree is staged in a temporary sibling directory, then swapped in
// with renames, so a reader never sees a half-written skill and files that
// are no longer part of the skill disappear with the old tree. An up-to-date
// managed copy is left untouched.
func Install(dir string, opts InstallOptions) (Result, error) {
	before, err := Inspect(dir)
	if err != nil {
		return Result{}, err
	}
	res := Result{Dir: dir, Before: before, DryRun: opts.DryRun}
	switch before.State {
	case StateUpToDate:
		res.Action = ActionUpToDate
		return res, nil
	case StateUnmanaged:
		if !opts.Force {
			return res, fmt.Errorf("%s: %w", dir, ErrUnmanaged)
		}
		res.Action = ActionUpdated
	case StateOutdated:
		res.Action = ActionUpdated
	default:
		res.Action = ActionInstalled
	}
	if opts.DryRun {
		return res, nil
	}

	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return res, err
	}
	staging, err := os.MkdirTemp(parent, "."+Name+".tmp-")
	if err != nil {
		return res, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(staging)
		}
	}()
	for _, f := range Files() {
		target := filepath.Join(staging, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return res, err
		}
		if err := os.WriteFile(target, f.Data, 0o644); err != nil {
			return res, err
		}
	}
	marker := Marker{Version: Version(), CLI: opts.CLIVersion}
	if err := os.WriteFile(filepath.Join(staging, MarkerFile), marker.encode(), 0o644); err != nil {
		return res, err
	}

	// Swap: move the old tree aside (rename cannot replace a non-empty
	// directory), move the staged tree in, then drop the old one.
	var old string
	if before.State != StateMissing {
		old, err = os.MkdirTemp(parent, "."+Name+".old-")
		if err != nil {
			return res, err
		}
		os.Remove(old)
		if err := os.Rename(dir, old); err != nil {
			return res, fmt.Errorf("move previous skill aside: %w", err)
		}
	}
	if err := os.Rename(staging, dir); err != nil {
		if old != "" {
			os.Rename(old, dir) // best-effort restore
		}
		return res, fmt.Errorf("install skill: %w", err)
	}
	cleanup = false
	if old != "" {
		if err := os.RemoveAll(old); err != nil {
			return res, fmt.Errorf("skill installed, but removing the previous copy failed: %w", err)
		}
	}
	return res, nil
}

// Uninstall removes dir only when it is a managed copy (marker present).
// Unmanaged directories are reported as skipped and left alone.
func Uninstall(dir string, dryRun bool) (Result, error) {
	before, err := Inspect(dir)
	if err != nil {
		return Result{}, err
	}
	res := Result{Dir: dir, Before: before, DryRun: dryRun}
	switch before.State {
	case StateMissing:
		res.Action = ActionMissing
		return res, nil
	case StateUnmanaged:
		res.Action = ActionSkipped
		return res, nil
	}
	res.Action = ActionRemoved
	if dryRun {
		return res, nil
	}
	return res, os.RemoveAll(dir)
}
