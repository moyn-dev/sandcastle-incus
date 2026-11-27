package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
	"golang.org/x/term"
)

// incusExecRunner runs a non-interactive exec natively and returns the remote
// command's exit status. Tests replace it; nil means incusx.RunExec.
type incusExecRunner func(configDir, remote, project, instance string, req api.InstanceExecPost, streams incusx.ExecStreams) (int, error)

// nativeIncusExec is an `sc incus exec` sc runs itself rather than through the
// incus CLI — see runNativeIncusExec for why.
type nativeIncusExec struct {
	remote       string // "" = the active Sandcastle remote
	instance     string
	project      string // "" = the tenant's Incus project
	disableStdin bool
	post         api.InstanceExecPost
}

// parseNativeIncusExec recognises the non-interactive `incus exec` invocations
// sc runs natively. It mirrors the incus CLI's flags and its interactive-mode
// decision; anything it does not fully understand (another subcommand, an
// unknown flag, a malformed value, an interactive session) returns false and
// goes through the incus CLI unchanged.
func parseNativeIncusExec(args []string, stdinTerminal, stdoutTerminal bool, getenv func(string) string) (nativeIncusExec, bool) {
	if len(args) < 2 || args[0] != "exec" {
		return nativeIncusExec{}, false
	}
	var (
		exec                          nativeIncusExec
		target                        string
		command                       []string
		mode                          = "auto"
		modeSet, forceTTY, forceNoTTY bool
		env                           []string
	)
	takeValue := func(i *int, inline string, hasInline bool) (string, bool) {
		if hasInline {
			return inline, true
		}
		if *i+1 >= len(args) {
			return "", false
		}
		*i++
		return args[*i], true
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			command = args[i+1:]
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if target == "" {
				target = arg
				continue
			}
			// The command starts without a `--`. pflag would read any later
			// dash-word as an exec flag; leave that judgement to incus.
			for _, rest := range args[i:] {
				if strings.HasPrefix(rest, "-") {
					return nativeIncusExec{}, false
				}
			}
			command = args[i:]
			break
		}
		if strings.HasPrefix(arg, "--") {
			name, inline, hasInline := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			switch name {
			case "disable-stdin", "force-interactive", "force-noninteractive":
				if hasInline {
					return nativeIncusExec{}, false
				}
				switch name {
				case "disable-stdin":
					exec.disableStdin = true
				case "force-interactive":
					forceTTY = true
				default:
					forceNoTTY = true
				}
			case "env", "mode", "user", "group", "cwd", "project":
				value, ok := takeValue(&i, inline, hasInline)
				if !ok {
					return nativeIncusExec{}, false
				}
				switch name {
				case "env":
					env = append(env, value)
				case "mode":
					mode, modeSet = value, true
				case "user", "group":
					id, err := strconv.ParseUint(value, 10, 32)
					if err != nil {
						return nativeIncusExec{}, false
					}
					if name == "user" {
						exec.post.User = uint32(id)
					} else {
						exec.post.Group = uint32(id)
					}
				case "cwd":
					exec.post.Cwd = value
				case "project":
					exec.project = value
				}
			default:
				return nativeIncusExec{}, false
			}
			continue
		}
		// Short flags: only the boolean ones, alone or bundled (-nT).
		for _, short := range arg[1:] {
			switch short {
			case 'n':
				exec.disableStdin = true
			case 't':
				forceTTY = true
			case 'T':
				forceNoTTY = true
			default:
				return nativeIncusExec{}, false
			}
		}
	}
	if target == "" || len(command) == 0 {
		return nativeIncusExec{}, false
	}
	if forceTTY && forceNoTTY {
		return nativeIncusExec{}, false // incus rejects it; let it say so
	}
	if modeSet && (forceTTY || forceNoTTY) {
		return nativeIncusExec{}, false
	}
	interactive := false
	switch {
	case exec.disableStdin:
	case mode == "interactive" || forceTTY:
		interactive = true
	case mode == "non-interactive" || forceNoTTY:
	case mode == "auto":
		interactive = stdinTerminal && stdoutTerminal
	default:
		return nativeIncusExec{}, false // unknown --mode: incus reports it
	}
	if interactive {
		return nativeIncusExec{}, false
	}

	if remote, instance, ok := strings.Cut(target, ":"); ok {
		exec.remote, exec.instance = remote, instance
	} else {
		exec.instance = target
	}
	if exec.instance == "" {
		return nativeIncusExec{}, false
	}

	environment := map[string]string{}
	if value := getenv("TERM"); value != "" {
		environment["TERM"] = value
	}
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		environment[key] = value
	}
	exec.post.Command = command
	exec.post.Environment = environment
	return exec, true
}

// runNativeIncusExec runs a non-interactive `sc incus exec` through
// incusx.ExecStream instead of the incus CLI. The incus CLI's exec loses the
// end of stdout/stderr on a link with latency and still exits 0 (issue #250);
// ExecStream delivers the whole stream or fails loudly. Interactive sessions
// keep using the incus CLI, which owns the PTY, raw mode and window resizes.
func runNativeIncusExec(config commandConfig, incusDir, projectName string, exec nativeIncusExec) error {
	remote := exec.remote
	if remote == "" {
		remote = config.adminConfig.Remote
	}
	project := exec.project
	if project == "" {
		project = projectName
	}
	var stdin io.Reader = osStdinFor(config)
	if exec.disableStdin {
		stdin = strings.NewReader("")
	}
	if os.Getenv("VERBOSE") == "1" {
		fmt.Fprintf(config.stderr, "[verbose] sc incus exec (native): remote=%s project=%s instance=%s command=%s\n",
			remote, project, exec.instance, shellCommandLine(exec.post.Command))
	}
	runner := config.incusExec
	if runner == nil {
		runner = incusx.RunExec
	}
	status, err := runner(incusDir, remote, project, exec.instance, exec.post, incusx.ExecStreams{
		Stdin:  stdin,
		Stdout: config.stdout,
		Stderr: config.stderr,
	})
	if err != nil {
		return err
	}
	if status != 0 {
		// Same message the incus CLI path produces via *exec.ExitError.
		return fmt.Errorf("exit status %d", status)
	}
	return nil
}

func isTerminalWriter(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

// incusExecTerminals reports whether stdin and stdout are terminals, the
// inputs to incus's interactive-mode decision.
func incusExecTerminals(config commandConfig) (bool, bool) {
	return isTerminalInput(config), isTerminalWriter(config.stdout)
}
