package localdns

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"gopkg.in/yaml.v2"
)

type CommandRunner interface {
	Run(context.Context, []string) error
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("command is empty")
	}
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type FileManager struct {
	Runner CommandRunner
}

type State struct {
	Tenants []TenantState `yaml:"tenants" json:"tenants"`
}

type TenantState struct {
	Tenant      string        `yaml:"tenant" json:"tenant"`
	DNSSuffix   string        `yaml:"dnsSuffix" json:"dnsSuffix"`
	DNSEndpoint EndpointState `yaml:"dnsEndpoint" json:"dnsEndpoint"`
}

type EndpointState struct {
	IP   string `yaml:"ip" json:"ip"`
	Port int    `yaml:"port" json:"port"`
}

func (m FileManager) Install(ctx context.Context, plan Plan) (Result, error) {
	if err := m.installOrRefresh(ctx, plan); err != nil {
		return Result{}, err
	}
	return Result{Reference: plan.Reference, Action: "install", StatePath: plan.StatePath, ResolverPath: plan.ResolverPath}, nil
}

func (m FileManager) Refresh(ctx context.Context, plan Plan) (Result, error) {
	if err := m.installOrRefresh(ctx, plan); err != nil {
		return Result{}, err
	}
	return Result{Reference: plan.Reference, Action: "refresh", StatePath: plan.StatePath, ResolverPath: plan.ResolverPath}, nil
}

func (m FileManager) installOrRefresh(ctx context.Context, plan Plan) error {
	legacyRemoved, err := writeLocalDNS(plan)
	if err != nil {
		return err
	}
	runner := m.runner()
	if legacyRemoved {
		// The pre-link-scope drop-in put the tenant server in resolved's
		// GLOBAL list; only a resolved restart drops it. The restart cascades
		// to every enabled per-suffix unit (PartOf), which re-apply their
		// link scopes.
		if err := runner.Run(ctx, []string{"systemctl", "restart", "systemd-resolved"}); err != nil {
			return err
		}
	}
	for _, command := range resolverInstallCommands(plan.ResolverStrategy, plan.DNSSuffix) {
		if err := runner.Run(ctx, command.Args); err != nil {
			return err
		}
	}
	return nil
}

func (m FileManager) Uninstall(ctx context.Context, plan Plan) (Result, error) {
	state, err := readState(plan.StatePath)
	if err != nil {
		return Result{}, err
	}
	state.Tenants = removeTenant(state.Tenants, plan.Reference)
	if err := writeState(plan.StatePath, state); err != nil {
		return Result{}, err
	}
	// Stop + disable while the unit file still exists — its ExecStop tears
	// down the dummy link and with it the resolved scope.
	runner := m.runner()
	for _, command := range ResolverPreUninstallCommands(plan.ResolverStrategy, plan.DNSSuffix) {
		if err := runner.Run(ctx, command.Args); err != nil {
			return Result{}, err
		}
	}
	if err := os.Remove(plan.ResolverPath); err != nil && !os.IsNotExist(err) {
		return Result{}, err
	}
	if err := m.syncPlatformResolver(ctx, plan); err != nil {
		return Result{}, err
	}
	return Result{Reference: plan.Reference, Action: "uninstall", StatePath: plan.StatePath, ResolverPath: plan.ResolverPath}, nil
}

func (m FileManager) runner() CommandRunner {
	if m.Runner != nil {
		return m.Runner
	}
	return ExecCommandRunner{}
}

func (m FileManager) syncPlatformResolver(ctx context.Context, plan Plan) error {
	state, err := readState(plan.StatePath)
	if err != nil {
		return err
	}
	commands := ResolverSyncCommands(plan.ResolverStrategy, state)
	runner := m.runner()
	for _, command := range commands {
		if err := runner.Run(ctx, command.Args); err != nil {
			return err
		}
	}
	return nil
}

func writeLocalDNS(plan Plan) (legacyRemoved bool, err error) {
	state, err := readState(plan.StatePath)
	if err != nil {
		return false, err
	}
	entry, err := tenantState(plan)
	if err != nil {
		return false, err
	}
	state.Tenants = upsertTenant(state.Tenants, entry)
	if err := writeState(plan.StatePath, state); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(plan.ResolverPath), 0o755); err != nil {
		return false, err
	}
	resolver, err := resolverContent(plan)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(plan.ResolverPath, []byte(resolver), 0o644); err != nil {
		return false, err
	}
	if plan.ResolverStrategy == StrategySystemdResolve && resolverDirOverride() == "" {
		if err := os.Remove(legacyResolvedDropInPath(plan.DNSSuffix)); err == nil {
			legacyRemoved = true
		}
	}
	return legacyRemoved, nil
}

func readState(path string) (State, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		legacy := legacyStatePath(path)
		if legacy == "" || !isDir(filepath.Dir(legacy)) {
			return State{}, nil
		}
		// Not migrated yet: the next writeState moves it to path.
		content, err = os.ReadFile(legacy)
		if os.IsNotExist(err) {
			return State{}, nil
		}
	}
	if err != nil {
		return State{}, err
	}
	if len(content) == 0 {
		return State{}, nil
	}
	var state State
	if err := yaml.Unmarshal(content, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func writeState(path string, state State) error {
	created := missingAncestors(filepath.Dir(path))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	sort.Slice(state.Tenants, func(i, j int) bool {
		return state.Tenants[i].DNSSuffix < state.Tenants[j].DNSSuffix
	})
	content, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return err
	}
	if os.IsNotExist(statErr) {
		created = append(created, path)
	}
	chownToSudoInvoker(created)
	removeLegacyState(path)
	return nil
}

// removeLegacyState drops ~/.sandcastle/dns.yaml once its content lives at
// path, then the ~/.sandcastle directory if that left it empty. A `.sandcastle`
// selection file in $HOME is not a directory and is never touched. Failures are
// ignored: the new file already wins on every read.
func removeLegacyState(path string) {
	legacy := legacyStatePath(path)
	if legacy == "" || !isDir(filepath.Dir(legacy)) {
		return
	}
	_ = os.Remove(legacy)
	_ = os.Remove(filepath.Dir(legacy)) // fails unless empty
}

// missingAncestors lists dir and each parent that does not exist yet, outermost
// first: the paths a MkdirAll(dir) is about to create.
func missingAncestors(dir string) []string {
	var missing []string
	for ; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil || filepath.Dir(dir) == dir {
			break
		}
		missing = append([]string{dir}, missing...)
	}
	return missing
}

// chownToSudoInvoker hands paths this process just created back to the user who
// ran sudo. The elevated `dns apply-elevated` child keeps the invoker's HOME, so
// a root-owned ~/.config/sandcastle would break the user's next config.yml
// write. Outside sudo it does nothing.
func chownToSudoInvoker(paths []string) {
	if os.Geteuid() != 0 || len(paths) == 0 {
		return
	}
	uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uidErr != nil || gidErr != nil {
		return
	}
	for _, path := range paths {
		_ = os.Lchown(path, uid, gid)
	}
}

func isDir(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}

func tenantState(plan Plan) (TenantState, error) {
	dnsIP, dnsPort, err := net.SplitHostPort(plan.DNSEndpoint)
	if err != nil {
		return TenantState{}, err
	}
	port, err := strconv.Atoi(dnsPort)
	if err != nil {
		return TenantState{}, err
	}
	ref, err := naming.ParseTenantRef(plan.Reference)
	if err != nil {
		return TenantState{}, err
	}
	return TenantState{
		Tenant:    ref.Tenant,
		DNSSuffix: plan.DNSSuffix,
		DNSEndpoint: EndpointState{
			IP:   dnsIP,
			Port: port,
		},
	}, nil
}

func resolverContent(plan Plan) (string, error) {
	if plan.ResolverStrategy == StrategySystemdResolve && resolverDirOverride() == "" {
		return SystemdResolvedUnit(plan.DNSSuffix, plan.DNSEndpoint)
	}
	host, port, err := net.SplitHostPort(plan.DNSEndpoint)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("nameserver %s\nport %s\n", host, port), nil
}

func upsertTenant(tenants []TenantState, entry TenantState) []TenantState {
	for index := range tenants {
		if tenants[index].Tenant == entry.Tenant {
			tenants[index] = entry
			return tenants
		}
	}
	return append(tenants, entry)
}

func removeTenant(tenants []TenantState, reference string) []TenantState {
	ref, err := naming.ParseTenantRef(reference)
	if err != nil {
		return tenants
	}
	output := tenants[:0]
	for _, entry := range tenants {
		if entry.Tenant == ref.Tenant {
			continue
		}
		output = append(output, entry)
	}
	return output
}
