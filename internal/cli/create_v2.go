package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
	"slices"
)

// v2DefaultMachineImage is the stock cloud image v2 machines launch from: the
// /cloud variant carries cloud-init, which applies the project default profile
// (login user + SSH key + sshd). The plain variant would boot without any user.
const v2DefaultMachineImage = "images:debian/13/cloud"

// projectDefaultImage is the image a machine launches from when --image is
// not given: the project's `sc project set-image` choice, else the stock
// default.
func projectDefaultImage(summary tenant.Summary, project string) string {
	for _, p := range summary.Projects {
		if p.Name == project && strings.TrimSpace(p.Image) != "" {
			return strings.TrimSpace(p.Image)
		}
	}
	return v2DefaultMachineImage
}

// v2TenantSummary resolves the current tenant against the remote and reports
// whether it is a v2 tenant (per-project Incus projects, freeform machines).
//
// The error is separate from the bool on purpose: "the remote said no such
// tenant" and "the remote could not be reached" are different answers, and
// collapsing them is how an unreachable host came to be reported as
// `Sandcastle tenant <name> not found`. Callers that genuinely do not care
// (best-effort decoration) discard it explicitly.
func v2TenantSummary(ctx context.Context, config commandConfig) (tenant.Summary, bool, error) {
	name := strings.TrimSpace(config.adminConfig.Tenant)
	if name == "" || config.tenantStore == nil {
		return tenant.Summary{}, false, nil
	}
	// Several installs can share one Incus daemon (every sidecar's Incus Reach
	// lands on the same host API), so a same-named tenant may exist once per
	// install. Scope the lookup to the install the current remote belongs to.
	tenants, err := tenant.ListForPrefix(ctx, config.tenantStore, installPrefixForRemote(config, name))
	if err != nil {
		return tenant.Summary{}, false, err
	}
	for _, candidate := range tenants {
		if candidate.Tenant == name {
			return candidate, true, nil
		}
	}
	return tenant.Summary{}, false, nil
}

// scopedListTenants lists tenant summaries scoped to the install the
// configured remote belongs to. Several installs can share one Incus daemon
// (every sidecar's Incus Reach lands on the same host API) and the shared
// client certificate sees every enrolled install's projects, so a same-named
// tenant may exist once per install — matching by tenant name alone can land
// on the wrong install (e.g. `sc list` right after `sc create` showing the
// OTHER install's empty machine set). Unscoped fallback (empty prefix) when
// the remote name has another shape (admin remotes, v1).
func scopedListTenants(ctx context.Context, config commandConfig, tenantName string) ([]tenant.Summary, error) {
	return tenant.ListForPrefix(ctx, config.tenantStore, installPrefixForRemote(config, tenantName))
}

// installPrefixForRemote resolves which install's projects the CLI is pointed
// at. It prefers the active remote's PINNED PROJECT (robust for URL-based remote
// names like sc-obelix-thieso2-dev, which don't encode the install prefix),
// deriving the prefix from <prefix>-<tenant>-<project>, and falls back to
// inverting a legacy sc-<prefix>-<tenant> remote name. Without this scoping,
// two installs sharing a tenant name (same GitHub user) collapse together and
// switching the remote fails to switch what sc shows.
func installPrefixForRemote(config commandConfig, tenantName string) string {
	if prefix := installPrefixFromProject(scconfig.SharedIncusRemoteProject(config.adminConfig.Remote), tenantName); prefix != "" {
		return prefix
	}
	return installPrefixFromRemoteName(config.adminConfig.Remote, tenantName)
}

// installPrefixFromProject extracts the install prefix from a pinned project
// name shaped <prefix>-<tenant>-<project> (or <prefix>-<tenant>): the segment
// before "-<tenant>". Returns "" when the project does not belong to tenantName.
func installPrefixFromProject(project string, tenantName string) string {
	project = strings.TrimSpace(project)
	tenantName = strings.TrimSpace(tenantName)
	if project == "" || tenantName == "" {
		return ""
	}
	marker := "-" + tenantName
	idx := strings.Index(project, marker)
	if idx <= 0 {
		return ""
	}
	rest := project[idx+len(marker):]
	if rest != "" && !strings.HasPrefix(rest, "-") {
		return "" // "-<tenant>" is a substring, not a real boundary
	}
	return project[:idx]
}

// installPrefixFromRemoteName maps the enrolled remote to its install's
// project prefix. The authoritative source is the remote's pinned project in
// the shared incus config (installPrefixFromRemotePin) — URL-named remotes
// ("sc-<install-label>", usertrust.RemoteNameForAuthHostname) carry no prefix
// in the name at all, and without the pin every lookup silently went unscoped,
// resurrecting the cross-install shadowing this scoping exists to prevent
// (seen live on majestix: `sc list` under install A showed install B's
// machines). Fallback: invert the legacy usertrust.RemoteInstallName shape
// "sc-<prefix>-<tenant>" / "sc-<tenant>". Returns "" (no scoping) when
// neither source identifies the install.
func installPrefixFromRemoteName(remote string, tenantName string) string {
	remote = strings.TrimSpace(remote)
	tenantName = strings.TrimSpace(tenantName)
	if tenantName == "" {
		return ""
	}
	if prefix := installPrefixFromRemotePin(remote, tenantName); prefix != "" {
		return prefix
	}
	if remote == "sc-"+tenantName {
		return naming.DefaultIncusProjectPrefix
	}
	if rest, ok := strings.CutPrefix(remote, "sc-"); ok {
		if prefix, ok := strings.CutSuffix(rest, "-"+tenantName); ok && prefix != "" {
			return prefix
		}
	}
	return ""
}

// splitMachineReference splits "[tenant@][[dns-suffix:]project:]machine"
// (ADR-0020) into its parts WITHOUT validating them. Colon count selects scope: 0 colons =
// machine only, 1 = project:machine, 2 = dns-suffix:project:machine (the
// leftmost part names the install by its DNS suffix). The project defaults to
// the configured Current Project, then to "default". A returned dnsSuffix of ""
// means "the current install".
//
// Validation is the caller's, because the two callers want different rules:
// parseV2MachineReference demands literal names, parseMachineSelector admits
// globs. Everything else about the grammar has to stay identical between them,
// which is why the split lives here rather than being written twice.
func splitMachineReference(reference string, currentProject string) (dnsSuffix string, project string, machine string, err error) {
	reference = strings.TrimSpace(reference)
	project = strings.TrimSpace(currentProject)
	parts := strings.Split(reference, ":")
	switch len(parts) {
	case 1:
		machine = parts[0]
	case 2:
		project = strings.TrimSpace(parts[0])
		machine = parts[1]
	case 3:
		dnsSuffix = strings.TrimSpace(parts[0])
		project = strings.TrimSpace(parts[1])
		machine = parts[2]
	default:
		return "", "", "", fmt.Errorf("invalid machine reference %q: expected [[dns-suffix:]project:]machine", reference)
	}
	if project == "" {
		project = naming.DefaultProjectName
	}
	machine = strings.TrimSpace(machine)
	if machine == "" {
		return "", "", "", fmt.Errorf("machine name is required")
	}
	return dnsSuffix, project, machine, nil
}

// parseV2MachineReference is splitMachineReference plus strict validation: it
// resolves a reference that must name exactly one machine. Use
// parseMachineSelector where a wildcard is allowed. currentTenant is unused now
// that the legacy "tenant/" prefix is dropped (ADR-0020); it is retained in the
// signature for callers.
func parseV2MachineReference(reference string, currentTenant string, currentProject string) (dnsSuffix string, project string, machine string, err error) {
	_ = currentTenant
	dnsSuffix, project, machine, err = splitMachineReference(reference, currentProject)
	if err != nil {
		return "", "", "", err
	}
	if dnsSuffix != "" {
		if err := naming.ValidateInstallSuffix(dnsSuffix); err != nil {
			return "", "", "", err
		}
	}
	if err := naming.ValidateProjectName(project); err != nil {
		return "", "", "", err
	}
	if err := naming.ValidateMachineName(machine); err != nil {
		return "", "", "", err
	}
	return dnsSuffix, project, machine, nil
}

// resolveV2MachineReference parses "[[dns-suffix:]project:]machine" (ADR-0020)
// and verifies the project actually exists in the tenant — otherwise a mistyped
// project surfaces as a raw Incus "User does not have permission for project …"
// from the nonexistent project's name. A machine part that matches an existing
// project usually means the reference was written backwards; suggest the swap.
func resolveV2MachineReference(summary tenant.Summary, reference string, currentProject string) (project string, machine string, err error) {
	dnsSuffix, project, machine, err := parseV2MachineReference(reference, summary.Tenant, currentProject)
	if err != nil {
		return "", "", err
	}
	// An explicit install suffix that matches the current install is a no-op;
	// one that names a different install requires switching to that install's
	// remote, which is not wired inline yet (ADR-0020; see implementation-notes).
	currentInstall := strings.TrimSpace(summary.DNSSuffix)
	if dnsSuffix != "" && dnsSuffix != currentInstall {
		return "", "", fmt.Errorf("reference %q addresses install %q, but the current remote is install %q; "+
			"inline cross-install addressing is not available yet — select that install's remote first",
			reference, dnsSuffix, currentInstall)
	}
	if _, ok := findProject(summary, project); !ok {
		// e.g. `sc c obelix-sc:dev` — `obelix-sc` is a remote name, not a
		// project. Address another install as dns-suffix:project:machine.
		return "", "", unknownProjectError(summary, project, machine)
	}
	return project, machine, nil
}

// v2ReferenceHasProject reports whether the reference names its project
// explicitly ("[tenant/]project:machine") rather than leaving it to be inferred.
func v2ReferenceHasProject(reference string) bool {
	reference = strings.TrimSpace(reference)
	if _, rest, ok := strings.Cut(reference, "/"); ok {
		reference = rest
	}
	return strings.Contains(reference, ":")
}

// resolveV2MachineTarget resolves a reference to a machine that must already
// exist. An explicit "project:machine" is taken at its word. A bare machine
// name means the CURRENT project when the machine exists there — `sc del dev`
// in project newbuild2 is newbuild2:dev, never a question about the eleven
// other projects with a dev. Only when the current project has no such
// machine is the name looked up across the tenant: one hit resolves silently,
// several ask which one is meant, and no hit falls back to the inferred
// project so the caller's own "not found" names the project it looked in.
// Use a wildcard (`sc del '*:dev'`) to act across projects deliberately.
func resolveV2MachineTarget(ctx context.Context, config commandConfig, summary tenant.Summary, reference string) (project string, machine string, err error) {
	project, machine, err = resolveV2MachineReference(summary, reference, config.adminConfig.Project)
	if err != nil || v2ReferenceHasProject(reference) {
		return project, machine, err
	}
	// The current project first, and cheaply: one project-scoped listing
	// (or the Auth App cache), never a sweep of every project of the tenant.
	if current := strings.TrimSpace(config.adminConfig.Project); current != "" {
		if found, err := v2MachineInProject(ctx, config, summary, current, machine); err == nil && found {
			return current, machine, nil
		}
	}
	projects, err := v2MachineProjects(ctx, config, summary, machine)
	if err != nil {
		return "", "", err
	}
	switch len(projects) {
	case 0:
		return project, machine, nil
	case 1:
		return projects[0], machine, nil
	}
	qualified := make([]string, 0, len(projects))
	for _, candidate := range projects {
		qualified = append(qualified, candidate+":"+machine)
	}
	if !isTerminalInput(config) {
		return "", "", fmt.Errorf("machine %q exists in %d projects (%s); name the one you mean as project:machine",
			machine, len(projects), strings.Join(qualified, ", "))
	}
	choice, err := promptChoice(config, fmt.Sprintf("Machine %q exists in %d projects:", machine, len(projects)), qualified)
	if err != nil {
		return "", "", err
	}
	return projects[choice], machine, nil
}

// v2MachineInProject reports whether the named machine exists in ONE project:
// the Auth App cache when it answers, else a project-scoped store listing.
func v2MachineInProject(ctx context.Context, config commandConfig, summary tenant.Summary, project string, machine string) (bool, error) {
	if projects, ok := v2MachineProjectsViaCache(ctx, config, summary, project, machine); ok {
		return slices.Contains(projects, project), nil
	}
	if config.machineStore == nil {
		return false, fmt.Errorf("machine metadata store is not configured")
	}
	machines, err := listMachinesScoped(ctx, config.machineStore, summary, project)
	if err != nil {
		return false, err
	}
	for _, managed := range machines {
		if managed.Name == machine && firstNonEmptyString(managed.Project, naming.DefaultProjectName) == project {
			return true, nil
		}
	}
	return false, nil
}

// v2MachineProjectsViaCache answers "which projects hold this machine" from
// the Auth App's event-fed resource cache — one request instead of one Incus
// listing per project (a 26-project tenant took ~8 s live). ok=false on any
// non-answer, exactly like `sc ls`'s cache fallback; the caller then lists.
func v2MachineProjectsViaCache(ctx context.Context, config commandConfig, summary tenant.Summary, project string, machine string) ([]string, bool) {
	client := config.authResources
	if client == nil {
		token := strings.TrimSpace(config.adminConfig.AuthToken)
		baseURL := commandAuthHostname(config, "")
		if token == "" || baseURL == "" {
			return nil, false
		}
		client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: token, Tenant: strings.TrimSpace(config.adminConfig.Tenant)}
	}
	cacheCtx, cancel := context.WithTimeout(ctx, resourceCacheRequestTimeout())
	defer cancel()
	result, err := client.ListResources(cacheCtx, authapp.ResourceListRequest{
		Tenant:  summary.Tenant,
		Project: firstNonEmptyString(project, "*"),
		Machine: machine,
		Include: []string{authapp.ResourceKindMachines},
	})
	if err != nil {
		verboseCLI(config, "machine lookup: cache unavailable (%v); listing live", err)
		return nil, false
	}
	seen := map[string]bool{}
	var projects []string
	for _, m := range result.Machines {
		if m.Name != machine {
			continue
		}
		p := firstNonEmptyString(m.Project, naming.DefaultProjectName)
		if !seen[p] {
			seen[p] = true
			projects = append(projects, p)
		}
	}
	sort.Strings(projects)
	return projects, true
}

// v2MachineProjects returns, sorted, the projects of the tenant that hold a
// machine with the given name: the Auth App cache when it answers, else a
// listing of every project.
func v2MachineProjects(ctx context.Context, config commandConfig, summary tenant.Summary, machine string) ([]string, error) {
	if projects, ok := v2MachineProjectsViaCache(ctx, config, summary, "*", machine); ok {
		return projects, nil
	}
	if config.machineStore == nil {
		return nil, fmt.Errorf("machine metadata store is not configured")
	}
	machines, err := config.machineStore.ListMachines(ctx, summary)
	if err != nil {
		return nil, err
	}
	projects := []string{}
	for _, candidate := range machines {
		if candidate.Name == machine {
			projects = append(projects, candidate.Project)
		}
	}
	sort.Strings(projects)
	return projects, nil
}

// launchV2Options are the create-time knobs shared by every command that can
// bring a machine into existence (`sc create`, and `sc connect`/`sc fix` when
// the machine is missing). They only apply on creation: an existing machine
// keeps the instance type and profiles it was created with.
type launchV2Options struct {
	VM bool
	// HomeShare adds the project's homeshare profile, mounting the shared
	// /home volume; without it the machine gets a machine-local /home.
	HomeShare bool
	// ConfirmCreate, when set, is asked before a machine that does not exist
	// is brought into being, and aborts the dial if it returns an error. It is
	// how `sc connect` keeps a mistyped name from provisioning a container:
	// commands that leave it nil (`sc fix`) create silently as before.
	ConfirmCreate func(project string, machine string) error
}

type createV2Options struct {
	Image     string
	VM        bool
	DryRun    bool
	HomeShare bool
	// Bare replaces the project profile's cloud-init with the bare document
	// (hostname + Caddy leaf only). Create-time only, like the profile choice:
	// cloud-init has already run by the time anything else could change it.
	Bare bool
	// Hostnames are the explicit Machine Public Hostnames (ADR-0028) to
	// claim for the machine — before it exists — and stamp in the create call.
	Hostnames []string
	Aliases   []string
}

func runCreateMachineV2(ctx context.Context, config commandConfig, opts *rootOptions, summary tenant.Summary, reference string, options createV2Options) error {
	project, machine, err := resolveV2MachineReference(summary, reference, config.adminConfig.Project)
	if err != nil {
		return err
	}
	image := strings.TrimSpace(options.Image)
	if image != "" {
		if err := tenant.ValidateMachineImageRef(image); err != nil {
			return err
		}
	}
	if image == "" {
		image = projectDefaultImage(summary, project)
	}
	// The Dev Image gets no Caddy/TLS ingress (it is reached over SSH, not
	// HTTPS) — detected by the --image the machine launches from matching the
	// admin-configured Dev Image alias, the only signal available here.
	devImage := image == strings.TrimSpace(config.adminConfig.Images.Dev)
	// The machine's public-name set (ADR-0028): the derived name from the
	// project's Project Domain in the tenant summary, plus every explicit
	// --hostname. Explicit names are claimed through the Auth App BEFORE the
	// instance exists (a refused name creates nothing) and released again if
	// the create fails; the create call stamps the whole set on the instance
	// and everything downstream (output, certificate request, connect) reads
	// the stamped value back rather than re-deriving it.
	derived := zoneModePublicHostname(summary, project, machine)
	for _, label := range options.Aliases {
		if derived == "" {
			return fmt.Errorf("--alias requires a Project Domain")
		}
		if strings.ContainsAny(label, ".*") || strings.TrimSpace(label) == "" {
			return fmt.Errorf("alias %q must be one DNS label", label)
		}
		options.Hostnames = append(options.Hostnames, label+"."+strings.SplitN(derived, ".", 2)[1])
	}
	explicit, err := normalizeHostnameFlags(options.Hostnames)
	if err != nil {
		return err
	}
	var hostnameClient authMachineHostnameClient
	if len(explicit) > 0 {
		client, ok := hostnameAuthClient(config)
		if !ok {
			return fmt.Errorf("%s", hostnameVerbsUnavailable)
		}
		hostnameClient = client
	}
	publicHostnames := explicit
	if derived != "" {
		publicHostnames = append([]string{derived}, explicit...)
	}
	sort.Strings(publicHostnames)
	request := incusx.CreateMachineV2Request{
		IncusProject:    summary.V2IncusProjectName(project),
		Name:            machine,
		Image:           image,
		VM:              options.VM,
		HomeShare:       options.HomeShare,
		Bare:            options.Bare,
		DevImage:        devImage,
		PublicHostnames: publicHostnames,
		ProjectDomain:   strings.TrimPrefix(derived, machine+"."),
	}
	outcomes := map[string]machineCertificateOutcome{}
	if derived != "" {
		outcomes[derived] = machineCertificateOutcome{State: "project"}
	}
	if options.DryRun {
		// A dry run validates the explicit names server-side (rolled back)
		// so a conflicting name is reported now, not at the real create.
		if hostnameClient != nil {
			planned, err := claimMachineHostnamesBeforeCreate(ctx, hostnameClient, summary.Tenant, project, machine, explicit, true)
			if err != nil {
				return err
			}
			for _, name := range planned {
				outcomes[name.Hostname] = name.Outcome
			}
		}
		payload := incusx.CreateMachineV2Result{Name: machine, Type: machineTypeLabel(options.VM), Project: request.IncusProject, Image: image, HomeShare: options.HomeShare, Bare: options.Bare, DevImage: request.DevImage && !options.Bare, PublicHostnames: publicHostnames}
		if len(publicHostnames) > 0 {
			payload.PublicHostname = publicHostnames[0]
		}
		payload.CertificateDecisions = createCertificateDecisions(publicHostnames, outcomes)
		payload.Path = machinePath(config.adminConfig.Remote, summary.Tenant, project, payload.Name)
		return writeOutput(config.stdout, opts.output, formatCreateMachineV2(config.adminConfig.Remote, summary, project, payload, true, outcomes), payload)
	}
	var claimed []claimedHostname
	if hostnameClient != nil {
		claimed, err = claimMachineHostnamesBeforeCreate(ctx, hostnameClient, summary.Tenant, project, machine, explicit, false)
		if err != nil {
			return err
		}
		for _, entry := range claimed {
			outcomes[entry.Hostname] = entry.Outcome
		}
	}
	result, err := config.tenantCreator.CreateMachineV2(ctx, request)
	if err != nil {
		if hostnameClient != nil && len(claimed) > 0 {
			if releaseErrs := releaseMachineHostnames(ctx, hostnameClient, summary.Tenant, project, machine, claimed); len(releaseErrs) > 0 {
				return fmt.Errorf("%w (and could not release the claimed hostnames: %v)", err, errors.Join(releaseErrs...))
			}
		}
		return err
	}
	// The derived name uses the existing project certificate; creation orders nothing.
	if derived != "" && !result.DevImage {
		outcomes[derived] = machineCertificateOutcome{State: "project"}
	}
	result.CertificateDecisions = createCertificateDecisions(result.PublicHostnames, outcomes)
	result.Path = machinePath(config.adminConfig.Remote, summary.Tenant, project, result.Name)
	return writeOutput(config.stdout, opts.output, formatCreateMachineV2(config.adminConfig.Remote, summary, project, result, false, outcomes), result)
}

// runConnectV2 implements `sc connect` (alias `c`) for v2 tenants: create the
// machine if it doesn't exist, start it if it is stopped, wait for sshd, then
// open an SSH session as the profile login user with the login SSH key.
//
// A bare machine (`sc create --bare`) has neither user nor sshd, so it is
// reached with an Incus exec session instead — same command, different door.
func runConnectV2(ctx context.Context, config commandConfig, summary tenant.Summary, reference string, command []string, launch launchV2Options) error {
	dialed, err := dialV2Machine(ctx, config, summary, reference, launch)
	if err != nil {
		return err
	}
	if dialed.bare {
		return connectV2Bare(ctx, config, summary, dialed, command)
	}
	return runSSHSession(ctx, config, dialed, command)
}

// runSSHSession opens the SSH session a dial resolved — shared by the live
// path (runConnectV2) and the cache-first path (dialV2MachineViaCache).
func runSSHSession(ctx context.Context, config commandConfig, dialed dialedV2Machine, command []string) error {
	sshArgs := dialed.sshArgs
	// ssh joins its trailing arguments with spaces into ONE remote command
	// string that the remote shell re-splits, so argv must be shell-quoted here
	// or `sh -c 'echo hi'` arrives as `sh -c echo hi`.
	if line := remoteCommandLine(command); line != "" {
		sshArgs = append(sshArgs, line)
	}
	fmt.Fprintf(config.stdout, "Connecting to %s: ssh %s@%s\n", currentMachinePath(config, dialed.project, dialed.machine), dialed.loginUser, dialed.privateIP)
	logSSHCommand(config, sshArgs)
	sshCmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	sshCmd.Stdin = osStdinFor(config)
	sshCmd.Stdout = config.stdout
	sshCmd.Stderr = config.stderr
	return sshCmd.Run()
}

// logSSHCommand prints the exact ssh command line about to run under
// VERBOSE=1 — identity file, IdentitiesOnly, HostKeyAlias, the lot — so a
// session that works through `sc` but not through a bare `ssh user@ip` can be
// compared argument by argument (the usual difference: the CLI key is pinned
// with -i, and plain ssh never offers it). It is the same `[verbose] … command:`
// trace `sc incus` prints for the incus CLI.
func logSSHCommand(config commandConfig, sshArgs []string) {
	if os.Getenv("VERBOSE") != "1" {
		return
	}
	fmt.Fprintf(config.stderr, "[verbose] ssh command: %s\n", shellCommandLine(append([]string{"ssh"}, sshArgs...)))
}

// connectV2Bare opens a session on a machine that has no sshd: `incus exec`
// over the tenant's own restricted certificate, as root, since a bare machine
// has no login user to be.
//
// It shells out to the incus CLI rather than driving the exec websocket
// directly — that is what gives an interactive PTY, window resizing and signal
// handling for free, and it is the same path `sc incus` already takes.
//
// The shell is chosen in the machine: bash when it is there, sh otherwise. A
// bare machine is whatever image the tenant pointed --image at, and assuming
// bash on a busybox-ish one would turn a working session into "no such file".
func connectV2Bare(ctx context.Context, config commandConfig, summary tenant.Summary, dialed dialedV2Machine, command []string) error {
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return fmt.Errorf("no Sandcastle-managed Incus config found for remote %q; add one with: sc remote add", config.adminConfig.Remote)
	}
	// No -t/-T: incus allocates a PTY exactly when stdin AND stdout are
	// terminals, which is the right answer for both `sc c web` at a prompt and
	// `sc c web -- cmd` in a pipeline. Forcing either would break the other.
	remote := []string{"exec", dialed.machine, "--"}
	if line := remoteCommandLine(command); line != "" {
		remote = append(remote, "/bin/sh", "-c", line)
		fmt.Fprintf(config.stdout, "Connecting to %s: incus exec %s (bare machine — no sshd)\n", currentMachinePath(config, dialed.project, dialed.machine), dialed.machine)
	} else {
		remote = append(remote, "/bin/sh", "-c", bareLoginShellCommand)
		fmt.Fprintf(config.stdout, "Connecting to %s: incus exec %s as root (bare machine — no user, no sshd)\n", currentMachinePath(config, dialed.project, dialed.machine), dialed.machine)
	}
	incusProject := summary.V2IncusProjectName(dialed.project)
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+incusProject)
	return runner(ctx, remote, env, osStdinFor(config), config.stdout, config.stderr)
}

// bareLoginShellCommand prefers bash and falls back to sh, in the machine. exec
// replaces the wrapper either way, so no extra process survives the session.
const bareLoginShellCommand = "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi"

// dialedV2Machine carries everything needed to run ssh against a resolved,
// running machine: the base ssh argv (options + login target, no remote command
// yet) plus the login user and IP for messaging.
type dialedV2Machine struct {
	sshArgs   []string
	loginUser string
	privateIP string
	project   string
	machine   string
	// bare means the machine has no sshd to dial: sshArgs, loginUser and
	// privateIP are unset and only project/machine are populated.
	bare bool
}

// dialV2Machine resolves a machine reference, ensures the machine exists and is
// up (creating it if absent, like `sc connect`), waits for sshd, and builds the
// ssh argv with strict host-key checking. Callers append their own remote
// command (or feed one on stdin). Shared by `sc connect` and `sc fix`.
func dialV2Machine(ctx context.Context, config commandConfig, summary tenant.Summary, reference string, launch launchV2Options) (dialedV2Machine, error) {
	vm := launch.VM
	// A wildcard selects among machines that already exist; it must land on
	// exactly one before the ensure-and-create path below can run.
	reference, err := resolveSingleMachineReference(ctx, config, summary, reference)
	if err != nil {
		return dialedV2Machine{}, err
	}
	project, machineName, err := resolveV2MachineReference(summary, reference, config.adminConfig.Project)
	if err != nil {
		return dialedV2Machine{}, err
	}
	request := incusx.CreateMachineV2Request{
		IncusProject: summary.V2IncusProjectName(project),
		Name:         machineName,
		Image:        projectDefaultImage(summary, project),
		VM:           vm,
		HomeShare:    launch.HomeShare,
		// Only used when the ensure has to create: the public-name set a
		// machine born here gets — the derived name, decided exactly like
		// `sc create` decides it (explicit hostnames are `sc create`'s).
		PublicHostnames: derivedPublicHostnames(summary, project, machineName),
		ProjectDomain:   strings.TrimPrefix(zoneModePublicHostname(summary, project, machineName), machineName+"."),
	}
	if confirm := launch.ConfirmCreate; confirm != nil {
		request.ConfirmCreate = func() error { return confirm(project, machineName) }
	}
	ensured, err := config.tenantCreator.EnsureMachineV2(ctx, request)
	if err != nil {
		return dialedV2Machine{}, err
	}
	switch {
	case ensured.Created:
		fmt.Fprintf(config.stdout, "Machine %s created.\n", currentMachinePath(config, project, machineName))
	case ensured.Started:
		fmt.Fprintf(config.stdout, "Machine %s started.\n", currentMachinePath(config, project, machineName))
	}
	// A bare machine has no sshd and no user, so everything below this point —
	// the cloud-init wait, the port probe, the host-key pinning — could only
	// ever end in a timeout. Report it instead and let the caller decide:
	// `sc connect` execs a shell over the Incus API, `sc fix` gives up.
	// Checked AFTER the ensure so a stopped bare machine is started first, and
	// only for machines that already existed: a just-created one is never bare
	// (this path always creates from the default profile).
	if !ensured.Created {
		bare, err := config.tenantCreator.MachineIsBareV2(ctx, summary.V2IncusProjectName(project), machineName)
		if err != nil {
			return dialedV2Machine{}, err
		}
		if bare {
			return dialedV2Machine{bare: true, project: project, machine: machineName}, nil
		}
	}
	if ensured.PrivateIP == "" {
		return dialedV2Machine{}, fmt.Errorf("machine %s has no IP yet — still booting; retry in a few seconds (watch with: sc list)", machineName)
	}
	// A fresh machine needs cloud-init to install and start sshd. VMs take
	// longer: image download + firmware/kernel boot before cloud-init even runs.
	sshWait := 120 * time.Second
	if vm {
		sshWait = 240 * time.Second
	}
	sshDeadline := time.Now().Add(sshWait)
	// cloud-init deletes and regenerates every SSH host key on a machine's first
	// boot, and sshd is already listening before it does. Both waits share one
	// deadline, so waiting for the keys to settle costs no extra worst case.
	waitForCloudInitV2(ctx, config, summary.V2IncusProjectName(project), machineName, sshDeadline)
	for !probeSSHPort(ensured.PrivateIP, 3*time.Second) {
		if !time.Now().Before(sshDeadline) {
			if has, err := config.tenantCreator.MachineHasCloudInitV2(ctx, summary.V2IncusProjectName(project), machineName); err == nil && !has {
				return dialedV2Machine{}, fmt.Errorf("machine %s (%s) has no cloud-init, so it never got its login user, SSH keys or sshd: its image is not a cloud variant. Recreate it from one (e.g. images:ubuntu/26.04/cloud): sc delete %s --yes && sc create %s --image <ref>/cloud, or fix the project default with sc project set-image", machineName, ensured.PrivateIP, machineName, machineName)
			}
			return dialedV2Machine{}, fmt.Errorf("machine %s (%s) did not open SSH within %s — cloud-init may still be running", machineName, ensured.PrivateIP, sshWait)
		}
		select {
		case <-ctx.Done():
			return dialedV2Machine{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	sshKey, err := prepareLoginSSHKey(loginSSHKeyRequest{})
	if err != nil {
		return dialedV2Machine{}, err
	}
	// A project's profile can carry the SSH key from an earlier login. A newly
	// created Machine must receive the key this CLI will actually offer before
	// the first connection, otherwise creation succeeds but `sc connect` is
	// immediately locked out. Existing Machines are repaired explicitly by
	// `sc fix --only ssh-key`.
	if ensured.Created {
		incusDir := resolveIncusDir(config.adminConfig.Remote)
		if incusDir == "" {
			return dialedV2Machine{}, fmt.Errorf("no Sandcastle-managed Incus config found for remote %q", config.adminConfig.Remote)
		}
		reconciler := incusx.MachineSSHKeyReconciler{
			Remote:     config.adminConfig.Remote,
			ConfigPath: incusDir + "/config.yml",
			Store:      config.machineStore,
		}
		if _, err := reconciler.ReconcileMachineUserSSHKey(ctx, summary, project, machineName, defaultLocalUnixUsername(), sshKey.PublicKey); err != nil {
			return dialedV2Machine{}, fmt.Errorf("reconcile current SSH key for new machine %s: %w", machineName, err)
		}
	}
	privateKeyPath := strings.TrimSuffix(sshKey.PublicKeyPath, ".pub")
	// Record the machine's authoritative host key under the names it answers
	// at, then dial its IP but check the key against the name (HostKeyAlias).
	// Names are stable; private IPs are recycled leases. With the true key
	// already on disk we can demand StrictHostKeyChecking=yes, so a rebuilt
	// machine never trips the MITM warning and a real impostor always does.
	// The machine's Machine Public Hostnames (ADR-0028) — the ensure read
	// them off the instance — are recorded beside the private names, while
	// HostKeyAlias is the Machine Private Hostname (ADR-0028: every machine
	// finalizes SSH naming) and the dial still goes to the tenant-bridge IP.
	publicHostnames := ensured.PublicHostnames
	names := v2MachineNames(summary, project, machineName, publicHostnames)
	sshArgs := []string{"-o", "IdentitiesOnly=yes", "-i", privateKeyPath}
	if len(names) > 0 && ensureV2HostKey(ctx, config, summary, project, machineName, publicHostnames, ensured.PrivateIP, ensured.PrivateCIDR) {
		sshArgs = append(sshArgs,
			"-o", "HostKeyAlias="+names[0],
			"-o", "StrictHostKeyChecking=yes",
			"-o", "CheckHostIP=no",
		)
	} else {
		sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new")
	}
	sshArgs = append(sshArgs, ensured.LoginUser+"@"+ensured.PrivateIP)
	return dialedV2Machine{
		sshArgs:   sshArgs,
		loginUser: ensured.LoginUser,
		privateIP: ensured.PrivateIP,
		project:   project,
		machine:   machineName,
	}, nil
}

// remoteCommandLine renders argv as a single command line for ssh, which
// concatenates its trailing arguments with spaces and lets the remote login
// shell re-split the result. Without quoting, `sc c web -- sh -c 'id -un'`
// reaches the machine as `sh -c id -un` and runs `id` with no arguments.
//
// A lone argument passes through verbatim so `sc c web -- 'ls -l /tmp'` stays a
// shell snippet, matching the v1 connect path (incusx.remoteShellCommand).
func remoteCommandLine(command []string) string {
	switch len(command) {
	case 0:
		return ""
	case 1:
		return strings.TrimSpace(command[0])
	}
	quoted := make([]string, 0, len(command))
	for _, arg := range command {
		quoted = append(quoted, shellQuoteArg(arg))
	}
	return strings.Join(quoted, " ")
}

// shellQuoteArg single-quotes a value for a POSIX shell. An embedded single
// quote is escaped by closing the quoted run, emitting an escaped quote, and
// reopening it.
func shellQuoteArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// osStdinFor hands the real stdin to interactive subprocesses when the command
// config carries os.Stdin (the normal CLI case); test configs keep their reader.
func osStdinFor(config commandConfig) io.Reader {
	if config.stdin != nil {
		return config.stdin
	}
	return os.Stdin
}

func machineTypeLabel(vm bool) string {
	if vm {
		return "virtual-machine"
	}
	return "container"
}

// derivedPublicHostnames is the public-name set a machine created by an
// ensure (sc connect / sc fix) gets: the derived name or nothing.
func derivedPublicHostnames(summary tenant.Summary, project, machine string) []string {
	if derived := zoneModePublicHostname(summary, project, machine); derived != "" {
		return []string{derived}
	}
	return nil
}

// formatCreateMachineV2 renders `sc create`'s text output. The machine's
// public names are read off result.PublicHostnames — the set stamped on the
// instance. Every machine prints its DNS: line (the Machine Private Hostname
// is always served, ADR-0028); a machine with public names — derived or
// explicit — adds one "Public name:" line per name under it, rendered from
// the per-name create-time certificate outcome in outcomes. A machine
// without public names renders exactly what it always did. outcomes is
// ignored for --dry-run.
func formatCreateMachineV2(remote string, summary tenant.Summary, project string, result incusx.CreateMachineV2Result, dryRun bool, outcomes map[string]machineCertificateOutcome) string {
	var builder strings.Builder
	verb := "created"
	if dryRun {
		verb = "would be created"
	}
	fmt.Fprintf(&builder, "Machine %s %s (%s, image %s).\n", machinePath(remote, summary.Tenant, project, result.Name), verb, result.Type, result.Image)
	// /workspace is always shared; /home only with --home-share, so say which
	// of the two shapes this machine got.
	if result.HomeShare {
		fmt.Fprintf(&builder, "Storage: shared /workspace + shared /home (homeshare profile).\n")
	} else {
		fmt.Fprintf(&builder, "Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n")
	}
	// Canonical Machine Private Hostname; the default project also answers at
	// the short alias (ADR-0018). Public names come on top, never instead.
	publicHostnames := result.PublicHostnames
	if len(publicHostnames) == 0 && strings.TrimSpace(result.PublicHostname) != "" {
		publicHostnames = []string{strings.TrimSpace(result.PublicHostname)}
	}
	canonical := result.Name + "." + project + "." + summary.DNSSuffix
	fqdn := canonical
	if project == naming.DefaultProjectName {
		fqdn += " (also: " + result.Name + "." + summary.DNSSuffix + ")"
	}
	dnsLine := func(booted bool) string {
		if booted {
			return "DNS: " + fqdn + " (auto-registers within seconds)"
		}
		return "DNS: " + fqdn + " (auto-registers after boot)"
	}
	// publicLines is one "Public name:" line per public name. --dry-run
	// makes no certificate request, so its lines carry the default
	// "pending" detail.
	publicLines := func() []string {
		var lines []string
		for _, name := range publicHostnames {
			outcome := machineCertificateOutcome{}
			if !dryRun || outcomes[name].State == "project" {
				outcome = outcomes[name]
			}
			lines = append(lines, formatPublicNameLine(name, project, result.DevImage, outcome))
		}
		return lines
	}
	// nameLines tells the user how the machine will be reached by name: the
	// private name first, then every public name.
	nameLines := func(booted bool) string {
		return strings.Join(append([]string{dnsLine(booted)}, publicLines()...), "\n")
	}
	if dryRun {
		builder.WriteString(nameLines(false))
		if result.Bare {
			fmt.Fprintf(&builder, "\nBare: no login user, no SSH key, no sshd — HTTPS only.")
		}
		if result.DevImage {
			fmt.Fprintf(&builder, "\nDev Image: no Caddy/TLS ingress — SSH only.")
		}
		return builder.String()
	}
	switch {
	case result.PrivateIP != "" && len(publicHostnames) > 0:
		// The Public name: lines are long; the IP stands alone above them.
		fmt.Fprintf(&builder, "IP: %s\n%s\n", result.PrivateIP, nameLines(true))
	case result.PrivateIP != "":
		fmt.Fprintf(&builder, "IP: %s   %s\n", result.PrivateIP, nameLines(true))
	default:
		fmt.Fprintf(&builder, "Still booting — no IP leased yet. Watch it with: sc list\n")
		fmt.Fprintf(&builder, "%s\n", nameLines(false))
	}
	// A bare machine has no user to ssh as, so the usual SSH advice would be a
	// dead end. Point at the two things it does offer instead.
	if result.Bare {
		fmt.Fprintf(&builder, "HTTPS: https://%s   (Caddy with the tenant-CA leaf, proxying to localhost:3000)\n", canonical)
		if len(publicHostnames) > 0 {
			fmt.Fprintf(&builder, "HTTPS (public): https://%s   (Let's Encrypt; served once the certificate lands)\n", strings.Join(publicHostnames, ", https://"))
		}
		fmt.Fprintf(&builder, "Bare: no login user, no sshd — `sc connect` will not work; get a shell with: sc incus exec %s -- /bin/sh", result.Name)
		return builder.String()
	}
	if result.DevImage {
		fmt.Fprintf(&builder, "Dev Image: no Caddy/TLS ingress — SSH only.\n")
	}
	loginUser := result.LoginUser
	if loginUser == "" {
		loginUser = tenant.DefaultV2UnixUser
	}
	if result.PrivateIP != "" {
		fmt.Fprintf(&builder, "SSH: ssh %s@%s   (cloud-init may still be installing sshd)", loginUser, result.PrivateIP)
	}
	// writeOutput adds the final newline, so never hand it one.
	return strings.TrimRight(builder.String(), "\n")
}

// requireV2Tenant resolves the current tenant. v1 is gone, so every Sandcastle
// tenant is v2 and a lookup miss simply means the tenant does not exist — there
// is no other shape it could be.
func requireV2Tenant(ctx context.Context, config commandConfig) (tenant.Summary, error) {
	summary, ok, err := v2TenantSummary(ctx, config)
	if err != nil {
		// The lookup never got an answer — say so, instead of turning an
		// unreachable remote into a claim about the tenant.
		return tenant.Summary{}, err
	}
	if !ok {
		name := strings.TrimSpace(config.adminConfig.Tenant)
		if name == "" {
			return tenant.Summary{}, fmt.Errorf("a tenant is required (set one with `sc config set tenant <name>` or log in)")
		}
		return tenant.Summary{}, fmt.Errorf("Sandcastle tenant %s not found", name)
	}
	return summary, nil
}

func createCertificateDecisions(names []string, outcomes map[string]machineCertificateOutcome) map[string]string {
	if len(names) == 0 {
		return nil
	}
	decisions := make(map[string]string, len(names))
	for _, name := range names {
		decisions[name] = "per-name"
		if outcomes[name].State == "project" {
			decisions[name] = "project"
		}
	}
	return decisions
}
