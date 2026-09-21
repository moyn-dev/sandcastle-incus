package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/domain"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	machine "github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// defaultResourceCacheRequestTimeout bounds the GET /api/resources round trip
// `sc ls` makes before falling back to the live per-project Incus path. It is
// far shorter than DeviceClient's default (5 minutes, sized for the
// device-login poll) because an unreachable or slow cache endpoint should fall
// back quickly rather than stall the listing — see implementation-notes.md.
//
// It is not, however, only about Sandcastle's own work: a cold TLS handshake
// to a Cloudflare-tunnelled Auth Hostname measured 0.7–2.2s on its own, and a
// 3-byte /healthz over the same tunnel 0.25–4.2s, so the earlier 3s budget
// expired on tunnel latency alone even with a minimal body. An endpoint that
// is actually down fails on connect long before this fires; only a live-but-
// slow one waits it out.
const defaultResourceCacheRequestTimeout = 5 * time.Second

// resourceCacheTimeoutEnv overrides that budget, for links slower still (or
// for a deployment that would rather never wait on the cache). A value that
// does not parse as a Go duration, or is not positive, is ignored.
const resourceCacheTimeoutEnv = "SANDCASTLE_LS_CACHE_TIMEOUT"

func resourceCacheRequestTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv(resourceCacheTimeoutEnv))
	if raw == "" {
		return defaultResourceCacheRequestTimeout
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return defaultResourceCacheRequestTimeout
	}
	return value
}

type listPayload struct {
	Tenant         tenant.Summary             `json:"tenant"`
	Remote         string                     `json:"remote,omitempty"`
	Project        string                     `json:"project,omitempty"`
	Machine        string                     `json:"machine,omitempty"`
	AllProjects    bool                       `json:"allProjects"`
	Machines       []meta.Machine             `json:"machines"`
	Unmanaged      []machine.UnmanagedMachine `json:"unmanaged,omitempty"`
	UnmanagedCount int                        `json:"unmanagedCount"`
	// Networks, StoragePools, StorageVolumes, Profiles, and Images are only
	// ever populated by the cache-backed path (listMachinesViaCache) — the
	// live per-project path never fetched these resource types and leaves
	// them empty, which is what keeps toggle-off/fallback output byte-for-byte
	// identical to pre-wish `sc ls`.
	Networks       []api.Network           `json:"networks,omitempty"`
	StoragePools   []api.StoragePool       `json:"storagePools,omitempty"`
	StorageVolumes []api.StorageVolumeFull `json:"storageVolumes,omitempty"`
	Profiles       []api.Profile           `json:"profiles,omitempty"`
	Images         []api.Image             `json:"images,omitempty"`
}

// listRenderOptions selects which cache-only resource-type sections `sc ls`
// prints, driven by its --networks/--storage-pools/--storage-volumes/
// --profiles/--images flags. The zero value renders exactly today's
// instances-only table — required for byte-for-byte toggle-off/fallback
// compatibility regardless of what a cache-backed result happens to carry.
type listRenderOptions struct {
	ShowNetworks       bool
	ShowStoragePools   bool
	ShowStorageVolumes bool
	ShowProfiles       bool
	ShowImages         bool
}

// resourceKinds is the include= selection these options imply: exactly the
// sections formatMachineList will print. "machines" is unconditional — it is
// the listing itself — and everything else rides on its flag, so a plain
// `sc ls` never asks the cache endpoint for the networks/pools/volumes/
// profiles/images it would then throw away. On a real install that is the
// difference between a 4.4 KB and a 79 KB response over a tunnelled Auth
// Hostname, i.e. between a cache hit and a silent fallback to the live path.
func (o listRenderOptions) resourceKinds() []string {
	kinds := []string{authapp.ResourceKindMachines}
	if o.ShowNetworks {
		kinds = append(kinds, authapp.ResourceKindNetworks)
	}
	if o.ShowStoragePools {
		kinds = append(kinds, authapp.ResourceKindStoragePools)
	}
	if o.ShowStorageVolumes {
		kinds = append(kinds, authapp.ResourceKindStorageVolumes)
	}
	if o.ShowProfiles {
		kinds = append(kinds, authapp.ResourceKindProfiles)
	}
	if o.ShowImages {
		kinds = append(kinds, authapp.ResourceKindImages)
	}
	return kinds
}

// multiListPayload is what a `sc ls` whose install part globs returns: one
// section per enrolled install swept. Kept separate from listPayload so the
// single-install shape — which scripts already parse — is untouched.
type multiListPayload struct {
	RemotePattern string        `json:"remotePattern"`
	Remotes       []listPayload `json:"remotes"`
	// Warnings names installs the sweep could not read. A listing reports them
	// and shows the rest, rather than failing whole because one install of
	// several is down.
	Warnings []string `json:"warnings,omitempty"`
}

type tenantListPayload struct {
	Tenants []tenant.Summary `json:"tenants"`
}

type tenantResourcesPayload struct {
	Tenant    tenant.Summary             `json:"tenant"`
	Machines  []meta.Machine             `json:"machines"`
	Unmanaged []machine.UnmanagedMachine `json:"unmanaged,omitempty"`
}

func newListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var allProjects bool
	var showNetworks, showStoragePools, showStorageVolumes, showProfiles, showImages bool
	var pathOpts pathListOptions
	command := &cobra.Command{
		Use:               "list [[remote:]project[:machine] | path...]",
		Aliases:           []string{"ls"},
		Short:             "List Sandcastle machines, or the children of a Sandcastle Path",
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: pathCompletion(config, levelMachine),
		Long: `List Sandcastle machines in the current install's project.

With a Sandcastle Path (/remote/tenant/project/machine, or a relative path
such as .., ../*dev or ~), ls lists like a shell: the children of every
directory the path matches — remotes under /, tenants under a remote,
projects under a tenant, machines under a project — each under a "path:"
header when there are several. -d prints the matching names instead of
their contents, -l a table with the level's columns, -R recurses. With no
argument ls lists the current project's machines as before, or the children
of the Current Position when sc cd has moved it above a project.

The argument may carry a "<remote>:" prefix to list another enrolled install
without switching to it — e.g. "sc ls obelix:home" (project home on remote
obelix) or "sc ls obelix:" (that remote's default project). A leading part is
read as a remote only when it names an enrolled one; "sc remote list" shows
them.

Every part accepts shell-style wildcards:

  sc ls 'gbrain:*'        every machine in project gbrain
  sc ls -a 'g*:d*'        d* machines in every project matching g*
  sc ls -a '*:web-*'      the web-* machines of every project
  sc ls -a '*:*:*'        every machine on every enrolled install
  sc ls 'o*:gbrain:d*'    …scoped to the installs matching o*

Globbing installs needs all three parts spelled out: a two-part reference stays
[remote:]project or project:machine. Quote the pattern so the shell does not
expand it first.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if listInPathMode(config, args, pathOpts) {
				payload, err := listPaths(cmd.Context(), config, args, pathOpts)
				if err != nil {
					return err
				}
				return writeOutput(config.stdout, opts.output, formatPathList(payload, pathOpts), payload)
			}
			if len(args) > 1 {
				return fmt.Errorf("several arguments need Sandcastle Paths (/remote/tenant/project/machine); the colon grammar takes one reference")
			}
			remoteOverride, project, machineName := splitListReference(optionalArg(args), localRemoteExists)
			request := listMachinesRequest{
				Project:     project,
				Machine:     machineName,
				AllProjects: allProjects,
			}
			if naming.IsPattern(remoteOverride) {
				payload, err := listMachinesAcrossRemotes(cmd.Context(), config, defaultRemoteFanout(), remoteOverride, request)
				if err != nil {
					return err
				}
				for i := range payload.Remotes {
					stampMachinePaths(payload.Remotes[i].Remote, &payload.Remotes[i])
				}
				text := formatMultiMachineListShort(payload)
				if pathOpts.Long {
					text = formatMultiMachineList(payload)
				}
				return writeOutput(config.stdout, opts.output, text, payload)
			}
			runCfg := config
			if remoteOverride != "" && remoteOverride != strings.TrimSpace(config.adminConfig.Remote) {
				scoped, restore, err := listConfigForRemote(config, remoteOverride)
				if err != nil {
					return err
				}
				defer restore()
				runCfg = scoped
			}
			renderOpts := listRenderOptions{
				ShowNetworks:       showNetworks,
				ShowStoragePools:   showStoragePools,
				ShowStorageVolumes: showStorageVolumes,
				ShowProfiles:       showProfiles,
				ShowImages:         showImages,
			}
			result, ok := listMachinesViaCache(cmd.Context(), runCfg, request, renderOpts)
			if !ok {
				var err error
				result, err = listMachines(cmd.Context(), runCfg, request)
				if err != nil {
					return err
				}
			}
			listed := listedScopePath(runCfg, result)
			stampMachinePaths(strings.TrimSpace(runCfg.adminConfig.Remote), &result)
			text := formatMachineListShort(result)
			if pathOpts.Long {
				// The table's own context line is the listed path in the
				// plain case; only a filtered listing adds a second line.
				text = formatMachineList(result, renderOpts)
			}
			if !strings.HasPrefix(text, listed+"\n") {
				text = listed + "\n" + text
			}
			return writeOutput(config.stdout, opts.output, text, result)
		},
	}
	command.Flags().BoolVarP(&allProjects, "all-projects", "a", false, "list machines across all projects")
	command.Flags().BoolVarP(&pathOpts.Long, "long", "l", false, "long listing: the table with the level's columns (default: names only)")
	command.Flags().BoolVarP(&pathOpts.Directory, "directory", "d", false, "path mode: list the matching names, not their contents")
	command.Flags().BoolVarP(&pathOpts.Recursive, "recursive", "R", false, "path mode: list subdirectories recursively")
	command.Flags().BoolVar(&showNetworks, "networks", false, "also list networks (cache-backed only; no effect when falling back to the live query)")
	command.Flags().BoolVar(&showStoragePools, "storage-pools", false, "also list storage pools (cache-backed only; no effect when falling back to the live query)")
	command.Flags().BoolVar(&showStorageVolumes, "storage-volumes", false, "also list storage volumes (cache-backed only; no effect when falling back to the live query)")
	command.Flags().BoolVar(&showProfiles, "profiles", false, "also list profiles (cache-backed only; no effect when falling back to the live query)")
	command.Flags().BoolVar(&showImages, "images", false, "also list images (cache-backed only; no effect when falling back to the live query)")
	return command
}

// stampMachinePaths fills every machine's Sandcastle Path in a listing.
func stampMachinePaths(remote string, result *listPayload) {
	if remote == "" {
		remote = strings.TrimSpace(result.Remote)
	}
	for i := range result.Machines {
		m := &result.Machines[i]
		m.Path = machinePath(remote, result.Tenant.Tenant, m.Project, m.Name)
	}
}

// listedScopePath is the first line of a colon-mode listing: the Sandcastle
// Path of what was listed — the project, or the tenant when the listing
// spans projects — so the names below always say where they live (which
// `sc ls obelix:home` from another install would otherwise leave open).
func listedScopePath(config commandConfig, result listPayload) string {
	remote := strings.TrimSpace(result.Remote)
	if remote == "" {
		remote = strings.TrimSpace(config.adminConfig.Remote)
	}
	segments := []string{remote, strings.TrimSpace(result.Tenant.Tenant)}
	if project := strings.TrimSpace(result.Project); project != "" && !result.AllProjects && !naming.IsPattern(project) {
		segments = append(segments, project)
	}
	return formatPath(segments)
}

// formatMachineListShort is `sc ls` without -l: one machine per line, as a
// bare name inside the listed project and as project/name when the listing
// spans projects; unmanaged instances are marked. The table is -l.
func formatMachineListShort(result listPayload) string {
	if len(result.Machines) == 0 && len(result.Unmanaged) == 0 {
		return "No Sandcastle machines found in " + listContext(result) + "."
	}
	qualify := result.AllProjects || naming.IsPattern(strings.TrimSpace(result.Project))
	var b strings.Builder
	for _, m := range result.Machines {
		if qualify {
			fmt.Fprintf(&b, "%s/%s\n", m.Project, m.Name)
		} else {
			fmt.Fprintln(&b, m.Name)
		}
	}
	for _, u := range result.Unmanaged {
		fmt.Fprintf(&b, "%s (unmanaged)\n", u.Name)
	}
	return strings.TrimRight(b.String(), "\n")
}

// formatMultiMachineListShort is the cross-install `sc ls` without -l: one
// absolute Sandcastle Path per machine.
func formatMultiMachineListShort(payload multiListPayload) string {
	var b strings.Builder
	for _, warning := range payload.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", warning)
	}
	total := 0
	for _, section := range payload.Remotes {
		for _, m := range section.Machines {
			fmt.Fprintln(&b, formatPath([]string{section.Remote, section.Tenant.Tenant, m.Project, m.Name}))
			total++
		}
		for _, u := range section.Unmanaged {
			fmt.Fprintf(&b, "%s (unmanaged)\n", formatPath([]string{section.Remote, section.Tenant.Tenant, "-", u.Name}))
			total++
		}
	}
	if total == 0 {
		fmt.Fprintf(&b, "No Sandcastle machines found on installs matching %q.", payload.RemotePattern)
	}
	return strings.TrimRight(b.String(), "\n")
}

// listInPathMode decides between the two grammars of `sc ls`: any path
// argument, -d/-R, or a Current Position above the project level selects
// the tree walk; otherwise the colon listing runs, so `sc ls gbrain:*` and
// `sc ls -a` inside a project keep their filters (-l picks the table in
// both modes).
func listInPathMode(config commandConfig, args []string, options pathListOptions) bool {
	if options.Directory || options.Recursive {
		return true
	}
	for _, arg := range args {
		if isPathReference(arg) {
			return true
		}
	}
	// Above a project every name is a child of the position (a tenant's
	// projects, a remote's tenants), so bare names are relative paths too.
	return len(currentPosition(config)) < levelProject
}

// listMachinesViaCache attempts `sc ls`'s cache-first path: the t2
// GET /api/resources endpoint, scoped and filtered the same way the live path
// (listMachines) scopes and filters, before any Incus round trip. ok is false
// on ANY non-answer — no stored AuthToken, no configured Auth Hostname,
// endpoint unreachable, non-200/not-ready response, or request timeout — and
// the caller must fall through to listMachines unchanged. The fallback reason
// is logged only under VERBOSE=1, matching the existing
// "[verbose] incus api: …" trace style (see incusx's logIncusAPICall).
func listMachinesViaCache(ctx context.Context, config commandConfig, request listMachinesRequest, renderOpts listRenderOptions) (listPayload, bool) {
	client := config.authResources
	if client == nil {
		token := strings.TrimSpace(config.adminConfig.AuthToken)
		if token == "" {
			logListCacheFallback(config, "no stored AuthToken")
			return listPayload{}, false
		}
		baseURL := commandAuthHostname(config, "")
		if baseURL == "" {
			logListCacheFallback(config, "no configured Auth Hostname")
			return listPayload{}, false
		}
		client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: token, Tenant: strings.TrimSpace(config.adminConfig.Tenant)}
	}
	tenantName, projectFilter := splitListTenantAndProject(config, request)
	cacheCtx, cancel := context.WithTimeout(ctx, resourceCacheRequestTimeout())
	defer cancel()
	result, err := client.ListResources(cacheCtx, authapp.ResourceListRequest{
		Tenant:  tenantName,
		Project: projectFilter,
		Machine: strings.TrimSpace(request.Machine),
		Include: renderOpts.resourceKinds(),
	})
	if err != nil {
		logListCacheFallback(config, err.Error())
		return listPayload{}, false
	}
	if stale, found := runningWithoutAddress(result.Machines); found {
		logListCacheFallback(config, fmt.Sprintf("cached machine %s/%s is running with no address", stale.Project, stale.Name))
		return listPayload{}, false
	}
	return listPayload{
		Tenant:         result.Tenant,
		Remote:         strings.TrimSpace(config.adminConfig.Remote),
		Project:        result.Project,
		Machine:        result.Machine,
		AllProjects:    result.AllProjects,
		Machines:       result.Machines,
		Networks:       result.Networks,
		StoragePools:   result.StoragePools,
		StorageVolumes: result.StorageVolumes,
		Profiles:       result.Profiles,
		Images:         result.Images,
	}, true
}

// runningWithoutAddress returns the first cached machine that is running but
// carries no private address — the one shape a cache-backed answer must not be
// trusted on, so `sc ls` treats it as a miss and re-reads live.
//
// Nothing on the Incus event bus fires when a guest picks up its DHCP lease.
// api.EventLifecycleInstanceUpdated — which ADR-0023 decision 3 leans on for
// "IP/NIC changes" — is emitted from exactly two places upstream, both at the
// tail of the instance driver's Update(), i.e. a config change made through the
// API. A guest acquiring an address is not an API operation and emits nothing.
// The cache refreshes a project on instance-created/instance-started, both of
// which land before the lease does, and that decision keeps no periodic resync,
// so the empty address captured at start time survives until some unrelated
// event happens to touch the same project. Meanwhile the machine is fully
// reachable (ssh works) and `sc ls` prints a blank IP column.
//
// Falling back costs one live per-project read for listings in that state. A
// machine that genuinely has no address while running — no NIC device, or a VM
// whose incus-agent never came up — makes the fallback permanent for any
// listing that includes it, which is exactly pre-cache `sc ls` behaviour:
// slower, never wrong. Printing an address the machine does not have, or
// omitting one it does, is the worse failure.
func runningWithoutAddress(machines []meta.Machine) (meta.Machine, bool) {
	for _, candidate := range machines {
		if candidate.Running && strings.TrimSpace(candidate.PrivateIP) == "" {
			return candidate, true
		}
	}
	return meta.Machine{}, false
}

// splitListTenantAndProject mirrors the tenant/project resolution at the top
// of listMachines() — the "tenant/project" scoped-project cut and the
// fall-back to the locally pinned project when the request carries none —
// so the cache request is scoped identically to what the live path would
// have queried. It intentionally does NOT replicate listMachines()'s
// project-existence validation: the cache endpoint does that itself
// server-side (404 on an unknown literal project), and any such error already
// falls back to the live path, which performs the real validation and
// produces the real user-facing error.
func splitListTenantAndProject(config commandConfig, request listMachinesRequest) (tenantName, projectFilter string) {
	tenantName = strings.TrimSpace(config.adminConfig.Tenant)
	projectFilter = strings.TrimSpace(request.Project)
	if scopedTenant, scopedProject, ok := strings.Cut(projectFilter, "/"); ok {
		tenantName = strings.TrimSpace(scopedTenant)
		projectFilter = strings.TrimSpace(scopedProject)
	}
	if projectFilter == "" && strings.TrimSpace(config.adminConfig.Project) != "" && !request.AllProjects {
		projectFilter = strings.TrimSpace(config.adminConfig.Project)
	}
	return tenantName, projectFilter
}

func logListCacheFallback(config commandConfig, reason string) {
	if os.Getenv("VERBOSE") != "1" {
		return
	}
	stderr := config.stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "[verbose] incus api: sc ls cache-backed endpoint unavailable (%s), falling back to live per-project query\n", reason)
}

func listTenants(ctx context.Context, store tenant.IncusTenantStore) ([]tenant.Summary, error) {
	return tenant.List(ctx, store)
}

func formatTenantList(tenants []tenant.Summary) string {
	if len(tenants) == 0 {
		return "No Sandcastle tenants found."
	}
	var builder strings.Builder
	for _, tenant := range tenants {
		fmt.Fprintf(&builder, "%s\t%s\t%s\n", tenant.Tenant, tenant.DNSSuffix, tenant.Status)
	}
	return strings.TrimRight(builder.String(), "\n")
}

type listMachinesRequest struct {
	Project     string
	Machine     string
	AllProjects bool
}

func optionalArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// splitListReference parses `sc ls` addressing: "[remote:]project[:machine]".
//
//	obelix:home     → ("obelix", "home", "")     remote obelix, project home
//	obelix:         → ("obelix", "", "")         remote obelix, its default project
//	obelix:gbrain:d* → ("obelix", "gbrain", "d*")
//	gbrain:*        → ("", "gbrain", "*")        project gbrain, all machines
//	g*:d*           → ("", "g*", "d*")
//	home            → ("", "home", "")
//
// A two-part reference is ambiguous — "a:b" is either remote:project or
// project:machine — and is resolved the same way rebindForReference resolves
// it for every other command: the leading part is a remote only if it names an
// ENROLLED one. remoteKnown is injected so this stays a pure function.
func splitListReference(arg string, remoteKnown func(string) bool) (remote, project, machine string) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", ""
	}
	parts := strings.Split(arg, ":")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	switch len(parts) {
	case 1:
		return "", parts[0], ""
	case 2:
		// "obelix:" (trailing colon, no machine part) always addresses a
		// remote — that shape has no other reading, so it does not depend on
		// the remote being resolvable from here.
		if parts[1] == "" || (remoteKnown != nil && remoteKnown(parts[0])) {
			return parts[0], parts[1], ""
		}
		return "", parts[0], parts[1]
	default:
		// Three or more parts: only remote:project:machine is meaningful. Extra
		// parts fold into the machine part, where validation rejects them.
		return parts[0], parts[1], strings.Join(parts[2:], ":")
	}
}

// listConfigForRemote rebinds the listing stores to another enrolled remote so
// `sc ls <remote>:...` reads that install without a durable switch. INCUS_CONF is
// pointed at that remote's incus config dir (the ADR-0021 shared dir for enrolled
// installs) for the duration and restored by the returned func; the project
// defaults to that remote's own pin when the arg carried none.
func listConfigForRemote(base commandConfig, remote string) (commandConfig, func(), error) {
	incusDir := scconfig.ResolveConfigPath(remote)
	if incusDir == "" {
		return base, func() {}, fmt.Errorf("no enrolled Sandcastle remote %q; run `sc remote list` to see installs", remote)
	}
	prev, had := os.LookupEnv("INCUS_CONF")
	os.Setenv("INCUS_CONF", incusDir)
	restore := func() {
		if had {
			os.Setenv("INCUS_CONF", prev)
		} else {
			os.Unsetenv("INCUS_CONF")
		}
	}
	sharedRemote := incusx.NewSharedRemote(remote).WithVerbose(os.Getenv("VERBOSE") == "1", os.Stderr)
	cfg := base
	cfg.adminConfig = adminForRemote(base.adminConfig, remote)
	cfg.tenantStore = incusx.NewTenantStoreForSharedRemote(sharedRemote)
	cfg.machineStore = incusx.NewHostOverrideManagerForSharedRemote(sharedRemote)
	return cfg, restore, nil
}

func listMachines(ctx context.Context, config commandConfig, request listMachinesRequest) (result listPayload, err error) {
	defer func() {
		if err == nil {
			enrichProjectCertificates(ctx, config, &result)
		}
	}()
	return listMachinesRaw(ctx, config, request)
}

func listMachinesRaw(ctx context.Context, config commandConfig, request listMachinesRequest) (listPayload, error) {
	tenantName := strings.TrimSpace(config.adminConfig.Tenant)
	projectFilter := strings.TrimSpace(request.Project)
	if scopedTenant, scopedProject, ok := strings.Cut(projectFilter, "/"); ok {
		tenantName = strings.TrimSpace(scopedTenant)
		projectFilter = strings.TrimSpace(scopedProject)
	}
	ref, err := naming.ParseTenantRef(tenantName)
	if err != nil {
		return listPayload{}, fmt.Errorf("tenant is required; set SANDCASTLE_TENANT or local tenant config")
	}
	tenants, err := scopedListTenants(ctx, config, ref.Tenant)
	if err != nil {
		return listPayload{}, err
	}
	var summary tenant.Summary
	found := false
	for _, candidate := range tenants {
		if candidate.Tenant == ref.Tenant {
			summary = candidate
			found = true
			break
		}
	}
	if !found {
		return listPayload{}, fmt.Errorf("Sandcastle tenant %s not found", ref.String())
	}
	if config.machineStore == nil {
		return listPayload{}, fmt.Errorf("machine metadata store is not configured")
	}
	machineFilter := strings.TrimSpace(request.Machine)
	if machineFilter != "" {
		if err := validateNamePart("machine", machineFilter); err != nil {
			return listPayload{}, err
		}
	}
	if projectFilter != "" {
		if err := validateNamePart("project", projectFilter); err != nil {
			return listPayload{}, err
		}
		// A literal project must exist — a typo should say so rather than come
		// back as an empty listing. A project GLOB matching nothing is just an
		// empty set, the same as a machine glob matching nothing.
		if !naming.IsPattern(projectFilter) && !summaryHasProject(summary, projectFilter) {
			return listPayload{}, unknownProject{err: fmt.Errorf("Sandcastle project %s not found in tenant %s", projectFilter, summary.Tenant)}
		}
	} else if strings.TrimSpace(config.adminConfig.Project) != "" && !request.AllProjects {
		projectFilter = strings.TrimSpace(config.adminConfig.Project)
	}
	// The project filter — glob or not — is pushed into the store, which
	// resolves it against the tenant summary's project list (already in hand,
	// no Incus call) before querying anything. A glob that matches no project
	// therefore costs zero round trips.
	machines, unmanaged, err := listMachinesAndUnmanaged(ctx, config.machineStore, summary, projectFilter)
	if err != nil {
		return listPayload{}, err
	}
	filtered := make([]meta.Machine, 0, len(machines))
	for _, machine := range machines {
		if projectFilter != "" && !naming.MatchName(projectFilter, machine.Project) {
			continue
		}
		if machineFilter != "" && !naming.MatchName(machineFilter, machine.Name) {
			continue
		}
		filtered = append(filtered, machine)
	}
	// The unmanaged bucket carries no project, so only the machine-name filter
	// can apply to it.
	filteredUnmanaged := make([]machine.UnmanagedMachine, 0, len(unmanaged))
	for _, candidate := range unmanaged {
		if machineFilter != "" && !naming.MatchName(machineFilter, candidate.Name) {
			continue
		}
		filteredUnmanaged = append(filteredUnmanaged, candidate)
	}
	return listPayload{
		Tenant:         summary,
		Remote:         strings.TrimSpace(config.adminConfig.Remote),
		Project:        projectFilter,
		Machine:        machineFilter,
		AllProjects:    projectFilter == "",
		Machines:       filtered,
		Unmanaged:      filteredUnmanaged,
		UnmanagedCount: len(filteredUnmanaged),
	}, nil
}

// listMachinesAndUnmanaged reads the tenant's machines, scoped to projectFilter
// (a project name or a glob) when the caller has one. The scope is pushed down
// into the store rather than applied to the result: listing the whole tenant
// costs one Incus round trip per project, and `sc list` under a pinned project
// only ever shows one of them.
func listMachinesAndUnmanaged(ctx context.Context, store machine.Store, tenant tenant.Summary, projectFilter string) ([]meta.Machine, []machine.UnmanagedMachine, error) {
	if projectFilter != "" {
		if scoped, ok := store.(machine.ProjectScopedCombinedStore); ok {
			return scoped.ListMachinesAndUnmanagedInProject(ctx, tenant, projectFilter)
		}
	}
	if combined, ok := store.(machine.CombinedStore); ok {
		return combined.ListMachinesAndUnmanaged(ctx, tenant)
	}
	if projectFilter != "" {
		if scoped, ok := store.(machine.ProjectScopedStore); ok {
			machines, err := scoped.ListMachinesInProject(ctx, tenant, projectFilter)
			if err != nil {
				return nil, nil, err
			}
			unmanaged, err := listUnmanagedMachines(ctx, store, tenant)
			if err != nil {
				return nil, nil, err
			}
			return machines, unmanaged, nil
		}
	}
	machines, err := store.ListMachines(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	unmanaged, err := listUnmanagedMachines(ctx, store, tenant)
	if err != nil {
		return nil, nil, err
	}
	return machines, unmanaged, nil
}

func listUnmanagedMachines(ctx context.Context, store machine.Store, tenant tenant.Summary) ([]machine.UnmanagedMachine, error) {
	unmanagedStore, ok := store.(machine.UnmanagedStore)
	if !ok {
		return nil, nil
	}
	machines, err := unmanagedStore.ListUnmanagedMachines(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("list unmanaged machines for %s: %w", tenant.Tenant, err)
	}
	return machines, nil
}

func summaryHasProject(summary tenant.Summary, name string) bool {
	for _, candidate := range summary.Projects {
		if candidate.Name == name {
			return true
		}
	}
	return false
}

// listContext names the remote (always) and project (when filtered to one) the
// listing covers, so output — especially an empty result — says WHICH install
// and project it looked in.
func listContext(result listPayload) string {
	// The plain case reads as a path: remote:tenant:project[:machine].
	if p, m := strings.TrimSpace(result.Project), strings.TrimSpace(result.Machine); !result.AllProjects && !naming.IsPattern(p) && !naming.IsPattern(m) {
		if path := scopePath(result.Remote, result.Tenant.Tenant, p, m); path != "" {
			return path
		}
	}
	parts := make([]string, 0, 3)
	if r := strings.TrimSpace(result.Remote); r != "" {
		parts = append(parts, fmt.Sprintf("remote %q", r))
	}
	if p := strings.TrimSpace(result.Project); p != "" && !result.AllProjects {
		label := "project"
		if naming.IsPattern(p) {
			label = "projects matching"
		}
		parts = append(parts, fmt.Sprintf("%s %q", label, p))
	}
	if m := strings.TrimSpace(result.Machine); m != "" {
		label := "machine"
		if naming.IsPattern(m) {
			label = "machines matching"
		}
		parts = append(parts, fmt.Sprintf("%s %q", label, m))
	}
	if len(parts) == 0 {
		return "the current install"
	}
	return strings.Join(parts, ", ")
}

// listMachinesAcrossRemotes sweeps every enrolled install matching pattern.
// Unlike the lifecycle verbs — which refuse to act on a partial sweep — a
// listing reports the installs it could not read as warnings and still shows
// what the others returned: a broken install should not blind you to the rest.
func listMachinesAcrossRemotes(ctx context.Context, config commandConfig, fanout remoteFanout, pattern string, request listMachinesRequest) (multiListPayload, error) {
	payload := multiListPayload{RemotePattern: pattern}
	var projectMissing error
	err := fanout.forEachRemoteScope(config, pattern, func(remote string, scoped commandConfig) error {
		result, err := listMachines(ctx, scoped, request)
		if err != nil {
			// An install that simply does not have the named project has
			// nothing to contribute — installs have different project sets.
			var missing unknownProject
			if errors.As(err, &missing) {
				projectMissing = err
				return nil
			}
			return err
		}
		payload.Remotes = append(payload.Remotes, result)
		return nil
	})
	if err != nil {
		// No install answered at all — that is a failure, not a warning.
		if len(payload.Remotes) == 0 {
			return multiListPayload{}, err
		}
		payload.Warnings = strings.Split(err.Error(), "\n")
	}
	// The project existed on no install at all: that is a typo, not an empty set.
	if len(payload.Remotes) == 0 && projectMissing != nil {
		return multiListPayload{}, projectMissing
	}
	return payload, nil
}

// multiListContext names the sweep for the header line, so an empty result
// still says where it looked.
func multiListContext(payload multiListPayload) string {
	parts := []string{fmt.Sprintf("remotes matching %q", payload.RemotePattern)}
	if len(payload.Remotes) > 0 {
		first := payload.Remotes[0]
		if p := strings.TrimSpace(first.Project); p != "" && !first.AllProjects {
			label := "project"
			if naming.IsPattern(p) {
				label = "projects matching"
			}
			parts = append(parts, fmt.Sprintf("%s %q", label, p))
		}
		if m := strings.TrimSpace(first.Machine); m != "" {
			label := "machine"
			if naming.IsPattern(m) {
				label = "machines matching"
			}
			parts = append(parts, fmt.Sprintf("%s %q", label, m))
		}
	}
	return strings.Join(parts, ", ")
}

func formatMultiMachineList(payload multiListPayload) string {
	var builder strings.Builder
	for _, warning := range payload.Warnings {
		fmt.Fprintf(&builder, "warning: %s\n", warning)
	}
	total := 0
	for _, section := range payload.Remotes {
		total += len(section.Machines) + len(section.Unmanaged)
	}
	if total == 0 {
		fmt.Fprintf(&builder, "No Sandcastle machines found in %s.", multiListContext(payload))
		return strings.TrimRight(builder.String(), "\n")
	}
	fmt.Fprintf(&builder, "%s\n", multiListContext(payload))
	table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "REMOTE\tPROJECT\tMACHINE\tTYPE\tFQDN\tCERT\tIP\tCREATED\tRENDERED\tSTATE")
	for _, section := range payload.Remotes {
		// The FQDN comes from each section's OWN tenant summary — installs have
		// different DNS suffixes, so one shared summary would mislabel rows.
		for _, machine := range section.Machines {
			state := "stopped"
			if machine.Running {
				state = "running"
			}
			fmt.Fprintf(
				table,
				"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				section.Remote,
				machine.Project,
				machine.Name,
				machineTypeCell(machine),
				machineFQDN(section.Tenant, machine),
				machineCertCell(machine),
				machine.PrivateIP,
				formatListCreatedAt(machine.CreatedAt),
				displayValue(machine.RenderedVersion),
				state,
			)
		}
		for _, unmanaged := range section.Unmanaged {
			state := unmanaged.Status
			if state == "" {
				if unmanaged.Running {
					state = "running"
				} else {
					state = "stopped"
				}
			}
			fmt.Fprintf(
				table,
				"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				section.Remote,
				"-",
				unmanaged.Name,
				machineTypeShort(unmanaged.Type),
				"-",
				"-",
				displayValue(unmanaged.PrivateIP),
				formatListCreatedAt(unmanaged.CreatedAt),
				"-",
				"unmanaged:"+state,
			)
		}
	}
	_ = table.Flush()
	return strings.TrimRight(builder.String(), "\n")
}

func formatMachineList(result listPayload, opts listRenderOptions) string {
	hasExtras := (opts.ShowNetworks && len(result.Networks) > 0) ||
		(opts.ShowStoragePools && len(result.StoragePools) > 0) ||
		(opts.ShowStorageVolumes && len(result.StorageVolumes) > 0) ||
		(opts.ShowProfiles && len(result.Profiles) > 0) ||
		(opts.ShowImages && len(result.Images) > 0)
	if len(result.Machines) == 0 && len(result.Unmanaged) == 0 && !hasExtras {
		return "No Sandcastle machines found in " + listContext(result) + "."
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s\n", listContext(result))
	if len(result.Machines) > 0 || len(result.Unmanaged) > 0 {
		table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "PROJECT\tMACHINE\tTYPE\tFQDN\tCERT\tTUNNEL\tTAILNET\tIP\tCREATED\tRENDERED\tSTATE")
		for _, machine := range result.Machines {
			state := "stopped"
			if machine.Running {
				state = "running"
			}
			fmt.Fprintf(
				table,
				"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				machine.Project,
				machine.Name,
				machineTypeCell(machine),
				machineFQDN(result.Tenant, machine),
				machineCertCell(machine),
				machineTunnelCell(machine),
				displayValue(strings.Join(machine.TailnetPublications, ",")),
				machine.PrivateIP,
				formatListCreatedAt(machine.CreatedAt),
				displayValue(machine.RenderedVersion),
				state,
			)
		}
		for _, unmanaged := range result.Unmanaged {
			state := unmanaged.Status
			if state == "" {
				if unmanaged.Running {
					state = "running"
				} else {
					state = "stopped"
				}
			}
			fmt.Fprintf(
				table,
				"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				"-",
				unmanaged.Name,
				machineTypeShort(unmanaged.Type),
				"-",
				"-",
				displayValue(unmanaged.PrivateIP),
				formatListCreatedAt(unmanaged.CreatedAt),
				"-",
				"unmanaged:"+state,
			)
		}
		_ = table.Flush()
	}
	if opts.ShowNetworks {
		formatNetworksSection(&builder, result.Networks)
	}
	if opts.ShowStoragePools {
		formatStoragePoolsSection(&builder, result.StoragePools)
	}
	if opts.ShowStorageVolumes {
		formatStorageVolumesSection(&builder, result.StorageVolumes)
	}
	if opts.ShowProfiles {
		formatProfilesSection(&builder, result.Profiles)
	}
	if opts.ShowImages {
		formatImagesSection(&builder, result.Images)
	}
	return strings.TrimRight(builder.String(), "\n")
}

// machineTunnelCell folds a Machine's connector collection like its FQDN
// public-name cell: the first stable name plus a count for further tunnels.
// The scalar fallback keeps cache responses from older Auth Apps readable.
func machineTunnelCell(machine meta.Machine) string {
	names := machine.MachineTunnelHostnames
	if len(names) == 0 && strings.TrimSpace(machine.MachineTunnelHostname) != "" {
		names = []string{machine.MachineTunnelHostname}
	}
	if len(names) == 0 {
		return "-"
	}
	pending := map[string]bool{}
	for _, name := range machine.MachineTunnelPendingHostnames {
		pending[name] = true
	}
	if len(names) == 1 {
		if pending[names[0]] {
			return names[0] + " (pending)"
		}
		return names[0]
	}
	state := ""
	if pending[names[0]] {
		state = " pending"
	}
	return fmt.Sprintf("%s (+%d%s)", names[0], len(names)-1, state)
}

// The resource-type sections below are appended only when their flag was
// passed AND the cache-backed path actually returned data for it — the live
// per-project path never populates these fields (see listPayload), so on
// fallback the flags are silently no-ops, matching the "instances only on
// fallback, no user-visible error" behavior the plan calls for.

func formatNetworksSection(builder *strings.Builder, networks []api.Network) {
	if len(networks) == 0 {
		return
	}
	fmt.Fprintln(builder, "\nNETWORKS")
	table := tabwriter.NewWriter(builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PROJECT\tNETWORK\tTYPE\tMANAGED")
	for _, n := range networks {
		fmt.Fprintf(table, "%s\t%s\t%s\t%v\n", n.Project, n.Name, n.Type, n.Managed)
	}
	_ = table.Flush()
}

func formatStoragePoolsSection(builder *strings.Builder, pools []api.StoragePool) {
	if len(pools) == 0 {
		return
	}
	fmt.Fprintln(builder, "\nSTORAGE POOLS")
	table := tabwriter.NewWriter(builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "STORAGE POOL\tDRIVER\tSTATUS")
	for _, p := range pools {
		fmt.Fprintf(table, "%s\t%s\t%s\n", p.Name, p.Driver, displayValue(p.Status))
	}
	_ = table.Flush()
}

func formatStorageVolumesSection(builder *strings.Builder, volumes []api.StorageVolumeFull) {
	if len(volumes) == 0 {
		return
	}
	fmt.Fprintln(builder, "\nSTORAGE VOLUMES")
	table := tabwriter.NewWriter(builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PROJECT\tVOLUME\tTYPE\tCONTENT")
	for _, v := range volumes {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", v.Project, v.Name, v.Type, displayValue(v.ContentType))
	}
	_ = table.Flush()
}

func formatProfilesSection(builder *strings.Builder, profiles []api.Profile) {
	if len(profiles) == 0 {
		return
	}
	fmt.Fprintln(builder, "\nPROFILES")
	table := tabwriter.NewWriter(builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PROJECT\tPROFILE\tUSED BY")
	for _, p := range profiles {
		fmt.Fprintf(table, "%s\t%s\t%d\n", p.Project, p.Name, len(p.UsedBy))
	}
	_ = table.Flush()
}

func formatImagesSection(builder *strings.Builder, images []api.Image) {
	if len(images) == 0 {
		return
	}
	fmt.Fprintln(builder, "\nIMAGES")
	table := tabwriter.NewWriter(builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PROJECT\tFINGERPRINT\tALIAS\tARCH\tTYPE")
	for _, img := range images {
		fingerprint := img.Fingerprint
		if len(fingerprint) > 12 {
			fingerprint = fingerprint[:12]
		}
		alias := "-"
		if len(img.Aliases) > 0 {
			names := make([]string, 0, len(img.Aliases))
			for _, a := range img.Aliases {
				names = append(names, a.Name)
			}
			alias = strings.Join(names, ", ")
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", img.Project, fingerprint, alias, displayValue(img.Architecture), displayValue(img.Type))
	}
	_ = table.Flush()
}

func displayValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

// machineTypeShort renders an Incus instance type as the compact table label:
// CT for containers, VM for virtual machines.
// machineTypeCell renders the listing's TYPE column. A bare machine is marked
// there rather than in a column of its own: it is a property of what the
// machine IS, and the mark is what tells a reader why `sc connect` opens an
// Incus exec session on that row and an SSH session on the others.
func machineTypeCell(m meta.Machine) string {
	if m.Bare {
		return machineTypeShort(m.Type) + " (bare)"
	}
	return machineTypeShort(m.Type)
}

func machineTypeShort(instanceType string) string {
	switch instanceType {
	case "virtual-machine":
		return "VM"
	case meta.MachineTypeContainer, "":
		return "CT"
	default:
		return instanceType
	}
}

// machineCertCell is the `sc ls` CERT column (ADR-0027 spec §1.5, folded
// per ADR-0028): a machine without a public name has no Machine
// Certificate, so "-"; otherwise the WORST of the machine's per-hostname
// states (meta.Machine.CertState) collapses to pending / ok / failed. A
// machine the reconciler has not stamped yet is pending — `sc create`
// returns before any certificate exists. An unrecognised state is shown
// verbatim rather than guessed at.
func machineCertCell(machine meta.Machine) (cell string) {
	defer func() {
		if machine.ProjectCertState != "" {
			cell += " (project " + machine.ProjectCertState
			if machine.ProjectCertNotAfter != "" {
				cell += "; expires " + machine.ProjectCertNotAfter
			}
			cell += ")"
		}
	}()
	if !machine.HasPublicHostname() {
		return "-"
	}
	state := strings.TrimSpace(machine.CertState)
	switch {
	case state == "", state == meta.CertStatePending, state == meta.CertStateIssued:
		return "pending"
	case state == meta.CertStateInstalled, state == meta.CertStateRenewing:
		return "ok"
	case strings.HasPrefix(state, meta.CertStateFailedPrefix):
		return "failed"
	default:
		return state
	}
}

// machineFQDN is the `sc ls` FQDN column: the first Machine Public Hostname
// — with "(+N)" when the machine has more (ADR-0028; `--json` carries the
// whole list) — else the canonical Machine Private Hostname.
func machineFQDN(tenant tenant.Summary, machine meta.Machine) string {
	if names := machine.PublicNames(); len(names) > 0 {
		if extra := len(names) - 1; extra > 0 {
			return fmt.Sprintf("%s (+%d)", names[0], extra)
		}
		return names[0]
	}
	suffix := strings.Trim(strings.TrimSpace(tenant.DNSSuffix), ".")
	if suffix == "" {
		suffix = strings.Trim(strings.TrimSpace(tenant.Tenant), ".")
	}
	if machine.Name == "" || machine.Project == "" || suffix == "" {
		return "-"
	}
	// The canonical Machine Private Hostname is <machine>.<project>.<suffix>
	// for every project (ADR-0018); the default project also answers at the
	// short alias, but the list teaches the canonical form.
	return machine.Name + "." + machine.Project + "." + suffix
}

func formatListCreatedAt(createdAt string) string {
	createdAt = strings.TrimSpace(createdAt)
	if createdAt == "" {
		return "-"
	}
	parsed, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return createdAt
	}
	return parsed.Local().Format("2006-01-02 15:04:05")
}

func formatTenantResources(result tenantResourcesPayload) string {
	var b strings.Builder
	t := result.Tenant
	fmt.Fprintf(&b, "tenant:   %s\n", t.Tenant)
	fmt.Fprintf(&b, "cidr:     %s\n", displayValue(t.PrivateCIDR))
	fmt.Fprintf(&b, "dns:      %s\n", displayValue(t.DNSSuffix))
	if len(t.Projects) > 0 {
		names := make([]string, 0, len(t.Projects))
		for _, p := range t.Projects {
			names = append(names, p.Name)
		}
		fmt.Fprintf(&b, "projects: %s\n", strings.Join(names, ", "))
	}
	if len(t.PublicRoutes) > 0 {
		routes := make([]string, 0, len(t.PublicRoutes))
		for _, r := range t.PublicRoutes {
			routes = append(routes, r.Hostname)
		}
		fmt.Fprintf(&b, "routes:   %s\n", strings.Join(routes, ", "))
	}
	if t.Tailscale.State != "" {
		fmt.Fprintf(&b, "tailscale: %s\n", t.Tailscale.State)
	}
	if len(result.Machines) == 0 && len(result.Unmanaged) == 0 {
		fmt.Fprintf(&b, "\nNo machines found.")
		return b.String()
	}
	fmt.Fprintln(&b)
	table := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PROJECT\tMACHINE\tTYPE\tFQDN\tCERT\tIP\tCREATED\tRENDERED\tSTATE")
	for _, m := range result.Machines {
		state := "stopped"
		if m.Running {
			state = "running"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			m.Project, m.Name, machineTypeCell(m), machineFQDN(t, m), machineCertCell(m), m.PrivateIP, formatListCreatedAt(m.CreatedAt), displayValue(m.RenderedVersion), state)
	}
	for _, u := range result.Unmanaged {
		state := u.Status
		if state == "" {
			if u.Running {
				state = "running"
			} else {
				state = "stopped"
			}
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			"-", u.Name, machineTypeShort(u.Type), "-", "-", displayValue(u.PrivateIP), formatListCreatedAt(u.CreatedAt), "-", "unmanaged:"+state)
	}
	_ = table.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// Resolve shared state at read time; instance keys deliberately contain no
// expiry, so renewal does not require rewriting every machine's metadata.
func enrichProjectCertificates(ctx context.Context, config commandConfig, result *listPayload) {
	if !projectAuthAppAvailable(config, "") {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, machineCertificateRequestTimeout)
	defer cancel()
	for _, project := range result.Tenant.Projects {
		if project.Domain == "" {
			continue
		}
		cert, err := projectAuthClient(config).GetProjectDomain(ctx, project.Name)
		if err != nil || cert.CertState == "" {
			continue
		}
		for i := range result.Machines {
			m := &result.Machines[i]
			if m.Project != project.Name {
				continue
			}
			if m.CertStates == nil {
				m.CertStates = map[string]string{}
			}
			covered := false
			for _, name := range m.PublicNames() {
				if domain.CoveredByProjectCertificate(name, project.Domain) {
					m.CertStates[name] = cert.CertState
					covered = true
				}
			}
			if covered {
				m.ProjectCertState, m.ProjectCertNotAfter = cert.CertState, cert.CertNotAfter
				m.CertState = meta.WorstCertState(m.CertStates, m.PublicNames())
				if cert.CertNotAfter != "" && (m.CertNotAfter == "" || cert.CertNotAfter < m.CertNotAfter) {
					m.CertNotAfter = cert.CertNotAfter
				}
			}
		}
	}
}
