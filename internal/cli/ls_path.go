package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// The tree behind `sc ls <path>`: every level's children, one data source per
// level, so a path listing is a walk over them. Root lists enrolled remotes
// (local incus config), a remote its accessible tenants (Auth App), a tenant
// its projects (Auth App resource cache, live Incus fallback) and a project
// its machines (`sc ls`'s own cache-first listing).

// pathEntry is one child of a directory in the tree.
type pathEntry struct {
	Name string `json:"name"`
	// Kind is the child's level: remote, tenant, project or machine.
	Kind string `json:"kind"`
	// Fields carries the long-format columns for the entry, in column order.
	Fields []string `json:"fields,omitempty"`
}

// pathListing is one directory's listing.
type pathListing struct {
	Path    string      `json:"path"`
	Level   string      `json:"level"`
	Entries []pathEntry `json:"entries"`
	// Machine is set when the path named a machine (a leaf) rather than a
	// directory; Entries is then that one machine.
	Machine bool `json:"machine,omitempty"`
}

// pathListPayload is what `sc ls <path…>` returns: one listing per matched
// directory (or leaf), plus the directories that could not be read.
type pathListPayload struct {
	Listings []pathListing `json:"listings"`
	Warnings []string      `json:"warnings,omitempty"`
}

// pathListOptions are `sc ls`'s path-mode flags.
type pathListOptions struct {
	Long      bool
	Directory bool
	Recursive bool
}

// longColumns are the long-format headers per directory level.
func longColumns(depth int) []string {
	switch depth {
	case levelRoot:
		return []string{"REMOTE", "TENANT", "PROJECT", "AUTH"}
	case levelRemote:
		return []string{"TENANT", "ROLE", "PERSONAL"}
	case levelTenant:
		return []string{"PROJECT", "DOMAIN", "IMAGE"}
	default:
		return []string{"MACHINE", "TYPE", "STATE", "IP", "CREATED", "RENDERED"}
	}
}

// configForPosition returns a command config bound to the remote and tenant
// a path names. The current remote costs nothing; another enrolled remote is
// bound like the "<remote>:" prefix binds it, carrying that install's own
// login (the bare binding only carries its certificate). A tenant other than
// the remote's is set as the Current Tenant of the returned config. The
// returned func unbinds and MUST be called.
func configForPosition(config commandConfig, remote string, tenant string) (commandConfig, func(), error) {
	noop := func() {}
	current := strings.TrimSpace(config.adminConfig.Remote)
	if remote == "" || remote == current {
		if tenant == "" || tenant == strings.TrimSpace(config.adminConfig.Tenant) {
			return config, noop, nil
		}
		scoped := config
		scoped.adminConfig.Tenant = tenant
		return newUserCommandConfig(scoped.name, scoped.stdin, scoped.stdout, scoped.stderr, scoped.adminConfig), noop, nil
	}
	dir := scconfig.ResolveConfigPath(remote)
	if dir == "" {
		return config, noop, fmt.Errorf("no enrolled Sandcastle remote %q; run `sc remote list` to see installs", remote)
	}
	prev, had := os.LookupEnv("INCUS_CONF")
	os.Setenv("INCUS_CONF", dir)
	restore := func() {
		if had {
			os.Setenv("INCUS_CONF", prev)
		} else {
			os.Unsetenv("INCUS_CONF")
		}
	}
	admin := adminForRemote(config.adminConfig, remote)
	if tenant != "" {
		admin.Tenant = tenant
		admin.Project = shortProjectName(scconfig.SharedIncusRemoteProject(remote), tenant)
	}
	return newUserCommandConfig(config.name, config.stdin, config.stdout, config.stderr, admin), restore, nil
}

// childrenOf lists the children of a directory in the tree.
func childrenOf(ctx context.Context, config commandConfig, segments []string) ([]pathEntry, error) {
	switch len(segments) {
	case levelRoot:
		return remoteEntries()
	case levelRemote:
		return tenantEntries(ctx, config, segments[0])
	case levelTenant:
		return projectEntries(ctx, config, segments[0], segments[1])
	case levelProject:
		return machineEntries(ctx, config, segments[0], segments[1], segments[2])
	default:
		return nil, fmt.Errorf("%s is a machine, not a directory", formatPath(segments))
	}
}

func remoteEntries() ([]pathEntry, error) {
	incusDir, _ := scconfig.SharedIncusDirExplained()
	remotes, err := readLocalRemotes(incusDir)
	if err != nil {
		return nil, fmt.Errorf("read incus remotes from %s: %w", incusDir, err)
	}
	cfg, _ := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	entries := []pathEntry{}
	for _, row := range sandcastleRemoteRows(remotes, cfg) {
		tenant := cfg.TenantForRemote(row.Name)
		entries = append(entries, pathEntry{Name: row.Name, Kind: "remote", Fields: []string{row.Name, tenant, shortProjectName(row.Project, tenant), row.AuthHostname}})
	}
	return entries, nil
}

// tenantEntries lists the tenant a remote is enrolled for (ADR-0021: one
// remote per install and tenant). Two remotes may be enrollments of the
// same install for different tenants — the personal login and a Shared
// Tenant switch — and that install's Auth App lists every tenant the user
// can access, so listing "accessible tenants" showed every machine twice.
// The same tenant name on two installs stays two entries, under its two
// remotes. The Auth App is still asked, for the role and personal columns;
// when it does not answer the entry is the name alone, never an error, so
// a down install does not hide its path.
func tenantEntries(ctx context.Context, config commandConfig, remote string) ([]pathEntry, error) {
	served := tenantOfRemote(config, remote)
	bound, restore, err := configForPosition(config, remote, "")
	if err != nil {
		return nil, err
	}
	defer restore()
	entries := []pathEntry{}
	if client, err := tenantClient(bound); err == nil {
		if tenants, err := client.ListTenants(ctx); err == nil {
			for _, row := range tenantListRows(tenants, strings.TrimSpace(bound.adminConfig.Tenant)) {
				if served == "" || row.Tenant == served {
					entries = append(entries, pathEntry{Name: row.Tenant, Kind: "tenant", Fields: []string{row.Tenant, row.Role, yesNo(row.Personal)}})
				}
			}
		} else if served == "" {
			return nil, err
		}
	} else if served == "" {
		return nil, err
	}
	if len(entries) == 0 && served != "" {
		entries = append(entries, pathEntry{Name: served, Kind: "tenant", Fields: []string{served, "-", "-"}})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func projectEntries(ctx context.Context, config commandConfig, remote string, tenantName string) ([]pathEntry, error) {
	bound, restore, err := configForPosition(config, remote, tenantName)
	if err != nil {
		return nil, err
	}
	defer restore()
	summary, err := currentTenantSummary(ctx, bound)
	if err != nil {
		return nil, err
	}
	entries := []pathEntry{}
	for _, project := range summary.Projects {
		entries = append(entries, pathEntry{Name: project.Name, Kind: "project", Fields: []string{project.Name, project.Domain, project.Image}})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func machineEntries(ctx context.Context, config commandConfig, remote string, tenantName string, project string) ([]pathEntry, error) {
	cache := treeCacheFrom(ctx)
	key := remote + "/" + tenantName
	if cache != nil {
		if byProject, ok := cache.machines[key]; ok {
			return machineEntriesOf(byProject[project]), nil
		}
	}
	bound, restore, err := configForPosition(config, remote, tenantName)
	if err != nil {
		return nil, err
	}
	defer restore()
	if cache != nil && cache.batch[key] {
		// A glob is about to visit several projects of this tenant: one
		// tenant-wide request, served per project from memory, instead of
		// one round trip per project (22 projects took 3.7 s that way).
		request := listMachinesRequest{AllProjects: true}
		result, ok := listMachinesViaCache(ctx, bound, request, listRenderOptions{})
		if !ok {
			if result, err = listMachines(ctx, bound, request); err != nil {
				return nil, err
			}
		}
		byProject := map[string][]meta.Machine{}
		for _, m := range result.Machines {
			byProject[m.Project] = append(byProject[m.Project], m)
		}
		cache.machines[key] = byProject
		return machineEntriesOf(byProject[project]), nil
	}
	request := listMachinesRequest{Project: project}
	result, ok := listMachinesViaCache(ctx, bound, request, listRenderOptions{})
	if !ok {
		if result, err = listMachines(ctx, bound, request); err != nil {
			return nil, err
		}
	}
	return machineEntriesOf(result.Machines), nil
}

func machineEntriesOf(machines []meta.Machine) []pathEntry {
	entries := []pathEntry{}
	for _, m := range machines {
		state := "stopped"
		if m.Running {
			state = "running"
		}
		entries = append(entries, pathEntry{Name: m.Name, Kind: "machine", Fields: []string{m.Name, m.Type, state, m.PrivateIP, formatListCreatedAt(m.CreatedAt), displayValue(m.RenderedVersion)}})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries
}

// treeCache is one path listing's memory: machines already fetched per
// tenant (remote/tenant → project → machines), and the tenants a glob is
// about to sweep, whose first project visit fetches the whole tenant. It
// rides the context so childrenOf keeps its signature for completion.
type treeCache struct {
	machines map[string]map[string][]meta.Machine
	batch    map[string]bool
}

type treeCacheKey struct{}

func withTreeCache(ctx context.Context) (context.Context, *treeCache) {
	cache := &treeCache{machines: map[string]map[string][]meta.Machine{}, batch: map[string]bool{}}
	return context.WithValue(ctx, treeCacheKey{}, cache), cache
}

func treeCacheFrom(ctx context.Context) *treeCache {
	cache, _ := ctx.Value(treeCacheKey{}).(*treeCache)
	return cache
}

// markBatch notes that the projects of a tenant-level match will be swept.
func (c *treeCache) markBatch(segments []string) {
	if c != nil && len(segments) == levelTenant {
		c.batch[segments[0]+"/"+segments[1]] = true
	}
}

// pathMatch is one path a (possibly globbing) argument expanded to.
type pathMatch struct {
	Segments []string
	// Entry is set for a machine (leaf) match, carrying its long fields.
	Entry *pathEntry
	// Loose marks a match a "**" produced: its depth is not the pattern's,
	// so a literal segment after it is checked against the children rather
	// than appended on trust.
	Loose bool
}

// expandPath expands globs in a path against the tree, one pattern segment
// at a time over the current set of matches. A literal directory segment is
// taken as is (listing it later reports whether it exists); a literal
// machine is checked against its project, since a leaf has no listing of its
// own to fail. "**" matches zero or more levels: each match stays and every
// descendant joins, as deep as the remaining segments leave room for. A
// subtree that cannot be read under "**" becomes a warning rather than
// failing the whole expansion.
func expandPath(ctx context.Context, config commandConfig, segments []string, warnings *[]string) ([]pathMatch, error) {
	matches := []pathMatch{{Segments: []string{}}}
	for index, segment := range segments {
		last := index == len(segments)-1
		remaining := fixedSegments(segments[index+1:])
		next := []pathMatch{}
		for _, match := range matches {
			if match.Entry != nil {
				continue // a machine has no children
			}
			if segment == globstar {
				loose := match
				loose.Loose = true
				next = append(next, loose)
				next = append(next, descendants(ctx, config, match.Segments, levelMachine-remaining, warnings)...)
				continue
			}
			if naming.IsPattern(segment) {
				treeCacheFrom(ctx).markBatch(match.Segments)
			}
			leaf := len(match.Segments) == levelProject
			if !naming.IsPattern(segment) && !leaf && !match.Loose {
				next = append(next, pathMatch{Segments: appendSegment(match.Segments, segment)})
				continue
			}
			children, err := childrenOf(ctx, config, match.Segments)
			if err != nil {
				if match.Loose {
					if warnings != nil {
						*warnings = append(*warnings, fmt.Sprintf("%s: %v", formatPath(match.Segments), err))
					}
					continue
				}
				return nil, err
			}
			for _, child := range children {
				if !naming.MatchName(segment, child.Name) {
					continue
				}
				expanded := pathMatch{Segments: appendSegment(match.Segments, child.Name), Loose: match.Loose}
				if leaf {
					entry := child
					expanded.Entry = &entry
				}
				next = append(next, expanded)
			}
		}
		if len(next) == 0 {
			if last && !naming.IsPattern(segment) {
				return nil, fmt.Errorf("no such %s: %s", levelName(len(segments)), formatPath(segments))
			}
			return nil, fmt.Errorf("nothing matches %q in %s", segment, formatPath(segments[:index]))
		}
		matches = dedupeMatches(next)
	}
	return matches, nil
}

// descendants walks a directory down to maxDepth, returning every path
// below it (machines as leaves with their entry).
func descendants(ctx context.Context, config commandConfig, segments []string, maxDepth int, warnings *[]string) []pathMatch {
	if len(segments) >= maxDepth {
		return nil
	}
	if maxDepth > levelProject {
		treeCacheFrom(ctx).markBatch(segments)
	}
	children, err := childrenOf(ctx, config, segments)
	if err != nil {
		if warnings != nil {
			*warnings = append(*warnings, fmt.Sprintf("%s: %v", formatPath(segments), err))
		}
		return nil
	}
	out := []pathMatch{}
	for _, child := range children {
		childSegments := appendSegment(segments, child.Name)
		match := pathMatch{Segments: childSegments, Loose: true}
		if len(childSegments) == levelMachine {
			entry := child
			match.Entry = &entry
		}
		out = append(out, match)
		if len(childSegments) < levelMachine {
			out = append(out, descendants(ctx, config, childSegments, maxDepth, warnings)...)
		}
	}
	return out
}

func appendSegment(segments []string, segment string) []string {
	return append(append(make([]string, 0, len(segments)+1), segments...), segment)
}

// dedupeMatches drops paths a "**" produced twice (as itself and as a
// descendant of a shallower match), keeping first-seen order.
func dedupeMatches(matches []pathMatch) []pathMatch {
	seen := map[string]bool{}
	out := make([]pathMatch, 0, len(matches))
	for _, match := range matches {
		key := formatPath(match.Segments)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, match)
	}
	return out
}

// listPaths is `sc ls` in path mode: each argument is expanded, every match
// is listed (a directory's children, or the leaf itself), and directories
// recurse with -R.
func listPaths(ctx context.Context, config commandConfig, args []string, options pathListOptions) (pathListPayload, error) {
	ctx, _ = withTreeCache(ctx)
	payload := pathListPayload{Listings: []pathListing{}}
	if len(args) == 0 {
		args = []string{"."}
	}
	for _, arg := range args {
		segments, err := resolvePath(config, arg)
		if err != nil {
			return payload, err
		}
		matches, err := expandPath(ctx, config, segments, &payload.Warnings)
		if err != nil {
			return payload, err
		}
		for _, match := range matches {
			if len(match.Segments) == levelRoot {
				// "**" matched nothing: the argument's own directory.
				if err := listDirectory(ctx, config, match.Segments, options.Recursive, &payload); err != nil {
					return payload, err
				}
				continue
			}
			if match.Entry != nil {
				payload.Listings = append(payload.Listings, pathListing{Path: formatPath(match.Segments), Level: "machine", Machine: true, Entries: []pathEntry{*match.Entry}})
				continue
			}
			if options.Directory {
				payload.Listings = append(payload.Listings, pathListing{Path: formatPath(match.Segments), Level: levelName(len(match.Segments)), Entries: []pathEntry{{Name: match.Segments[len(match.Segments)-1], Kind: levelName(len(match.Segments))}}})
				continue
			}
			if err := listDirectory(ctx, config, match.Segments, options.Recursive, &payload); err != nil {
				return payload, err
			}
		}
	}
	payload.Warnings = dedupeStrings(payload.Warnings)
	return payload, nil
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// listDirectory appends one directory's listing, recursing into its child
// directories when asked. A child that cannot be read becomes a warning, so
// one unreachable install does not hide the others (as `sc ls '*:*:*'` does).
func listDirectory(ctx context.Context, config commandConfig, segments []string, recursive bool, payload *pathListPayload) error {
	if recursive {
		// -R visits every project of a tenant: fetch its machines once.
		treeCacheFrom(ctx).markBatch(segments)
	}
	children, err := childrenOf(ctx, config, segments)
	if err != nil {
		if len(segments) > levelRoot && len(payload.Listings) > 0 {
			payload.Warnings = append(payload.Warnings, fmt.Sprintf("%s: %v", formatPath(segments), err))
			return nil
		}
		return err
	}
	payload.Listings = append(payload.Listings, pathListing{Path: formatPath(segments), Level: levelName(len(segments)), Entries: children})
	if !recursive || len(segments) >= levelProject {
		return nil
	}
	for _, child := range children {
		if err := listDirectory(ctx, config, append(append([]string{}, segments...), child.Name), recursive, payload); err != nil {
			return err
		}
	}
	return nil
}

// formatPathList renders path-mode output the way ls does with files and
// directories: every matched machine (a leaf) is a file — all of them go
// first, together, one path per line, or one table with the path in the
// MACHINE column under -l; then every matched directory as its own block,
// its Sandcastle Path on the first line and its entries below, blocks
// separated by a blank line. -d prints only the matching paths.
func formatPathList(payload pathListPayload, options pathListOptions) string {
	var b strings.Builder
	for _, warning := range payload.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", warning)
	}
	if options.Directory {
		for _, listing := range payload.Listings {
			fmt.Fprintln(&b, listing.Path)
		}
		return strings.TrimRight(b.String(), "\n")
	}
	leaves := []pathEntry{}
	for _, listing := range payload.Listings {
		if !listing.Machine {
			continue
		}
		for _, entry := range listing.Entries {
			named := entry
			named.Fields = append([]string{listing.Path}, entry.Fields[1:]...)
			named.Name = listing.Path
			leaves = append(leaves, named)
		}
	}
	blockBefore := false
	if len(leaves) > 0 {
		if options.Long {
			writeEntryTable(&b, levelProject, leaves)
		} else {
			for _, leaf := range leaves {
				fmt.Fprintln(&b, leaf.Name)
			}
		}
		blockBefore = true
	}
	for _, listing := range payload.Listings {
		if listing.Machine {
			continue
		}
		if blockBefore {
			b.WriteString("\n")
		}
		blockBefore = true
		fmt.Fprintln(&b, listing.Path)
		if len(listing.Entries) == 0 {
			continue
		}
		if options.Long {
			writeEntryTable(&b, entryDepth(listing), listing.Entries)
			continue
		}
		for _, entry := range listing.Entries {
			fmt.Fprintln(&b, entry.Name)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// entryDepth is the directory depth whose columns describe the listing's
// entries: a machine listing shows machine columns, a project listing too.
func entryDepth(listing pathListing) int {
	if listing.Machine {
		return levelProject
	}
	switch listing.Level {
	case "root":
		return levelRoot
	case "remote":
		return levelRemote
	case "tenant":
		return levelTenant
	}
	return levelProject
}

func writeEntryTable(b *strings.Builder, depth int, entries []pathEntry) {
	table := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, strings.Join(longColumns(depth), "\t"))
	for _, entry := range entries {
		fields := entry.Fields
		if len(fields) == 0 {
			fields = []string{entry.Name}
		}
		fmt.Fprintln(table, strings.Join(fields, "\t"))
	}
	table.Flush()
}
