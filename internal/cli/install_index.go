package cli

import (
	"fmt"
	"sort"
	"strings"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

// installIndex is the client's map from Sandcastle Paths to Incus remotes
// (ADR-0032): each install the client knows, by Install Name, with the remote
// enrolled for each of its tenants. It is built from the user config alone,
// so one read answers every path lookup of a command.
type installIndex struct {
	// installs is sorted by Name.
	installs []installRecord
	// remotes maps an enrolled remote to the install and tenant it serves.
	remotes map[string]remotePlace
}

// installRecord is one install: a distinct Auth Hostname.
type installRecord struct {
	Name string
	// AuthHost is empty for a remote enrolled before logins recorded their
	// install; such a remote stands in as an install of its own name.
	AuthHost string
	// Remotes maps a tenant to the remote enrolled for it on this install.
	Remotes map[string]string
}

// remotePlace is where a remote sits in the tree. Tenant is empty when the
// enrollment predates remote_tenants.
type remotePlace struct {
	Install string
	Tenant  string
}

func loadInstallIndex() installIndex {
	cfg, _ := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	return buildInstallIndex(cfg)
}

// buildInstallIndex derives the installs from the Auth Hostnames recorded in
// installs and auth_tokens. Hostnames are compared by their full Install
// Label, so "https://x.dev" and "x.dev/" are one install.
func buildInstallIndex(cfg scconfig.SandcastleConfig) installIndex {
	hosts := map[string]string{} // full label → Auth Hostname
	addHost := func(raw string) string {
		host := normalizeAuthHostname(raw)
		key := usertrust.InstallLabelFromAuthHostname(host)
		if current, ok := hosts[key]; key != "" && (!ok || host < current) {
			hosts[key] = host
		}
		return key
	}
	remoteKeys := map[string]string{}
	for remote, host := range cfg.Installs {
		if key := addHost(host); key != "" {
			remoteKeys[strings.TrimSpace(remote)] = key
		}
	}
	for host := range cfg.AuthTokens {
		if key := usertrust.InstallLabelFromAuthHostname(host); hosts[key] == "" {
			addHost(host)
		}
	}

	firstLabels := map[string]int{}
	for _, host := range hosts {
		firstLabels[firstHostLabel(host)]++
	}
	names := map[string]string{} // full label → Install Name
	byName := map[string]*installRecord{}
	ix := installIndex{remotes: map[string]remotePlace{}}
	for key, host := range hosts {
		name := firstHostLabel(host)
		if name == "" || firstLabels[name] > 1 {
			name = key
		}
		names[key] = name
		byName[name] = &installRecord{Name: name, AuthHost: host, Remotes: map[string]string{}}
	}
	for remote, key := range remoteKeys {
		name := names[key]
		tenantName := cfg.TenantForRemote(remote)
		ix.remotes[remote] = remotePlace{Install: name, Tenant: tenantName}
		if tenantName == "" {
			continue
		}
		// Two remotes recorded for one pair: keep the smaller name, so the
		// choice does not depend on map order.
		if existing := byName[name].Remotes[tenantName]; existing == "" || remote < existing {
			byName[name].Remotes[tenantName] = remote
		}
	}
	for remote, tenantName := range cfg.RemoteTenants {
		remote, tenantName = strings.TrimSpace(remote), strings.TrimSpace(tenantName)
		if _, ok := ix.remotes[remote]; ok || remote == "" || tenantName == "" || byName[remote] != nil {
			continue
		}
		byName[remote] = &installRecord{Name: remote, Remotes: map[string]string{tenantName: remote}}
		ix.remotes[remote] = remotePlace{Install: remote, Tenant: tenantName}
	}
	for _, record := range byName {
		ix.installs = append(ix.installs, *record)
	}
	sort.Slice(ix.installs, func(i, j int) bool { return ix.installs[i].Name < ix.installs[j].Name })
	return ix
}

func (ix installIndex) install(name string) (installRecord, bool) {
	for _, record := range ix.installs {
		if record.Name == name {
			return record, true
		}
	}
	return installRecord{}, false
}

func (ix installIndex) names() []string {
	names := make([]string, 0, len(ix.installs))
	for _, record := range ix.installs {
		names = append(names, record.Name)
	}
	return names
}

// installNameOf is the first path segment for a remote: its install, or the
// remote itself when the client recorded none.
func (ix installIndex) installNameOf(remote string) string {
	remote = strings.TrimSpace(remote)
	if place, ok := ix.remotes[remote]; ok && place.Install != "" {
		return place.Install
	}
	return remote
}

// remoteFor is the remote enrolled for a tenant of an install, or "".
func (ix installIndex) remoteFor(install, tenantName string) string {
	record, ok := ix.install(install)
	if !ok {
		return ""
	}
	return record.Remotes[tenantName]
}

// sortedRemotes lists an install's remotes, the one named like the install
// first: that is the personal login whenever the tenant's DNS suffix is the
// install's own label.
func (r installRecord) sortedRemotes() []string {
	remotes := make([]string, 0, len(r.Remotes))
	for _, remote := range r.Remotes {
		remotes = append(remotes, remote)
	}
	sort.Slice(remotes, func(i, j int) bool {
		if (remotes[i] == r.Name) != (remotes[j] == r.Name) {
			return remotes[i] == r.Name
		}
		return remotes[i] < remotes[j]
	})
	return remotes
}

// sortedTenants lists the tenants enrolled on an install.
func (r installRecord) sortedTenants() []string {
	tenants := make([]string, 0, len(r.Remotes))
	for tenantName := range r.Remotes {
		tenants = append(tenants, tenantName)
	}
	sort.Strings(tenants)
	return tenants
}

// anchorRemote is a remote that speaks for an install as a whole, for its
// Auth App and for an install-level position: the current remote when it
// belongs to the install, else the install's first remote.
func (ix installIndex) anchorRemote(config commandConfig, install string) string {
	current := strings.TrimSpace(config.adminConfig.Remote)
	if current != "" && ix.installNameOf(current) == install {
		return current
	}
	if record, ok := ix.install(install); ok {
		if remotes := record.sortedRemotes(); len(remotes) > 0 {
			return remotes[0]
		}
	}
	for remote, place := range ix.remotes {
		if place.Install == install {
			return remote
		}
	}
	return ""
}

// errTenantNotEnrolled marks a known install whose tenant has no remote on
// this client yet; `sc cd` enrols one, other commands report it.
type errTenantNotEnrolled struct{ install, tenant string }

func (e errTenantNotEnrolled) Error() string {
	return fmt.Sprintf("tenant %s on install %s is not enrolled on this client: `sc cd /%s/%s` enrols it", e.tenant, e.install, e.install, e.tenant)
}

// positionRemote resolves (install, tenant) to the remote that serves it.
// The directory's own pairing comes second: an owner who switched to another
// tenant of the install keeps the install's remote (no member enrollment).
// A first segment that is no install but an enrolled remote is that remote,
// the reading for clients whose logins recorded no install.
func (ix installIndex) positionRemote(config commandConfig, install, tenantName string) (string, error) {
	if remote := ix.remoteFor(install, tenantName); remote != "" {
		return remote, nil
	}
	current := strings.TrimSpace(config.adminConfig.Remote)
	if current != "" && ix.installNameOf(current) == install && strings.TrimSpace(config.adminConfig.Tenant) == tenantName {
		return current, nil
	}
	if _, ok := ix.install(install); ok {
		return "", errTenantNotEnrolled{install: install, tenant: tenantName}
	}
	if place, ok := ix.remotes[install]; ok && place.Install == install {
		return install, nil
	}
	remotes, err := enrolledRemoteNames()
	if err == nil && containsString(remotes, install) {
		return install, nil
	}
	hint := "run `sc login <auth-hostname>` to enroll"
	if names := ix.names(); len(names) > 0 {
		hint = "installs: " + strings.Join(names, ", ")
	}
	return "", fmt.Errorf("no install %q; %s", install, hint)
}

// matchingRemotes lists the remotes a pair of install and tenant patterns
// reaches, sorted.
func (ix installIndex) matchingRemotes(installPattern, tenantPattern string) []string {
	remotes := []string{}
	for _, record := range ix.installs {
		if !naming.MatchName(installPattern, record.Name) {
			continue
		}
		for tenantName, remote := range record.Remotes {
			if naming.MatchName(tenantPattern, tenantName) {
				remotes = append(remotes, remote)
			}
		}
	}
	sort.Strings(remotes)
	return remotes
}
