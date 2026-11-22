package cli

import (
	"fmt"
	"os"
	"strings"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
	"github.com/moyn-dev/sandcastle-incus/internal/usertrust"
)

// resolveConnectTarget decides whether a parsed machine reference targets a
// DIFFERENT install than the current one and, if so, which incus remote to
// switch to. dnsSuffix comes from the reference; currentSuffix is the current
// install's Tenant DNS Suffix; remoteExists reports whether a named incus remote
// is enrolled locally. Returns "" for a same-install reference (no switch).
//
// ADR-0021: one remote per install, named by the DNS suffix; the reference's
// project is applied per-call after the switch (switchConfigToRemote), so there
// is no per-project remote to enroll — the only failure is "not logged into that
// install".
func resolveConnectTarget(dnsSuffix, currentSuffix string, remoteExists func(string) bool) (switchTo string, err error) {
	dnsSuffix = strings.TrimSpace(dnsSuffix)
	if dnsSuffix == "" || dnsSuffix == strings.TrimSpace(currentSuffix) {
		return "", nil // same install — nothing to switch
	}
	target := usertrust.RemoteNameForSuffix(dnsSuffix)
	if target == "" {
		return "", fmt.Errorf("cannot form a remote name for install %q", dnsSuffix)
	}
	if remoteExists(target) {
		return target, nil
	}
	return "", fmt.Errorf(
		"unknown install %q — you're not logged in there; log in first:\n  sc login <%s auth-host>",
		dnsSuffix, dnsSuffix)
}

// localRemoteExists reports whether an incus remote of that name is enrolled in
// any of the client's config dirs (shared or per-remote).
func localRemoteExists(name string) bool {
	return scconfig.ResolveConfigPath(name) != ""
}

// switchConfigToRemote returns a copy of cfg rebound to targetRemote: it points
// INCUS_CONF at that remote's config dir (its restricted cert), rebuilds the two
// remote-scoped stores connect uses (the tenant summary source and the
// machine-ensure client), and — crucially — re-points adminConfig.Tenant to the
// TARGET install's tenant. The summary lookup keys off the tenant name, so
// without this it would still resolve the *current* tenant on the new remote.
// project is the reference's project, used to strip the pinned incus project
// (`<prefix>-<tenant>-<project>`) back to its tenant. All other (local)
// capabilities carry over unchanged.
func switchConfigToRemote(cfg commandConfig, targetRemote, project string) commandConfig {
	dir := scconfig.ResolveConfigPath(targetRemote)
	if dir != "" {
		os.Setenv("INCUS_CONF", dir)
	}
	switched := cfg
	switched.adminConfig.Remote = targetRemote
	switched.adminConfig.Project = "" // the reference carries the project
	switched.tenantStore = incusx.NewTenantStoreForSharedRemote(incusx.NewSharedRemote(targetRemote))
	switched.tenantCreator = incusx.NewTenantCreator(targetRemote)
	if remotes, err := readLocalRemotes(dir); err == nil {
		for _, r := range remotes {
			if r.Name == targetRemote {
				if tenant := tenantFromPinnedProject(r.Project, project); tenant != "" {
					switched.adminConfig.Tenant = tenant
				}
				break
			}
		}
	}
	return switched
}

// tenantFromPinnedProject recovers the tenant from a remote's pinned incus
// project `<prefix>-<tenant>-<project>` given the known project. The trailing
// `-<project>` is stripped (handles dashed projects), then the single-token
// prefix (e.g. "sc2") before the first dash — leaving the tenant (which may
// itself contain dashes). Returns "" if the shape doesn't match.
func tenantFromPinnedProject(pinnedProject, project string) string {
	rest := strings.TrimSuffix(strings.TrimSpace(pinnedProject), "-"+strings.TrimSpace(project))
	if rest == pinnedProject || rest == "" {
		return "" // project suffix didn't match
	}
	if i := strings.Index(rest, "-"); i >= 0 {
		return rest[i+1:]
	}
	return ""
}
