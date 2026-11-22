package cli

import (
	"strings"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/usertrust"
)

// installRemoteName keeps each Incus remote name bound to one install. Tenant
// names repeat across installs (obelix and miraculix both have moyn-dev), and
// reusing a remote recorded for another install would re-point it, silently
// moving that install's tenant on this client to the new one.
func installRemoteName(cfg scconfig.SandcastleConfig, name string, authHost string) string {
	name = strings.TrimSpace(name)
	host := normalizeAuthHostname(authHost)
	if name == "" || host == "" || remoteFreeForInstall(cfg, name, host) {
		return name
	}
	full := usertrust.InstallLabelFromAuthHostname(host)
	for _, label := range []string{firstHostLabel(host), full} {
		if label == "" {
			continue
		}
		if candidate := name + "-" + label; remoteFreeForInstall(cfg, candidate, host) {
			return candidate
		}
	}
	return name + "-" + full
}

func remoteFreeForInstall(cfg scconfig.SandcastleConfig, name string, host string) bool {
	recorded := normalizeAuthHostname(cfg.AuthHostnameForRemote(name))
	return recorded == "" || recorded == host
}

func firstHostLabel(host string) string {
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if idx := strings.IndexByte(host, '.'); idx > 0 {
		host = host[:idx]
	}
	return usertrust.InstallLabelFromAuthHostname(host)
}
