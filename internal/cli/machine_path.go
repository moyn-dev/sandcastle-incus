package cli

import "strings"

// machinePath renders a machine by its full address — tenant@remote:project:
// machine — so every message says WHERE the machine is. With directory
// selections and Shared Tenants the same bare name can exist in several
// places, and "Machine dev does not exist in project default" no longer
// tells the user which remote and tenant they are in. The tenant@ part
// reads like the shell prompt on the machine; the rest is the reference
// grammar every command accepts (and the parser tolerates the tenant@
// prefix, so the printed path pastes back). Empty parts are skipped.
func machinePath(remote, tenantName, project, machine string) string {
	return scopePath(remote, tenantName, project, machine)
}

// scopePath is machinePath without a machine: tenant@remote:project. The
// first two arguments are remote and tenant; the rest are colon-joined.
func scopePath(remote, tenantName string, rest ...string) string {
	head := strings.TrimSpace(remote)
	if t := strings.TrimSpace(tenantName); t != "" {
		if head != "" {
			head = t + "@" + head
		} else {
			head = t + "@"
		}
	}
	kept := make([]string, 0, len(rest)+1)
	if head != "" {
		kept = append(kept, head)
	}
	for _, part := range rest {
		if part = strings.TrimSpace(part); part != "" {
			kept = append(kept, part)
		}
	}
	path := strings.Join(kept, ":")
	return strings.TrimSuffix(path, "@:")
}

// currentMachinePath is machinePath for the CLI's active remote and tenant.
func currentMachinePath(config commandConfig, project, machine string) string {
	return machinePath(config.adminConfig.Remote, config.adminConfig.Tenant, project, machine)
}
