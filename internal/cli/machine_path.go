package cli

import "strings"

// machinePath renders a machine by its full address — remote:tenant:project:
// machine — so every message says WHERE the machine is. With directory
// selections and Shared Tenants the same bare name can exist in several
// places, and "Machine dev does not exist in project default" no longer
// tells the user which remote and tenant they are in. Empty parts are
// skipped (a listing across remotes has no single remote).
func machinePath(remote, tenantName, project, machine string) string {
	return scopePath(remote, tenantName, project, machine)
}

// scopePath is machinePath without a machine: remote:tenant:project.
func scopePath(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, ":")
}

// currentMachinePath is machinePath for the CLI's active remote and tenant.
func currentMachinePath(config commandConfig, project, machine string) string {
	return machinePath(config.adminConfig.Remote, config.adminConfig.Tenant, project, machine)
}
