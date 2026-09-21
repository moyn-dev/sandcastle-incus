package cli

import "strings"

// machinePath renders a machine by its Sandcastle Path —
// /remote/tenant/project/machine — so every message says WHERE the machine
// is. With directory selections and Shared Tenants the same bare name can
// exist in several places, and "Machine dev does not exist in project
// default" no longer tells the user which remote and tenant they are in.
// The path is the grammar every command accepts, so a printed path pastes
// back. When the remote or the tenant is unknown the legacy
// tenant@remote:project:machine rendering is used, with empty parts skipped
// — a path with a hole would not paste back.
func machinePath(remote, tenantName, project, machine string) string {
	return scopePath(remote, tenantName, project, machine)
}

// scopePath is machinePath without a machine: /remote/tenant/project. The
// first two arguments are remote and tenant; the rest follow as segments.
func scopePath(remote, tenantName string, rest ...string) string {
	if r, t := strings.TrimSpace(remote), strings.TrimSpace(tenantName); r != "" && t != "" {
		segments := []string{r, t}
		for _, part := range rest {
			if part = strings.TrimSpace(part); part != "" {
				segments = append(segments, part)
			}
		}
		return formatPath(segments)
	}
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
