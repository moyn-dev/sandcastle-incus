package cli

import "strings"

// machinePath renders a machine by its Sandcastle Path —
// /install/tenant/project/machine — so every message says WHERE the machine
// is. With directory selections and Shared Tenants the same bare name can
// exist in several places, and "Machine dev does not exist in project
// default" no longer tells the user which install and tenant they are in.
// The path is the grammar every command accepts, so a printed path pastes
// back. When the remote or the tenant is unknown the colon reference of the
// remaining parts is rendered instead — a path with a hole would not paste
// back.
func machinePath(remote, tenantName, project, machine string) string {
	return scopePath(remote, tenantName, project, machine)
}

// remoteMachinePath is machinePath in the remote form of ADR-0030
// (/remote/tenant/project/machine), which machine JSON carries as
// remote_path for one minor release after ADR-0032.
func remoteMachinePath(remote, tenantName, project, machine string) string {
	return renderScopePath(strings.TrimSpace(remote), remote, tenantName, project, machine)
}

// scopePath is machinePath without a machine: /install/tenant/project. The
// first two arguments are the remote and the tenant; the remote is printed
// as its install. The rest follow as segments.
func scopePath(remote, tenantName string, rest ...string) string {
	head := ""
	if strings.TrimSpace(remote) != "" {
		head = loadInstallIndex().installNameOf(remote)
	}
	return renderScopePath(head, remote, tenantName, rest...)
}

func renderScopePath(head, remote, tenantName string, rest ...string) string {
	if t := strings.TrimSpace(tenantName); head != "" && t != "" {
		segments := []string{head, t}
		for _, part := range rest {
			if part = strings.TrimSpace(part); part != "" {
				segments = append(segments, part)
			}
		}
		return formatPath(segments)
	}
	kept := make([]string, 0, len(rest)+1)
	if r := strings.TrimSpace(remote); r != "" {
		kept = append(kept, r)
	}
	for _, part := range rest {
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
