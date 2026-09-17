package cli

import (
	"fmt"
	"strings"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

// directorySelection preserves local history while capturing the effective pair
// on the first switch (including any per-invocation environment overrides).
func directorySelection(config commandConfig) (scconfig.DirectoryConfig, error) {
	local, _, err := scconfig.LoadDirectoryConfig("")
	if err != nil {
		return local, err
	}
	if local.RemoteProjects == nil {
		local.RemoteProjects = map[string]string{}
	}
	if local.Remote != "" && local.Project != "" {
		local.RemoteProjects[local.Remote] = local.Project
	}
	local.Remote = strings.TrimSpace(config.adminConfig.Remote)
	local.Project = strings.TrimSpace(config.adminConfig.Project)
	if local.Project == "" {
		local.Project = "default"
	}
	local.RemoteProjects[local.Remote] = local.Project
	return local, nil
}

func selectionSource(config commandConfig) string {
	if path := config.adminConfig.DirectoryConfigPath; path != "" {
		return "Selection file: " + path
	}
	return fmt.Sprintf("Selection file: none (.sandcastle not found; global fallback: %s / Incus defaults)", scconfig.DefaultConfigPath())
}
