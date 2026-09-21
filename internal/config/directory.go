package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/naming"
	"gopkg.in/yaml.v2"
)

// DirectoryConfig is a directory's selection. Credentials remain in the user config.
type DirectoryConfig struct {
	Remote  string `yaml:"remote"`
	Project string `yaml:"project"`
	// Tenant is the directory's Current Tenant (a Shared Tenant or the
	// user's own); empty means whatever the remote was enrolled for.
	Tenant         string            `yaml:"tenant,omitempty"`
	RemoteProjects map[string]string `yaml:"remote_projects,omitempty"`
}

// LoadDirectoryConfig walks from start to the filesystem root. Only the nearest
// file is read; an unreadable or invalid file is an error, never a fallback.
// With no file, path is empty. An empty start uses the working directory.
func LoadDirectoryConfig(start string) (cfg DirectoryConfig, path string, err error) {
	if start == "" {
		start, err = os.Getwd()
		if err != nil {
			return
		}
	}
	dir, err := filepath.Abs(start)
	if err != nil {
		return cfg, "", err
	}
	for {
		path = filepath.Join(dir, ".sandcastle")
		data, readErr := os.ReadFile(path)
		if readErr == nil {
			if err = yaml.UnmarshalStrict(data, &cfg); err == nil {
				err = cfg.validate()
			}
			if err != nil {
				return cfg, path, fmt.Errorf("read %s: %w", path, err)
			}
			return cfg, path, nil
		}
		_, statErr := os.Lstat(path)
		if !os.IsNotExist(readErr) || statErr == nil {
			return cfg, path, fmt.Errorf("read %s: %w", path, readErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cfg, "", nil
		}
		dir = parent
	}
}

func (c DirectoryConfig) validate() error {
	if strings.TrimSpace(c.Remote) == "" {
		return fmt.Errorf("remote is required")
	}
	if strings.TrimSpace(c.Project) == "" {
		return fmt.Errorf("project is required")
	}
	if err := naming.ValidateProjectName(c.Project); err != nil {
		return err
	}
	for _, project := range c.RemoteProjects {
		if err := naming.ValidateProjectName(project); err != nil {
			return err
		}
	}
	return nil
}

// SaveDirectoryConfig updates the nearest file, or creates one in the working
// directory. Atomic replacement prevents interrupted switches truncating it.
func SaveDirectoryConfig(cfg DirectoryConfig) (string, error) {
	_, path, err := LoadDirectoryConfig("")
	if err != nil {
		return "", err
	}
	if path == "" {
		path, err = filepath.Abs(".sandcastle")
		if err != nil {
			return "", err
		}
	}
	if err := cfg.validate(); err != nil {
		return "", err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	// Follow an existing file symlink when replacing its contents.
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	}
	file, err := os.CreateTemp(filepath.Dir(target), ".sandcastle-*")
	if err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(file.Name(), target); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// SelectRemote resolves an enrolled remote's identity without persisting it.
// Unknown remotes retain the legacy behavior used by explicit global config edits.
func (c *SandcastleConfig) SelectRemote(remote string) {
	c.Remote = remote
	host := c.AuthHostnameForRemote(remote)
	if host == "" {
		return
	}
	if tenant := c.TenantForRemote(remote); tenant != "" {
		c.Tenant = tenant
	}
	c.AuthHostname = host
	ambiguous := false
	normalize := func(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
	for other, otherHost := range c.Installs {
		if other != remote && normalize(otherHost) == normalize(host) {
			ambiguous = true
			break
		}
	}
	c.AuthToken = c.AuthTokenForRemote(remote)
	c.Broker = c.BrokerForRemote(remote)
	if !ambiguous {
		if c.AuthToken == "" {
			c.AuthToken = c.AuthTokenForAuthHostname(host)
		}
		if c.Broker == "" {
			c.Broker = c.BrokerForAuthHostname(host)
		}
	}
}

// LoadUserWithError resolves directory selection before applying environment
// overrides. The legacy global selection is used only when no local file exists.
func LoadUserWithError() (Admin, error) {
	cfg, err := LoadSandcastleConfig(DefaultConfigPath())
	if err != nil {
		return Admin{}, err
	}
	originalRemote := cfg.Remote
	local, path, err := LoadDirectoryConfig("")
	if err != nil {
		return Admin{}, err
	}
	if path != "" {
		cfg.Remote, cfg.Project = local.Remote, local.Project
	} else if remote := SharedIncusDefaultRemote(); remote != "" {
		cfg.Remote = remote
	}
	env := loadProcessEnv()
	remote := firstNonEmpty(strings.TrimSpace(env["SANDCASTLE_REMOTE"]), cfg.Remote)
	// A directory must not borrow the previous install's credentials when it
	// refers to an unknown enrollment. Explicit environment credentials still win.
	if path != "" && remote != originalRemote && cfg.AuthHostnameForRemote(remote) == "" {
		cfg.Tenant, cfg.AuthHostname, cfg.AuthToken, cfg.Broker = "", "", "", ""
	}
	if path != "" || remote != originalRemote {
		cfg.SelectRemote(remote)
	}
	// The directory's tenant wins over the remote's enrolled tenant: a
	// Shared Tenant's remote and its members' Personal Tenants are distinct
	// selections that `sc tenant switch` records here.
	if path != "" && strings.TrimSpace(local.Tenant) != "" && (remote == local.Remote || strings.TrimSpace(env["SANDCASTLE_REMOTE"]) == "") {
		cfg.Tenant = strings.TrimSpace(local.Tenant)
	}
	admin := adminFromConfigAndEnv(cfg, env)
	admin.DirectoryConfigPath = path
	return admin, nil
}
