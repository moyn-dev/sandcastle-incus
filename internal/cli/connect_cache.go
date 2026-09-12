package cli

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/hostkeys"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// connectCacheEnv is the client-side kill switch for the cache-first connect
// path ("0"/"false"/"off" disables it). The server-side toggle is the same
// SANDCASTLE_RESOURCE_CACHE the `sc ls` cache rides on.
const connectCacheEnv = "SANDCASTLE_CONNECT_CACHE"

// connectCacheKeyscan is swapped out by tests; the real thing asks the
// machine's sshd directly what keys it serves.
var connectCacheKeyscan = hostkeys.Keyscan

// dialV2MachineViaCache is `sc connect`'s cache-first path: it answers the
// happy case — the referenced machine is cached as running with an address,
// and known_hosts already pins the identity its sshd is presenting — with ONE
// auth-app request plus ONE ssh-keyscan against the machine itself, instead of
// the ~10 sequential live Incus API calls of the full dial (project probe,
// profile read, instance + state reads, cloud-init gate, three host-key
// fetches). Anything short of that certainty returns ok=false and the caller
// runs the live path unchanged, exactly like `sc ls`'s cache fallback:
//
//   - the reference globs, dots, or names an enrolled remote / other install
//     (the live path owns rebinding and cross-install switching);
//   - no stored auth token / hostname, cache disabled, request failed;
//   - the machine is missing, stopped, bare, or has no cached address
//     (creation, starting, and the bare exec door are live-path work);
//   - known_hosts has no key for the machine, or the key sshd presents does
//     not match it (a rebuilt machine — the live path re-reads authoritative
//     keys and repairs known_hosts; the cache path must never pin around that).
//
// The keyscan doubles as the sshd reachability probe: a machine the cache
// wrongly believes is up fails it and falls back to the live path, which
// starts it.
func dialV2MachineViaCache(ctx context.Context, config commandConfig, reference string) (dialedV2Machine, bool) {
	if !connectCacheEnabled(os.Getenv(connectCacheEnv)) {
		return dialedV2Machine{}, false
	}
	project, machineName, ok := cacheableConnectReference(config, reference)
	if !ok {
		logConnectCacheFallback(config, "reference needs live resolution")
		return dialedV2Machine{}, false
	}
	client := config.authResources
	if client == nil {
		token := strings.TrimSpace(config.adminConfig.AuthToken)
		baseURL := commandAuthHostname(config, "")
		if token == "" || baseURL == "" {
			logConnectCacheFallback(config, "no stored AuthToken/Auth Hostname")
			return dialedV2Machine{}, false
		}
		client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: token}
	}
	cacheCtx, cancel := context.WithTimeout(ctx, resourceCacheRequestTimeout())
	defer cancel()
	result, err := client.ListResources(cacheCtx, authapp.ResourceListRequest{
		Tenant:  strings.TrimSpace(config.adminConfig.Tenant),
		Project: project,
		Machine: machineName,
		Include: []string{authapp.ResourceKindMachines, authapp.ResourceKindProfiles},
	})
	if err != nil {
		logConnectCacheFallback(config, err.Error())
		return dialedV2Machine{}, false
	}
	cached, found := cachedConnectMachine(result.Machines, project, machineName)
	switch {
	case !found:
		logConnectCacheFallback(config, "machine not in cache")
		return dialedV2Machine{}, false
	case cached.Bare:
		logConnectCacheFallback(config, "machine is bare (exec door is live-path work)")
		return dialedV2Machine{}, false
	case !cached.Running || strings.TrimSpace(cached.PrivateIP) == "":
		logConnectCacheFallback(config, "machine not cached as running with an address")
		return dialedV2Machine{}, false
	}
	summary := result.Tenant
	names := v2MachineNames(summary, project, machineName, cached.PublicHostname)
	if len(names) == 0 {
		logConnectCacheFallback(config, "cached tenant summary has no DNS suffix")
		return dialedV2Machine{}, false
	}
	keysConfig := hostKeysConfig(config, summary, "")
	recorded := keysConfig.Recorded(names[0])
	if len(recorded) == 0 {
		logConnectCacheFallback(config, "no recorded host key for "+names[0])
		return dialedV2Machine{}, false
	}
	// One round trip to the machine itself: proves sshd is up AND that the
	// pinned identity is the one it presents. A rebuilt machine mismatches here
	// and takes the live path, which repairs known_hosts authoritatively.
	scanned, err := connectCacheKeyscan(ctx, cached.PrivateIP)
	if err != nil {
		logConnectCacheFallback(config, "keyscan "+cached.PrivateIP+": "+err.Error())
		return dialedV2Machine{}, false
	}
	if !recordedKeyMatchesScan(recorded, scanned) {
		logConnectCacheFallback(config, "host key on port 22 does not match known_hosts (machine rebuilt?)")
		return dialedV2Machine{}, false
	}
	loginUser := cachedConnectLoginUser(summary, result.Profiles)
	sshKey, err := prepareLoginSSHKey(loginSSHKeyRequest{})
	if err != nil {
		logConnectCacheFallback(config, err.Error())
		return dialedV2Machine{}, false
	}
	verboseCLI(config, "connect cache: hit — %s/%s at %s (skipping live Incus resolution)", project, machineName, cached.PrivateIP)
	privateKeyPath := strings.TrimSuffix(sshKey.PublicKeyPath, ".pub")
	sshArgs := []string{
		"-o", "IdentitiesOnly=yes", "-i", privateKeyPath,
		"-o", "HostKeyAlias=" + names[0],
		"-o", "StrictHostKeyChecking=yes",
		"-o", "CheckHostIP=no",
		loginUser + "@" + cached.PrivateIP,
	}
	return dialedV2Machine{
		sshArgs:   sshArgs,
		loginUser: loginUser,
		privateIP: cached.PrivateIP,
		project:   project,
		machine:   machineName,
	}, true
}

// cacheableConnectReference parses the reference shapes the cache path serves:
// "machine" (with a configured current project) and "project:machine". Globs,
// dotted cross-install forms, multi-colon forms, and a first segment that is a
// locally enrolled remote (a rebind, not a project) all defer to the live path.
func cacheableConnectReference(config commandConfig, reference string) (project string, machine string, ok bool) {
	reference = strings.TrimSpace(reference)
	if reference == "" || strings.ContainsAny(reference, "*?[.") {
		return "", "", false
	}
	parts := strings.Split(reference, ":")
	switch len(parts) {
	case 1:
		project = strings.TrimSpace(config.adminConfig.Project)
		machine = parts[0]
	case 2:
		project, machine = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if localRemoteExists(project) {
			return "", "", false
		}
	default:
		return "", "", false
	}
	if project == "" || machine == "" {
		return "", "", false
	}
	return project, machine, true
}

// cachedConnectMachine picks the referenced machine out of the cache answer.
// The request already filtered by project+machine, but the filter is a match
// pattern — verify the exact row rather than trusting result shape.
func cachedConnectMachine(machines []meta.Machine, project string, name string) (meta.Machine, bool) {
	for _, machine := range machines {
		if machine.Name == name && (machine.Project == project || machine.Project == "") {
			return machine, true
		}
	}
	return meta.Machine{}, false
}

// cachedConnectLoginUser resolves the SSH login user without a live profile
// read: the admin-side tenant summary carries the stored login user; failing
// that, the cached default profile's cloud-init user-data names it (same
// `- name:` extraction the live path's profile read does); the v2 default
// user is the same last resort the live path has.
func cachedConnectLoginUser(summary tenant.Summary, profiles []api.Profile) string {
	if user := strings.TrimSpace(summary.UnixUser); user != "" {
		return user
	}
	for _, profile := range profiles {
		if profile.Name != "default" {
			continue
		}
		if match := cachedProfileUserPattern.FindStringSubmatch(profile.Config["cloud-init.user-data"]); match != nil {
			return match[1]
		}
	}
	return tenant.DefaultV2UnixUser
}

// cachedProfileUserPattern mirrors incusx's v2ProfileUserPattern: the first
// `- name:` entry of the profile's cloud-init user-data is the login user.
var cachedProfileUserPattern = regexp.MustCompile(`(?m)^\s*-\s*name:\s*(\S+)`)

// recordedKeyMatchesScan reports whether what sshd presents agrees with what
// known_hosts pins: at least one scanned key must equal a recorded key of the
// same type, and no scanned type that IS recorded may disagree. ssh negotiates
// one of the offered keys, so a single agreeing pair with no contradictions is
// exactly the certainty StrictHostKeyChecking=yes needs.
func recordedKeyMatchesScan(recorded []hostkeys.Key, scanned []hostkeys.Key) bool {
	byType := map[string]map[string]bool{}
	for _, key := range recorded {
		if byType[key.Type] == nil {
			byType[key.Type] = map[string]bool{}
		}
		byType[key.Type][key.Key] = true
	}
	matched := false
	for _, key := range scanned {
		known, ok := byType[key.Type]
		if !ok {
			continue
		}
		if !known[key.Key] {
			return false
		}
		matched = true
	}
	return matched
}

func connectCacheEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

func logConnectCacheFallback(config commandConfig, reason string) {
	verboseCLI(config, "connect cache: falling back to live resolution (%s)", reason)
}
