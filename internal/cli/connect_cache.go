package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	"github.com/moyn-dev/sandcastle-incus/internal/hostkeys"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
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
func dialV2MachineViaCache(ctx context.Context, config commandConfig, reference string) (dialedV2Machine, connectCacheMiss, bool) {
	miss := func(reason connectCacheMissReason, subject string, cause error) (dialedV2Machine, connectCacheMiss, bool) {
		missed := connectCacheMiss{reason: reason, subject: subject, cause: cause}
		if reason != missCacheDisabled {
			verboseCLI(config, "connect cache: falling back to live resolution (%s)", missed.detail())
		}
		return dialedV2Machine{}, missed, false
	}
	if !connectCacheEnabled(os.Getenv(connectCacheEnv)) {
		return miss(missCacheDisabled, "", nil)
	}
	project, machineName, ok := cacheableConnectReference(config, reference)
	if !ok {
		return miss(missReferenceNeedsLive, reference, nil)
	}
	baseURL := commandAuthHostname(config, "")
	authHost := strings.TrimPrefix(baseURL, "https://")
	client := config.authResources
	if client == nil {
		token := strings.TrimSpace(config.adminConfig.AuthToken)
		if token == "" || baseURL == "" {
			return miss(missNotLoggedIn, authHost, nil)
		}
		client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: token, Tenant: strings.TrimSpace(config.adminConfig.Tenant)}
	}
	cacheCtx, cancel := context.WithTimeout(ctx, connectCacheRequestTimeout())
	defer cancel()
	result, err := client.ListResources(cacheCtx, authapp.ResourceListRequest{
		Tenant:  strings.TrimSpace(config.adminConfig.Tenant),
		Project: project,
		Machine: machineName,
		Include: []string{authapp.ResourceKindMachines, authapp.ResourceKindProfiles},
	})
	if err != nil {
		return miss(resourceCacheErrorReason(err), authHost, err)
	}
	cached, found := cachedConnectMachine(result.Machines, project, machineName)
	switch {
	case !found:
		return miss(missMachineNotCached, machineName, nil)
	case cached.Bare:
		return miss(missMachineBare, machineName, nil)
	case !cached.Running || strings.TrimSpace(cached.PrivateIP) == "":
		return miss(missMachineNotRunning, machineName, nil)
	}
	summary := result.Tenant
	names := v2MachineNames(summary, project, machineName, cached.PublicNames())
	if len(names) == 0 {
		return miss(missNoDNSSuffix, summary.Tenant, nil)
	}
	// One round trip to the machine itself: proves sshd is up AND that the
	// pinned identity is the one it presents. A rebuilt machine mismatches here
	// and takes the live path, which repairs known_hosts authoritatively.
	switch pin, err := checkHostKeyPin(ctx, hostKeysConfig(config, summary, "").Recorded(names[0]), cached.PrivateIP); pin {
	case pinNotRecorded:
		return miss(missNoRecordedHostKey, names[0], nil)
	case pinUnreachable:
		return miss(missSSHUnreachable, cached.PrivateIP, err)
	case pinChanged:
		return miss(missHostKeyChanged, names[0], nil)
	}
	loginUser := cachedConnectLoginUser(summary, result.Profiles)
	sshKey, err := prepareLoginSSHKey(loginSSHKeyRequest{})
	if err != nil {
		return miss(missNoLoginKey, "", err)
	}
	verboseCLI(config, "connect cache: hit — %s/%s at %s (skipping live Incus resolution)", project, machineName, cached.PrivateIP)
	return dialedV2Machine{
		sshArgs:   pinnedSSHArgs(sshKey.PublicKeyPath, names[0], loginUser, cached.PrivateIP),
		loginUser: loginUser,
		privateIP: cached.PrivateIP,
		project:   project,
		machine:   machineName,
	}, connectCacheMiss{}, true
}

type connectCacheMissReason int

const (
	missCacheDisabled connectCacheMissReason = iota
	missReferenceNeedsLive
	missNotLoggedIn
	missTokenRejected
	missAuthAppTimeout
	missCacheUnavailable
	missMachineNotCached
	missMachineNotRunning
	missMachineBare
	missNoDNSSuffix
	missNoRecordedHostKey
	missSSHUnreachable
	missHostKeyChanged
	missNoLoginKey
)

type connectCacheMiss struct {
	reason  connectCacheMissReason
	subject string
	cause   error
}

func (m connectCacheMiss) explain() (why string, hint string) {
	switch m.reason {
	case missReferenceNeedsLive:
		return fmt.Sprintf("reference %q needs live resolution", m.subject), "name one machine as project:machine for the fast path"
	case missNotLoggedIn:
		return "no Auth App login is stored for this remote", "run: sc login " + firstNonEmptyString(m.subject, "<auth-host>")
	case missTokenRejected:
		return m.subject + " rejected the stored login token", "run: sc login " + m.subject
	case missAuthAppTimeout:
		return fmt.Sprintf("%s did not answer within %s", m.subject, connectCacheRequestTimeout()),
			"the Auth App is slow or unreachable; " + resourceCacheTimeoutEnv + " sets how long sc waits for it"
	case missCacheUnavailable:
		return "the resource cache at " + m.subject + " is unavailable", "connecting over the Incus API instead"
	case missMachineNotCached:
		return "machine " + m.subject + " is not in the resource cache", "it is looked up live, and created if it does not exist"
	case missMachineNotRunning:
		return "machine " + m.subject + " is not running", "it is started first"
	case missMachineBare:
		return "machine " + m.subject + " is bare", "a bare machine has no sshd and is always reached over the Incus API"
	case missNoDNSSuffix:
		return "the resource cache knows no DNS suffix for tenant " + m.subject, "connecting over the Incus API instead"
	case missNoRecordedHostKey:
		return "no recorded host key for " + m.subject, "this connect pins it, the next one is fast"
	case missSSHUnreachable:
		return "sshd at " + m.subject + " did not answer a key scan", "checking the machine over the Incus API"
	case missHostKeyChanged:
		return "the host key of " + m.subject + " does not match known_hosts", "the machine was probably rebuilt; its keys are re-read over the Incus API"
	case missNoLoginKey:
		return "the login SSH key is not usable", "the live path reports the details"
	}
	return "", ""
}

func (m connectCacheMiss) detail() string {
	why, _ := m.explain()
	if m.cause != nil {
		return why + ": " + m.cause.Error()
	}
	return why
}

func (m connectCacheMiss) authAppUnusable() bool {
	switch m.reason {
	case missTokenRejected, missAuthAppTimeout, missCacheUnavailable:
		return true
	}
	return false
}

func resourceCacheErrorReason(err error) connectCacheMissReason {
	var listErr *authapp.ResourceListError
	switch {
	case errors.As(err, &listErr) && (listErr.StatusCode == http.StatusUnauthorized || listErr.StatusCode == http.StatusForbidden):
		return missTokenRejected
	case errors.Is(err, context.DeadlineExceeded):
		return missAuthAppTimeout
	}
	return missCacheUnavailable
}

func warnSlowConnect(config commandConfig, miss connectCacheMiss) {
	why, hint := miss.explain()
	if why == "" || config.stderr == nil {
		return
	}
	fmt.Fprintf(config.stderr, "sc: slow connect (%s); %s\n", why, hint)
}

type hostKeyPin int

const (
	pinConfirmed hostKeyPin = iota
	pinNotRecorded
	pinUnreachable
	pinChanged
)

func checkHostKeyPin(ctx context.Context, recorded []hostkeys.Key, ip string) (hostKeyPin, error) {
	if len(recorded) == 0 {
		return pinNotRecorded, nil
	}
	scanned, err := connectCacheKeyscan(ctx, ip)
	if err != nil {
		return pinUnreachable, err
	}
	if !recordedKeyMatchesScan(recorded, scanned) {
		return pinChanged, nil
	}
	return pinConfirmed, nil
}

func pinnedSSHArgs(publicKeyPath string, alias string, loginUser string, ip string) []string {
	return []string{
		"-o", "IdentitiesOnly=yes", "-i", strings.TrimSuffix(publicKeyPath, ".pub"),
		"-o", "HostKeyAlias=" + alias,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "CheckHostIP=no",
		loginUser + "@" + ip,
	}
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
