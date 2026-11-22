package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/hostkeys"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestCacheableConnectReference(t *testing.T) {
	config := commandConfig{adminConfig: scconfig.Admin{Project: "pinned"}}
	cases := []struct {
		ref     string
		project string
		machine string
		ok      bool
	}{
		{"dev", "pinned", "dev", true},
		{"wordpress:dev", "wordpress", "dev", true},
		{"web*", "", "", false},                 // glob → live selector
		{"dev.wordpress.obelix", "", "", false}, // dotted cross-install form
		{"suffix:wordpress:dev", "", "", false}, // multi-colon → live
		{"", "", "", false},
		{":dev", "", "", false},
	}
	for _, c := range cases {
		project, machine, ok := cacheableConnectReference(config, c.ref)
		if ok != c.ok || project != c.project || machine != c.machine {
			t.Fatalf("ref %q → (%q, %q, %v), want (%q, %q, %v)", c.ref, project, machine, ok, c.project, c.machine, c.ok)
		}
	}
	// A bare machine name with NO pinned project cannot resolve from cache.
	if _, _, ok := cacheableConnectReference(commandConfig{}, "dev"); ok {
		t.Fatal("bare reference with no configured project must fall back")
	}
}

func TestRecordedKeyMatchesScan(t *testing.T) {
	ed := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAA_ed"}
	rsa := hostkeys.Key{Type: "ssh-rsa", Key: "AAAA_rsa"}
	changed := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAA_other"}
	if !recordedKeyMatchesScan([]hostkeys.Key{ed, rsa}, []hostkeys.Key{ed}) {
		t.Fatal("agreeing key must match")
	}
	if recordedKeyMatchesScan([]hostkeys.Key{ed}, []hostkeys.Key{changed}) {
		t.Fatal("a changed key of a recorded type must NOT match (rebuilt machine)")
	}
	if recordedKeyMatchesScan([]hostkeys.Key{ed}, []hostkeys.Key{rsa}) {
		t.Fatal("no overlapping type gives no certainty — must not match")
	}
	if recordedKeyMatchesScan(nil, []hostkeys.Key{ed}) {
		t.Fatal("nothing recorded must not match")
	}
}

func TestCachedConnectLoginUser(t *testing.T) {
	if user := cachedConnectLoginUser(tenant.Summary{UnixUser: "thies"}, nil); user != "thies" {
		t.Fatalf("summary user: %q", user)
	}
	profiles := cachedTestProfiles("default", "#cloud-config\nusers:\n  - name: alice\n    uid: 2000\n")
	if user := cachedConnectLoginUser(tenant.Summary{}, profiles); user != "alice" {
		t.Fatalf("profile user: %q", user)
	}
	if user := cachedConnectLoginUser(tenant.Summary{}, nil); user != tenant.DefaultV2UnixUser {
		t.Fatalf("fallback user: %q", user)
	}
}

// The full cache-first dial: cached running machine + agreeing pinned host key
// yields a strict-checking ssh argv with no live Incus involvement at all.
func TestDialV2MachineViaCacheHit(t *testing.T) {
	home := useLoginHomeForTest(t)
	key := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAAC3TestKey"}
	writeKnownHostsForTest(t, home, "dev.wordpress.obelix", key)
	stubConnectCacheKeyscan(t, []hostkeys.Key{key}, nil)

	fake := &fakeResourceClient{result: authapp.ResourceListResult{
		Tenant: tenant.Summary{Tenant: "thieso2", DNSSuffix: "obelix", UnixUser: "thies", PrivateCIDR: "10.123.0.0/24"},
		Machines: []meta.Machine{
			{Name: "dev", Project: "wordpress", Running: true, PrivateIP: "10.123.0.176"},
		},
	}}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "thieso2"}, authResources: fake}

	dialed, _, ok := dialV2MachineViaCache(context.Background(), config, "wordpress:dev")
	if !ok {
		t.Fatal("expected a cache hit")
	}
	args := strings.Join(dialed.sshArgs, " ")
	for _, want := range []string{
		"HostKeyAlias=dev.wordpress.obelix",
		"StrictHostKeyChecking=yes",
		"thies@10.123.0.176",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("sshArgs %q missing %q", args, want)
		}
	}
	if fake.lastRequest.Project != "wordpress" || fake.lastRequest.Machine != "dev" {
		t.Fatalf("cache request = %+v", fake.lastRequest)
	}
}

func TestDialV2MachineViaCacheFallsBack(t *testing.T) {
	home := useLoginHomeForTest(t)
	key := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAAC3TestKey"}
	writeKnownHostsForTest(t, home, "dev.wordpress.obelix", key)
	summary := tenant.Summary{Tenant: "thieso2", DNSSuffix: "obelix", UnixUser: "thies"}
	running := meta.Machine{Name: "dev", Project: "wordpress", Running: true, PrivateIP: "10.123.0.176"}
	unpinned := meta.Machine{Name: "fresh", Project: "wordpress", Running: true, PrivateIP: "10.123.0.177"}

	cases := []struct {
		name    string
		ref     string
		result  authapp.ResourceListResult
		err     error
		scan    []hostkeys.Key
		scanErr error
		want    connectCacheMissReason
	}{
		{name: "glob", ref: "wordpress:d*", want: missReferenceNeedsLive},
		{name: "token rejected", err: &authapp.ResourceListError{StatusCode: http.StatusUnauthorized, Message: "user not found"}, want: missTokenRejected},
		{name: "token forbidden", err: &authapp.ResourceListError{StatusCode: http.StatusForbidden, Message: "no"}, want: missTokenRejected},
		{name: "auth app timeout", err: fmt.Errorf("Get \"https://auth\": %w", context.DeadlineExceeded), want: missAuthAppTimeout},
		{name: "cache not ready", err: &authapp.ResourceListError{StatusCode: http.StatusServiceUnavailable, Message: "resource cache not ready"}, want: missCacheUnavailable},
		{name: "network error", err: errors.New("connection refused"), want: missCacheUnavailable},
		{name: "machine missing", result: authapp.ResourceListResult{Tenant: summary}, want: missMachineNotCached},
		{name: "machine stopped", result: authapp.ResourceListResult{Tenant: summary,
			Machines: []meta.Machine{{Name: "dev", Project: "wordpress", Running: false}}}, want: missMachineNotRunning},
		{name: "machine bare", result: authapp.ResourceListResult{Tenant: summary,
			Machines: []meta.Machine{{Name: "dev", Project: "wordpress", Running: true, PrivateIP: "10.123.0.176", Bare: true}}}, want: missMachineBare},
		{name: "no suffix", result: authapp.ResourceListResult{Tenant: tenant.Summary{Tenant: "thieso2"},
			Machines: []meta.Machine{running}}, want: missNoDNSSuffix},
		{name: "no recorded host key", ref: "wordpress:fresh", result: authapp.ResourceListResult{Tenant: summary,
			Machines: []meta.Machine{unpinned}}, scan: []hostkeys.Key{key}, want: missNoRecordedHostKey},
		{name: "keyscan fails", result: authapp.ResourceListResult{Tenant: summary,
			Machines: []meta.Machine{running}}, scanErr: errors.New("connection refused"), want: missSSHUnreachable},
		{name: "key mismatch (rebuilt)", result: authapp.ResourceListResult{Tenant: summary,
			Machines: []meta.Machine{running}}, scan: []hostkeys.Key{{Type: "ssh-ed25519", Key: "AAAAC3Rebuilt"}}, want: missHostKeyChanged},
	}
	for _, c := range cases {
		stubConnectCacheKeyscan(t, c.scan, c.scanErr)
		fake := &fakeResourceClient{result: c.result, err: c.err}
		config := commandConfig{adminConfig: scconfig.Admin{Tenant: "thieso2"}, authResources: fake}
		ref := c.ref
		if ref == "" {
			ref = "wordpress:dev"
		}
		_, miss, ok := dialV2MachineViaCache(context.Background(), config, ref)
		if ok {
			t.Fatalf("%s: expected fallback to the live path", c.name)
		}
		if miss.reason != c.want {
			t.Fatalf("%s: reason = %d (%s), want %d", c.name, miss.reason, miss.detail(), c.want)
		}
	}
}

func TestConnectCacheEnvDisables(t *testing.T) {
	t.Setenv(connectCacheEnv, "0")
	fake := &fakeResourceClient{}
	var stderr bytes.Buffer
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "thieso2"}, authResources: fake, stderr: &stderr}
	_, miss, ok := dialV2MachineViaCache(context.Background(), config, "wordpress:dev")
	if ok {
		t.Fatal("disabled cache must fall back")
	}
	if fake.calls != 0 {
		t.Fatalf("disabled cache must not call the auth-app (calls=%d)", fake.calls)
	}
	warnSlowConnect(config, miss)
	if stderr.Len() != 0 {
		t.Fatalf("a cache the user disabled must not warn, got %q", stderr.String())
	}
}

func TestSlowConnectWarningForARejectedTokenNamesTheLogin(t *testing.T) {
	t.Setenv("SANDCASTLE_AUTH_HOSTNAME", "https://obelix.example.dev")
	t.Setenv("VERBOSE", "")
	fake := &fakeResourceClient{err: &authapp.ResourceListError{StatusCode: http.StatusUnauthorized, Message: "invalid or expired CLI token"}}
	var stderr bytes.Buffer
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "thieso2"}, authResources: fake, stderr: &stderr}

	_, miss, _ := dialV2MachineViaCache(context.Background(), config, "wordpress:dev")
	warnSlowConnect(config, miss)

	want := "sc: slow connect (obelix.example.dev rejected the stored login token); run: sc login obelix.example.dev\n"
	if stderr.String() != want {
		t.Fatalf("stderr = %q\nwant     %q", stderr.String(), want)
	}
	if !miss.authAppUnusable() {
		t.Fatal("a rejected token makes the Auth App unusable for the rest of the command")
	}
}

func TestSlowConnectWarningIsOneLineForEveryReason(t *testing.T) {
	for reason := missReferenceNeedsLive; reason <= missNoLoginKey; reason++ {
		var stderr bytes.Buffer
		warnSlowConnect(commandConfig{stderr: &stderr}, connectCacheMiss{reason: reason, subject: "subject", cause: errors.New("multi\nline cause")})
		got := stderr.String()
		if !strings.HasPrefix(got, "sc: slow connect (") || strings.Count(got, "\n") != 1 {
			t.Fatalf("reason %d warned %q, want exactly one \"sc: slow connect (...)\" line", reason, got)
		}
		if strings.Contains(got, "(); ") || strings.HasSuffix(got, "; \n") {
			t.Fatalf("reason %d has no explanation or no hint: %q", reason, got)
		}
	}
}

func TestSlowConnectWarningsPromiseWhatTheLivePathDoes(t *testing.T) {
	cases := map[connectCacheMissReason]string{
		missAuthAppTimeout:    "did not answer within 2s",
		missNoRecordedHostKey: "this connect pins it, the next one is fast",
		missMachineNotRunning: "it is started first",
		missMachineNotCached:  "created if it does not exist",
	}
	for reason, want := range cases {
		why, hint := connectCacheMiss{reason: reason, subject: "subject"}.explain()
		if text := why + "; " + hint; !strings.Contains(text, want) {
			t.Fatalf("reason %d explains %q, want it to contain %q", reason, text, want)
		}
	}
}

func TestConnectCacheTimeoutIsShorterThanTheListingsAndSharesItsOverride(t *testing.T) {
	t.Setenv(resourceCacheTimeoutEnv, "")
	if got := connectCacheRequestTimeout(); got != 2*time.Second {
		t.Fatalf("connect default = %s, want 2s", got)
	}
	if got := resourceCacheRequestTimeout(); got != 5*time.Second {
		t.Fatalf("sc ls default = %s, want 5s (unchanged)", got)
	}
	t.Setenv(resourceCacheTimeoutEnv, "750ms")
	if connectCacheRequestTimeout() != 750*time.Millisecond || resourceCacheRequestTimeout() != 750*time.Millisecond {
		t.Fatalf("override not honoured: connect %s, ls %s", connectCacheRequestTimeout(), resourceCacheRequestTimeout())
	}
}

func TestLiveTenantStoreDropsOnlyTheCacheLayer(t *testing.T) {
	live := tenant.MemoryStore{}
	wrapped := cachedTenantStore{live: live, client: &fakeResourceClient{}}
	if _, ok := liveTenantStore(wrapped).(tenant.MemoryStore); !ok {
		t.Fatal("the cache layer must be unwrapped to the live store")
	}
	if _, ok := liveTenantStore(live).(tenant.MemoryStore); !ok {
		t.Fatal("a store without a cache layer is returned as it is")
	}
}

func TestPinnedAddressProbe(t *testing.T) {
	key := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAAC3TestKey"}
	rebuilt := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAAC3Rebuilt"}
	private := []netip.Addr{netip.MustParseAddr("10.123.0.176")}

	cases := []struct {
		name       string
		recorded   []hostkeys.Key
		addrs      []netip.Addr
		lookupErr  error
		scan       []hostkeys.Key
		scanErr    error
		wantIP     string
		wantPinned bool
	}{
		{name: "pinned key served", recorded: []hostkeys.Key{key}, addrs: private, scan: []hostkeys.Key{key}, wantIP: "10.123.0.176", wantPinned: true},
		{name: "nothing recorded", addrs: private, scan: []hostkeys.Key{key}},
		{name: "rebuilt machine", recorded: []hostkeys.Key{key}, addrs: private, scan: []hostkeys.Key{rebuilt}, wantIP: "10.123.0.176"},
		{name: "sshd down", recorded: []hostkeys.Key{key}, addrs: private, scanErr: errors.New("connection refused"), wantIP: "10.123.0.176"},
		{name: "name does not resolve", recorded: []hostkeys.Key{key}, lookupErr: errors.New("no such host"), scan: []hostkeys.Key{key}},
		{name: "name resolves to a public address", recorded: []hostkeys.Key{key}, addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}, scan: []hostkeys.Key{key}},
	}
	for _, c := range cases {
		stubConnectCacheKeyscan(t, c.scan, c.scanErr)
		original := connectLookupIPv4
		connectLookupIPv4 = func(context.Context, string) ([]netip.Addr, error) { return c.addrs, c.lookupErr }
		probe := startPinnedAddressProbe(context.Background(), c.recorded, "dev.wordpress.obelix")
		ip, pinned := probe.result()
		connectLookupIPv4 = original
		if ip != c.wantIP || pinned != c.wantPinned {
			t.Fatalf("%s: probe = (%q, %v), want (%q, %v)", c.name, ip, pinned, c.wantIP, c.wantPinned)
		}
	}
}

func cachedTestProfiles(name string, userData string) []api.Profile {
	return []api.Profile{{
		Name:       name,
		ProfilePut: api.ProfilePut{Config: map[string]string{"cloud-init.user-data": userData}},
	}}
}

func writeKnownHostsForTest(t *testing.T, home string, host string, key hostkeys.Key) {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line := host + " " + key.Type + " " + key.Key + "\n"
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stubConnectCacheKeyscan(t *testing.T, keys []hostkeys.Key, err error) {
	t.Helper()
	original := connectCacheKeyscan
	connectCacheKeyscan = func(ctx context.Context, host string) ([]hostkeys.Key, error) {
		return keys, err
	}
	t.Cleanup(func() { connectCacheKeyscan = original })
}
