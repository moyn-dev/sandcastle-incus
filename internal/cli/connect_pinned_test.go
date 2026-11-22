package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/hostkeys"
	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type pinnedDialServer struct {
	incusx.TenantCreateServer
	resource *pinnedDialResource
}

func (s pinnedDialServer) UseProject(string) incusx.TenantResourceServer { return s.resource }

type pinnedDialResource struct {
	incusx.TenantResourceServer
	instanceReads atomic.Int32
	stateReads    atomic.Int32
	fileReads     atomic.Int32
}

func (r *pinnedDialResource) GetProfile(string) (*api.Profile, string, error) {
	return &api.Profile{Name: "default", ProfilePut: api.ProfilePut{Config: map[string]string{
		"cloud-init.user-data": "users:\n  - name: sebastian\n",
	}}}, "", nil
}

func (r *pinnedDialResource) GetInstance(string) (*api.Instance, string, error) {
	r.instanceReads.Add(1)
	return &api.Instance{
		Name:            "dev",
		StatusCode:      api.Running,
		ExpandedDevices: map[string]map[string]string{"eth0": {"type": "nic"}},
	}, "", nil
}

func (r *pinnedDialResource) GetInstanceState(string) (*api.InstanceState, string, error) {
	r.stateReads.Add(1)
	return &api.InstanceState{Network: map[string]api.InstanceStateNetwork{
		"eth0": {Addresses: []api.InstanceStateNetworkAddress{{Family: "inet", Scope: "global", Address: "10.123.0.176", Netmask: "24"}}},
	}}, "", nil
}

func (r *pinnedDialResource) GetInstanceFile(string, string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	r.fileReads.Add(1)
	return nil, nil, errors.New("the pinned path must not read files from the machine")
}

func dialPinnedForTest(t *testing.T, lookup func(context.Context, string) ([]netip.Addr, error)) (dialedV2Machine, *pinnedDialResource) {
	t.Helper()
	home := useLoginHomeForTest(t)
	key := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAAC3TestKey"}
	writeKnownHostsForTest(t, home, "dev.wordpress.obelix", key)
	stubConnectCacheKeyscan(t, []hostkeys.Key{key}, nil)
	original := connectLookupIPv4
	connectLookupIPv4 = lookup
	t.Cleanup(func() { connectLookupIPv4 = original })

	resource := &pinnedDialResource{}
	var stdout, stderr bytes.Buffer
	config := commandConfig{
		stdout:        &stdout,
		stderr:        &stderr,
		adminConfig:   scconfig.Admin{Tenant: "thieso2", Project: "wordpress"},
		tenantCreator: incusx.TenantCreator{Server: pinnedDialServer{resource: resource}},
	}
	summary := tenant.Summary{Tenant: "thieso2", DNSSuffix: "obelix", Projects: []meta.Project{{Name: "wordpress"}}}
	dialed, err := dialV2Machine(context.Background(), config, summary, "wordpress:dev", launchV2Options{})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(dialed.sshArgs, " ")
	for _, want := range []string{"HostKeyAlias=dev.wordpress.obelix", "StrictHostKeyChecking=yes", "sebastian@10.123.0.176"} {
		if !strings.Contains(args, want) {
			t.Fatalf("sshArgs %q missing %q", args, want)
		}
	}
	if got := resource.fileReads.Load(); got != 0 {
		t.Fatalf("a running machine presenting its pinned key had %d files read (cloud-init gate or host keys), want 0", got)
	}
	if got := resource.instanceReads.Load(); got != 1 {
		t.Fatalf("the instance was fetched %d times, want 1", got)
	}
	return dialed, resource
}

func TestDialV2MachinePinnedSkipsIncusStateWhenTheNameResolves(t *testing.T) {
	_, resource := dialPinnedForTest(t, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.123.0.176")}, nil
	})
	if got := resource.stateReads.Load(); got != 0 {
		t.Fatalf("the instance state was read %d times, want 0", got)
	}
}

func TestDialV2MachinePinnedReadsTheAddressFromIncusWhenTheNameDoesNotResolve(t *testing.T) {
	_, resource := dialPinnedForTest(t, func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("no such host")
	})
	if got := resource.stateReads.Load(); got != 1 {
		t.Fatalf("the instance state was read %d times, want 1", got)
	}
}
