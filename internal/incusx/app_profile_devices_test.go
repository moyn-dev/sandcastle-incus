package incusx

import (
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func devicesTestPlan() tenant.CreatePlanV2 {
	return tenant.CreatePlanV2{
		Tenant:      "acme",
		Bridge:      "sc2-acme",
		StoragePool: "default",
	}
}

// Every machine in a v2 app project mounts the /.sc shared-scripts layers via
// the default profile (spec #127): platform read-only, local read-write —
// the per-layer writability contract, enforced at the disk device.
func TestV2AppProfileDevicesAttachSCVolumes(t *testing.T) {
	devices := v2AppProfileDevices(devicesTestPlan())

	platform, ok := devices["sc-platform"]
	if !ok {
		t.Fatalf("no sc-platform device: %v", devices)
	}
	if platform["source"] != tenant.V2SCPlatformVolumeName || platform["path"] != tenant.SCPlatformPath {
		t.Fatalf("sc-platform device = %v", platform)
	}
	if platform["readonly"] != "true" {
		t.Fatalf("platform layer must be read-only to machines: %v", platform)
	}

	local, ok := devices["sc-local"]
	if !ok {
		t.Fatalf("no sc-local device: %v", devices)
	}
	if local["source"] != tenant.V2SCLocalVolumeName || local["path"] != tenant.SCLocalPath {
		t.Fatalf("sc-local device = %v", local)
	}
	if local["readonly"] != "" {
		t.Fatalf("local layer must be tenant-writable: %v", local)
	}
}

// The default profile shares /workspace and the /.sc layers, never /home —
// a shared /home is opt-in through the separate homeshare profile.
func TestV2AppProfileDevicesShareWorkspaceNotHome(t *testing.T) {
	devices := v2AppProfileDevices(devicesTestPlan())
	if _, ok := devices["home"]; ok {
		t.Fatalf("default profile must not share /home: %v", devices)
	}
	for _, name := range []string{"workspace", "sc-platform", "sc-local"} {
		if _, ok := devices[name]; !ok {
			t.Fatalf("missing %s device in the default profile: %v", name, devices)
		}
	}
}

// The homeshare profile carries the shared /home device and nothing else, so
// it composes with default instead of overriding any of its devices.
func TestV2HomeShareProfileDevicesOnlyHome(t *testing.T) {
	devices := v2HomeShareProfileDevices(devicesTestPlan())
	if len(devices) != 1 {
		t.Fatalf("homeshare profile must carry only /home: %v", devices)
	}
	home, ok := devices["home"]
	if !ok {
		t.Fatalf("no home device: %v", devices)
	}
	if home["source"] != tenant.V2HomeVolumeName || home["path"] != "/home" || home["pool"] != "default" {
		t.Fatalf("home device = %v", home)
	}
}

// A machine only gets the homeshare profile when asked for it; default is
// always present so the shared bridge, cloud-init login and /workspace apply.
func TestV2MachineProfiles(t *testing.T) {
	if got := v2MachineProfiles(false); len(got) != 1 || got[0] != "default" {
		t.Fatalf("without --home-share = %v", got)
	}
	got := v2MachineProfiles(true)
	if len(got) != 2 || got[0] != "default" || got[1] != tenant.V2HomeShareProfileName {
		t.Fatalf("with --home-share = %v", got)
	}
}
