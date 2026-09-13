package meta

import (
	"encoding/json"
	"strings"
	"testing"
)

// DecodeMachine is the one place the ADR-0027 instance keys are read. An
// unstamped machine (every machine created before the feature) and one
// pinned to the literal "private" must come back private-mode with no
// certificate fields — even when a stray cert-state key is present — while a
// stamped zone-mode machine carries its public name and the mirrored state.
func TestDecodeMachine(t *testing.T) {
	base := Machine{Tenant: "acme", Project: "website", Name: "codex", PrivateIP: "10.88.17.21", Running: true}
	for _, tc := range []struct {
		name   string
		config map[string]string
		want   Machine
		mode   string
	}{
		{"unstamped", map[string]string{}, base, NamingModePrivate},
		{"nil config", nil, base, NamingModePrivate},
		{"private literal", map[string]string{KeyV2PublicHostname: NamingModePrivate}, base, NamingModePrivate},
		{"private with stray cert keys", map[string]string{
			KeyV2PublicHostname: "private", KeyV2CertState: "installed", KeyV2CertNotAfter: "2026-12-01T00:00:00Z",
		}, base, NamingModePrivate},
		{"zone pending (unstamped cert)", map[string]string{KeyV2PublicHostname: "codex.baum.hase.de"},
			withZone(base, "codex.baum.hase.de", "", ""), NamingModeZone},
		{"zone installed", map[string]string{
			KeyV2PublicHostname: " codex.baum.hase.de ", KeyV2CertState: "installed", KeyV2CertNotAfter: "2026-12-01T00:00:00Z",
		}, withZone(base, "codex.baum.hase.de", "installed", "2026-12-01T00:00:00Z"), NamingModeZone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeMachine(tc.config, base)
			if got.NamingMode() != tc.mode {
				t.Fatalf("NamingMode = %q, want %q", got.NamingMode(), tc.mode)
			}
			if got.PublicHostname != tc.want.PublicHostname || got.CertState != tc.want.CertState || got.CertNotAfter != tc.want.CertNotAfter {
				t.Fatalf("DecodeMachine = %#v, want %#v", got, tc.want)
			}
			// Nothing else on the machine is touched.
			got.PublicHostname, got.CertState, got.CertNotAfter = "", "", ""
			if got.Tenant != base.Tenant || got.Project != base.Project || got.Name != base.Name || got.PrivateIP != base.PrivateIP || got.Running != base.Running {
				t.Fatalf("DecodeMachine altered unrelated fields: %#v", got)
			}
		})
	}
}

func withZone(m Machine, hostname, state, notAfter string) Machine {
	m.PublicHostname, m.CertState, m.CertNotAfter = hostname, state, notAfter
	return m
}

// The zone fields are omitempty, so an unstamped machine's JSON is unchanged
// by their existence (the resource-cache payload and `sc ls --json` both
// serialise meta.Machine).
func TestMachineJSONOmitsZoneFieldsForPrivateMachine(t *testing.T) {
	data, err := json.Marshal(Machine{Name: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"publicHostname", "certState", "certNotAfter"} {
		if strings.Contains(string(data), key) {
			t.Fatalf("private machine JSON carries %q: %s", key, data)
		}
	}
	data, err = json.Marshal(Machine{Name: "codex", PublicHostname: "codex.baum.hase.de", CertState: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"publicHostname":"codex.baum.hase.de"`) || !strings.Contains(string(data), `"certState":"pending"`) {
		t.Fatalf("zone machine JSON = %s", data)
	}
}

func TestMachineConfigRoundTrip(t *testing.T) {
	input := Machine{
		Tenant:          "acme",
		Project:         "website",
		Name:            "codex",
		Type:            MachineTypeContainer,
		Template:        "ai",
		AppPort:         3000,
		PrivateIP:       "10.88.17.21",
		LinuxUser:       "alice",
		CloudIdentity:   "gcp",
		DockerAutostart: true,
		HomeDir:         "website/codex",
		WorkspaceDir:    "website/codex",
		ContainerTools:  true,
		ExtraSANs:       []string{"app.example.test"},
		CreatedBy:       "alice",
	}
	config, err := MachineConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if config[KeyAppPort] != "3000" {
		t.Fatalf("app port scalar = %q", config[KeyAppPort])
	}
	if config[KeyMachine] != "codex" {
		t.Fatalf("machine scalar = %q", config[KeyMachine])
	}
	output, err := ParseMachineConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if output.Name != input.Name || output.PrivateIP != input.PrivateIP || output.LinuxUser != input.LinuxUser || output.CloudIdentity != input.CloudIdentity || output.DockerAutostart != input.DockerAutostart {
		t.Fatalf("round trip = %#v, want %#v", output, input)
	}
	if len(output.ExtraSANs) != 1 {
		t.Fatalf("extra SANs = %#v", output.ExtraSANs)
	}
	if !output.ContainerTools {
		t.Fatalf("ContainerTools = false, want true")
	}
}

func TestRouteConfigRoundTrip(t *testing.T) {
	input := Route{
		Hostname:        "app.example.com",
		TargetTenant:    "acme",
		TargetProject:   "website",
		TargetMachine:   "codex",
		TargetIP:        "10.248.0.20",
		RoutePort:       5173,
		CreatedBy:       "alice",
		IngressAttached: true,
	}
	config, err := RouteConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if config[KeyKind] != KindRoute {
		t.Fatalf("kind = %q", config[KeyKind])
	}
	if config[KeyHostname] != "app.example.com" {
		t.Fatalf("hostname scalar = %q", config[KeyHostname])
	}
	if config[KeyTenant] != "acme" {
		t.Fatalf("tenant scalar = %q", config[KeyTenant])
	}
	if config[KeyAppPort] != "5173" {
		t.Fatalf("app port scalar = %q", config[KeyAppPort])
	}
	if config[KeyCreatedBy] != "alice" {
		t.Fatalf("created by scalar = %q", config[KeyCreatedBy])
	}
	output, err := ParseRouteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if output.Hostname != input.Hostname || output.TargetIP != input.TargetIP || output.RoutePort != input.RoutePort || output.CreatedBy != input.CreatedBy {
		t.Fatalf("round trip = %#v, want %#v", output, input)
	}
}

func TestParseRejectsUnmanagedConfig(t *testing.T) {
	_, err := ParseMachineConfig(map[string]string{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIsManaged(t *testing.T) {
	if IsManaged(map[string]string{}) {
		t.Fatal("empty config should be unmanaged")
	}
	if !IsManaged(map[string]string{KeyKind: KindInfra, KeyVersion: "1"}) {
		t.Fatal("Sandcastle config should be managed")
	}
}
