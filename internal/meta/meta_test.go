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
	if hostname != "" {
		m.PublicHostnames = []string{hostname}
	}
	return m
}

// Publication summaries are opt-in metadata independent of a Machine Public
// Hostname. Private machines must retain them so `sc ls` can show active
// tunnels and tailnet publications.
func TestDecodeMachineReadsPublicationMetadataWithoutPublicHostname(t *testing.T) {
	got := DecodeMachine(map[string]string{
		KeyV2MachineTunnelHostname: "  codex.tunnel.example  ",
		KeyV2TailnetPublications:   " API.TAILNET.EXAMPLE, web.tailnet.example, api.tailnet.example ",
	}, Machine{Name: "codex"})

	if got.HasPublicHostname() {
		t.Fatalf("private Machine unexpectedly has public hostnames: %+v", got)
	}
	if got.MachineTunnelHostname != "codex.tunnel.example" {
		t.Fatalf("MachineTunnelHostname = %q", got.MachineTunnelHostname)
	}
	if len(got.MachineTunnelPendingHostnames) != 0 {
		t.Fatalf("unexpected pending tunnel metadata: %v", got.MachineTunnelPendingHostnames)
	}
	if publications := strings.Join(got.TailnetPublications, ","); publications != "api.tailnet.example,web.tailnet.example" {
		t.Fatalf("TailnetPublications = %q", publications)
	}
}

// ADR-0028: DecodeMachine reads the list key first and falls back to the
// legacy single key; PublicHostname stays the first of the sorted list.
func TestDecodeMachineReadsBothPublicHostnameKeys(t *testing.T) {
	base := Machine{Name: "web"}
	for _, tc := range []struct {
		name   string
		config map[string]string
		want   []string
	}{
		{"list only", map[string]string{KeyV2PublicHostnames: "web12.tc42.uk, Web.baum.hase.de,"}, []string{"web.baum.hase.de", "web12.tc42.uk"}},
		{"list wins over single", map[string]string{KeyV2PublicHostnames: "web12.tc42.uk", KeyV2PublicHostname: "web.baum.hase.de"}, []string{"web12.tc42.uk"}},
		{"single only", map[string]string{KeyV2PublicHostname: "web.baum.hase.de"}, []string{"web.baum.hase.de"}},
		{"single private, list absent", map[string]string{KeyV2PublicHostname: "private"}, nil},
		{"single private, list present", map[string]string{KeyV2PublicHostname: "private", KeyV2PublicHostnames: "web12.tc42.uk"}, []string{"web12.tc42.uk"}},
		{"empty list value", map[string]string{KeyV2PublicHostnames: " , "}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeMachine(tc.config, base)
			if strings.Join(got.PublicHostnames, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("PublicHostnames = %v, want %v", got.PublicHostnames, tc.want)
			}
			first := ""
			if len(tc.want) > 0 {
				first = tc.want[0]
			}
			if got.PublicHostname != first || got.HasPublicHostname() != (len(tc.want) > 0) {
				t.Fatalf("PublicHostname = %q, has = %v", got.PublicHostname, got.HasPublicHostname())
			}
		})
	}
	if FormatPublicHostnames([]string{"B.example", "a.example", "", "a.example"}) != "a.example,b.example" || FormatPublicHostnames(nil) != "" {
		t.Fatalf("FormatPublicHostnames")
	}
	// A payload carrying only the legacy single field (an older Auth App's
	// cache) still counts as a public name.
	if names := (Machine{PublicHostname: "web.baum.hase.de"}).PublicNames(); strings.Join(names, ",") != "web.baum.hase.de" {
		t.Fatalf("PublicNames from single field = %v", names)
	}
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

// ADR-0028: the cert-state mirror is per hostname (`host=state,…`, sorted);
// DecodeMachine keeps the map and folds the worst state into CertState; a
// bare pre-ADR-0028 value is read as the first name's.
func TestCertStatesPerHostname(t *testing.T) {
	if got := FormatCertStates(map[string]string{"web.baum.hase.de": "installed", "Shop.tc42.uk.": "failed:rate-limited", "": "x", "z": ""}); got != "shop.tc42.uk=failed:rate-limited,web.baum.hase.de=installed" {
		t.Fatalf("FormatCertStates = %q", got)
	}
	if FormatCertStates(nil) != "" {
		t.Fatal("empty map must render empty")
	}
	names := []string{"shop.tc42.uk", "web.baum.hase.de"}
	states := ParseCertStates(" shop.tc42.uk=installed, web.baum.hase.de=issued ,,", names)
	if len(states) != 2 || states["shop.tc42.uk"] != "installed" || states["web.baum.hase.de"] != "issued" {
		t.Fatalf("ParseCertStates = %v", states)
	}
	if legacy := ParseCertStates("installed", names); len(legacy) != 1 || legacy["shop.tc42.uk"] != "installed" {
		t.Fatalf("legacy value = %v", legacy)
	}
	if ParseCertStates("installed", nil) != nil || ParseCertStates("", names) != nil {
		t.Fatal("nothing to parse must yield nil")
	}
	for _, tc := range []struct {
		states map[string]string
		want   string
	}{
		{nil, ""},
		{map[string]string{"shop.tc42.uk": "installed", "web.baum.hase.de": "installed"}, "installed"},
		{map[string]string{"shop.tc42.uk": "installed", "web.baum.hase.de": "renewing"}, "renewing"},
		{map[string]string{"shop.tc42.uk": "issued", "web.baum.hase.de": "renewing"}, "issued"},
		{map[string]string{"shop.tc42.uk": "pending", "web.baum.hase.de": "issued"}, "pending"},
		{map[string]string{"shop.tc42.uk": "installed"}, "pending"}, // web has no entry yet
		{map[string]string{"shop.tc42.uk": "weird", "web.baum.hase.de": "pending"}, "weird"},
		{map[string]string{"shop.tc42.uk": "failed:validation", "web.baum.hase.de": "weird"}, "failed:validation"},
		{map[string]string{"gone.tc42.uk": "failed:expired", "shop.tc42.uk": "installed", "web.baum.hase.de": "installed"}, "failed:expired"}, // stale entry still counts
	} {
		if got := WorstCertState(tc.states, names); got != tc.want {
			t.Fatalf("WorstCertState(%v) = %q, want %q", tc.states, got, tc.want)
		}
	}
	m := DecodeMachine(map[string]string{
		KeyV2PublicHostnames: "web.baum.hase.de,shop.tc42.uk",
		KeyV2CertState:       "shop.tc42.uk=installed,web.baum.hase.de=failed:rate-limited",
		KeyV2CertNotAfter:    "2026-12-01T00:00:00Z",
	}, Machine{Name: "web"})
	if m.CertState != "failed:rate-limited" || m.CertStates["shop.tc42.uk"] != "installed" || m.CertNotAfter != "2026-12-01T00:00:00Z" {
		t.Fatalf("DecodeMachine = %+v", m)
	}
	if m.CertStateOf("shop.tc42.uk") != "installed" || m.CertStateOf("web.baum.hase.de") != "failed:rate-limited" || m.CertStateOf("new.tc42.uk") != CertStatePending {
		t.Fatalf("CertStateOf = %q / %q / %q", m.CertStateOf("shop.tc42.uk"), m.CertStateOf("web.baum.hase.de"), m.CertStateOf("new.tc42.uk"))
	}
	// An older Auth App's cache payload: only the folded state, applied to
	// every name.
	legacy := Machine{PublicHostname: "web.baum.hase.de", PublicHostnames: []string{"web.baum.hase.de"}, CertState: "installed"}
	if legacy.CertStateOf("web.baum.hase.de") != "installed" {
		t.Fatalf("legacy CertStateOf = %q", legacy.CertStateOf("web.baum.hase.de"))
	}
	// A private machine never carries states, whatever the config says.
	if p := DecodeMachine(map[string]string{KeyV2CertState: "x=installed"}, Machine{}); p.CertStates != nil || p.CertState != "" {
		t.Fatalf("private machine decoded states: %+v", p)
	}
}
