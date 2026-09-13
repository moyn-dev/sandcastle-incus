package meta

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	Prefix = "user.sandcastle."

	KeyKind        = Prefix + "kind"
	KeyVersion     = Prefix + "version"
	KeyTenant      = Prefix + "tenant"
	KeyProject     = Prefix + "project"
	KeyMachine     = Prefix + "machine"
	KeyType        = Prefix + "type"
	KeyHostname    = Prefix + "hostname"
	KeyPrivateCIDR = Prefix + "private_cidr"
	// KeyV2CIDR is where v2 stores a tenant's private /24, on the kind=infra
	// project (v1 keeps it in the tenant metadata under KeyPrivateCIDR). Must
	// match incusx's keyV2CIDR.
	KeyV2CIDR = Prefix + "v2.cidr"
	// KeyV2Suffix is where v2 stores the Tenant DNS Suffix, on the kind=infra
	// project (ADR-0018: tenant-chosen, defaults to the tenant name).
	KeyV2Suffix = Prefix + "v2.suffix"
	// KeyV2DefaultProject is where v2 stores the short name of the tenant's
	// initial project, on the kind=infra project. The user names it at first
	// login (issue #93); it replaces the hardcoded "default" as the tenant's one
	// project. Remembered so an idempotent re-login re-derives the same name
	// instead of re-creating a duplicate "-default" project. Empty ⇒ "default".
	KeyV2DefaultProject = Prefix + "v2.default-project"
	// KeyV2Prefix is where v2 stores the installation prefix, on the kind=infra
	// project — several sandcastles can share one Incus host (--prefix).
	KeyV2Prefix = Prefix + "v2.prefix"
	// KeyV2User is where v2 stores the profile login (Unix) user, on the
	// kind=infra project. It is the actual user@host for SSH — NOT the tenant
	// name. Must match incusx's keyV2User.
	KeyV2User = Prefix + "v2.user"
	// KeyV2SSHKey is where v2 stores the tenant's login SSH public key, on the
	// kind=infra project — the durable record an idempotent re-provision must
	// reuse (#134). Must match incusx's keyV2SSHKey.
	KeyV2SSHKey = Prefix + "v2.sshkey"

	// KeyV2CloudIdentity / KeyV2DockerAutostart hold a v2 project's settings on
	// its own kind=project Incus project. They used to be written into a
	// `.sandcastle/projects` file on the tenant's workspace volume that nothing
	// ever read back, so `sc project set-cloud-identity` was a no-op.
	KeyV2CloudIdentity   = Prefix + "v2.cloud-identity"
	KeyV2DockerAutostart = Prefix + "v2.docker-autostart"
	// KeyV2TailnetEgress holds the tenant's tailnet-egress toggle on the
	// kind=infra project (ADR-0026): "true" means machines reach tailnet peers
	// (100.64.0.0/10) through the sidecar — a DHCP classless static route on the
	// tenant bridge plus a masquerade on the sidecar's tailscale0. Absent/other
	// means off. Deliberately NOT part of v2InfraMetadata: the converge reads it,
	// only `sc tailscale egress` writes it.
	KeyV2TailnetEgress = Prefix + "v2.tailnet-egress"
	// KeyV2Bare marks an INSTANCE created with `sc create --bare`: no login
	// user, no SSH key, no sshd. `sc connect` reads it to pick an Incus exec
	// session over SSH, which on such a machine could only ever time out.
	KeyV2Bare = Prefix + "v2.bare"
	// KeyV2Domain holds a project's Project Domain (ADR-0027), normalized, on
	// its own kind=project Incus project. Written by the Auth App when the
	// domain is claimed (`sc project create --domain`, `set-domain`), removed
	// by `unset-domain`. Absent ⇒ a private-mode project.
	KeyV2Domain = Prefix + "v2.domain"
	// KeyV2PublicHostname is the LEGACY single-name record of ADR-0027: the
	// derived Machine Public Hostname `<machine>.<Project Domain>`, or the
	// literal NamingModePrivate. Superseded by KeyV2PublicHostnames (ADR-0028):
	// readers accept both during the transition (the list wins when present),
	// writers write only the list. The reconciler still stamps it on first
	// sight of an unlisted Machine until slice 3 of #172 retires that path.
	KeyV2PublicHostname = Prefix + "v2.public-hostname"
	// KeyV2PublicHostnames is the INSTANCE's set of Machine Public Hostnames
	// (ADR-0028): a comma-separated, sorted, lowercase list — the derived
	// `<machine>.<Project Domain>` when the project has a domain, plus every
	// explicit hostname the tenant added (`sc create --hostname`, `sc hostname
	// add`). Written by `sc create` in the create call and rewritten by the
	// Auth App whenever a hostname is added or removed. Absent ⇒ no public
	// names (and, during the transition, fall back to KeyV2PublicHostname).
	KeyV2PublicHostnames = Prefix + "v2.public-hostnames"
	// KeyV2CertState mirrors a zone-mode Machine's Machine Certificate state
	// (pending | issued | installed | renewing | failed:<reason>) into instance
	// config, so the ADR-0023 cache path and the live Incus path render the
	// same CERT column without any CLI code asking the Auth Database. Written
	// by the reconciler, only for zone-mode Machines.
	KeyV2CertState = Prefix + "v2.cert-state"
	// KeyV2CertNotAfter is the RFC 3339 UTC expiry of the INSTALLED Machine
	// Certificate; empty until one is installed. Reconciler-written, zone-mode
	// Machines only.
	KeyV2CertNotAfter = Prefix + "v2.cert-not-after"
	// KeyBinaryVersion records the release version (vX.Y.Z) of the sandcastle
	// binary last pushed into an instance (#124 §7) — auth-app, broker, tenant
	// sidecars. Written on every binary push; missing means "unknown" and is
	// treated as outdated. NOT the topology schema version — that is KeyVersion.
	KeyBinaryVersion = Prefix + "binary-version"

	KeyAppPort   = Prefix + "app_port"
	KeyLinuxUser = Prefix + "linux_user"
	KeyCreatedBy = Prefix + "created_by"
	KeyState     = Prefix + "state"

	KindMachine   = "machine"
	KindRoute     = "route"
	KindSidecar   = "sidecar"
	KindInfra     = "infra"    // v2 per-tenant infra project (holds the sidecar + CIDR)
	KindV2Project = "project"  // v2 per-project Incus project (app machines)
	KindAuthApp   = "auth-app" // Auth App appliance instance
	KindBroker    = "broker"   // Sandcastle Broker appliance instance/project

	Version = 1

	MachineTypeContainer = "container"

	TailscaleStateRunningLoggedOut = "running-logged-out"

	// NamingModePrivate is the literal value of the legacy KeyV2PublicHostname
	// key meaning "no derived public name". Naming Mode itself is retired
	// (ADR-0028): a Machine always has its Machine Private Hostname and
	// additionally a set of Machine Public Hostnames. NamingModeZone survives
	// only as the reconciler's log vocabulary until slice 3 of #172.
	NamingModePrivate = "private"
	NamingModeZone    = "zone"

	// Machine Certificate states as mirrored into KeyV2CertState. A failed
	// state carries a reason suffix: CertStateFailedPrefix + "<reason>".
	CertStatePending      = "pending"
	CertStateIssued       = "issued"
	CertStateInstalled    = "installed"
	CertStateRenewing     = "renewing"
	CertStateFailedPrefix = "failed:"
)

type Project struct {
	Name            string `json:"name"`
	CreatedBy       string `json:"createdBy,omitempty"`
	CloudIdentity   string `json:"cloudIdentity,omitempty"`
	DockerAutostart bool   `json:"dockerAutostart,omitempty"`
	// Domain is the project's Project Domain (KeyV2Domain, ADR-0027); empty
	// for a private-mode project.
	Domain string `json:"domain,omitempty"`
}

type Tailscale struct {
	State            string   `json:"state,omitempty"`
	Tailnet          string   `json:"tailnet,omitempty"`
	Hostname         string   `json:"hostname,omitempty"`
	AdvertisedRoutes []string `json:"advertisedRoutes,omitempty"`
	TailscaleIPs     []string `json:"tailscaleIPs,omitempty"`
	LastCheckedAt    string   `json:"lastCheckedAt,omitempty"`
}

type MachineRef struct {
	Project string `json:"project"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
}

type PublicRoute struct {
	Hostname  string `json:"hostname"`
	Project   string `json:"project"`
	Machine   string `json:"machine"`
	RoutePort int    `json:"routePort"`
}

type TenantStorageShare struct {
	SourceTenant  string                        `json:"sourceTenant"`
	SourceProject string                        `json:"sourceProject"`
	SourceDir     string                        `json:"sourceDir"`
	Name          string                        `json:"name"`
	Availability  string                        `json:"availability,omitempty"`
	CreatedBy     string                        `json:"createdBy,omitempty"`
	CreatedAt     string                        `json:"createdAt,omitempty"`
	Recipients    []TenantStorageShareRecipient `json:"recipients,omitempty"`
}

type TenantStorageShareRecipient struct {
	Tenant     string `json:"tenant"`
	State      string `json:"state"`
	OfferedBy  string `json:"offeredBy,omitempty"`
	OfferedAt  string `json:"offeredAt,omitempty"`
	AcceptedBy string `json:"acceptedBy,omitempty"`
	AcceptedAt string `json:"acceptedAt,omitempty"`
	DeclinedBy string `json:"declinedBy,omitempty"`
	DeclinedAt string `json:"declinedAt,omitempty"`
}

type Machine struct {
	Tenant          string   `json:"tenant"`
	Project         string   `json:"project"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Template        string   `json:"template,omitempty"`
	AppPort         int      `json:"appPort"`
	PrivateIP       string   `json:"privateIP"`
	TailscaleIP     string   `json:"tailscaleIP,omitempty"`
	LinuxUser       string   `json:"linuxUser,omitempty"`
	CloudIdentity   string   `json:"cloudIdentity,omitempty"`
	DockerAutostart bool     `json:"dockerAutostart,omitempty"`
	HomeDir         string   `json:"homeDir,omitempty"`
	WorkspaceDir    string   `json:"workspaceDir,omitempty"`
	ContainerTools  bool     `json:"containerTools,omitempty"`
	ExtraSANs       []string `json:"extraSANs,omitempty"`
	CreatedBy       string   `json:"createdBy,omitempty"`
	CreatedAt       string   `json:"createdAt,omitempty"`
	Running         bool     `json:"running,omitempty"`
	// Bare marks a machine created with `sc create --bare`: no login user, no
	// sshd, no shared storage. It changes how the machine is reached, so a
	// listing says so rather than leaving `sc connect` to time out.
	Bare bool `json:"bare,omitempty"`
	// Machine Public Hostnames (ADR-0028). PublicHostnames is the machine's
	// full set of public names from KeyV2PublicHostnames (sorted; falling back
	// to the legacy single KeyV2PublicHostname during the transition), empty
	// for a machine with no public name. PublicHostname is kept for one
	// release as the FIRST element of that list (empty when the list is);
	// new code reads PublicHostnames. CertState and CertNotAfter mirror
	// KeyV2CertState / KeyV2CertNotAfter and are only read when the machine
	// has at least one public name.
	PublicHostname  string   `json:"publicHostname,omitempty"`
	PublicHostnames []string `json:"publicHostnames,omitempty"`
	CertState       string   `json:"certState,omitempty"`
	CertNotAfter    string   `json:"certNotAfter,omitempty"`
}

// PublicNames returns the machine's public-name set, tolerating a payload
// that carries only the legacy single PublicHostname — the resource cache of
// an Auth App from before ADR-0028, or a hand-built value.
func (m Machine) PublicNames() []string {
	if len(m.PublicHostnames) > 0 {
		return m.PublicHostnames
	}
	if name := strings.TrimSpace(m.PublicHostname); name != "" {
		return []string{name}
	}
	return nil
}

// HasPublicHostname reports whether the machine carries at least one Machine
// Public Hostname (derived or explicit).
func (m Machine) HasPublicHostname() bool {
	return len(m.PublicNames()) > 0
}

// NamingMode is the retired ADR-0027 mode, kept for one release as a
// readability shim: NamingModeZone when the machine has any public name,
// NamingModePrivate otherwise. Prefer HasPublicHostname.
func (m Machine) NamingMode() string {
	if m.HasPublicHostname() {
		return NamingModeZone
	}
	return NamingModePrivate
}

// PublicHostnameFromConfig reads the legacy single-name record off an
// instance's own config: the derived Machine Public Hostname, or "" when the
// key is absent or holds the literal NamingModePrivate. Kept for the
// transition; new readers use PublicHostnamesFromConfig.
func PublicHostnameFromConfig(config map[string]string) string {
	hostname := strings.TrimSpace(config[KeyV2PublicHostname])
	if hostname == "" || hostname == NamingModePrivate {
		return ""
	}
	return hostname
}

// PublicHostnamesFromConfig reads a machine's set of Machine Public Hostnames
// (ADR-0028) off its own config: KeyV2PublicHostnames when present (split,
// normalized, sorted, deduplicated), else the legacy single
// KeyV2PublicHostname as a one-element list, else nothing.
func PublicHostnamesFromConfig(config map[string]string) []string {
	if list := ParsePublicHostnames(config[KeyV2PublicHostnames]); len(list) > 0 {
		return list
	}
	if single := PublicHostnameFromConfig(config); single != "" {
		return []string{single}
	}
	return nil
}

// ParsePublicHostnames splits the KeyV2PublicHostnames value: comma-separated
// names, lowercased and trimmed, sorted, without duplicates or blanks.
func ParsePublicHostnames(value string) []string {
	var names []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(value, ",") {
		name := strings.Trim(strings.ToLower(strings.TrimSpace(part)), ".")
		if name == "" || name == NamingModePrivate {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// FormatPublicHostnames renders a set of names as the KeyV2PublicHostnames
// value: the ParsePublicHostnames normalization, joined with commas. An empty
// set renders as "" (the key is then deleted, never written empty).
func FormatPublicHostnames(names []string) string {
	return strings.Join(ParsePublicHostnames(strings.Join(names, ",")), ",")
}

// DecodeMachine fills the public-name fields of machine from an instance's
// own config (ADR-0027/0028). It is the one place those keys are read, and
// every instance → Machine conversion — the live per-project sweep and the
// ADR-0023 resource-cache renderer alike — funnels through it, so the two
// paths cannot disagree on a machine's public names or certificate state. A
// machine without public names comes back untouched: the certificate keys
// are ignored unless the machine has a public name, so a stray cert-state on
// an unstamped machine can never make it render as anything but private.
func DecodeMachine(config map[string]string, machine Machine) Machine {
	machine.PublicHostnames = PublicHostnamesFromConfig(config)
	machine.PublicHostname = ""
	if len(machine.PublicHostnames) == 0 {
		machine.CertState = ""
		machine.CertNotAfter = ""
		return machine
	}
	machine.PublicHostname = machine.PublicHostnames[0]
	machine.CertState = strings.TrimSpace(config[KeyV2CertState])
	machine.CertNotAfter = strings.TrimSpace(config[KeyV2CertNotAfter])
	return machine
}

type Route struct {
	Hostname        string `json:"hostname"`
	TargetTenant    string `json:"targetTenant"`
	TargetProject   string `json:"targetProject"`
	TargetMachine   string `json:"targetMachine"`
	TargetIP        string `json:"targetIP"`
	RoutePort       int    `json:"routePort"`
	CreatedBy       string `json:"createdBy,omitempty"`
	IngressAttached bool   `json:"ingressAttached,omitempty"`
}

func MachineConfig(machine Machine) (map[string]string, error) {
	state, err := encodeState(machine)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		KeyKind:      KindMachine,
		KeyVersion:   strconv.Itoa(Version),
		KeyTenant:    machine.Tenant,
		KeyProject:   machine.Project,
		KeyMachine:   machine.Name,
		KeyType:      machine.Type,
		KeyAppPort:   strconv.Itoa(machine.AppPort),
		KeyLinuxUser: machine.LinuxUser,
		KeyCreatedBy: machine.CreatedBy,
		KeyState:     state,
	}, nil
}

func ParseMachineConfig(config map[string]string) (Machine, error) {
	if err := requireKind(config, KindMachine); err != nil {
		return Machine{}, err
	}
	var machine Machine
	if err := decodeState(config[KeyState], &machine); err != nil {
		return Machine{}, err
	}
	if machine.Type == "" && config[KeyType] != "" {
		machine.Type = config[KeyType]
	}
	if machine.Type == "" {
		machine.Type = MachineTypeContainer
	}
	if machine.LinuxUser == "" && config[KeyLinuxUser] != "" {
		machine.LinuxUser = config[KeyLinuxUser]
	}
	if machine.LinuxUser == "" {
		machine.LinuxUser = machine.CreatedBy
	}
	return machine, nil
}

func RouteConfig(route Route) (map[string]string, error) {
	state, err := encodeState(route)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		KeyKind:      KindRoute,
		KeyVersion:   strconv.Itoa(Version),
		KeyHostname:  route.Hostname,
		KeyTenant:    route.TargetTenant,
		KeyProject:   route.TargetProject,
		KeyMachine:   route.TargetMachine,
		KeyAppPort:   strconv.Itoa(route.RoutePort),
		KeyCreatedBy: route.CreatedBy,
		KeyState:     state,
	}, nil
}

func ParseRouteConfig(config map[string]string) (Route, error) {
	if err := requireKind(config, KindRoute); err != nil {
		return Route{}, err
	}
	var route Route
	if err := decodeState(config[KeyState], &route); err != nil {
		return Route{}, err
	}
	return route, nil
}

func IsManaged(config map[string]string) bool {
	return config[KeyKind] != "" && config[KeyVersion] != ""
}

func requireKind(config map[string]string, kind string) error {
	if config[KeyKind] != kind {
		return fmt.Errorf("metadata kind = %q, want %q", config[KeyKind], kind)
	}
	if config[KeyVersion] != strconv.Itoa(Version) {
		return fmt.Errorf("metadata version = %q, want %d", config[KeyVersion], Version)
	}
	return nil
}

func encodeState(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeState(value string, target any) error {
	if value == "" {
		return fmt.Errorf("metadata state is required")
	}
	return json.Unmarshal([]byte(value), target)
}
