package tenant

import (
	"strconv"
	"strings"
)

// Tailnet egress (ADR-0026, ADR-0033): machines are not tailnet nodes, so
// without help a packet from a machine to a tailnet address follows the default
// route to the host bridge gateway and dies on the public uplink. Egress steers
// that traffic at the sidecar (a DHCP classless static route on the tenant
// bridge) and masquerades it onto the sidecar's tailscale0, so tailnet peers see
// a normal connection from the sidecar's tailnet IP and need no knowledge of the
// tenant CIDR. The tailnet ACL still governs what the sidecar's tag may reach —
// egress delivers packets, the ACL decides their fate.

// EgressSteeredPrefixes are the destinations option 121 sends to the sidecar,
// in order: tailnet node addresses (the CGNAT range), then the private range
// other tailnet routers advertise subnet routes from — every Sandcastle tenant
// pool is a /16 inside 10.0.0.0/8, so this reaches other installs' machines.
// The tenant's own /24 stays on-link (more specific), so gateway, broker and
// DNS are unaffected; 10.x destinations no tailnet route covers fall through
// the sidecar's main table back to the host.
var EgressSteeredPrefixes = []string{"100.64.0.0/10", "10.0.0.0/8"}

// BridgeDHCPOptions renders the tenant bridge's raw.dnsmasq value: always the
// CoreDNS resolver option (ADR-0018), plus — with egress on — a classless
// static route (option 121) steering EgressSteeredPrefixes at the sidecar.
// RFC 3442 requires a client that receives option 121 to IGNORE the router
// option, so the default route must ride along in the same option or clients
// would lose their gateway.
func BridgeDHCPOptions(dnsAddress, gatewayAddress string, egress bool) string {
	options := "dhcp-option=6," + dnsAddress
	if !egress {
		return options
	}
	routes := make([]string, 0, 2*len(EgressSteeredPrefixes)+2)
	for _, prefix := range EgressSteeredPrefixes {
		routes = append(routes, prefix, dnsAddress)
	}
	routes = append(routes, "0.0.0.0/0", gatewayAddress)
	return options + "\ndhcp-option=121," + strings.Join(routes, ",")
}

// SidecarAcceptRoutesFlag is the sidecar's tailscale accept-routes setting:
// the sidecar installs other routers' subnet routes only while egress is on,
// and an explicit false restores the default when egress is switched off.
func SidecarAcceptRoutesFlag(egress bool) string {
	return "--accept-routes=" + strconv.FormatBool(egress)
}

// SidecarEgressNftRuleset renders /etc/sandcastle-egress.nft. The
// declare/delete/declare idiom makes `nft -f` an atomic, idempotent replace of
// our own table. This NAT is independent of the bridge's ipv4.nat=true (the
// host masquerades machine→internet); it covers only the tailscale0 path, and
// any destination tailscaled routes there (node or accepted subnet route).
func SidecarEgressNftRuleset(privateCIDR string) string {
	return `table ip sandcastle-egress
delete table ip sandcastle-egress
table ip sandcastle-egress {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "tailscale0" ip saddr ` + privateCIDR + ` masquerade
	}
}
`
}

// SidecarOwnSubnetRulePriority sits ahead of tailscaled's policy rules
// (5210-5270): with --accept-routes, table 52 is consulted before main, so a
// tailnet router advertising a prefix that covers the tenant's own /24 (two
// installs on the same default pool) would otherwise capture the sidecar's own
// bridge traffic.
const SidecarOwnSubnetRulePriority = 5200

// SidecarOwnSubnetRuleCleanup removes the own-subnet rule; idempotent.
func SidecarOwnSubnetRuleCleanup() string {
	return "while ip rule del priority " + strconv.Itoa(SidecarOwnSubnetRulePriority) + " 2>/dev/null; do :; done"
}

// SidecarEgressScript renders /usr/local/sbin/sandcastle-sidecar-egress, run by
// the oneshot unit at boot and on converge.
func SidecarEgressScript(privateCIDR string) string {
	return `#!/bin/sh
set -eu
sysctl -qw net.ipv4.ip_forward=1
` + SidecarOwnSubnetRuleCleanup() + `
ip rule add to ` + privateCIDR + ` lookup main priority ` + strconv.Itoa(SidecarOwnSubnetRulePriority) + `
exec nft -f /etc/sandcastle-egress.nft
`
}

// SidecarEgressUnit renders the systemd oneshot applying the egress rules.
func SidecarEgressUnit() string {
	return `[Unit]
Description=Sandcastle sidecar tailnet egress (NAT machines onto tailscale0)
After=sandcastle-sidecar-network.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sandcastle-sidecar-egress
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`
}
