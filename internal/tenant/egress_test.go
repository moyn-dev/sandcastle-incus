package tenant

import "testing"

// With egress off the bridge carries only the CoreDNS resolver option — the
// pre-ADR-0026 value, byte-identical so existing bridges stay converged.
func TestBridgeDHCPOptionsOff(t *testing.T) {
	got := BridgeDHCPOptions("10.249.7.3", "10.249.7.1", false)
	if got != "dhcp-option=6,10.249.7.3" {
		t.Fatalf("BridgeDHCPOptions(off) = %q", got)
	}
}

// With egress on, option 121 steers the CGNAT range and 10.0.0.0/8 (other
// installs' subnet routes), in that order, at the sidecar AND must
// carry the default route: RFC 3442 makes clients that receive option 121
// ignore the router option, so omitting 0.0.0.0/0 would cut every machine off
// from its gateway.
func TestBridgeDHCPOptionsOnCarriesDefaultRoute(t *testing.T) {
	got := BridgeDHCPOptions("10.249.7.3", "10.249.7.1", true)
	want := "dhcp-option=6,10.249.7.3\ndhcp-option=121,100.64.0.0/10,10.249.7.3,10.0.0.0/8,10.249.7.3,0.0.0.0/0,10.249.7.1"
	if got != want {
		t.Fatalf("BridgeDHCPOptions(on) = %q, want %q", got, want)
	}
}

// The ruleset is an atomic idempotent replace (declare/delete/declare) that
// masquerades every tenant-sourced packet leaving tailscale0, whatever its
// destination: accepted subnet routes sit outside the CGNAT range.
func TestSidecarEgressNftRuleset(t *testing.T) {
	got := SidecarEgressNftRuleset("10.249.7.0/24")
	want := `table ip sandcastle-egress
delete table ip sandcastle-egress
table ip sandcastle-egress {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "tailscale0" ip saddr 10.249.7.0/24 masquerade
	}
}
`
	if got != want {
		t.Fatalf("SidecarEgressNftRuleset =\n%s\nwant\n%s", got, want)
	}
}
