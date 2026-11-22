package dns

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/moyn-dev/sandcastle-incus/internal/cidr"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

type Applier interface {
	Apply(context.Context, Tenant) (ApplyResult, error)
}

type Tenant struct {
	IncusName    string `json:"incusName"`
	InfraProject string `json:"infraProject"`
	Tenant       string `json:"tenant"`
	DNSSuffix    string `json:"dnsSuffix"`
	// DefaultProject is the short name of the tenant's default project (issue
	// #93); the short-alias record follows it. Empty ⇒ "default".
	DefaultProject string `json:"defaultProject,omitempty"`
	PrivateCIDR    string `json:"privateCIDR"`
}

type ApplyResult struct {
	Tenant      Tenant         `json:"tenant"`
	DNSAddress  string         `json:"dnsAddress"`
	Machines    []meta.Machine `json:"machines"`
	Files       []File         `json:"files"`
	RecordCount int            `json:"recordCount"`
}

func PlanApply(summary Tenant, machines []meta.Machine) (ApplyResult, error) {
	dnsAddress, err := dnsAddress(summary.PrivateCIDR)
	if err != nil {
		return ApplyResult{}, err
	}
	files, err := RenderTenant(summary.DNSSuffix, dnsAddress, summary.DefaultProject, machines)
	if err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{
		Tenant:      summary,
		DNSAddress:  dnsAddress,
		Machines:    machines,
		Files:       files,
		RecordCount: 2 + len(machines)*2,
	}, nil
}

func dnsAddress(privateCIDR string) (string, error) {
	return roleAddress(privateCIDR, cidr.DNSHostOctet)
}

func roleAddress(privateCIDR string, hostOctet byte) (string, error) {
	prefix, err := netip.ParsePrefix(privateCIDR)
	if err != nil {
		return "", err
	}
	addr := prefix.Masked().Addr().As4()
	addr[3] = hostOctet
	candidate := netip.AddrFrom4(addr)
	if !prefix.Contains(candidate) {
		return "", fmt.Errorf("address .%d is outside %s", hostOctet, privateCIDR)
	}
	return candidate.String(), nil
}
