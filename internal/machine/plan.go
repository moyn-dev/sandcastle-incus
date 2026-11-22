package machine

import (
	"context"
	"fmt"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/certs"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

const DefaultAppPort = 3000
const (
	DefaultLinuxUID = 1000
	DefaultLinuxGID = 1000
)
const (
	TemplateAI   = "ai"
	TemplateBase = "base"
)
const (
	CaddyfilePath       = "/etc/caddy/Caddyfile"
	MachineCertPath     = "/etc/caddy/certs/tls.crt"
	MachineCertKeyPath  = "/etc/caddy/certs/tls.key"
	machineCertKeyMode  = 0o600
	machineCertFileMode = 0o644
)

type Device map[string]string

type File struct {
	Path    string `json:"path"`
	Content []byte `json:"-"`
	Mode    int    `json:"mode"`
}

type Store interface {
	ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error)
}

// ProjectScopedStore is the scoped form of Store: a store that can answer for a
// subset of a tenant's projects — projectFilter is a project name or a
// shell-style glob — without querying the rest. A whole-tenant listing costs one
// Incus round trip per project, so callers that can narrow at all should
// type-assert for this and use it.
type ProjectScopedStore interface {
	ListMachinesInProject(ctx context.Context, summary tenant.Summary, projectFilter string) ([]meta.Machine, error)
}

type UnmanagedMachine struct {
	Tenant       string `json:"tenant"`
	Name         string `json:"name"`
	InstanceName string `json:"instanceName"`
	Type         string `json:"type,omitempty"`
	PrivateIP    string `json:"privateIp,omitempty"`
	Status       string `json:"status,omitempty"`
	CreatedAt    string `json:"createdAt,omitempty"`
	Running      bool   `json:"running"`
}

type UnmanagedStore interface {
	ListUnmanagedMachines(ctx context.Context, summary tenant.Summary) ([]UnmanagedMachine, error)
}

type CombinedStore interface {
	ListMachinesAndUnmanaged(ctx context.Context, summary tenant.Summary) ([]meta.Machine, []UnmanagedMachine, error)
}

// ProjectScopedCombinedStore is CombinedStore scoped to one Sandcastle project.
// See ProjectScopedStore.
type ProjectScopedCombinedStore interface {
	ListMachinesAndUnmanagedInProject(ctx context.Context, summary tenant.Summary, projectFilter string) ([]meta.Machine, []UnmanagedMachine, error)
}

func IssueCertificateFiles(machineName string, projectName string, suffix string, caCertPEM []byte, caKeyPEM []byte) ([]File, error) {
	return IssueCertificateFilesWithExtraSANs(machineName, projectName, suffix, nil, caCertPEM, caKeyPEM)
}

func IssueCertificateFilesWithExtraSANs(machineName string, projectName string, suffix string, extraSANs []string, caCertPEM []byte, caKeyPEM []byte) ([]File, error) {
	hostname := MachineHostname(machineName, projectName, suffix)
	leaf, err := certs.IssueMachineLeaf(
		caCertPEM,
		caKeyPEM,
		hostname,
		certs.MachineDNSNames(machineName+"."+projectName, suffix, extraSANs),
		time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("issue machine certificate: %w", err)
	}
	return []File{
		{Path: MachineCertPath, Content: leaf.CertificatePEM, Mode: machineCertFileMode},
		{Path: MachineCertKeyPath, Content: leaf.PrivateKeyPEM, Mode: machineCertKeyMode},
	}, nil
}

func MachineHostname(machineName string, projectName string, suffix string) string {
	return machineName + "." + projectName + "." + suffix
}

func ShortMachineHostname(machineName string, projectName string) string {
	return machineName + "." + projectName
}

type tenantFilterableStore interface {
	WithTenantFilter(...string) tenant.IncusTenantStore
}

// errV2TenantUnsupported keeps the v1 machine-plan machinery (connect, delete,
// restart, port, …) from proceeding on a v2 tenant: its freeform instances use
// plain names, not the v1 <project>-<machine> convention, so v1 plans would
// target instances that don't exist.
