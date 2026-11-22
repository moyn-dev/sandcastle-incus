package incusx

import (
	"context"
	"fmt"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"github.com/moyn-dev/sandcastle-incus/internal/projectbroker"
)

type RouteBrokerTrustServer interface {
	GetCertificates() ([]api.Certificate, error)
}

type RouteBrokerTrustMapper struct {
	Remote     string
	ConfigPath string
	Server     RouteBrokerTrustServer
}

func NewRouteBrokerTrustMapper(remote string) RouteBrokerTrustMapper {
	return RouteBrokerTrustMapper{Remote: remote}
}

func NewRouteBrokerTrustMapperForServer(server incus.InstanceServer) RouteBrokerTrustMapper {
	return RouteBrokerTrustMapper{Server: server}
}

func (m RouteBrokerTrustMapper) PrincipalForFingerprint(ctx context.Context, fingerprint string) (projectbroker.TrustPrincipal, error) {
	server := m.Server
	if server == nil {
		loaded, err := LoadCLIConfig(m.ConfigPath)
		if err != nil {
			return projectbroker.TrustPrincipal{}, fmt.Errorf("load Incus config: %w", err)
		}
		remote := m.Remote
		if remote == "" {
			remote = loaded.DefaultRemote
		}
		instanceServer, err := connectInstanceServer(loaded, remote)
		if err != nil {
			return projectbroker.TrustPrincipal{}, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
		}
		server = instanceServer
	}
	certificates, err := server.GetCertificates()
	if err != nil {
		return projectbroker.TrustPrincipal{}, fmt.Errorf("list Incus certificates: %w", err)
	}
	normalized := normalizeFingerprint(fingerprint)
	for _, certificate := range certificates {
		if normalizeFingerprint(certificate.Fingerprint) != normalized {
			continue
		}
		user := userFromCertificate(certificate)
		if user == "" {
			return projectbroker.TrustPrincipal{}, fmt.Errorf("certificate %s is not a Sandcastle restricted user certificate", fingerprint)
		}
		return projectbroker.TrustPrincipal{
			Fingerprint: normalized,
			User:        user,
			Projects:    append([]string{}, certificate.Projects...),
		}, nil
	}
	return projectbroker.TrustPrincipal{}, fmt.Errorf("certificate fingerprint %s is not trusted", fingerprint)
}

func userFromCertificate(certificate api.Certificate) string {
	if certificate.Type != api.CertificateTypeClient || !certificate.Restricted {
		return ""
	}
	return userFromCertificateName(certificate.CertificatePut.Name)
}

func userFromCertificateName(name string) string {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "sandcastle-") {
		return ""
	}
	user := strings.TrimPrefix(name, "sandcastle-")
	if err := naming.ValidateTenantName(user); err != nil {
		return ""
	}
	return user
}

func normalizeFingerprint(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), ":", "")
}
