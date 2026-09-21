package incusx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

// errRestrictedCertificateNotFound marks a Grant/Revoke lookup that found no
// trust entry under the plan's certificate name. With shared client identity
// the keypair's one trust entry is named after whichever tenant enrolled it
// first, so callers holding the caller's certificate can recover by unioning
// projects into that entry by fingerprint instead (EnsureClientCertificate).
var errRestrictedCertificateNotFound = errors.New("restricted certificate not found")

type TrustServer interface {
	GetCertificates() ([]api.Certificate, error)
	UpdateCertificate(fingerprint string, certificate api.CertificatePut, ETag string) error
	DeleteCertificate(fingerprint string) error
	CreateCertificateToken(certificate api.CertificatesPost) (incus.Operation, error)
}

type TrustManager struct {
	Remote     string
	ConfigPath string
	Server     TrustServer
}

func NewTrustManager(remote string) TrustManager {
	return TrustManager{Remote: remote}
}

func NewTrustManagerForServer(server incus.InstanceServer) TrustManager {
	return TrustManager{Server: server}
}

func (m TrustManager) Grant(ctx context.Context, plan usertrust.UserPlan) error {
	server, err := m.server()
	if err != nil {
		return err
	}
	certs, err := findCertificates(server, plan.CertificateName)
	if err != nil {
		return err
	}
	granted := 0
	for _, cert := range certs {
		if err := validateGrantCertificate(cert, plan.CertificateName); err != nil {
			return err
		}
		// A restricted client entry with ZERO projects is a dead keypair: every
		// live device holds at least one project (enrollment grants one, and
		// #113 sweeps entries a teardown emptied). Extending it would re-arm
		// standing trust nothing legitimate uses (#115) — skip, never grant.
		if len(cert.Projects) == 0 {
			continue
		}
		if err := extendCertificateProjects(server, cert, plan); err != nil {
			return err
		}
		granted++
	}
	if granted == 0 {
		return fmt.Errorf("every trust entry named %q holds no projects (dead keypairs from torn-down tenants); remove them (`incus config trust remove <fingerprint>`) and re-enroll the user", plan.CertificateName)
	}
	return nil
}

// extendCertificateProjects unions plan.Projects into one trust entry — the
// shared write behind Grant and GrantTenantFleet.
func extendCertificateProjects(server TrustServer, cert api.Certificate, plan usertrust.UserPlan) error {
	projects := mergeProjects(cert.Projects, plan.Projects)
	if err := server.UpdateCertificate(cert.Fingerprint, api.CertificatePut{
		Name:        cert.Name,
		Type:        api.CertificateTypeClient,
		Restricted:  true,
		Projects:    projects,
		Certificate: cert.Certificate,
		Description: plan.Description,
	}, ""); err != nil {
		return fmt.Errorf("update certificate %s: %w", cert.Fingerprint[:min(12, len(cert.Fingerprint))], err)
	}
	return nil
}

// GrantTenantFleet extends the tenant's OTHER enrolled devices with
// plan.Projects: trust entries under plan.CertificateName that ALREADY hold a
// project inside the tenant's namespace (the infra project or anything under
// `<namespace>-`). Same-named entries with no such project are never touched —
// a name-bucket Grant re-armed dead keypairs whose project names recurred
// (#115); an entry emptied by a teardown, or one granting only another
// tenant's projects, is not part of this tenant's fleet. The CALLER's own
// certificate is extended separately by fingerprint (EnsureClientCertificate).
// Finding no fleet entries is a no-op, not an error.
func (m TrustManager) GrantTenantFleet(ctx context.Context, plan usertrust.UserPlan, tenantNamespace string) error {
	tenantNamespace = strings.TrimSpace(tenantNamespace)
	if tenantNamespace == "" || strings.TrimSpace(plan.CertificateName) == "" {
		return nil
	}
	server, err := m.server()
	if err != nil {
		return err
	}
	certificates, err := server.GetCertificates()
	if err != nil {
		return fmt.Errorf("list Incus certificates: %w", err)
	}
	for _, cert := range certificates {
		if cert.Name != plan.CertificateName || cert.Type != api.CertificateTypeClient || !cert.Restricted {
			continue
		}
		inFleet := false
		for _, project := range cert.Projects {
			if project == tenantNamespace || strings.HasPrefix(project, tenantNamespace+"-") {
				inFleet = true
				break
			}
		}
		if !inFleet {
			continue
		}
		if err := extendCertificateProjects(server, cert, plan); err != nil {
			return err
		}
	}
	return nil
}

func (m TrustManager) Revoke(ctx context.Context, plan usertrust.UserPlan) error {
	server, err := m.server()
	if err != nil {
		return err
	}
	certs, err := findCertificates(server, plan.CertificateName)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if err := validateGrantCertificate(cert, plan.CertificateName); err != nil {
			return err
		}
		projects := removeProjects(cert.Projects, plan.Projects)
		if err := server.UpdateCertificate(cert.Fingerprint, api.CertificatePut{
			Name:        cert.Name,
			Type:        api.CertificateTypeClient,
			Restricted:  true,
			Projects:    projects,
			Certificate: cert.Certificate,
			Description: plan.Description,
		}, ""); err != nil {
			return fmt.Errorf("update certificate %s: %w", cert.Fingerprint[:12], err)
		}
	}
	return nil
}

func (m TrustManager) Delete(ctx context.Context, plan usertrust.UserPlan) error {
	server, err := m.server()
	if err != nil {
		return err
	}
	certs, err := findCertificates(server, plan.CertificateName)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if err := validateGrantCertificate(cert, plan.CertificateName); err != nil {
			return err
		}
		if err := server.DeleteCertificate(cert.Fingerprint); err != nil {
			return fmt.Errorf("delete certificate %s: %w", cert.Fingerprint[:12], err)
		}
	}
	return nil
}

func (m TrustManager) ListTenantUsers(ctx context.Context, plan usertrust.TenantUsersPlan) (usertrust.TenantUsersResult, error) {
	server, err := m.server()
	if err != nil {
		return usertrust.TenantUsersResult{}, err
	}
	certificates, err := server.GetCertificates()
	if err != nil {
		return usertrust.TenantUsersResult{}, fmt.Errorf("list Incus certificates: %w", err)
	}
	users := []string{}
	for _, cert := range certificates {
		if cert.Type != api.CertificateTypeClient || !cert.Restricted {
			continue
		}
		// A tenant's users are the entries holding ANY project of its
		// namespace: a Personal Tenant's own login certificate holds the app
		// projects but not the infra project, so matching the infra project
		// alone listed "none" for every personal tenant.
		if !holdsTenantProject(cert.Projects, plan.IncusProject) {
			continue
		}
		user := strings.TrimPrefix(cert.Name, usertrust.CertificateNamePrefix)
		if user == "" {
			user = cert.Name
		}
		users = append(users, user)
	}
	sort.Strings(users)
	return usertrust.TenantUsersResult{
		Tenant:       plan.Tenant,
		IncusProject: plan.IncusProject,
		Users:        users,
	}, nil
}

// EnsureClientCertificate implements shared client identity across installs
// sharing one Incus daemon: when the client's existing certificate is already
// trusted (enrolled by ANY install), Incus keys trust by fingerprint — one
// entry, one project list — so this unions the plan's projects into that
// entry instead of trying to add the certificate again. Returns whether the
// certificate was found (true = enrollment token redemption will be a no-op
// for the client; the union here is what actually grants access).
func (m TrustManager) EnsureClientCertificate(ctx context.Context, certificatePEM string, plan usertrust.UserPlan) (bool, error) {
	fingerprint, err := certificatePEMFingerprint(certificatePEM)
	if err != nil {
		return false, err
	}
	server, err := m.server()
	if err != nil {
		return false, err
	}
	certificates, err := server.GetCertificates()
	if err != nil {
		return false, err
	}
	for _, cert := range certificates {
		if !strings.EqualFold(cert.Fingerprint, fingerprint) {
			continue
		}
		projects := mergeProjects(cert.Projects, plan.Projects)
		description := cert.Description
		if description == "" {
			description = plan.Description
		}
		if err := server.UpdateCertificate(cert.Fingerprint, api.CertificatePut{
			Name:        cert.Name,
			Type:        api.CertificateTypeClient,
			Restricted:  true,
			Projects:    projects,
			Certificate: cert.Certificate,
			Description: description,
		}, ""); err != nil {
			return false, fmt.Errorf("extend certificate %s: %w", cert.Fingerprint[:12], err)
		}
		return true, nil
	}
	return false, nil
}

// certificatePEMFingerprint returns the SHA-256 fingerprint (hex) of the
// first certificate in the PEM, matching Incus trust-store fingerprints.
func certificatePEMFingerprint(certificatePEM string) (string, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate in PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func (m TrustManager) CreateToken(ctx context.Context, plan usertrust.UserPlan) (usertrust.TokenResult, error) {
	server, err := m.server()
	if err != nil {
		return usertrust.TokenResult{}, err
	}
	// A certificate add token can only be minted when the daemon is listening on
	// the network ("Can't issue token when server isn't listening on network").
	// A freshly `incus admin init --minimal`'d host only has the unix socket, so
	// ensure the network listener is on before provisioning issues a token.
	if err := ensureServerListening(server); err != nil {
		return usertrust.TokenResult{}, err
	}
	op, err := server.CreateCertificateToken(api.CertificatesPost{
		Token: true,
		CertificatePut: api.CertificatePut{
			Name:        plan.CertificateName,
			Type:        api.CertificateTypeClient,
			Restricted:  plan.Restricted,
			Projects:    plan.Projects,
			Description: plan.Description,
		},
	})
	if err != nil {
		return usertrust.TokenResult{}, err
	}
	opAPI := op.Get()
	token, err := (&opAPI).ToCertificateAddToken()
	if err != nil {
		return usertrust.TokenResult{}, err
	}
	remoteName := plan.RemoteName
	if remoteName == "" {
		remoteName = usertrust.RestrictedName(plan.User)
	}
	return usertrust.TokenResult{
		User:            plan.User,
		CertificateName: plan.CertificateName,
		RemoteName:      remoteName,
		Restricted:      plan.Restricted,
		Projects:        plan.Projects,
		Token:           token.String(),
	}, nil
}

// defaultHostHTTPSAddress is where the host Incus listens for the network API.
// mTLS + restricted per-tenant certs are the isolation boundary (ADR-0017), so
// binding all interfaces is intentional; the client's remote URL is pinned to the
// sidecar's tailnet IP, not to whatever addresses the daemon advertises.
const defaultHostHTTPSAddress = ":8443"

// ensureServerListening turns on the daemon's network listener if it is off, so
// CreateCertificateToken can mint enrollment tokens. It is idempotent and a no-op
// when core.https_address is already set or the server can't be introspected.
func ensureServerListening(server TrustServer) error {
	full, ok := server.(incus.InstanceServer)
	if !ok {
		return nil
	}
	info, etag, err := full.GetServer()
	if err != nil {
		return fmt.Errorf("read Incus server config: %w", err)
	}
	if strings.TrimSpace(info.Config["core.https_address"]) != "" {
		return nil
	}
	put := info.Writable()
	if put.Config == nil {
		put.Config = map[string]string{}
	}
	put.Config["core.https_address"] = defaultHostHTTPSAddress
	if err := full.UpdateServer(put, etag); err != nil {
		return fmt.Errorf("enable Incus network listener (core.https_address=%s): %w", defaultHostHTTPSAddress, err)
	}
	return nil
}

func (m TrustManager) server() (TrustServer, error) {
	if m.Server != nil {
		return m.Server, nil
	}
	loaded, err := LoadCLIConfig(m.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := m.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	server, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return server, nil
}

func findCertificates(server TrustServer, name string) ([]api.Certificate, error) {
	certificates, err := server.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("list Incus certificates: %w", err)
	}
	var matches []api.Certificate
	for _, cert := range certificates {
		if cert.Name == name {
			matches = append(matches, cert)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("restricted certificate %q not found; create a token first and add the client certificate: %w", name, errRestrictedCertificateNotFound)
	}
	return matches, nil
}

func validateGrantCertificate(certificate api.Certificate, name string) error {
	if certificate.Type != api.CertificateTypeClient {
		return fmt.Errorf("restricted certificate %q is %q, want client certificate", name, certificate.Type)
	}
	if !certificate.Restricted {
		return fmt.Errorf("restricted certificate %q is not restricted", name)
	}
	return nil
}

func mergeProjects(existing []string, added []string) []string {
	seen := map[string]bool{}
	merged := make([]string, 0, len(existing)+len(added))
	for _, project := range append(existing, added...) {
		if project == "" || seen[project] {
			continue
		}
		seen[project] = true
		merged = append(merged, project)
	}
	return merged
}

func removeProjects(existing []string, removed []string) []string {
	removedSet := map[string]bool{}
	for _, project := range removed {
		removedSet[project] = true
	}
	result := make([]string, 0, len(existing))
	for _, project := range existing {
		if project == "" || removedSet[project] {
			continue
		}
		result = append(result, project)
	}
	return result
}

func containsProject(projects []string, want string) bool {
	for _, project := range projects {
		if project == want {
			return true
		}
	}
	return false
}

// memberDeviceCertificates finds a Tenant Member's live device certificates:
// the entries named plan.CertificateName, else — shared client identity: a
// keypair's ONE trust entry is named after whichever tenant/install enrolled
// it first — every restricted client entry that already holds a project of
// the member's own Personal Tenant (memberNamespace = <prefix>-<member>).
// Dead entries (no projects) are never returned.
func memberDeviceCertificates(server TrustServer, plan usertrust.UserPlan, memberNamespace string) ([]api.Certificate, error) {
	certificates, err := server.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("list Incus certificates: %w", err)
	}
	var named, holders []api.Certificate
	for _, cert := range certificates {
		if cert.Type != api.CertificateTypeClient || !cert.Restricted || len(cert.Projects) == 0 {
			continue
		}
		if cert.Name == plan.CertificateName {
			named = append(named, cert)
			continue
		}
		for _, project := range cert.Projects {
			if memberNamespace != "" && (project == memberNamespace || strings.HasPrefix(project, memberNamespace+"-")) {
				holders = append(holders, cert)
				break
			}
		}
	}
	if len(named) > 0 {
		return named, nil
	}
	if len(holders) > 0 {
		return holders, nil
	}
	return nil, fmt.Errorf("no live restricted certificate for %s: none named %q and none holding a project of %s (the member must `sc login` on this install first)", plan.User, plan.CertificateName, memberNamespace)
}

// GrantTenantMember extends a Tenant Member's device certificates (see
// memberDeviceCertificates) with plan.Projects.
func (m TrustManager) GrantTenantMember(ctx context.Context, plan usertrust.UserPlan, memberNamespace string) error {
	server, err := m.server()
	if err != nil {
		return err
	}
	certs, err := memberDeviceCertificates(server, plan, memberNamespace)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if err := extendCertificateProjects(server, cert, usertrust.UserPlan{Projects: plan.Projects, Description: cert.Description}); err != nil {
			return err
		}
	}
	return nil
}

// RevokeTenantMember removes plan.Projects from a Tenant Member's device
// certificates (see memberDeviceCertificates). A member with no live entry
// has nothing to revoke.
func (m TrustManager) RevokeTenantMember(ctx context.Context, plan usertrust.UserPlan, memberNamespace string) error {
	server, err := m.server()
	if err != nil {
		return err
	}
	certs, err := memberDeviceCertificates(server, plan, memberNamespace)
	if err != nil {
		return nil
	}
	for _, cert := range certs {
		if err := server.UpdateCertificate(cert.Fingerprint, api.CertificatePut{
			Name: cert.Name, Type: api.CertificateTypeClient, Restricted: true,
			Projects: removeProjects(cert.Projects, plan.Projects), Certificate: cert.Certificate, Description: cert.Description,
		}, ""); err != nil {
			return fmt.Errorf("update certificate %s: %w", cert.Fingerprint[:min(12, len(cert.Fingerprint))], err)
		}
	}
	return nil
}

// holdsTenantProject reports whether the project list touches the tenant's
// namespace: the infra project itself or any `<infra>-<project>`.
func holdsTenantProject(projects []string, infraProject string) bool {
	for _, project := range projects {
		if project == infraProject || strings.HasPrefix(project, infraProject+"-") {
			return true
		}
	}
	return false
}
