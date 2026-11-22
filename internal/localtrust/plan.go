package localtrust

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type Request struct {
	Reference string
	// InstallPrefix scopes the tenant lookup to one install. Several installs
	// can share an Incus daemon with the same tenant name; without this the
	// plan could pick the OTHER install's tenant and derive its DNS suffix,
	// naming a trust entry that belongs to a different CA.
	InstallPrefix string
}

type Plan struct {
	Reference       string `json:"reference"`
	IncusProject    string `json:"incusProject"`
	DNSSuffix       string `json:"dnsSuffix"`
	StoragePool     string `json:"storagePool"`
	CAVolume        string `json:"caVolume"`
	Instance        string `json:"instance,omitempty"`
	CertificatePath string `json:"certificatePath"`
	TrustName       string `json:"trustName"`
	Platform        string `json:"platform"`
	Warning         string `json:"warning"`
}

type Result struct {
	Reference string `json:"reference"`
	TrustName string `json:"trustName"`
	Platform  string `json:"platform"`
	Action    string `json:"action"`
	Target    string `json:"target,omitempty"`
	// Removed reports whether an uninstall actually removed a trust entry. A
	// silent "success" that removed nothing is how a mismatched trust name went
	// unnoticed.
	Removed bool `json:"removed,omitempty"`
}

type Manager interface {
	Install(context.Context, Plan) (Result, error)
	Uninstall(context.Context, Plan) (Result, error)
}

func PlanInstall(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request Request) (Plan, error) {
	return plan(ctx, admin, store, request)
}

func PlanUninstall(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request Request) (Plan, error) {
	return plan(ctx, admin, store, request)
}

func plan(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request Request) (Plan, error) {
	if err := admin.Validate(); err != nil {
		return Plan{}, err
	}
	ref, err := tenantRef(request.Reference, admin.Tenant)
	if err != nil {
		return Plan{}, err
	}
	summaries, err := tenant.ListForPrefix(ctx, store, request.InstallPrefix)
	if err != nil {
		return Plan{}, err
	}
	for _, summary := range summaries {
		if summary.Tenant == ref.Tenant {
			return Plan{
				Reference:       ref.String(),
				IncusProject:    summary.IncusName,
				DNSSuffix:       summary.DNSSuffix,
				StoragePool:     summary.IncusName,
				CAVolume:        tenant.CAVolumeName,
				CertificatePath: tenant.TenantCACertPath,
				TrustName:       planTrustName(ref, summary),
				Platform:        runtime.GOOS,
				Warning:         "Trusting this tenant CA allows the tenant to mint certificates trusted by this machine.",
			}, nil
		}
	}
	return Plan{}, fmt.Errorf("tenant %q not found", ref.String())
}

func tenantRef(reference string, currentTenant string) (naming.TenantRef, error) {
	value := strings.TrimSpace(reference)
	if value == "" {
		value = strings.TrimSpace(currentTenant)
	}
	if value == "" {
		return naming.TenantRef{}, fmt.Errorf("tenant reference is required")
	}
	return naming.ParseTenantRef(value)
}

func trustName(ref naming.TenantRef) string {
	return "Sandcastle " + ref.String() + " tenant CA"
}

// planTrustName names the trust entry the way the CA itself is named.
//
// A v2 tenant's CA is minted by the sidecar leaf signer with
// CN="Sandcastle <suffix> tenant CA", and the install path names the local entry
// after that CN. Deriving the name from the TENANT instead (the v1 rule) yields
// a filename that never matches what was installed, so `sc trust uninstall`
// removed nothing and reported success.
func planTrustName(ref naming.TenantRef, summary tenant.Summary) string {
	if suffix := strings.TrimSpace(summary.DNSSuffix); suffix != "" {
		return "Sandcastle " + suffix + " tenant CA"
	}
	return trustName(ref)
}

func CertFilename(plan Plan) string {
	name := strings.NewReplacer("/", "-", " ", "-", "_", "-").Replace(strings.ToLower(plan.TrustName))
	return name + ".crt"
}
