package machine

import (
	"context"

	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// PasswordReconciler sets the Unix login password and the Samba password for
// the tenant owner's Linux user across every machine in a tenant. The same
// secret is used for both, so a single `sandcastle password set` enables both
// interactive login and SMB access to the [home] and [workspace] shares.
type PasswordReconciler interface {
	ReconcileTenantPassword(ctx context.Context, summary tenant.Summary, password string) error
}
