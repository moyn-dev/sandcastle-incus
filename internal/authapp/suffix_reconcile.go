package authapp

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/svclog"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// suffixClaimReconcileInterval is deliberately slow — DNS-suffix claims only
// churn on tenant create/delete, which is rare, and the claim's own UNIQUE
// constraint already guarantees correctness; this loop just garbage-collects
// claims orphaned by a tenant deleted out-of-band (e.g. `sc-adm tenant delete`,
// which runs against Incus and cannot reach the auth database).
const suffixClaimReconcileInterval = 5 * time.Minute

// pruneOrphanSuffixClaims releases every claim whose tenant is absent from live,
// with one guard: an EMPTY live set is never trusted. A genuinely empty install
// has no claims worth pruning, and refusing to prune here means a transient
// tenant-listing hiccup can never wipe the whole registry. Returns the count
// pruned.
func pruneOrphanSuffixClaims(ctx context.Context, db *sql.DB, live []string) (int, error) {
	if db == nil {
		return 0, nil
	}
	if len(live) == 0 {
		return 0, nil
	}
	return ReconcileDNSSuffixClaims(ctx, db, live)
}

// reconcileSuffixClaimsOnce lists the install's live tenants and prunes orphaned
// claims. A listing error aborts WITHOUT pruning (the guard above only covers an
// empty result; a hard error must not be read as "no tenants").
func (r HTTPRunner) reconcileSuffixClaimsOnce(ctx context.Context, db *sql.DB) (int, error) {
	if db == nil || r.Tenants == nil {
		return 0, nil
	}
	summaries, err := tenant.ListForPrefix(ctx, r.Tenants, r.Admin.IncusProjectPrefix)
	if err != nil {
		return 0, fmt.Errorf("list tenants for DNS suffix reconcile: %w", err)
	}
	live := make([]string, 0, len(summaries))
	for _, s := range summaries {
		if name := strings.TrimSpace(s.Tenant); name != "" {
			live = append(live, name)
		}
	}
	return pruneOrphanSuffixClaims(ctx, db, live)
}

// projectDomainClaimGC is the Project Domain half of the slow loop (ADR-0027
// §4.6): claims whose <tenant>/<project> is no longer a live app project are
// dropped (with the slice-6 release hook), and live projects carrying
// KeyV2Domain without a claim row are reported — once per project+domain —
// and never auto-claimed. The live set comes from the same tenant listing.
type projectDomainClaimGC struct {
	logged map[string]struct{}
}

// reconcileProjectDomainClaimsOnce returns the dropped claims and the newly
// seen unclaimed Incus keys. A listing error aborts without pruning.
func (r HTTPRunner) reconcileProjectDomainClaimsOnce(ctx context.Context, db *sql.DB, gc *projectDomainClaimGC) ([]ProjectDomainClaim, []string, error) {
	if db == nil || r.Tenants == nil {
		return nil, nil, nil
	}
	summaries, err := tenant.ListForPrefix(ctx, r.Tenants, r.Admin.IncusProjectPrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("list tenants for project domain reconcile: %w", err)
	}
	liveProjects, liveDomains := liveProjectDomains(summaries)
	dropped, err := ReconcileProjectDomainClaims(ctx, db, liveProjects, func(ctx context.Context, claim ProjectDomainClaim) {
		onProjectDomainReleased(ctx, db, claim)
	})
	if err != nil {
		return dropped, nil, err
	}
	unclaimed, err := UnclaimedProjectDomains(ctx, db, liveDomains)
	if err != nil {
		return dropped, nil, err
	}
	var fresh []string
	for _, entry := range unclaimed {
		if _, seen := gc.logged[entry]; seen {
			continue
		}
		gc.logged[entry] = struct{}{}
		fresh = append(fresh, entry)
	}
	return dropped, fresh, nil
}

// liveProjectDomains derives the GC inputs from tenant summaries: every live
// project per tenant, and the Incus KeyV2Domain value per "<tenant>/<project>".
func liveProjectDomains(summaries []tenant.Summary) (map[string][]string, map[string]string) {
	liveProjects := map[string][]string{}
	liveDomains := map[string]string{}
	for _, s := range summaries {
		tenantName := strings.TrimSpace(s.Tenant)
		if tenantName == "" {
			continue
		}
		for _, p := range s.Projects {
			name := strings.TrimSpace(p.Name)
			if name == "" {
				continue
			}
			liveProjects[tenantName] = append(liveProjects[tenantName], name)
			if d := strings.TrimSpace(p.Domain); d != "" {
				liveDomains[tenantName+"/"+name] = d
			}
		}
	}
	return liveProjects, liveDomains
}

// runSuffixClaimReconcileLoop prunes orphaned DNS-suffix claims (and Project
// Domain claims, ADR-0027 §4.6) once at startup and then every
// suffixClaimReconcileInterval, until ctx is cancelled. Errors are logged and
// the loop continues.
func (r HTTPRunner) runSuffixClaimReconcileLoop(ctx context.Context, db *sql.DB, logger *svclog.Logger) {
	gc := &projectDomainClaimGC{logged: map[string]struct{}{}}
	run := func() {
		pruned, err := r.reconcileSuffixClaimsOnce(ctx, db)
		if err != nil {
			logger.Message(ctx, "ERROR", "auth-app DNS suffix claim reconcile: %v", err)
			return
		}
		if pruned > 0 {
			logger.Message(ctx, "INFO", "auth-app pruned %d orphaned DNS suffix claim(s)", pruned)
		}
		dropped, unclaimed, err := r.reconcileProjectDomainClaimsOnce(ctx, db, gc)
		if err != nil {
			logger.Message(ctx, "ERROR", "auth-app project domain claim reconcile: %v", err)
		}
		for _, claim := range dropped {
			logger.Message(ctx, "INFO", "auth-app pruned orphaned project domain claim %s (%s/%s)", claim.Domain, claim.Tenant, claim.Project)
		}
		for _, entry := range unclaimed {
			logger.Message(ctx, "WARN", "auth-app project %s carries user.sandcastle.v2.domain without a claim; ignored (sc project set-domain claims it, unset-domain clears it)", entry)
		}
	}
	run()
	ticker := time.NewTicker(suffixClaimReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
