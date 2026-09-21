package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/domain"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Project certificates share encrypted storage and ARI/backoff with machine
// certificates. The reserved owner is not a valid machine name. A partial
// unique index enforces one certificate per tenant/project.
const projectCertificateOwner = "@project"

func ensureProjectCertificate(ctx context.Context, db *sql.DB, c ProjectDomainClaim, directory string, now time.Time) (machineCertificate, error) {
	row, err := getMachineCertificate(ctx, db, c.Domain)
	if err == nil {
		if row.Tenant != c.Tenant || row.Project != c.Project || row.Machine != projectCertificateOwner {
			return row, fmt.Errorf("certificate for %s is not owned by project %s/%s", c.Domain, c.Tenant, c.Project)
		}
		return row, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return row, err
	}
	return requestMachineCertificate(ctx, db, machineCertificateRequest{Hostname: c.Domain, Tenant: c.Tenant, Project: c.Project, Machine: projectCertificateOwner, Zone: c.Zone, DirectoryURL: directory}, now)
}

func (r *zoneReconciler) reconcileProjectCertificate(ctx context.Context, c ProjectDomainClaim, now time.Time) (*orderCandidate, error) {
	row, err := ensureProjectCertificate(ctx, r.db, c, r.directory, now)
	if err != nil {
		return nil, err
	}
	if row.DirectoryURL != r.directory {
		row, err = resetMachineCertificate(ctx, r.db, row.Hostname, r.directory, now)
		if err != nil {
			return nil, err
		}
	}
	if row.usable(r.directory, now) && !now.Before(row.ARICheckAfter) {
		row, err = r.refreshARI(ctx, row, now)
		if err != nil {
			return nil, err
		}
	}
	// Issuance and renewal are independent of whether any machines are running.
	state := machineCertificateState(row, r.directory, now)
	if row.usable(r.directory, now) {
		state = machineCertStateInstalled
	}
	if due, ok := orderDue(row, state, now); ok {
		return &orderCandidate{target: zoneTarget{hostname: c.Domain, zone: c.Zone}, due: due}, nil
	}
	return nil, nil
}

func (r *zoneReconciler) serveProjectCertificate(ctx context.Context, t zoneTarget, now time.Time) (targetOutcome, error) {
	out := targetOutcome{state: "project"}
	row, err := getMachineCertificate(ctx, r.db, t.projectDomain)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil || !row.usable(r.directory, now) || !t.machine.Running {
		return out, err
	}
	// Check each machine independently; a global pushed serial cannot describe
	// delivery to an entire project (including machines copied or restarted).
	target := t
	target.hostname = t.projectDomain
	drift, err := r.driftCheck(ctx, target, row)
	if err != nil {
		return out, err
	}
	if !drift {
		installedKey, readErr := r.machines.ReadInstanceFile(ctx, t.machine.IncusProject, t.machine.Name, tenant.MachineTLSHostKeyPath(t.projectDomain))
		if readErr != nil && !errors.Is(readErr, ErrInstanceFileNotFound) {
			return out, readErr
		}
		key, keyErr := machineCertificateKeyPEM(ctx, r.db, row)
		if keyErr != nil {
			return out, keyErr
		}
		drift = readErr != nil || strings.TrimSpace(installedKey) != strings.TrimSpace(key)
	}
	if drift {
		_, err = r.push(ctx, target, row, now)
	}
	return out, err
}

func projectCertificateCovers(ctx context.Context, db *sql.DB, tenant, project, hostname string) (bool, error) {
	c, found, err := GetProjectDomainClaim(ctx, db, tenant, project)
	return found && domain.CoveredByProjectCertificate(hostname, c.Domain), err
}

func (h handler) projectCertificateStatus(ctx context.Context, result *ProjectDomainResult) {
	result.SANs = machineCertificateHostnames(result.Domain)
	result.CertState = machineCertStatePending
	row, err := getMachineCertificate(ctx, h.db, result.Domain)
	if err != nil || row.Machine != projectCertificateOwner || row.Tenant != result.Tenant || row.Project != result.Project {
		return
	}
	result.CertState = machineCertificateState(row, h.acmeDirectory, timeNow())
	result.CertNotAfter = formatCertTime(row.NotAfter)
}
