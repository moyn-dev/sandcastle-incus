package authapp

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestProjectCertificateEmptyProjectAndCopy(t *testing.T) {
	h := newZoneHarness(t)
	h.passes(2)
	if len(h.issuer.calls) != 1 || strings.Join(h.issuer.calls[0].Hostnames, ",") != "baum.hase.de,*.baum.hase.de" {
		t.Fatalf("orders: %+v", h.issuer.calls)
	}
	row := h.row("baum.hase.de")
	if row.Machine != projectCertificateOwner || row.Tenant != "acme" || row.Project != "zp" {
		t.Fatalf("owner: %+v", row)
	}
	x1 := zoneMachine("x1", "10.249.7.9", true)
	h.fleet.machines = []ZoneMachine{x1}
	h.ready(x1.IncusProject, x1.Name, x1.PublicHostnames...)
	h.passes(1)
	h.claimHostname("admin-x1.baum.hase.de", "zp", "x1")
	h.passes(2)
	if len(h.issuer.calls) != 1 || h.fleet.pushCount() != 1 {
		t.Fatalf("alias caused order/push: %d/%d", len(h.issuer.calls), h.fleet.pushCount())
	}
	// Raw incus copy: name changes, all source user keys survive.
	x2 := h.fleet.machine(x1.IncusProject, "x1")
	x2.Name, x2.BridgeIPv4 = "x2", "10.249.7.10"
	x2.CertState, x2.CertNotAfter = "installed", "2099-01-01T00:00:00Z"
	h.fleet.machines = append(h.fleet.machines, x2)
	h.ready(x2.IncusProject, x2.Name, x2.PublicHostnames...)
	h.passes(2)
	copied := h.fleet.machine(x2.IncusProject, "x2")
	if strings.Join(copied.PublicHostnames, ",") != "x2.baum.hase.de" || copied.CertState != "project" || copied.CertNotAfter != "" {
		t.Fatalf("copied metadata: %+v", copied)
	}
	if len(h.issuer.calls) != 1 || h.fleet.pushCount() != 2 {
		t.Fatalf("copy orders/pushes: %d/%d", len(h.issuer.calls), h.fleet.pushCount())
	}
	for _, push := range h.fleet.pushes {
		if push.Hostname != row.Hostname || push.CertPEM != row.CertPEM {
			t.Fatalf("different certificate: %+v", push)
		}
	}
	h.fleet.machines = h.fleet.machines[:1]
	h.passes(1)
	for _, name := range []string{"x1.baum.hase.de", "admin-x1.baum.hase.de", "x2.baum.hase.de"} {
		if _, err := getMachineCertificate(h.ctx, h.db, name); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("per-name row %s: %v", name, err)
		}
	}
	for _, rec := range h.dns.list("hase.de.") {
		if strings.Contains(rec.Name, "x2.baum") {
			t.Fatalf("copy DNS survived: %+v", rec)
		}
	}
}

func TestProjectCertificateRenewalDistributesAndOldLeafExpires(t *testing.T) {
	a, b := zoneMachine("a", "10.249.7.9", true), zoneMachine("b", "10.249.7.10", false)
	h := newZoneHarness(t, a, b)
	h.ready(a.IncusProject, a.Name, a.PublicHostnames...)
	// A pre-upgrade leaf remains stored, but is never used or renewed.
	h.requestExplicit(MachineHostname{Hostname: "a.baum.hase.de", Tenant: "acme", Project: "zp", Machine: "a", Zone: "hase.de"})
	old, err := h.issuer.Issue(h.ctx, "hase.de", []string{"a.baum.hase.de", "*.a.baum.hase.de"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storeIssuedMachineCertificate(h.ctx, h.db, "a.baum.hase.de", old, h.now); err != nil {
		t.Fatal(err)
	}
	h.passes(2)
	project := h.row("baum.hase.de")
	h.now = project.RenewAfter.Add(time.Second)
	h.issuer.now = h.now
	h.passes(2)
	renewed := h.row("baum.hase.de")
	if renewed.Serial == project.Serial {
		t.Fatal("project did not renew")
	}
	if h.row("a.baum.hase.de").CertPEM != old.CertPEM {
		t.Fatal("legacy leaf renewed")
	}
	h.fleet.machines[1].Running = true
	h.ready(b.IncusProject, b.Name, b.PublicHostnames...)
	orders := len(h.issuer.calls)
	h.passes(2)
	if len(h.issuer.calls) != orders {
		t.Fatal("start ordered a certificate")
	}
	cert, err := h.fleet.ReadInstanceFile(h.ctx, b.IncusProject, b.Name, tenant.MachineTLSHostCertPath("baum.hase.de"))
	if err != nil || cert != renewed.CertPEM {
		t.Fatalf("started machine lacks renewed cert: %v", err)
	}
	h.now = project.NotAfter.Add(time.Second)
	h.passes(1)
	if _, err := getMachineCertificate(h.ctx, h.db, "a.baum.hase.de"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expired legacy row: %v", err)
	}
}

func TestProjectAliasAndPerNameCertificateDecisions(t *testing.T) {
	h := newZoneHarness(t, zoneMachine("web", "10.249.7.9", true))
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	for _, tt := range []struct {
		host    string
		project bool
	}{
		{"admin-web.baum.hase.de", true}, {"admin.web.baum.hase.de", false},
		{"outside.hase.de", false}, {"*.web.baum.hase.de", false},
	} {
		h.claimHostname(tt.host, "zp", "web")
		covered, err := projectCertificateCovers(h.ctx, h.db, "acme", "zp", tt.host)
		if err != nil || covered != tt.project {
			t.Fatalf("%s: %v %v", tt.host, covered, err)
		}
	}
	h.passes(2)
	for _, name := range []string{"admin.web.baum.hase.de", "outside.hase.de", "*.web.baum.hase.de"} {
		if !h.row(name).hasCertificate() {
			t.Fatalf("no per-name cert: %s", name)
		}
	}
	if _, err := getMachineCertificate(h.ctx, h.db, "admin-web.baum.hase.de"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("alias row: %v", err)
	}
	for _, call := range h.issuer.calls {
		for _, san := range call.Hostnames {
			if strings.HasPrefix(san, "*.*.") {
				t.Fatalf("invalid wildcard SAN: %s", san)
			}
		}
	}
}

func TestProjectAliasAPIHasNoCertificateSideEffects(t *testing.T) {
	h, db, token, _ := projectDomainTestHandler(t, &fakeProjectDomains{})
	if code, _ := zoneRequest(t, h, token, http.MethodPut, "/api/projects/zp/domain", `{"domain":"baum.hase.de"}`); code != http.StatusOK {
		t.Fatalf("set domain: %d", code)
	}
	for _, dry := range []bool{true, false} {
		body := `{"hostname":"admin-web.baum.hase.de","dryRun":false}`
		if dry {
			body = `{"hostname":"admin-web.baum.hase.de","dryRun":true}`
		}
		code, result, _ := hostnameRequest(t, h, token, http.MethodPost, "/api/machines/zp/web/hostnames", body)
		if code != http.StatusOK || result.Certificate == nil || result.Certificate.State != "project" {
			t.Fatalf("alias: %d %+v", code, result)
		}
		if _, err := getMachineCertificate(context.Background(), db, "admin-web.baum.hase.de"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("alias certificate row: %v", err)
		}
		rows, err := MachineHostnamesOf(context.Background(), db, "acme", "zp", "web")
		if err != nil || (dry && len(rows) != 0) || (!dry && len(rows) != 1) {
			t.Fatalf("dry=%v rows=%v err=%v", dry, rows, err)
		}
	}
	code, _, _ := hostnameRequest(t, h, token, http.MethodDelete, "/api/machines/zp/web/hostnames/admin-web.baum.hase.de", "")
	if code != http.StatusOK {
		t.Fatalf("remove: %d", code)
	}
}

func TestZoneApexRemainsPerName(t *testing.T) {
	h := newZoneHarness(t)
	addZone(t, h.db, "tc42.uk")
	h.claimHostname("tc42.uk", "zp", "web")
	covered, err := projectCertificateCovers(h.ctx, h.db, "acme", "zp", "tc42.uk")
	if err != nil || covered {
		t.Fatalf("apex: %v %v", covered, err)
	}
	if got := machineCertificateHostnames("tc42.uk"); strings.Join(got, ",") != "tc42.uk,*.tc42.uk" {
		t.Fatalf("SANs: %v", got)
	}
}

func TestWildcardAndApexDNSLifecycle(t *testing.T) {
	for _, host := range []string{"*.solo.hase.de", "hase.de"} {
		t.Run(host, func(t *testing.T) {
			m := privateMachine("web", "10.249.7.9", true)
			m.PublicHostnames = []string{host}
			h := newPerNameZoneHarness(t, m)
			h.ready(m.IncusProject, m.Name, host)
			h.dns.add("hase.de.", libdns.RR{Name: relativeChallengeName(host, "hase.de."), Type: "TXT", Data: "stale"})
			h.passes(2)
			if len(recordNames(h.dns.list("hase.de."), "TXT")) != 0 {
				t.Fatal("challenge not swept")
			}
			records := recordNames(h.dns.list("hase.de."), "A")
			expected := "*.solo=10.249.7.9"
			if host == "hase.de" {
				expected = "*=10.249.7.9,@=10.249.7.9"
			}
			if strings.Join(records, ",") != expected {
				t.Fatalf("records: %v", records)
			}
			h.fleet.machines[0].Running = false
			h.fleet.machines[0].BridgeIPv4 = ""
			h.passes(1)
			if strings.Join(recordNames(h.dns.list("hase.de."), "A"), ",") != expected {
				t.Fatal("stopped records removed")
			}
			h.fleet.machines = nil
			h.passes(1)
			if len(recordNames(h.dns.list("hase.de."), "A")) != 0 {
				t.Fatal("deleted records retained")
			}
		})
	}
}

func TestProjectCertificateStatusAndUnset(t *testing.T) {
	h := newZoneHarness(t)
	h.passes(1)
	view := ProjectDomainResult{Tenant: "acme", Project: "zp", Domain: "baum.hase.de"}
	(handler{db: h.db, acmeDirectory: LetsEncryptStagingDirectory}).projectCertificateStatus(h.ctx, &view)
	if view.CertState != "issued" || view.CertNotAfter == "" || strings.Join(view.SANs, ",") != "baum.hase.de,*.baum.hase.de" {
		t.Fatalf("status: %+v", view)
	}
	claim, found, err := ReleaseProjectDomainClaim(h.ctx, h.db, "acme", "zp")
	if err != nil || !found {
		t.Fatalf("release: %v %v", found, err)
	}
	if err := onProjectDomainReleased(h.ctx, h.db, claim); err != nil {
		t.Fatal(err)
	}
	if _, err := getMachineCertificate(h.ctx, h.db, claim.Domain); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("project row survived unset: %v", err)
	}
}
