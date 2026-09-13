package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/meta"
)

func claimHostname(t *testing.T, db *sql.DB, hostname, tenant, project, machine string) MachineHostname {
	t.Helper()
	row, err := ClaimMachineHostname(context.Background(), db, ClaimMachineHostnameRequest{Hostname: hostname, Tenant: tenant, Project: project, Machine: machine, UserKey: tenant})
	if err != nil {
		t.Fatalf("claim %s for %s/%s:%s: %v", hostname, tenant, project, machine, err)
	}
	return row
}

// ── validation ───────────────────────────────────────────────────────────────

func TestClaimMachineHostname_ValidatesZoneApexAndLength(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	addZone(t, db, "tc42.uk")

	cases := map[string]string{
		"web.nosuch.example": "no Public DNS Zone covers web.nosuch.example — ask your admin",
		"tc42.uk":            `machine hostname "tc42.uk" is a zone apex; use at least one label below tc42.uk`,
		"_acme.tc42.uk":      `invalid machine hostname "_acme.tc42.uk": labels may not start with "_"`,
		"*.tc42.uk":          `invalid machine hostname "*.tc42.uk": labels may not start with "*"`,
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 55) + ".tc42.uk": `machine hostname "` + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 55) + `.tc42.uk" is too long: "*.<hostname>" must fit in 253 characters`,
	}
	for hostname, want := range cases {
		_, err := ClaimMachineHostname(ctx, db, ClaimMachineHostnameRequest{Hostname: hostname, Tenant: "acme", Project: "zp", Machine: "web"})
		if err == nil || err.Error() != want {
			t.Fatalf("%s: err = %v, want %q", hostname, err, want)
		}
	}
	// The admin wording lists the registered zones.
	_, err := ClaimMachineHostname(ctx, db, ClaimMachineHostnameRequest{Hostname: "web.nosuch.example", Tenant: "acme", Project: "zp", Machine: "web", AdminView: true})
	if err == nil || err.Error() != "no Public DNS Zone covers web.nosuch.example; registered zones: hase.de, tc42.uk" {
		t.Fatalf("admin view: %v", err)
	}
	// Apex-LEVEL names (directly under the zone) are allowed (ADR-0028 §2).
	row := claimHostname(t, db, "Web12.TC42.uk.", "acme", "zp", "web")
	if row.Hostname != "web12.tc42.uk" || row.Zone != "tc42.uk" || row.Tenant != "acme" || row.Project != "zp" || row.Machine != "web" || row.CreatedAt == "" {
		t.Fatalf("row = %+v", row)
	}
	// Deeper names too, in a zone that is itself a name inside a Cloudflare zone.
	addZoneInside(t, db, "sc.igel.de", "igel.de")
	if row := claimHostname(t, db, "a.b.sc.igel.de", "acme", "zp", "web"); row.Zone != "sc.igel.de" {
		t.Fatalf("zone = %q", row.Zone)
	}
}

// ── conflict classes, every direction ────────────────────────────────────────

func TestClaimMachineHostname_ConflictClasses(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	addZone(t, db, "tc42.uk")
	claim(t, db, "baum.hase.de", "acme", "zp")
	claimHostname(t, db, "web12.tc42.uk", "acme", "zp", "web")
	claimHostname(t, db, "deep.x.y.tc42.uk", "beta", "p", "m")
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "*.shop.tc42.uk", Tenant: "other", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "www.blog.tc42.uk", Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
		t.Fatal(err)
	}
	install := ClaimMachineHostnameRequest{AuthHostname: "login.sc.hase.de", RouteBaseDomain: "routes.hase.de"}
	flat := func(h string) string {
		return fmt.Sprintf("machine hostname %q overlaps a name already claimed on this install; choose another", h)
	}
	reserved := func(h string) string { return fmt.Sprintf("machine hostname %q is reserved by this install", h) }

	cases := []struct {
		name, hostname, tenant, project, machine, want, class string
		sameTenant                                            bool
	}{
		// hostname vs hostname
		{"exact cross-tenant", "web12.tc42.uk", "evil", "x", "m", flat("web12.tc42.uk"), HostnameClaimConflictExact, false},
		{"descendant cross-tenant", "api.web12.tc42.uk", "evil", "x", "m", flat("api.web12.tc42.uk"), HostnameClaimConflictDescendant, false},
		{"ancestor cross-tenant", "y.tc42.uk", "evil", "x", "m", flat("y.tc42.uk"), HostnameClaimConflictAncestor, false},
		{"exact same tenant other machine", "web12.tc42.uk", "acme", "zp", "api", `machine hostname "web12.tc42.uk" overlaps "web12.tc42.uk" held by machine "zp:web" in this tenant`, HostnameClaimConflictExact, true},
		{"descendant same tenant", "api.web12.tc42.uk", "acme", "zp", "api", `machine hostname "api.web12.tc42.uk" overlaps "web12.tc42.uk" held by machine "zp:web" in this tenant`, HostnameClaimConflictDescendant, true},
		// hostname vs Project Domain (inside, equal, above)
		{"inside a foreign project domain", "web.baum.hase.de", "evil", "x", "m", flat("web.baum.hase.de"), HostnameClaimConflictDomain, false},
		{"equal to a project domain", "baum.hase.de", "evil", "x", "m", flat("baum.hase.de"), HostnameClaimConflictDomain, false},
		{"inside own project domain", "api.baum.hase.de", "acme", "zp", "web", `machine hostname "api.baum.hase.de" overlaps project domain "baum.hase.de" claimed by project "zp" in this tenant`, HostnameClaimConflictDomain, true},
		// hostname vs Public Route (equal after wildcard strip, or covering)
		{"route wildcard stripped, equal", "shop.tc42.uk", "evil", "x", "m", reserved("shop.tc42.uk"), HostnameClaimConflictRoute, false},
		{"route inside candidate", "blog.tc42.uk", "acme", "zp", "web", reserved("blog.tc42.uk"), HostnameClaimConflictRoute, false},
		// hostname vs install names (equal, above — below is allowed, see after the loop)
		{"auth hostname equal", "login.sc.hase.de", "acme", "zp", "web", reserved("login.sc.hase.de"), HostnameClaimConflictInstall, false},
		{"auth hostname ancestor", "sc.hase.de", "acme", "zp", "web", reserved("sc.hase.de"), HostnameClaimConflictInstall, false},
	}
	for _, tc := range cases {
		req := install
		req.Hostname, req.Tenant, req.Project, req.Machine = tc.hostname, tc.tenant, tc.project, tc.machine
		_, err := ClaimMachineHostname(ctx, db, req)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		var claimErr *HostnameClaimError
		if !errors.As(err, &claimErr) {
			t.Fatalf("%s: not a HostnameClaimError: %T", tc.name, err)
		}
		if claimErr.Class != tc.class || claimErr.SameTenant != tc.sameTenant {
			t.Fatalf("%s: class/sameTenant = %s/%v, want %s/%v", tc.name, claimErr.Class, claimErr.SameTenant, tc.class, tc.sameTenant)
		}
	}
	// Below the Auth Hostname / route base is NOT reserved (ADR-0028; live-run
	// finding F9): only the name itself or an ancestor is. A real Public Route
	// collision is caught by the route scan.
	{
		req := install
		req.Hostname, req.Tenant, req.Project, req.Machine = "x.routes.hase.de", "acme", "zp", "web"
		if _, err := ClaimMachineHostname(ctx, db, req); err != nil {
			t.Fatalf("a hostname below the route base must be claimable: %v", err)
		}
	}
	// Siblings never conflict; a same-machine identical re-claim is a no-op.
	claimHostname(t, db, "web13.tc42.uk", "evil", "x", "m")
	row, err := ClaimMachineHostname(ctx, db, ClaimMachineHostnameRequest{Hostname: "web12.tc42.uk", Tenant: "acme", Project: "zp", Machine: "web"})
	var already *MachineHostnameAlreadyHeldError
	if !errors.As(err, &already) || row.Hostname != "web12.tc42.uk" || err.Error() != `machine hostname "web12.tc42.uk" already held by this machine` {
		t.Fatalf("re-claim: %+v, %v", row, err)
	}
	// Nothing leaked: the refused claims left no rows.
	rows, _ := ListMachineHostnames(ctx, db)
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}

	// ── the reverse directions ──
	// A Project Domain cannot be claimed inside, equal to, or above a hostname.
	domainFlat := func(d string) string {
		return fmt.Sprintf("project domain %q overlaps a domain already claimed on this install; choose another", d)
	}
	for _, tc := range []struct{ domain, tenant, want string }{
		{"web12.tc42.uk", "evil", domainFlat("web12.tc42.uk")},
		{"api.web12.tc42.uk", "evil", domainFlat("api.web12.tc42.uk")},
		{"y.tc42.uk", "evil", domainFlat("y.tc42.uk")},
		{"x.y.tc42.uk", "acme", domainFlat("x.y.tc42.uk")}, // beta's deep hostname, cross-tenant
		{"api.web12.tc42.uk", "acme", `project domain "api.web12.tc42.uk" overlaps hostname "web12.tc42.uk" held by machine "zp:web" in this tenant`},
	} {
		_, _, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: tc.domain, Tenant: tc.tenant, Project: "np"})
		var domainErr *DomainClaimError
		if !errors.As(err, &domainErr) || domainErr.Class != DomainClaimConflictHostname || err.Error() != tc.want {
			t.Fatalf("project domain %s (%s): %v", tc.domain, tc.tenant, err)
		}
	}
	// A sibling Project Domain is fine.
	claim(t, db, "eiche.tc42.uk", "evil", "np")
	// A Public Route cannot be published equal to or inside a hostname.
	for _, hostname := range []string{"web12.tc42.uk", "*.web12.tc42.uk", "www.web12.tc42.uk", "WEB12.tc42.uk."} {
		_, err := UpsertRoute(ctx, db, Route{Hostname: hostname, Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80})
		var routeErr *RouteInsideMachineHostnameError
		if !errors.As(err, &routeErr) || !strings.HasSuffix(err.Error(), `is inside machine hostname "web12.tc42.uk" claimed on this install`) {
			t.Fatalf("route %s: %v", hostname, err)
		}
	}
	// A route ABOVE a hostname is not blocked — a route reserves one level,
	// exactly as with Project Domains — and neither is a sibling.
	for _, hostname := range []string{"*.y.tc42.uk", "x.tc42.uk"} {
		if _, err := UpsertRoute(ctx, db, Route{Hostname: hostname, Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
			t.Fatalf("route %s beside hostnames: %v", hostname, err)
		}
	}
}

func TestClaimMachineHostname_DryRunStoresNothingAndConcurrentClaimsSerialize(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "tc42.uk")
	row, err := ClaimMachineHostname(ctx, db, ClaimMachineHostnameRequest{Hostname: "web12.tc42.uk", Tenant: "acme", Project: "zp", Machine: "web", DryRun: true})
	if err != nil || row.Hostname != "web12.tc42.uk" || row.Zone != "tc42.uk" {
		t.Fatalf("dry run: %+v, %v", row, err)
	}
	if rows, _ := ListMachineHostnames(ctx, db); len(rows) != 0 {
		t.Fatalf("dry run stored %+v", rows)
	}
	type outcome struct {
		err error
	}
	results := make(chan outcome, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			_, err := ClaimMachineHostname(ctx, db, ClaimMachineHostnameRequest{Hostname: "web12.tc42.uk", Tenant: fmt.Sprintf("t%d", i), Project: "p", Machine: "m"})
			results <- outcome{err: err}
		}(i)
	}
	wins, losses := 0, 0
	for i := 0; i < 8; i++ {
		r := <-results
		var claimErr *HostnameClaimError
		switch {
		case r.err == nil:
			wins++
		case errors.As(r.err, &claimErr):
			losses++
		default:
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if wins != 1 || losses != 7 {
		t.Fatalf("wins/losses = %d/%d", wins, losses)
	}
}

// ── release, project delete, GC, zone removal ────────────────────────────────

func TestMachineHostnames_ReleaseProjectDeleteAndGC(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "tc42.uk")
	claimHostname(t, db, "web12.tc42.uk", "acme", "zp", "web")
	claimHostname(t, db, "api12.tc42.uk", "acme", "zp", "api")
	claimHostname(t, db, "other.tc42.uk", "beta", "p", "m")

	// A name the machine does not hold — foreign or unknown — reads the same.
	for _, hostname := range []string{"other.tc42.uk", "nosuch.tc42.uk"} {
		_, err := ReleaseMachineHostname(ctx, db, "acme", "zp", "web", hostname)
		var notHeld *MachineHostnameNotHeldError
		if !errors.As(err, &notHeld) || err.Error() != fmt.Sprintf("machine hostname %q is not held by machine %q", hostname, "zp:web") {
			t.Fatalf("release %s: %v", hostname, err)
		}
	}
	released, err := ReleaseMachineHostname(ctx, db, "acme", "zp", "web", "WEB12.tc42.uk")
	if err != nil || released.Hostname != "web12.tc42.uk" {
		t.Fatalf("release: %+v, %v", released, err)
	}
	if names, _ := PublicHostnamesOfMachine(ctx, db, "acme", "zp", "web"); len(names) != 0 {
		t.Fatalf("names after release = %v", names)
	}
	// Zone removal is refused while a hostname is held under it.
	err = checkPublicDNSZoneRemovable(ctx, sqlProjectDomainClaims{db: db}, "tc42.uk")
	if err == nil || err.Error() != "public DNS zone tc42.uk still has machine hostnames: api12.tc42.uk (acme/zp:api), other.tc42.uk (beta/p:m); remove them first" {
		t.Fatalf("zone removal: %v", err)
	}
	// Project delete releases every hostname of the project's machines.
	rows, err := ReleaseMachineHostnamesOfProject(ctx, db, "acme", "zp")
	if err != nil || len(rows) != 1 || rows[0].Hostname != "api12.tc42.uk" {
		t.Fatalf("project release: %+v, %v", rows, err)
	}
	// GC: an empty live set is never trusted; a live project with a machine
	// listing prunes vanished machines; without a listing only vanished
	// projects are pruned.
	claimHostname(t, db, "web12.tc42.uk", "acme", "zp", "web")
	if dropped, err := ReconcileMachineHostnames(ctx, db, nil, nil, nil); err != nil || len(dropped) != 0 {
		t.Fatalf("empty live set: %v, %v", dropped, err)
	}
	live := map[string][]string{"acme": {"zp"}}
	if dropped, err := ReconcileMachineHostnames(ctx, db, live, nil, nil); err != nil || len(dropped) != 1 || dropped[0].Hostname != "other.tc42.uk" {
		t.Fatalf("project-only GC: %+v, %v", dropped, err)
	}
	var released2 []string
	dropped, err := ReconcileMachineHostnames(ctx, db, live, map[string]struct{}{"acme/zp/api": {}}, func(_ context.Context, h MachineHostname) {
		released2 = append(released2, h.Hostname)
	})
	if err != nil || len(dropped) != 1 || dropped[0].Hostname != "web12.tc42.uk" || strings.Join(released2, ",") != "web12.tc42.uk" {
		t.Fatalf("machine GC: %+v, %v, %v", dropped, err, released2)
	}
	if rows, _ := ListMachineHostnames(ctx, db); len(rows) != 0 {
		t.Fatalf("rows after GC = %+v", rows)
	}
	if err := checkPublicDNSZoneRemovable(ctx, sqlProjectDomainClaims{db: db}, "tc42.uk"); err != nil {
		t.Fatalf("zone removal after GC: %v", err)
	}
}

// ── the API ──────────────────────────────────────────────────────────────────

func hostnameRequest(t *testing.T, h http.Handler, token, method, path, body string) (int, MachineHostnamesResult, map[string]any) {
	t.Helper()
	code, out := zoneRequest(t, h, token, method, path, body)
	var result MachineHostnamesResult
	if names, ok := out["hostnames"].([]any); ok {
		for _, entry := range names {
			m := entry.(map[string]any)
			view := MachineHostnameView{Hostname: m["hostname"].(string)}
			view.Derived, _ = m["derived"].(bool)
			view.Zone, _ = m["zone"].(string)
			result.Hostnames = append(result.Hostnames, view)
		}
	}
	result.Hostname, _ = out["hostname"].(string)
	result.Zone, _ = out["zone"].(string)
	result.Released, _ = out["released"].(string)
	result.AlreadyHeld, _ = out["alreadyHeld"].(bool)
	result.DryRun, _ = out["dryRun"].(bool)
	if cert, ok := out["certificate"].(map[string]any); ok {
		state, _ := cert["state"].(string)
		result.Certificate = &MachineCertificateView{State: state}
	}
	return code, result, out
}

func TestMachineHostnamesAPI_RoundTrips(t *testing.T) {
	domains := &fakeProjectDomains{missing: map[string]bool{"acme/zp:nope": true}}
	h, db, acme, beta := projectDomainTestHandler(t, domains)
	ctx := context.Background()
	addZone(t, db, "tc42.uk")
	// acme/zp holds baum.hase.de → the derived name web.baum.hase.de.
	if code, _ := zoneRequest(t, h, acme, http.MethodPut, "/api/projects/zp/domain", `{"domain":"baum.hase.de"}`); code != http.StatusOK {
		t.Fatalf("set-domain: %d", code)
	}

	// list: the derived name only.
	code, result, _ := hostnameRequest(t, h, acme, http.MethodGet, "/api/machines/zp/web/hostnames", "")
	if code != http.StatusOK || strings.Join(result.Names(), ",") != "web.baum.hase.de" || !result.Hostnames[0].Derived || result.Hostnames[0].Zone != "hase.de" {
		t.Fatalf("list: %d %+v", code, result)
	}

	// create with hostnames (beforeCreate): claim + certificate row, no stamp.
	code, result, _ = hostnameRequest(t, h, acme, http.MethodPost, "/api/machines/zp/web/hostnames", `{"hostname":"Web12.TC42.uk","beforeCreate":true}`)
	if code != http.StatusOK || result.Hostname != "web12.tc42.uk" || result.Zone != "tc42.uk" || result.Certificate == nil || result.Certificate.State != machineCertStatePending {
		t.Fatalf("create claim: %d %+v", code, result)
	}
	if strings.Join(result.Names(), ",") != "web.baum.hase.de,web12.tc42.uk" {
		t.Fatalf("names after create claim = %v", result.Names())
	}
	if len(domains.stamped) != 0 {
		t.Fatalf("beforeCreate stamped the instance: %v", domains.calls)
	}
	if row, err := getMachineCertificate(ctx, db, "web12.tc42.uk"); err != nil || row.Tenant != "acme" || row.Project != "zp" || row.Machine != "web" || row.Zone != "tc42.uk" {
		t.Fatalf("certificate row: %+v, %v", row, err)
	}

	// add later: claim + row + the instance key rewritten with the full set.
	code, result, _ = hostnameRequest(t, h, acme, http.MethodPost, "/api/machines/zp/web/hostnames", `{"hostname":"www.web12.tc42.uk"}`)
	if code != http.StatusConflict {
		t.Fatalf("a name inside the machine's own hostname is still a conflict: %d %+v", code, result)
	}
	code, result, _ = hostnameRequest(t, h, acme, http.MethodPost, "/api/machines/zp/web/hostnames", `{"hostname":"web13.tc42.uk"}`)
	if code != http.StatusOK || strings.Join(result.Names(), ",") != "web.baum.hase.de,web12.tc42.uk,web13.tc42.uk" {
		t.Fatalf("add: %d %+v", code, result)
	}
	if got := strings.Join(domains.stamped["acme/zp:web"], ","); got != "web.baum.hase.de,web12.tc42.uk,web13.tc42.uk" {
		t.Fatalf("stamped list = %q (calls %v)", got, domains.calls)
	}
	// idempotent re-add
	code, result, _ = hostnameRequest(t, h, acme, http.MethodPost, "/api/machines/zp/web/hostnames", `{"hostname":"web13.tc42.uk"}`)
	if code != http.StatusOK || !result.AlreadyHeld {
		t.Fatalf("re-add: %d %+v", code, result)
	}
	// dry run: validated, nothing stored, nothing stamped.
	calls := len(domains.calls)
	code, result, _ = hostnameRequest(t, h, acme, http.MethodPost, "/api/machines/zp/web/hostnames", `{"hostname":"web14.tc42.uk","dryRun":true}`)
	if code != http.StatusOK || !result.DryRun || strings.Join(result.Names(), ",") != "web.baum.hase.de,web12.tc42.uk,web13.tc42.uk,web14.tc42.uk" {
		t.Fatalf("dry run: %d %+v", code, result)
	}
	if rows, _ := MachineHostnamesOf(ctx, db, "acme", "zp", "web"); len(rows) != 2 || len(domains.calls) != calls {
		t.Fatalf("dry run had effects: %+v %v", rows, domains.calls)
	}

	// apex-level name allowed; inside a Project Domain refused (400/409 texts verbatim).
	for body, want := range map[string][2]any{
		`{"hostname":"api.baum.hase.de"}`:              {http.StatusConflict, `machine hostname "api.baum.hase.de" overlaps project domain "baum.hase.de" claimed by project "zp" in this tenant`},
		`{"hostname":"tc42.uk"}`:                       {http.StatusBadRequest, `machine hostname "tc42.uk" is a zone apex; use at least one label below tc42.uk`},
		`{"hostname":"x.nosuch.example"}`:              {http.StatusBadRequest, "no Public DNS Zone covers x.nosuch.example — ask your admin"},
		`{"hostname":"login.sc.hase.de"}`:              {http.StatusConflict, `machine hostname "login.sc.hase.de" is reserved by this install`},
		`{"hostname":"_x.tc42.uk"}`:                    {http.StatusBadRequest, `invalid machine hostname "_x.tc42.uk": labels may not start with "_"`},
		`{"hostname":"web12.tc42.uk"}`:                 {http.StatusConflict, `machine hostname "web12.tc42.uk" overlaps "web12.tc42.uk" held by machine "zp:web" in this tenant`},
		`{"hostname":"web12.tc42.uk","tenant":"acme"}`: {http.StatusForbidden, "user beta is not authorized for tenant acme"},
	} {
		token := acme
		if strings.Contains(body, `"tenant":"acme"`) {
			token = beta
		}
		code, out := zoneRequest(t, h, token, http.MethodPost, "/api/machines/zp/api/hostnames", body)
		if code != want[0].(int) || out["error"] != want[1] {
			t.Fatalf("%s: %d %v, want %v", body, code, out, want)
		}
	}
	// cross-tenant: beta cannot see or touch acme's machine, and its own
	// claim of an overlapping name is refused flat.
	if code, out := zoneRequest(t, h, beta, http.MethodGet, "/api/machines/zp/web/hostnames?tenant=acme", ""); code != http.StatusForbidden || out["error"] != "user beta is not authorized for tenant acme" {
		t.Fatalf("beta list acme: %d %v", code, out)
	}
	if code, out := zoneRequest(t, h, beta, http.MethodDelete, "/api/machines/zp/web/hostnames/web12.tc42.uk?tenant=acme", ""); code != http.StatusForbidden {
		t.Fatalf("beta delete acme: %d %v", code, out)
	}
	if code, out := zoneRequest(t, h, beta, http.MethodPost, "/api/machines/proj/mach/hostnames", `{"hostname":"a.web12.tc42.uk"}`); code != http.StatusConflict || out["error"] != `machine hostname "a.web12.tc42.uk" overlaps a name already claimed on this install; choose another` {
		t.Fatalf("beta overlap: %d %v", code, out)
	}
	// beta's own apex-level claim on its own machine works.
	if code, result, _ := hostnameRequest(t, h, beta, http.MethodPost, "/api/machines/proj/mach/hostnames", `{"hostname":"beta.tc42.uk"}`); code != http.StatusOK || strings.Join(result.Names(), ",") != "beta.tc42.uk" {
		t.Fatalf("beta apex-level: %d %+v", code, result)
	}

	// A missing machine: the claim is released again (404).
	code, out := zoneRequest(t, h, acme, http.MethodPost, "/api/machines/zp/nope/hostnames", `{"hostname":"nope.tc42.uk"}`)
	if code != http.StatusNotFound {
		t.Fatalf("missing machine: %d %v", code, out)
	}
	if rows, _ := MachineHostnamesOf(ctx, db, "acme", "zp", "nope"); len(rows) != 0 {
		t.Fatalf("missing machine kept its claim: %+v", rows)
	}

	// remove: dry run first, then for real (the key is rewritten without it).
	code, result, _ = hostnameRequest(t, h, acme, http.MethodDelete, "/api/machines/zp/web/hostnames/web13.tc42.uk?dryRun=1", "")
	if code != http.StatusOK || !result.DryRun || result.Released != "web13.tc42.uk" || strings.Join(result.Names(), ",") != "web.baum.hase.de,web12.tc42.uk,web13.tc42.uk" {
		t.Fatalf("remove dry run: %d %+v", code, result)
	}
	code, result, _ = hostnameRequest(t, h, acme, http.MethodDelete, "/api/machines/zp/web/hostnames/web13.tc42.uk", "")
	if code != http.StatusOK || result.Released != "web13.tc42.uk" || strings.Join(result.Names(), ",") != "web.baum.hase.de,web12.tc42.uk" {
		t.Fatalf("remove: %d %+v", code, result)
	}
	if got := strings.Join(domains.stamped["acme/zp:web"], ","); got != "web.baum.hase.de,web12.tc42.uk" {
		t.Fatalf("stamped list after remove = %q", got)
	}
	// the derived name and unknown names are not removable per machine
	for _, name := range []string{"web.baum.hase.de", "web13.tc42.uk"} {
		if code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/machines/zp/web/hostnames/"+name, ""); code != http.StatusNotFound || out["error"] != fmt.Sprintf("machine hostname %q is not held by machine %q", name, "zp:web") {
			t.Fatalf("remove %s: %d %v", name, code, out)
		}
	}

	// project delete releases the project's hostnames (and beta's stay).
	if code, _ := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/zp", ""); code != http.StatusOK {
		t.Fatalf("project delete: %d", code)
	}
	rows, _ := ListMachineHostnames(ctx, db)
	if len(rows) != 1 || rows[0].Hostname != "beta.tc42.uk" {
		t.Fatalf("rows after project delete = %+v", rows)
	}

	// Without the Incus seam every mutation is 501; GET still answers.
	h2, _, acme2, _ := projectDomainTestHandler(t, nil)
	if code, _ := zoneRequest(t, h2, acme2, http.MethodPost, "/api/machines/zp/web/hostnames", `{"hostname":"x.hase.de"}`); code != http.StatusNotImplemented {
		t.Fatalf("POST without seam: %d", code)
	}
	if code, _ := zoneRequest(t, h2, acme2, http.MethodGet, "/api/machines/zp/web/hostnames", ""); code != http.StatusOK {
		t.Fatalf("GET without seam: %d", code)
	}
	if code, _ := zoneRequest(t, h2, "", http.MethodGet, "/api/machines/zp/web/hostnames", ""); code != http.StatusUnauthorized {
		t.Fatalf("GET without token: %d", code)
	}
}

// The slice-1 zone reconciler reads the list key: the derived name under
// the claim is the target, explicit names are left to slice 3, and the
// legacy single key is never stamped on such a machine. Explicit hostnames'
// pending certificate rows survive the row GC.
func TestZoneReconcile_ListKeyMachines(t *testing.T) {
	listed := ZoneMachine{Tenant: "acme", Project: "zp", IncusProject: "sc2-acme-zp", Name: "web", ProjectDomain: "baum.hase.de",
		PublicHostnames: []string{"web.baum.hase.de", "web12.tc42.uk"}, BridgeIPv4: "10.249.7.9", Running: true}
	explicitOnly := ZoneMachine{Tenant: "acme", Project: "zp", IncusProject: "sc2-acme-zp", Name: "solo", ProjectDomain: "baum.hase.de",
		PublicHostnames: []string{"solo.tc42.uk"}, BridgeIPv4: "10.249.7.10", Running: true}
	h := newZoneHarness(t, listed, explicitOnly)
	addZone(t, h.db, "tc42.uk")
	claimHostname(t, h.db, "web12.tc42.uk", "acme", "zp", "web")
	claimHostname(t, h.db, "solo.tc42.uk", "acme", "zp", "solo")
	for _, hostname := range []string{"web12.tc42.uk", "solo.tc42.uk"} {
		if _, err := requestMachineCertificate(h.ctx, h.db, machineCertificateRequest{Hostname: hostname, Tenant: "acme", Project: "zp", Machine: "x", Zone: "tc42.uk", DirectoryURL: LetsEncryptStagingDirectory}, h.now); err != nil {
			t.Fatal(err)
		}
	}
	h.fleet.setFile("sc2-acme-zp", "web", "/etc/sandcastle/caddy.ready", markerFor("web.baum.hase.de"))
	if err := h.pass(); err != nil {
		t.Fatal(err)
	}
	// The derived name got its records and a row; no legacy stamp on either machine.
	if _, err := getMachineCertificate(h.ctx, h.db, "web.baum.hase.de"); err != nil {
		t.Fatalf("derived row: %v", err)
	}
	for _, stamp := range h.fleet.stamps {
		if _, ok := stamp.Config[meta.KeyV2PublicHostname]; ok {
			t.Fatalf("legacy key stamped on a list-key machine: %+v", stamp)
		}
	}
	if got := h.fleet.machine("sc2-acme-zp", "solo").PublicHostname; got != "" {
		t.Fatalf("explicit-only machine got a legacy stamp %q", got)
	}
	// The explicit rows are live (not GC'd) although nothing orders them yet.
	for _, hostname := range []string{"web12.tc42.uk", "solo.tc42.uk"} {
		if _, err := getMachineCertificate(h.ctx, h.db, hostname); err != nil {
			t.Fatalf("explicit row %s: %v", hostname, err)
		}
	}
}
