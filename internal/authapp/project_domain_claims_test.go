package authapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// ── validation ───────────────────────────────────────────────────────────────

func TestNormalizeProjectDomain(t *testing.T) {
	cases := []struct {
		in, want, wantErr string
	}{
		{" Baum.Hase.DE. ", "baum.hase.de", ""},
		{"", "", "project domain is required"},
		{"_acme.hase.de", "", `invalid project domain "_acme.hase.de": labels may not start with "_"`},
		{"*.hase.de", "", `invalid project domain "*.hase.de": labels may not start with "*"`},
		{"bäum.hase.de", "", `invalid project domain "bäum.hase.de"`},
		{"-x.hase.de", "", `invalid project domain "-x.hase.de"`},
		{"a b.hase.de", "", `invalid project domain "a b.hase.de"`},
	}
	for _, tc := range cases {
		got, err := NormalizeProjectDomain(tc.in)
		if tc.wantErr == "" {
			if err != nil || got != tc.want {
				t.Fatalf("%q: got %q, %v", tc.in, got, err)
			}
			continue
		}
		if err == nil || err.Error() != tc.wantErr {
			t.Fatalf("%q: err = %v, want %q", tc.in, err, tc.wantErr)
		}
	}
}

func addZone(t *testing.T, db *sql.DB, zone string) {
	t.Helper()
	addZoneInside(t, db, zone, zone)
}

// addZoneInside registers zone as a Public DNS Zone living inside the
// Cloudflare zone cloudflareZone (the two are equal for a zone that is a
// Cloudflare zone itself).
func addZoneInside(t *testing.T, db *sql.DB, zone, cloudflareZone string) {
	t.Helper()
	if err := AddPublicDNSZone(context.Background(), db, zone, CloudflareZone{ID: "cf-" + cloudflareZone, Name: cloudflareZone}, "tok", "root"); err != nil {
		t.Fatal(err)
	}
}

func claim(t *testing.T, db *sql.DB, domain, tenant, project string) ProjectDomainClaim {
	t.Helper()
	c, _, err := ClaimProjectDomain(context.Background(), db, ClaimProjectDomainRequest{Domain: domain, Tenant: tenant, Project: project, UserKey: tenant})
	if err != nil {
		t.Fatalf("claim %s for %s/%s: %v", domain, tenant, project, err)
	}
	return c
}

func TestClaimProjectDomain_ValidatesZoneApexAndLength(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	addZone(t, db, "sc.igel.de")

	cases := map[string]string{
		"baum.nosuch.example": "no Public DNS Zone covers baum.nosuch.example — ask your admin",
		"hase.de":             `project domain "hase.de" is a zone apex; claim at least one label below hase.de`,
		"sc.igel.de":          `project domain "sc.igel.de" is a zone apex; claim at least one label below sc.igel.de`,
		"igel.de":             "no Public DNS Zone covers igel.de — ask your admin",
		strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + ".hase.de": `project domain "` + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + `.hase.de" is too long: "*.<63-char machine>.<d>" must fit in 253 characters`,
	}
	for domain, want := range cases {
		_, _, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: domain, Tenant: "acme", Project: "web"})
		if err == nil || err.Error() != want {
			t.Fatalf("%s: err = %v, want %q", domain, err, want)
		}
		var validation *ProjectDomainError
		if !errors.As(err, &validation) {
			t.Fatalf("%s: not a ProjectDomainError: %T", domain, err)
		}
	}
	// The admin roots see the registered zone list.
	_, _, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: "x.nosuch.example", Tenant: "acme", Project: "web", AdminView: true})
	if err == nil || err.Error() != "no Public DNS Zone covers x.nosuch.example; registered zones: hase.de, sc.igel.de" {
		t.Fatalf("admin view: %v", err)
	}
	// Exactly at the budget: 253 - 2 - 63 - 1 = 187 characters is fine.
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", projectDomainMaxLength-(63+1+63+1+len(".hase.de"))) + ".hase.de"
	if len(long) != projectDomainMaxLength {
		t.Fatalf("test domain is %d chars, want %d", len(long), projectDomainMaxLength)
	}
	if _, _, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: long, Tenant: "acme", Project: "web"}); err != nil {
		t.Fatalf("budget-exact domain refused: %v", err)
	}
	// Longest-suffix match: a domain under sc.igel.de is claimed under that
	// zone, not under a shorter one.
	c := claim(t, db, "dev.sc.igel.de", "acme", "dev")
	if c.Zone != "sc.igel.de" {
		t.Fatalf("zone = %q, want sc.igel.de", c.Zone)
	}
	if got, found, err := GetProjectDomainClaim(ctx, db, "acme", "dev"); err != nil || !found || got.Domain != "dev.sc.igel.de" || got.UserKey != "acme" || got.CreatedAt == "" {
		t.Fatalf("stored claim = %+v, %v, %v", got, found, err)
	}
}

// ── conflict classes ─────────────────────────────────────────────────────────

func TestClaimProjectDomain_ConflictClasses(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	claim(t, db, "baum.hase.de", "acme", "web")
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "*.shop.hase.de", Tenant: "other", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "www.blog.hase.de", Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
		t.Fatal(err)
	}
	install := ClaimProjectDomainRequest{AuthHostname: "login.sc.hase.de", RouteBaseDomain: "routes.hase.de"}

	flat := func(d string) string {
		return fmt.Sprintf("project domain %q overlaps a domain already claimed on this install; choose another", d)
	}
	reserved := func(d string) string { return fmt.Sprintf("project domain %q is reserved by this install", d) }
	cases := []struct {
		name, domain, tenant, project, want, class string
		sameTenant                                 bool
	}{
		{"exact cross-tenant", "baum.hase.de", "evil", "x", flat("baum.hase.de"), DomainClaimConflictExact, false},
		{"ancestor cross-tenant", "hase.de", "evil", "x", `project domain "hase.de" is a zone apex; claim at least one label below hase.de`, "", false},
		{"descendant cross-tenant", "api.baum.hase.de", "evil", "x", flat("api.baum.hase.de"), DomainClaimConflictDescendant, false},
		{"exact same tenant other project", "baum.hase.de", "acme", "api", `project domain "baum.hase.de" overlaps "baum.hase.de" claimed by project "web" in this tenant`, DomainClaimConflictExact, true},
		{"descendant same tenant", "api.baum.hase.de", "acme", "api", `project domain "api.baum.hase.de" overlaps "baum.hase.de" claimed by project "web" in this tenant`, DomainClaimConflictDescendant, true},
		{"route wildcard stripped, equal", "shop.hase.de", "evil", "x", reserved("shop.hase.de"), DomainClaimConflictRoute, false},
		{"route inside candidate", "blog.hase.de", "acme", "blog", reserved("blog.hase.de"), DomainClaimConflictRoute, false},
		{"route same tenant still reserved", "www.blog.hase.de", "acme", "blog", reserved("www.blog.hase.de"), DomainClaimConflictRoute, false},
		{"auth hostname ancestor", "sc.hase.de", "acme", "sc", reserved("sc.hase.de"), DomainClaimConflictInstall, false},
		{"auth hostname equal", "login.sc.hase.de", "acme", "sc", reserved("login.sc.hase.de"), DomainClaimConflictInstall, false},
		{"route base domain", "routes.hase.de", "acme", "r", reserved("routes.hase.de"), DomainClaimConflictInstall, false},
	}
	for _, tc := range cases {
		req := install
		req.Domain, req.Tenant, req.Project = tc.domain, tc.tenant, tc.project
		_, _, err := ClaimProjectDomain(ctx, db, req)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		if tc.class == "" {
			continue
		}
		var claimErr *DomainClaimError
		if !errors.As(err, &claimErr) {
			t.Fatalf("%s: not a DomainClaimError: %T", tc.name, err)
		}
		if claimErr.Class != tc.class || claimErr.SameTenant != tc.sameTenant {
			t.Fatalf("%s: class/sameTenant = %s/%v, want %s/%v", tc.name, claimErr.Class, claimErr.SameTenant, tc.class, tc.sameTenant)
		}
	}
	// The ancestor class proper needs a zone above the existing claim: register
	// a deeper claim and try to cover it.
	claim(t, db, "a.b.hase.de", "acme", "deep")
	_, _, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: "b.hase.de", Tenant: "evil", Project: "x"})
	var claimErr *DomainClaimError
	if !errors.As(err, &claimErr) || claimErr.Class != DomainClaimConflictAncestor || err.Error() != flat("b.hase.de") {
		t.Fatalf("ancestor: %v", err)
	}
	// Siblings never conflict.
	claim(t, db, "eiche.hase.de", "evil", "x")
	// Nothing leaked: the refused claims left no rows.
	claims, _ := ListProjectDomainClaims(ctx, db)
	if len(claims) != 3 {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestClaimProjectDomain_SameProjectNoopAndReplace(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	first := claim(t, db, "baum.hase.de", "acme", "web")

	// Identical re-claim: the existing claim comes back with the no-op error.
	got, prev, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: "BAUM.hase.de.", Tenant: "acme", Project: "web"})
	var already *ProjectDomainAlreadyClaimedError
	if !errors.As(err, &already) || err.Error() != `project domain "baum.hase.de" already claimed by this project` {
		t.Fatalf("re-claim: %v", err)
	}
	if got.Domain != first.Domain || prev == nil || prev.Domain != first.Domain {
		t.Fatalf("re-claim returned %+v / %+v", got, prev)
	}

	// A different domain for the same project replaces the claim (set-domain)
	// and reports the previous one for compensation.
	replaced, prev, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: "eiche.hase.de", Tenant: "acme", Project: "web"})
	if err != nil || replaced.Domain != "eiche.hase.de" || prev == nil || prev.Domain != "baum.hase.de" {
		t.Fatalf("replace: %+v, %+v, %v", replaced, prev, err)
	}
	claims, _ := ListProjectDomainClaims(ctx, db)
	if len(claims) != 1 || claims[0].Domain != "eiche.hase.de" {
		t.Fatalf("claims after replace = %+v", claims)
	}
	// The old domain is free again for anyone.
	claim(t, db, "baum.hase.de", "other", "p")

	// Release returns what was held; a second release finds nothing.
	released, found, err := ReleaseProjectDomainClaim(ctx, db, "acme", "web")
	if err != nil || !found || released.Domain != "eiche.hase.de" {
		t.Fatalf("release: %+v, %v, %v", released, found, err)
	}
	if _, found, _ := ReleaseProjectDomainClaim(ctx, db, "acme", "web"); found {
		t.Fatal("second release found a claim")
	}
	if err := restoreProjectDomainClaim(ctx, db, released); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := GetProjectDomainClaim(ctx, db, "acme", "web"); !found {
		t.Fatal("restore did not re-insert the claim")
	}
}

func TestClaimProjectDomain_DryRunStoresNothing(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	c, _, err := ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: "baum.hase.de", Tenant: "acme", Project: "web", DryRun: true})
	if err != nil || c.Domain != "baum.hase.de" || c.Zone != "hase.de" {
		t.Fatalf("dry run: %+v, %v", c, err)
	}
	if claims, _ := ListProjectDomainClaims(ctx, db); len(claims) != 0 {
		t.Fatalf("dry run stored %+v", claims)
	}
	// The dry run's rolled-back transaction leaves the database writable.
	claim(t, db, "baum.hase.de", "acme", "web")
	// And a dry run still reports conflicts.
	_, _, err = ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: "baum.hase.de", Tenant: "evil", Project: "x", DryRun: true})
	var claimErr *DomainClaimError
	if !errors.As(err, &claimErr) {
		t.Fatalf("dry-run conflict: %v", err)
	}
}

// The BEGIN IMMEDIATE transaction serializes concurrent claimers: of N racing
// claims for one domain exactly one wins and the rest see the flat refusal —
// never a bare SQLite error, never two rows.
func TestClaimProjectDomain_ConcurrentClaimsSerialize(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = ClaimProjectDomain(ctx, db, ClaimProjectDomainRequest{Domain: "baum.hase.de", Tenant: fmt.Sprintf("t%d", i), Project: "web"})
		}(i)
	}
	wg.Wait()
	wins := 0
	for i, err := range errs {
		if err == nil {
			wins++
			continue
		}
		var claimErr *DomainClaimError
		if !errors.As(err, &claimErr) {
			t.Fatalf("claimer %d: unexpected error %v", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins = %d, want 1", wins)
	}
	claims, _ := ListProjectDomainClaims(ctx, db)
	if len(claims) != 1 {
		t.Fatalf("claims = %+v", claims)
	}
}

// ── reverse check, claim source, GC ──────────────────────────────────────────

func TestUpsertRoute_RejectsHostnameInsideProjectDomain(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	claim(t, db, "baum.hase.de", "acme", "web")
	for _, hostname := range []string{"baum.hase.de", "www.baum.hase.de", "*.baum.hase.de", "WWW.Baum.Hase.DE."} {
		_, err := UpsertRoute(ctx, db, Route{Hostname: hostname, Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80})
		var inside *RouteInsideProjectDomainError
		if !errors.As(err, &inside) {
			t.Fatalf("%s: err = %v", hostname, err)
		}
		want := fmt.Sprintf("route hostname %q is inside project domain %q claimed on this install", strings.TrimPrefix(normalizeHostname(hostname), "*."), "baum.hase.de")
		if err.Error() != want {
			t.Fatalf("%s: %q, want %q", hostname, err.Error(), want)
		}
	}
	// Siblings and unrelated names are fine.
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "eiche.hase.de", Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "baum.hase.de.example", Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
		t.Fatal(err)
	}
	// An existing route is never retroactively broken by a later claim: the
	// claim scan refuses the claim instead (tested above), and a re-publish of
	// the same route stays idempotent.
	if _, err := UpsertRoute(ctx, db, Route{Hostname: "eiche.hase.de", Tenant: "acme", Project: "p", Machine: "m", BackendPort: 80}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLProjectDomainClaims_BlocksZoneRemoval(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	addZone(t, db, "igel.de")
	claim(t, db, "baum.hase.de", "acme", "web")
	claim(t, db, "a.hase.de", "beta", "p")
	source := sqlProjectDomainClaims{db: db}
	refs, err := source.ClaimsUnderZone(ctx, "hase.de")
	if err != nil || len(refs) != 2 || refs[0].Domain != "a.hase.de" || refs[1].Tenant != "acme" {
		t.Fatalf("refs = %+v, %v", refs, err)
	}
	err = RemovePublicDNSZone(ctx, db, source, "hase.de")
	if err == nil || err.Error() != "public DNS zone hase.de still has claimed project domains: a.hase.de (beta/p), baum.hase.de (acme/web); unset them first" {
		t.Fatalf("remove: %v", err)
	}
	if err := RemovePublicDNSZone(ctx, db, source, "igel.de"); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileProjectDomainClaims_GC(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	claim(t, db, "baum.hase.de", "acme", "web")
	claim(t, db, "api.hase.de", "acme", "api")
	claim(t, db, "beta.hase.de", "beta", "p")

	// An empty live set is never trusted.
	if dropped, err := ReconcileProjectDomainClaims(ctx, db, map[string][]string{}, nil); err != nil || len(dropped) != 0 {
		t.Fatalf("empty live set: %+v, %v", dropped, err)
	}
	var hooked []string
	live := map[string][]string{"acme": {"default", "web"}} // api gone, beta tenant gone
	dropped, err := ReconcileProjectDomainClaims(ctx, db, live, func(_ context.Context, c ProjectDomainClaim) {
		hooked = append(hooked, c.Domain)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 2 || dropped[0].Domain != "api.hase.de" || dropped[1].Domain != "beta.hase.de" {
		t.Fatalf("dropped = %+v", dropped)
	}
	if strings.Join(hooked, ",") != "api.hase.de,beta.hase.de" {
		t.Fatalf("hook saw %v", hooked)
	}
	claims, _ := ListProjectDomainClaims(ctx, db)
	if len(claims) != 1 || claims[0].Domain != "baum.hase.de" {
		t.Fatalf("claims = %+v", claims)
	}
	// Incus keys without a row are reported, never claimed.
	unclaimed, err := UnclaimedProjectDomains(ctx, db, map[string]string{
		"acme/web":   "baum.hase.de", // has a row
		"acme/rogue": "rogue.hase.de",
		"acme/none":  "",
	})
	if err != nil || strings.Join(unclaimed, ",") != "acme/rogue (rogue.hase.de)" {
		t.Fatalf("unclaimed = %v, %v", unclaimed, err)
	}
	if claims, _ := ListProjectDomainClaims(ctx, db); len(claims) != 1 {
		t.Fatalf("auto-claimed: %+v", claims)
	}
}

// ── handlers ─────────────────────────────────────────────────────────────────

// fakeProjectDomains records the Incus side of the domain endpoints.
type fakeProjectDomains struct {
	mu      sync.Mutex
	calls   []string
	missing map[string]bool     // "tenant/project" (or "tenant/project:machine") → not found
	stamped map[string][]string // "tenant/project:machine" → last KeyV2PublicHostnames list written
	fail    error
}

func (f *fakeProjectDomains) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeProjectDomains) CreateTenantProjectWithDomain(_ context.Context, tenant, project, _ string, domain string) (projectbroker.ProjectResult, error) {
	f.record("create " + tenant + "/" + project + " " + domain)
	if f.fail != nil {
		return projectbroker.ProjectResult{}, f.fail
	}
	return projectbroker.ProjectResult{Tenant: tenant, Project: project, IncusProject: "sc2-" + tenant + "-" + project, Domain: domain}, nil
}

func (f *fakeProjectDomains) SetProjectDomain(_ context.Context, tenant, project, domain string) error {
	f.record("set " + tenant + "/" + project + " " + domain)
	if f.missing[tenant+"/"+project] {
		return fmt.Errorf("%w: %s/%s", projectbroker.ErrProjectNotFound, tenant, project)
	}
	return f.fail
}

func (f *fakeProjectDomains) SetMachinePublicHostnames(_ context.Context, tenant, project, machine string, hostnames []string) error {
	f.record("stamp " + tenant + "/" + project + ":" + machine + " " + strings.Join(hostnames, ","))
	if f.missing[tenant+"/"+project] {
		return fmt.Errorf("%w: %s/%s", projectbroker.ErrProjectNotFound, tenant, project)
	}
	if f.missing[tenant+"/"+project+":"+machine] {
		return fmt.Errorf("%w: %s/%s:%s", ErrMachineNotFound, tenant, project, machine)
	}
	if f.stamped == nil {
		f.stamped = map[string][]string{}
	}
	f.stamped[tenant+"/"+project+":"+machine] = append([]string(nil), hostnames...)
	return f.fail
}

func (f *fakeProjectDomains) DeleteTenantProject(_ context.Context, tenant, project string) error {
	f.record("delete " + tenant + "/" + project)
	if f.missing[tenant+"/"+project] {
		return fmt.Errorf("%w: %s/%s", projectbroker.ErrProjectNotFound, tenant, project)
	}
	return f.fail
}

type fakeProjectCreator struct{ calls []string }

func (f *fakeProjectCreator) CreateTenantProject(_ context.Context, tenant, project, _ string) (projectbroker.ProjectResult, error) {
	f.calls = append(f.calls, tenant+"/"+project)
	return projectbroker.ProjectResult{Tenant: tenant, Project: project, IncusProject: "sc2-" + tenant + "-" + project}, nil
}

func projectDomainTestHandler(t *testing.T, domains TenantProjectDomainManager) (http.Handler, *sql.DB, string, string) {
	t.Helper()
	ctx := context.Background()
	db := newClaimsTestDB(t)
	for _, user := range []User{
		{UserKey: "acme", GitHubUsername: "acme", Allowlisted: true},
		{UserKey: "beta", GitHubUsername: "beta", Allowlisted: true},
	} {
		if err := UpsertUser(ctx, db, user); err != nil {
			t.Fatal(err)
		}
	}
	acme, err := CreateCLIToken(ctx, db, "acme", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	beta, err := CreateCLIToken(ctx, db, "beta", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	addZone(t, db, "hase.de")
	options := HandlerOptions{AuthHostname: "login.sc.hase.de", RouteBaseDomain: "routes.hase.de", Projects: &fakeProjectCreator{}}
	if domains != nil {
		options.ProjectDomains = domains
	}
	return NewHandler(db, options), db, acme, beta
}

func TestProjectsAPI_CreateWithDomainClaimsThenCreates(t *testing.T) {
	domains := &fakeProjectDomains{}
	h, db, acme, beta := projectDomainTestHandler(t, domains)

	// dry run: validated, nothing stored, nothing created
	code, out := zoneRequest(t, h, acme, http.MethodPost, "/api/projects", `{"project":"web","domain":"Baum.hase.de","dryRun":true}`)
	if code != http.StatusOK || out["domain"] != "baum.hase.de" || out["zone"] != "hase.de" || out["dryRun"] != true {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if claims, _ := ListProjectDomainClaims(context.Background(), db); len(claims) != 0 || len(domains.calls) != 0 {
		t.Fatalf("dry run had effects: %+v %v", claims, domains.calls)
	}

	code, out = zoneRequest(t, h, acme, http.MethodPost, "/api/projects", `{"project":"web","domain":"baum.hase.de"}`)
	if code != http.StatusOK || out["incusProject"] != "sc2-acme-web" || out["domain"] != "baum.hase.de" || out["zone"] != "hase.de" {
		t.Fatalf("create: %d %v", code, out)
	}
	if strings.Join(domains.calls, ",") != "create acme/web baum.hase.de" {
		t.Fatalf("calls = %v", domains.calls)
	}
	if c, found, _ := GetProjectDomainClaim(context.Background(), db, "acme", "web"); !found || c.Zone != "hase.de" || c.UserKey != "acme" {
		t.Fatalf("claim = %+v, %v", c, found)
	}

	// Verbatim refusals as {error}, 409 for conflicts, 400 for validation.
	for body, want := range map[string][2]any{
		`{"project":"other","domain":"baum.hase.de"}`:     {http.StatusConflict, `project domain "baum.hase.de" overlaps a domain already claimed on this install; choose another`},
		`{"project":"other","domain":"a.baum.hase.de"}`:   {http.StatusConflict, `project domain "a.baum.hase.de" overlaps a domain already claimed on this install; choose another`},
		`{"project":"other","domain":"hase.de"}`:          {http.StatusBadRequest, `project domain "hase.de" is a zone apex; claim at least one label below hase.de`},
		`{"project":"other","domain":"x.nosuch.example"}`: {http.StatusBadRequest, "no Public DNS Zone covers x.nosuch.example — ask your admin"},
		`{"project":"other","domain":"login.sc.hase.de"}`: {http.StatusConflict, `project domain "login.sc.hase.de" is reserved by this install`},
		`{"project":"other","domain":"_x.hase.de"}`:       {http.StatusBadRequest, `invalid project domain "_x.hase.de": labels may not start with "_"`},
	} {
		code, out := zoneRequest(t, h, beta, http.MethodPost, "/api/projects", body)
		if code != want[0].(int) || out["error"] != want[1] {
			t.Fatalf("%s: %d %v, want %v", body, code, out, want)
		}
	}
	// Same tenant, other project: the owner is named.
	code, out = zoneRequest(t, h, acme, http.MethodPost, "/api/projects", `{"project":"api","domain":"api.baum.hase.de"}`)
	if code != http.StatusConflict || out["error"] != `project domain "api.baum.hase.de" overlaps "baum.hase.de" claimed by project "web" in this tenant` {
		t.Fatalf("same tenant: %d %v", code, out)
	}
	// No claim leaked from any refusal, and Incus was never touched again.
	if claims, _ := ListProjectDomainClaims(context.Background(), db); len(claims) != 1 || len(domains.calls) != 1 {
		t.Fatalf("leak: %+v %v", claims, domains.calls)
	}
}

func TestProjectsAPI_CreateWithDomainCompensatesOnIncusFailure(t *testing.T) {
	domains := &fakeProjectDomains{fail: errors.New("incus exploded")}
	h, db, acme, _ := projectDomainTestHandler(t, domains)
	code, out := zoneRequest(t, h, acme, http.MethodPost, "/api/projects", `{"project":"web","domain":"baum.hase.de"}`)
	if code != http.StatusInternalServerError || out["error"] != "incus exploded" {
		t.Fatalf("%d %v", code, out)
	}
	if claims, _ := ListProjectDomainClaims(context.Background(), db); len(claims) != 0 {
		t.Fatalf("claim survived the failed create: %+v", claims)
	}
}

func TestProjectsAPI_CreateWithoutDomainIsUnchanged(t *testing.T) {
	creator := &fakeProjectCreator{}
	db := newClaimsTestDB(t)
	if err := UpsertUser(context.Background(), db, User{UserKey: "acme", GitHubUsername: "acme", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	token, _ := CreateCLIToken(context.Background(), db, "acme", timeNow())
	h := NewHandler(db, HandlerOptions{AuthHostname: "sc.example", Projects: creator})
	code, out := zoneRequest(t, h, token, http.MethodPost, "/api/projects", `{"project":"web"}`)
	if code != http.StatusOK || out["incusProject"] != "sc2-acme-web" || len(creator.calls) != 1 {
		t.Fatalf("%d %v %v", code, out, creator.calls)
	}
	// With no domain seam, a domain is refused with 501 — not silently dropped.
	code, out = zoneRequest(t, h, token, http.MethodPost, "/api/projects", `{"project":"zp","domain":"x.hase.de"}`)
	if code != http.StatusNotImplemented || out["error"] != projectDomainsUnavailableMessage || len(creator.calls) != 1 {
		t.Fatalf("no seam: %d %v", code, out)
	}
}

func TestProjectAPI_SetAndUnsetDomain(t *testing.T) {
	domains := &fakeProjectDomains{missing: map[string]bool{"acme/nope": true}}
	h, db, acme, beta := projectDomainTestHandler(t, domains)

	// no auth
	if code, _ := zoneRequest(t, h, "", http.MethodPut, "/api/projects/web/domain", `{"domain":"baum.hase.de"}`); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	// unknown project → 404 (the Incus write fails; the claim is released
	// again)
	if code, out := zoneRequest(t, h, acme, http.MethodPut, "/api/projects/nope/domain", `{"domain":"baum.hase.de"}`); code != http.StatusNotFound || out["error"] == "" {
		t.Fatalf("missing project: %d %v", code, out)
	}
	if claims, _ := ListProjectDomainClaims(context.Background(), db); len(claims) != 0 {
		t.Fatalf("missing project kept a claim: %+v", claims)
	}
	domains.calls = nil
	// dry run: validated, nothing written
	code, out := zoneRequest(t, h, acme, http.MethodPut, "/api/projects/web/domain", `{"domain":"baum.hase.de","dryRun":true}`)
	if code != http.StatusOK || out["domain"] != "baum.hase.de" || out["zone"] != "hase.de" || out["dryRun"] != true {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if claims, _ := ListProjectDomainClaims(context.Background(), db); len(claims) != 0 {
		t.Fatalf("dry run stored %+v", claims)
	}
	for _, call := range domains.calls {
		if strings.HasPrefix(call, "set ") {
			t.Fatalf("dry run touched Incus: %v", domains.calls)
		}
	}
	// set: DB row, then Incus key + profile
	domains.calls = nil
	code, out = zoneRequest(t, h, acme, http.MethodPut, "/api/projects/web/domain", `{"domain":"baum.hase.de"}`)
	if code != http.StatusOK || out["domain"] != "baum.hase.de" || out["zone"] != "hase.de" {
		t.Fatalf("set: %d %v", code, out)
	}
	if strings.Join(domains.calls, ",") != "set acme/web baum.hase.de" {
		t.Fatalf("calls = %v", domains.calls)
	}
	// GET reports the claim
	if code, out := zoneRequest(t, h, acme, http.MethodGet, "/api/projects/web/domain", ""); code != http.StatusOK || out["domain"] != "baum.hase.de" || out["zone"] != "hase.de" {
		t.Fatalf("get: %d %v", code, out)
	}
	// identical re-claim: 200, no-op, Incus untouched
	domains.calls = nil
	code, out = zoneRequest(t, h, acme, http.MethodPut, "/api/projects/web/domain", `{"domain":"baum.hase.de"}`)
	if code != http.StatusOK || out["alreadyClaimed"] != true || out["domain"] != "baum.hase.de" {
		t.Fatalf("re-claim: %d %v", code, out)
	}
	if strings.Join(domains.calls, ",") != "" {
		t.Fatalf("re-claim touched Incus: %v", domains.calls)
	}
	// another tenant cannot take it, nor its subtree
	if code, out := zoneRequest(t, h, beta, http.MethodPut, "/api/projects/peer/domain", `{"domain":"x.baum.hase.de"}`); code != http.StatusConflict || out["error"] != `project domain "x.baum.hase.de" overlaps a domain already claimed on this install; choose another` {
		t.Fatalf("cross tenant: %d %v", code, out)
	}
	// replace: the same project moves to another domain — allowed with
	// machines (the reconciler re-derives their names); the replaced
	// domain's certificate rows go with it like an unset.
	if _, err := requestMachineCertificate(context.Background(), db, machineCertificateRequest{Hostname: "web.baum.hase.de", Tenant: "acme", Project: "web", Machine: "web", Zone: "hase.de", DirectoryURL: LetsEncryptStagingDirectory}, time.Now()); err != nil {
		t.Fatal(err)
	}
	domains.calls = nil
	if code, out := zoneRequest(t, h, acme, http.MethodPut, "/api/projects/web/domain", `{"domain":"eiche.hase.de"}`); code != http.StatusOK || out["domain"] != "eiche.hase.de" {
		t.Fatalf("replace: %d %v", code, out)
	}
	if c, _, _ := GetProjectDomainClaim(context.Background(), db, "acme", "web"); c.Domain != "eiche.hase.de" {
		t.Fatalf("claim after replace = %+v", c)
	}
	if rows, _ := listAllMachineCertificates(context.Background(), db); len(rows) != 0 {
		t.Fatalf("replaced domain kept certificate rows: %+v", rows)
	}
	// unset dry run, then unset: row gone, key cleared
	if code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/web/domain?dryRun=1", ""); code != http.StatusOK || out["released"] != "eiche.hase.de" || out["dryRun"] != true {
		t.Fatalf("unset dry run: %d %v", code, out)
	}
	if _, found, _ := GetProjectDomainClaim(context.Background(), db, "acme", "web"); !found {
		t.Fatal("unset dry run released the claim")
	}
	domains.calls = nil
	if code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/web/domain", ""); code != http.StatusOK || out["released"] != "eiche.hase.de" {
		t.Fatalf("unset: %d %v", code, out)
	}
	if strings.Join(domains.calls, ",") != "set acme/web " {
		t.Fatalf("unset calls = %v", domains.calls)
	}
	if _, found, _ := GetProjectDomainClaim(context.Background(), db, "acme", "web"); found {
		t.Fatal("unset left the claim")
	}
	// unset with nothing to release still clears the Incus key (repair path)
	if code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/web/domain", ""); code != http.StatusOK || out["released"] != nil {
		t.Fatalf("unset nothing: %d %v", code, out)
	}
}

func TestProjectAPI_SetDomainCompensatesOnIncusFailure(t *testing.T) {
	domains := &fakeProjectDomains{}
	h, db, acme, _ := projectDomainTestHandler(t, domains)
	if code, _ := zoneRequest(t, h, acme, http.MethodPut, "/api/projects/web/domain", `{"domain":"baum.hase.de"}`); code != http.StatusOK {
		t.Fatalf("set: %d", code)
	}
	domains.fail = errors.New("incus exploded")
	code, out := zoneRequest(t, h, acme, http.MethodPut, "/api/projects/web/domain", `{"domain":"eiche.hase.de"}`)
	if code != http.StatusInternalServerError || out["error"] != "incus exploded" {
		t.Fatalf("%d %v", code, out)
	}
	// The previous claim is back; the new one is gone.
	c, found, _ := GetProjectDomainClaim(context.Background(), db, "acme", "web")
	if !found || c.Domain != "baum.hase.de" {
		t.Fatalf("claim after failed replace = %+v, %v", c, found)
	}
	claims, _ := ListProjectDomainClaims(context.Background(), db)
	if len(claims) != 1 {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestProjectAPI_DeleteReleasesClaimThenDeletes(t *testing.T) {
	domains := &fakeProjectDomains{missing: map[string]bool{"acme/nope": true}}
	h, db, acme, _ := projectDomainTestHandler(t, domains)
	if code, _ := zoneRequest(t, h, acme, http.MethodPut, "/api/projects/web/domain", `{"domain":"baum.hase.de"}`); code != http.StatusOK {
		t.Fatalf("set: %d", code)
	}
	if code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/default", ""); code != http.StatusBadRequest || out["error"] != "default project cannot be deleted" {
		t.Fatalf("default: %d %v", code, out)
	}
	if code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/web?dryRun=1", ""); code != http.StatusOK || out["released"] != "baum.hase.de" || out["dryRun"] != true {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if _, found, _ := GetProjectDomainClaim(context.Background(), db, "acme", "web"); !found {
		t.Fatal("dry run released the claim")
	}
	domains.calls = nil
	code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/web", "")
	if code != http.StatusOK || out["released"] != "baum.hase.de" || out["project"] != "web" {
		t.Fatalf("delete: %d %v", code, out)
	}
	if strings.Join(domains.calls, ",") != "delete acme/web" {
		t.Fatalf("calls = %v", domains.calls)
	}
	if _, found, _ := GetProjectDomainClaim(context.Background(), db, "acme", "web"); found {
		t.Fatal("delete left the claim")
	}
	// A project without a domain deletes too; a missing one is 404.
	if code, out := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/plain", ""); code != http.StatusOK || out["released"] != nil {
		t.Fatalf("plain: %d %v", code, out)
	}
	if code, _ := zoneRequest(t, h, acme, http.MethodDelete, "/api/projects/nope", ""); code != http.StatusNotFound {
		t.Fatalf("missing: %d", code)
	}
	// Without the seam every domain verb is 501.
	h2, _, acme2, _ := projectDomainTestHandler(t, nil)
	for _, req := range [][2]string{{http.MethodPut, "/api/projects/web/domain"}, {http.MethodDelete, "/api/projects/web/domain"}, {http.MethodDelete, "/api/projects/web"}} {
		if code, _ := zoneRequest(t, h2, acme2, req[0], req[1], `{"domain":"baum.hase.de"}`); code != http.StatusNotImplemented {
			t.Fatalf("%s %s without seam: %d", req[0], req[1], code)
		}
	}
}

// The slow loop's GC drops claims of projects that vanished and reports
// Incus keys without a row exactly once.
func TestReconcileProjectDomainClaimsOnce_LogsUnclaimedOnce(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	addZone(t, db, "hase.de")
	claim(t, db, "baum.hase.de", "acme", "web")
	claim(t, db, "gone.hase.de", "acme", "gone")
	appProject := func(name string, extra map[string]string) tenant.IncusProject {
		cfg := map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyVersion: "2", meta.KeyTenant: "acme"}
		for k, v := range extra {
			cfg[k] = v
		}
		return tenant.IncusProject{Name: name, Config: cfg}
	}
	store := fakeReconcileStore{projects: []tenant.IncusProject{
		appProject("sc2-acme-web", map[string]string{meta.KeyV2Domain: "baum.hase.de"}),
		appProject("sc2-acme-rogue", map[string]string{meta.KeyV2Domain: "rogue.hase.de"}),
	}}
	runner := HTTPRunner{Tenants: store, Admin: config.Admin{IncusProjectPrefix: "sc2"}}
	gc := &projectDomainClaimGC{logged: map[string]struct{}{}}
	dropped, unclaimed, err := runner.reconcileProjectDomainClaimsOnce(ctx, db, gc)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0].Domain != "gone.hase.de" {
		t.Fatalf("dropped = %+v", dropped)
	}
	if strings.Join(unclaimed, ",") != "acme/rogue (rogue.hase.de)" {
		t.Fatalf("unclaimed = %v", unclaimed)
	}
	_, unclaimed, err = runner.reconcileProjectDomainClaimsOnce(ctx, db, gc)
	if err != nil || len(unclaimed) != 0 {
		t.Fatalf("second pass: %v %v", unclaimed, err)
	}
	// A listing error aborts without pruning.
	failing := HTTPRunner{Tenants: fakeReconcileStore{err: errors.New("incus down")}}
	if _, _, err := failing.reconcileProjectDomainClaimsOnce(ctx, db, gc); err == nil {
		t.Fatal("listing error not surfaced")
	}
	if claims, _ := ListProjectDomainClaims(ctx, db); len(claims) != 1 {
		t.Fatalf("claims = %+v", claims)
	}
}

// Sanity: the JSON shape the CLI decodes.
func TestProjectDomainResultJSON(t *testing.T) {
	data, _ := json.Marshal(ProjectDomainResult{Tenant: "acme", Project: "web", Domain: "baum.hase.de", Zone: "hase.de"})
	if string(data) != `{"tenant":"acme","project":"web","domain":"baum.hase.de","zone":"hase.de"}` {
		t.Fatalf("json = %s", data)
	}
	rec := httptest.NewRecorder()
	writeAPIError(rec, http.StatusConflict, &DomainClaimError{Domain: "x.hase.de"})
	if rec.Code != http.StatusConflict || strings.TrimSpace(rec.Body.String()) != `{"error":"project domain \"x.hase.de\" overlaps a domain already claimed on this install; choose another"}` {
		t.Fatalf("error body = %d %s", rec.Code, rec.Body.String())
	}
}
