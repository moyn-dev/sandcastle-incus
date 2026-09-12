package authapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ── store ────────────────────────────────────────────────────────────────────

func TestPublicDNSZoneStore_AddEncryptsAndListsFingerprintOnly(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	if err := AddPublicDNSZone(ctx, db, "hase.de", "cf-1", "secret-token", "admin"); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT encrypted_token FROM public_dns_zones WHERE zone = 'hase.de'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "secret-token" || strings.Contains(stored, "secret-token") {
		t.Fatalf("token stored in clear: %q", stored)
	}
	zones, err := ListPublicDNSZones(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0].Zone != "hase.de" || zones[0].CloudflareZoneID != "cf-1" || zones[0].CreatedBy != "admin" {
		t.Fatalf("zones = %+v", zones)
	}
	if zones[0].TokenFingerprint != publicDNSZoneTokenFingerprint("secret-token") || len(zones[0].TokenFingerprint) != 8 {
		t.Fatalf("fingerprint = %q", zones[0].TokenFingerprint)
	}
	if zones[0].CreatedAt == "" || zones[0].UpdatedAt == "" {
		t.Fatalf("timestamps missing: %+v", zones[0])
	}
	token, err := PublicDNSZoneToken(ctx, db, "hase.de")
	if err != nil || token != "secret-token" {
		t.Fatalf("token = %q, %v", token, err)
	}
}

func TestPublicDNSZoneStore_RefusesDuplicateAndNesting(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	if err := AddPublicDNSZone(ctx, db, "sc.hase.de", "cf-1", "t", ""); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"sc.hase.de":     "public DNS zone sc.hase.de is already registered (use set-token to rotate its token)",
		"hase.de":        "public DNS zone hase.de overlaps registered zone sc.hase.de; zones may not nest",
		"dev.sc.hase.de": "public DNS zone dev.sc.hase.de overlaps registered zone sc.hase.de; zones may not nest",
	}
	for zone, want := range cases {
		err := AddPublicDNSZone(ctx, db, zone, "cf-2", "t", "")
		if err == nil || err.Error() != want {
			t.Fatalf("add %s: err = %v, want %q", zone, err, want)
		}
		var zoneErr *PublicDNSZoneError
		if !errors.As(err, &zoneErr) {
			t.Fatalf("add %s: not a PublicDNSZoneError: %T", zone, err)
		}
	}
	// A sibling is fine — "hase.de" is not a suffix of "otherhase.de".
	if err := AddPublicDNSZone(ctx, db, "otherhase.de", "cf-3", "t", ""); err != nil {
		t.Fatal(err)
	}
}

func TestPublicDNSZoneStore_SetTokenRotatesAndRemoveRefusesClaims(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	if err := AddPublicDNSZone(ctx, db, "hase.de", "cf-1", "old", ""); err != nil {
		t.Fatal(err)
	}
	if err := SetPublicDNSZoneToken(ctx, db, "hase.de", "cf-1b", "new"); err != nil {
		t.Fatal(err)
	}
	if token, _ := PublicDNSZoneToken(ctx, db, "hase.de"); token != "new" {
		t.Fatalf("token after rotate = %q", token)
	}
	if zone, _, _ := GetPublicDNSZone(ctx, db, "hase.de"); zone.CloudflareZoneID != "cf-1b" {
		t.Fatalf("zone id after rotate = %q", zone.CloudflareZoneID)
	}
	if err := SetPublicDNSZoneToken(ctx, db, "nope.de", "x", "y"); err == nil || err.Error() != "public DNS zone nope.de is not registered" {
		t.Fatalf("set-token unknown: %v", err)
	}

	claims := &fakeClaimSource{claims: map[string][]ProjectDomainClaimRef{
		"hase.de": {{Domain: "baum.hase.de", Tenant: "acme", Project: "baum"}, {Domain: "igel.hase.de", Tenant: "bob", Project: "igel"}},
	}}
	err := RemovePublicDNSZone(ctx, db, claims, "hase.de")
	want := "public DNS zone hase.de still has claimed project domains: baum.hase.de (acme/baum), igel.hase.de (bob/igel); unset them first"
	if err == nil || err.Error() != want {
		t.Fatalf("remove with claims: %v", err)
	}
	if _, found, _ := GetPublicDNSZone(ctx, db, "hase.de"); !found {
		t.Fatal("zone removed despite claims")
	}
	delete(claims.claims, "hase.de")
	if err := RemovePublicDNSZone(ctx, db, claims, "hase.de"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := GetPublicDNSZone(ctx, db, "hase.de"); found {
		t.Fatal("zone still present after remove")
	}
	if err := RemovePublicDNSZone(ctx, db, nil, "hase.de"); err == nil || err.Error() != "public DNS zone hase.de is not registered" {
		t.Fatalf("remove unknown: %v", err)
	}
}

func TestSecretEncryptionKeysAreDistinctPerPurpose(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	zoneKey, err := secretEncryptionKey(ctx, db, publicDNSZoneEncryptionKeyKey)
	if err != nil {
		t.Fatal(err)
	}
	oidcKey, err := oidcEncryptionKey(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if string(zoneKey) == string(oidcKey) {
		t.Fatal("zone key must not be the OIDC key")
	}
	again, _ := secretEncryptionKey(ctx, db, publicDNSZoneEncryptionKeyKey)
	if string(again) != string(zoneKey) {
		t.Fatal("zone key not stable across calls")
	}
	sealed, err := encryptSecret(zoneKey, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptSecret(oidcKey, sealed); err == nil {
		t.Fatal("decrypting with the wrong purpose key must fail")
	}
	plain, err := decryptSecret(zoneKey, sealed)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("roundtrip = %q, %v", plain, err)
	}
}

func TestNormalizePublicDNSZone(t *testing.T) {
	for input, want := range map[string]string{
		" Hase.DE. ": "hase.de",
		"sc.hase.de": "sc.hase.de",
	} {
		got, err := NormalizePublicDNSZone(input)
		if err != nil || got != want {
			t.Fatalf("normalize %q = %q, %v", input, got, err)
		}
	}
	for _, bad := range []string{"", "de", "-hase.de", "ha se.de", "*.hase.de", "_acme.hase.de", "hase..de"} {
		if _, err := NormalizePublicDNSZone(bad); err == nil {
			t.Fatalf("normalize %q: expected error", bad)
		}
	}
}

// ── Cloudflare validation against a fake server ──────────────────────────────

// fakeCloudflare mimics the two v4 calls the validator makes.
type fakeCloudflare struct {
	mu        sync.Mutex
	validTok  string
	zones     map[string]string // name -> id
	dnsDenied bool
	calls     []string
}

func (f *fakeCloudflare) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+f.validTok {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
			return
		}
		switch {
		case r.URL.Path == "/zones":
			name := r.URL.Query().Get("name")
			result := []map[string]any{}
			if id, ok := f.zones[name]; ok {
				result = append(result, map[string]any{"id": id, "name": name})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
		case strings.HasSuffix(r.URL.Path, "/dns_records"):
			if f.dnsDenied {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}],"result":null}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": []any{}})
		default:
			http.NotFound(w, r)
		}
	})
}

func TestCloudflareZoneClient_ValidatesTokenAndZone(t *testing.T) {
	fake := &fakeCloudflare{validTok: "good", zones: map[string]string{"hase.de": "cf-hase"}}
	server := httptest.NewServer(fake.handler())
	defer server.Close()
	client := CloudflareZoneClient{BaseURL: server.URL}

	id, err := client.ValidateZoneToken(context.Background(), "hase.de", "good")
	if err != nil || id != "cf-hase" {
		t.Fatalf("validate = %q, %v", id, err)
	}
	if len(fake.calls) != 2 || fake.calls[0] != "GET /zones?name=hase.de" || fake.calls[1] != "GET /zones/cf-hase/dns_records?per_page=1" {
		t.Fatalf("calls = %v", fake.calls)
	}

	_, err = client.ValidateZoneToken(context.Background(), "hase.de", "bad")
	if err == nil || err.Error() != "Cloudflare rejected the token for zone hase.de: Authentication error" {
		t.Fatalf("bad token: %v", err)
	}
	_, err = client.ValidateZoneToken(context.Background(), "igel.de", "good")
	if err == nil || !strings.HasPrefix(err.Error(), "Cloudflare rejected the token for zone igel.de: ") {
		t.Fatalf("invisible zone: %v", err)
	}
	fake.dnsDenied = true
	_, err = client.ValidateZoneToken(context.Background(), "hase.de", "good")
	if err == nil || err.Error() != "Cloudflare rejected the token for zone hase.de: Unauthorized to access requested resource" {
		t.Fatalf("dns denied: %v", err)
	}
	var zoneErr *PublicDNSZoneError
	if !errors.As(err, &zoneErr) || zoneErr.Kind != "rejected" {
		t.Fatalf("not a rejection: %T %v", err, err)
	}

	server.Close()
	_, err = client.ValidateZoneToken(context.Background(), "hase.de", "good")
	if err == nil || errors.As(err, &zoneErr) && zoneErr.Kind == "rejected" {
		t.Fatalf("transport failure must not read as a rejection: %v", err)
	}
}

// ── handlers ─────────────────────────────────────────────────────────────────

type fakeClaimSource struct {
	claims map[string][]ProjectDomainClaimRef
}

func (f *fakeClaimSource) ClaimsUnderZone(_ context.Context, zone string) ([]ProjectDomainClaimRef, error) {
	return f.claims[zone], nil
}

type fakeZoneValidator struct {
	ids    map[string]string
	reject string
	calls  int
}

func (f *fakeZoneValidator) ValidateZoneToken(_ context.Context, zone, token string) (string, error) {
	f.calls++
	if token != "good" {
		return "", &PublicDNSZoneError{Zone: zone, Kind: "rejected", Other: "Authentication error"}
	}
	id, ok := f.ids[zone]
	if !ok {
		return "", &PublicDNSZoneError{Zone: zone, Kind: "rejected", Other: "the token cannot see a zone named " + zone}
	}
	return id, nil
}

func zoneTestHandler(t *testing.T, validator CloudflareZoneValidator, claims ProjectDomainClaimSource) (http.Handler, string, string) {
	t.Helper()
	db := newClaimsTestDB(t)
	ctx := context.Background()
	for _, user := range []User{
		{UserKey: "root", GitHubUsername: "root", Allowlisted: true, SandcastleAdmin: true},
		{UserKey: "acme", GitHubUsername: "acme", Allowlisted: true},
	} {
		if err := UpsertUser(ctx, db, user); err != nil {
			t.Fatal(err)
		}
	}
	adminToken, err := CreateCLIToken(ctx, db, "root", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := CreateCLIToken(ctx, db, "acme", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(db, HandlerOptions{
		AuthHostname:        "sc2.thieso2.dev",
		CloudflareZones:     validator,
		ProjectDomainClaims: claims,
	})
	return h, adminToken, userToken
}

func zoneRequest(t *testing.T, h http.Handler, token, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	out := map[string]any{}
	if res.Body.Len() > 0 {
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: non-JSON body %q", method, path, res.Body.String())
		}
	}
	return res.Code, out
}

func TestPublicDNSZonesAPI_AdminOnly(t *testing.T) {
	h, _, userToken := zoneTestHandler(t, &fakeZoneValidator{}, nil)
	if code, out := zoneRequest(t, h, "", http.MethodGet, "/api/public-dns-zones", ""); code != http.StatusUnauthorized || out["error"] == "" {
		t.Fatalf("no token: %d %v", code, out)
	}
	if code, out := zoneRequest(t, h, userToken, http.MethodGet, "/api/public-dns-zones", ""); code != http.StatusForbidden || out["error"] != "Sandcastle Admin access is required" {
		t.Fatalf("non-admin: %d %v", code, out)
	}
	if code, _ := zoneRequest(t, h, userToken, http.MethodDelete, "/api/public-dns-zones/hase.de", ""); code != http.StatusForbidden {
		t.Fatalf("non-admin delete: %d", code)
	}
}

func TestPublicDNSZonesAPI_AddListSetTokenRemove(t *testing.T) {
	validator := &fakeZoneValidator{ids: map[string]string{"hase.de": "cf-hase", "igel.de": "cf-igel"}}
	claims := &fakeClaimSource{claims: map[string][]ProjectDomainClaimRef{}}
	h, admin, _ := zoneTestHandler(t, validator, claims)

	// dry-run add validates but stores nothing
	code, out := zoneRequest(t, h, admin, http.MethodPost, "/api/public-dns-zones", `{"zone":"Hase.DE.","token":"good","dryRun":true}`)
	if code != http.StatusOK || out["zone"] != "hase.de" || out["cloudflareZoneID"] != "cf-hase" || out["dryRun"] != true {
		t.Fatalf("dry-run add: %d %v", code, out)
	}
	code, out = zoneRequest(t, h, admin, http.MethodGet, "/api/public-dns-zones", "")
	if code != http.StatusOK || len(out["zones"].([]any)) != 0 {
		t.Fatalf("list after dry-run: %d %v", code, out)
	}

	// rejected token stores nothing, 422 with the verbatim text
	code, out = zoneRequest(t, h, admin, http.MethodPost, "/api/public-dns-zones", `{"zone":"hase.de","token":"bad"}`)
	if code != http.StatusUnprocessableEntity || out["error"] != "Cloudflare rejected the token for zone hase.de: Authentication error" {
		t.Fatalf("rejected add: %d %v", code, out)
	}
	code, out = zoneRequest(t, h, admin, http.MethodGet, "/api/public-dns-zones", "")
	if len(out["zones"].([]any)) != 0 {
		t.Fatalf("list after rejection: %d %v", code, out)
	}

	// real add
	code, out = zoneRequest(t, h, admin, http.MethodPost, "/api/public-dns-zones", `{"zone":"hase.de","token":"good"}`)
	if code != http.StatusCreated || out["zone"] != "hase.de" || out["cloudflareZoneID"] != "cf-hase" {
		t.Fatalf("add: %d %v", code, out)
	}
	// exists + nesting → 409, and neither consults Cloudflare
	before := validator.calls
	code, out = zoneRequest(t, h, admin, http.MethodPost, "/api/public-dns-zones", `{"zone":"hase.de","token":"good"}`)
	if code != http.StatusConflict || out["error"] != "public DNS zone hase.de is already registered (use set-token to rotate its token)" {
		t.Fatalf("duplicate add: %d %v", code, out)
	}
	code, out = zoneRequest(t, h, admin, http.MethodPost, "/api/public-dns-zones", `{"zone":"sc.hase.de","token":"good"}`)
	if code != http.StatusConflict || out["error"] != "public DNS zone sc.hase.de overlaps registered zone hase.de; zones may not nest" {
		t.Fatalf("nested add: %d %v", code, out)
	}
	if validator.calls != before {
		t.Fatalf("Cloudflare consulted for a refused add (%d → %d)", before, validator.calls)
	}
	// malformed zone → 400
	if code, _ = zoneRequest(t, h, admin, http.MethodPost, "/api/public-dns-zones", `{"zone":"de","token":"good"}`); code != http.StatusBadRequest {
		t.Fatalf("bad zone: %d", code)
	}

	// list shows fingerprint, claims count, created-by
	claims.claims["hase.de"] = []ProjectDomainClaimRef{{Domain: "baum.hase.de", Tenant: "acme", Project: "baum"}}
	code, out = zoneRequest(t, h, admin, http.MethodGet, "/api/public-dns-zones", "")
	zones := out["zones"].([]any)
	if code != http.StatusOK || len(zones) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	zone := zones[0].(map[string]any)
	if zone["zone"] != "hase.de" || zone["cloudflareZoneID"] != "cf-hase" || zone["claims"] != float64(1) || zone["createdBy"] != "root" {
		t.Fatalf("zone = %v", zone)
	}
	if fp, _ := zone["tokenFingerprint"].(string); len(fp) != 8 || fp == "good" {
		t.Fatalf("fingerprint = %v", zone["tokenFingerprint"])
	}
	if _, leaked := zone["token"]; leaked {
		t.Fatal("token leaked in list")
	}

	// set-token: unknown zone 404, rejected 422, dry-run 200 unchanged, real 200
	code, out = zoneRequest(t, h, admin, http.MethodPut, "/api/public-dns-zones/igel.de/token", `{"token":"good"}`)
	if code != http.StatusNotFound || out["error"] != "public DNS zone igel.de is not registered" {
		t.Fatalf("set-token unknown: %d %v", code, out)
	}
	code, out = zoneRequest(t, h, admin, http.MethodPut, "/api/public-dns-zones/hase.de/token", `{"token":"bad"}`)
	if code != http.StatusUnprocessableEntity || out["error"] != "Cloudflare rejected the token for zone hase.de: Authentication error" {
		t.Fatalf("set-token rejected: %d %v", code, out)
	}
	fpBefore := zone["tokenFingerprint"]
	code, out = zoneRequest(t, h, admin, http.MethodPut, "/api/public-dns-zones/hase.de/token", `{"token":"good","dryRun":true}`)
	if code != http.StatusOK || out["dryRun"] != true {
		t.Fatalf("set-token dry-run: %d %v", code, out)
	}
	validator.ids["hase.de"] = "cf-hase-2"
	code, out = zoneRequest(t, h, admin, http.MethodPut, "/api/public-dns-zones/hase.de/token", `{"token":"good"}`)
	if code != http.StatusOK || out["cloudflareZoneID"] != "cf-hase-2" {
		t.Fatalf("set-token: %d %v", code, out)
	}
	_, out = zoneRequest(t, h, admin, http.MethodGet, "/api/public-dns-zones", "")
	zone = out["zones"].([]any)[0].(map[string]any)
	if zone["cloudflareZoneID"] != "cf-hase-2" || zone["tokenFingerprint"] != fpBefore {
		// same token "good" → same fingerprint; id re-resolved
		t.Fatalf("after rotate: %v", zone)
	}

	// remove: refused while claimed (also on dry-run), then allowed
	want := "public DNS zone hase.de still has claimed project domains: baum.hase.de (acme/baum); unset them first"
	code, out = zoneRequest(t, h, admin, http.MethodDelete, "/api/public-dns-zones/hase.de?dryRun=1", "")
	if code != http.StatusConflict || out["error"] != want {
		t.Fatalf("remove dry-run claimed: %d %v", code, out)
	}
	code, out = zoneRequest(t, h, admin, http.MethodDelete, "/api/public-dns-zones/hase.de", "")
	if code != http.StatusConflict || out["error"] != want {
		t.Fatalf("remove claimed: %d %v", code, out)
	}
	delete(claims.claims, "hase.de")
	code, out = zoneRequest(t, h, admin, http.MethodDelete, "/api/public-dns-zones/hase.de?dryRun=1", "")
	if code != http.StatusOK || out["dryRun"] != true || out["zone"] != "hase.de" {
		t.Fatalf("remove dry-run: %d %v", code, out)
	}
	_, out = zoneRequest(t, h, admin, http.MethodGet, "/api/public-dns-zones", "")
	if len(out["zones"].([]any)) != 1 {
		t.Fatal("dry-run removed the zone")
	}
	code, _ = zoneRequest(t, h, admin, http.MethodDelete, "/api/public-dns-zones/hase.de", "")
	if code != http.StatusNoContent {
		t.Fatalf("remove: %d", code)
	}
	code, out = zoneRequest(t, h, admin, http.MethodDelete, "/api/public-dns-zones/hase.de", "")
	if code != http.StatusNotFound || out["error"] != "public DNS zone hase.de is not registered" {
		t.Fatalf("remove twice: %d %v", code, out)
	}
	_, out = zoneRequest(t, h, admin, http.MethodGet, "/api/public-dns-zones", "")
	if len(out["zones"].([]any)) != 0 {
		t.Fatal("zone still listed after remove")
	}
}

func TestPublicDNSZonesAPI_CloudflareUnreachableIsNotARejection(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	h, admin, _ := zoneTestHandler(t, CloudflareZoneClient{BaseURL: server.URL}, nil)
	code, out := zoneRequest(t, h, admin, http.MethodPost, "/api/public-dns-zones", `{"zone":"hase.de","token":"good"}`)
	if code != http.StatusBadGateway || strings.HasPrefix(out["error"].(string), "Cloudflare rejected") {
		t.Fatalf("unreachable: %d %v", code, out)
	}
	_, out = zoneRequest(t, h, admin, http.MethodGet, "/api/public-dns-zones", "")
	if len(out["zones"].([]any)) != 0 {
		t.Fatal("zone stored despite unreachable Cloudflare")
	}
}

// The client and the handler agree end to end, including verbatim error text.
func TestPublicDNSZoneClient_RoundTrip(t *testing.T) {
	validator := &fakeZoneValidator{ids: map[string]string{"hase.de": "cf-hase"}}
	h, admin, userToken := zoneTestHandler(t, validator, &fakeClaimSource{claims: map[string][]ProjectDomainClaimRef{}})
	server := httptest.NewServer(h)
	defer server.Close()
	ctx := context.Background()

	client := DeviceClient{BaseURL: server.URL, AuthToken: admin}
	result, err := client.AddPublicDNSZone(ctx, "hase.de", "good", false)
	if err != nil || result.Zone != "hase.de" || result.CloudflareZoneID != "cf-hase" {
		t.Fatalf("add = %+v, %v", result, err)
	}
	_, err = client.AddPublicDNSZone(ctx, "sc.hase.de", "good", false)
	if err == nil || err.Error() != "public DNS zone sc.hase.de overlaps registered zone hase.de; zones may not nest" {
		t.Fatalf("nested add error = %v", err)
	}
	_, err = client.SetPublicDNSZoneToken(ctx, "hase.de", "bad", false)
	if err == nil || err.Error() != "Cloudflare rejected the token for zone hase.de: Authentication error" {
		t.Fatalf("set-token error = %v", err)
	}
	zones, err := client.ListPublicDNSZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Zone != "hase.de" || zones[0].CreatedBy != "root" {
		t.Fatalf("list = %+v, %v", zones, err)
	}
	result, err = client.RemovePublicDNSZone(ctx, "hase.de", true)
	if err != nil || !result.DryRun || result.Zone != "hase.de" {
		t.Fatalf("remove dry-run = %+v, %v", result, err)
	}
	result, err = client.RemovePublicDNSZone(ctx, "hase.de", false)
	if err != nil || result.Zone != "hase.de" || result.DryRun {
		t.Fatalf("remove = %+v, %v", result, err)
	}
	if zones, _ := client.ListPublicDNSZones(ctx); len(zones) != 0 {
		t.Fatalf("list after remove = %+v", zones)
	}

	_, err = DeviceClient{BaseURL: server.URL, AuthToken: userToken}.ListPublicDNSZones(ctx)
	if err == nil || err.Error() != "Sandcastle Admin access is required" {
		t.Fatalf("non-admin list error = %v", err)
	}
}
