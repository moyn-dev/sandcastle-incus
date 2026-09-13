package authapp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/domain"
)

// The public_dns_zones table is the install's registry of Public DNS Zones
// (ADR-0027, spec public-dns-zones §1.3): the Cloudflare zones an admin has
// handed the Auth App a token for, under which tenants claim Project Domains.
// The zone name is the PK. A Public DNS Zone may be the Cloudflare zone itself
// (hase.de) or any name inside one (e2e.sc.tc42.uk inside tc42.uk): Cloudflare
// tokens are zone-scoped, so the containing Cloudflare zone — name and id — is
// resolved once, at add time, by the same call that proves the token works,
// and every record is written into that zone with a name relative to it. The
// token itself is sealed with encryptSecret and never leaves the process
// except towards Cloudflare. Zones may not nest — a zone's claims are
// unambiguous only if exactly one registered zone covers any given Project
// Domain.

// PublicDNSZone is a registered zone as the API and the CLI see it: never the
// token, only its fingerprint.
type PublicDNSZone struct {
	Zone string `json:"zone"`
	// CloudflareZone is the Cloudflare zone that contains Zone (equal to Zone
	// when the Public DNS Zone is a Cloudflare zone itself).
	CloudflareZone   string `json:"cloudflareZone"`
	CloudflareZoneID string `json:"cloudflareZoneID"`
	TokenFingerprint string `json:"tokenFingerprint"`
	Claims           int    `json:"claims"`
	CreatedBy        string `json:"createdBy"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
}

// PublicDNSZoneError carries the verbatim spec §2.1 texts for the registry's
// refusals so handlers can map them to a status without string matching.
type PublicDNSZoneError struct {
	Zone string
	// Kind is one of: "exists", "overlap", "not-found", "claimed", "rejected".
	Kind string
	// Other is the overlapping zone (overlap) or the Cloudflare message (rejected).
	Other string
	// Claims is the blocking claim list (claimed).
	Claims []ProjectDomainClaimRef
	// Hostnames is the blocking explicit Machine Public Hostname list
	// (claimed, ADR-0028) — reported when no Project Domain blocks.
	Hostnames []MachineHostnameRef
}

func (e *PublicDNSZoneError) Error() string {
	switch e.Kind {
	case "exists":
		return fmt.Sprintf("public DNS zone %s is already registered (use set-token to rotate its token)", e.Zone)
	case "overlap":
		return fmt.Sprintf("public DNS zone %s overlaps registered zone %s; zones may not nest", e.Zone, e.Other)
	case "not-found":
		return fmt.Sprintf("public DNS zone %s is not registered", e.Zone)
	case "claimed":
		if len(e.Claims) == 0 && len(e.Hostnames) > 0 {
			parts := make([]string, 0, len(e.Hostnames))
			for _, h := range e.Hostnames {
				parts = append(parts, fmt.Sprintf("%s (%s/%s:%s)", h.Hostname, h.Tenant, h.Project, h.Machine))
			}
			return fmt.Sprintf("public DNS zone %s still has machine hostnames: %s; remove them first", e.Zone, strings.Join(parts, ", "))
		}
		parts := make([]string, 0, len(e.Claims))
		for _, claim := range e.Claims {
			parts = append(parts, fmt.Sprintf("%s (%s/%s)", claim.Domain, claim.Tenant, claim.Project))
		}
		return fmt.Sprintf("public DNS zone %s still has claimed project domains: %s; unset them first", e.Zone, strings.Join(parts, ", "))
	case "rejected":
		return fmt.Sprintf("Cloudflare rejected the token for zone %s: %s", e.Zone, e.Other)
	}
	return fmt.Sprintf("public DNS zone %s: %s", e.Zone, e.Kind)
}

// ProjectDomainClaimRef names one Project Domain claimed under a zone — enough
// for the remove refusal text and the list's CLAIMS column.
type ProjectDomainClaimRef struct {
	Domain  string
	Tenant  string
	Project string
}

// ProjectDomainClaimSource answers "which Project Domains are claimed under
// this zone". The registry only consumes it; the default is
// sqlProjectDomainClaims over project_domain_claims
// (project_domain_claims.go), and tests inject a fake.
type ProjectDomainClaimSource interface {
	ClaimsUnderZone(ctx context.Context, zone string) ([]ProjectDomainClaimRef, error)
}

// noProjectDomainClaims answers "none" — for callers without a database.
type noProjectDomainClaims struct{}

func (noProjectDomainClaims) ClaimsUnderZone(context.Context, string) ([]ProjectDomainClaimRef, error) {
	return nil, nil
}

// publicDNSZoneTokenFingerprint is the first 8 hex characters of the token's
// SHA-256 — enough to tell two tokens apart in `list`, useless to an attacker.
func publicDNSZoneTokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])[:8]
}

// ListPublicDNSZones returns every registered zone, alphabetically, without
// the Claims count (the handler fills that from the claim source).
func ListPublicDNSZones(ctx context.Context, db *sql.DB) ([]PublicDNSZone, error) {
	rows, err := db.QueryContext(ctx, `
SELECT zone, cloudflare_zone, cloudflare_zone_id, encrypted_token, created_by, created_at, updated_at
FROM public_dns_zones
ORDER BY zone
`)
	if err != nil {
		return nil, fmt.Errorf("list public DNS zones: %w", err)
	}
	defer rows.Close()
	key, err := secretEncryptionKey(ctx, db, publicDNSZoneEncryptionKeyKey)
	if err != nil {
		return nil, err
	}
	zones := []PublicDNSZone{}
	for rows.Next() {
		var zone PublicDNSZone
		var encrypted string
		if err := rows.Scan(&zone.Zone, &zone.CloudflareZone, &zone.CloudflareZoneID, &encrypted, &zone.CreatedBy, &zone.CreatedAt, &zone.UpdatedAt); err != nil {
			return nil, err
		}
		zone.CloudflareZone = cloudflareZoneOrSelf(zone.Zone, zone.CloudflareZone)
		token, err := decryptSecret(key, encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt token for public DNS zone %s: %w", zone.Zone, err)
		}
		zone.TokenFingerprint = publicDNSZoneTokenFingerprint(string(token))
		zones = append(zones, zone)
	}
	return zones, rows.Err()
}

// GetPublicDNSZone returns one registered zone (without Claims).
func GetPublicDNSZone(ctx context.Context, db *sql.DB, zone string) (PublicDNSZone, bool, error) {
	zones, err := ListPublicDNSZones(ctx, db)
	if err != nil {
		return PublicDNSZone{}, false, err
	}
	for _, candidate := range zones {
		if candidate.Zone == zone {
			return candidate, true, nil
		}
	}
	return PublicDNSZone{}, false, nil
}

// cloudflareZoneOrSelf resolves the stored cloudflare_zone: rows written
// before the column existed carry ” and were registered by exact name, so
// the Public DNS Zone is its own Cloudflare zone.
func cloudflareZoneOrSelf(zone, cloudflareZone string) string {
	cloudflareZone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cloudflareZone)), ".")
	if cloudflareZone == "" {
		return zone
	}
	return cloudflareZone
}

// PublicDNSZoneToken returns the decrypted Cloudflare token for a zone — for
// the ACME issuer, never for an HTTP response.
func PublicDNSZoneToken(ctx context.Context, db *sql.DB, zone string) (string, error) {
	_, token, err := PublicDNSZoneCredentials(ctx, db, zone)
	return token, err
}

// PublicDNSZoneCredentials returns what the record reconciler needs to talk
// to Cloudflare about a zone: the Cloudflare zone that contains it (the zone
// name every libdns call must be addressed to) and the decrypted token.
func PublicDNSZoneCredentials(ctx context.Context, db *sql.DB, zone string) (cloudflareZone, token string, err error) {
	var encrypted string
	err = db.QueryRowContext(ctx, `SELECT cloudflare_zone, encrypted_token FROM public_dns_zones WHERE zone = ?`, zone).Scan(&cloudflareZone, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", &PublicDNSZoneError{Zone: zone, Kind: "not-found"}
	}
	if err != nil {
		return "", "", err
	}
	key, err := secretEncryptionKey(ctx, db, publicDNSZoneEncryptionKeyKey)
	if err != nil {
		return "", "", err
	}
	plain, err := decryptSecret(key, encrypted)
	if err != nil {
		return "", "", fmt.Errorf("decrypt token for public DNS zone %s: %w", zone, err)
	}
	return cloudflareZoneOrSelf(zone, cloudflareZone), string(plain), nil
}

// CheckPublicDNSZoneAddable is the pre-flight for `add`: the zone must be new
// and may neither contain nor sit inside a registered zone.
func CheckPublicDNSZoneAddable(ctx context.Context, db *sql.DB, zone string) error {
	rows, err := db.QueryContext(ctx, `SELECT zone FROM public_dns_zones ORDER BY zone`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var existing string
		if err := rows.Scan(&existing); err != nil {
			return err
		}
		if existing == zone {
			return &PublicDNSZoneError{Zone: zone, Kind: "exists"}
		}
		if strings.HasSuffix(zone, "."+existing) || strings.HasSuffix(existing, "."+zone) {
			return &PublicDNSZoneError{Zone: zone, Kind: "overlap", Other: existing}
		}
	}
	return rows.Err()
}

// AddPublicDNSZone stores a validated zone. The caller has already run
// CheckPublicDNSZoneAddable and the Cloudflare validation; the PK is the last
// line of defence against a racing add.
func AddPublicDNSZone(ctx context.Context, db *sql.DB, zone string, cloudflare CloudflareZone, token, createdBy string) error {
	if err := CheckPublicDNSZoneAddable(ctx, db, zone); err != nil {
		return err
	}
	key, err := secretEncryptionKey(ctx, db, publicDNSZoneEncryptionKeyKey)
	if err != nil {
		return err
	}
	encrypted, err := encryptSecret(key, []byte(strings.TrimSpace(token)))
	if err != nil {
		return err
	}
	now := timeNow().UTC().Format(time.RFC3339)
	_, err = db.ExecContext(ctx, `
INSERT INTO public_dns_zones (zone, cloudflare_zone, cloudflare_zone_id, encrypted_token, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`, zone, cloudflareZoneOrSelf(zone, cloudflare.Name), cloudflare.ID, encrypted, strings.TrimSpace(createdBy), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
			return &PublicDNSZoneError{Zone: zone, Kind: "exists"}
		}
		return fmt.Errorf("add public DNS zone: %w", err)
	}
	return nil
}

// SetPublicDNSZoneToken rotates a zone's token in place, re-recording the
// Cloudflare zone (name and id) the new token resolved.
func SetPublicDNSZoneToken(ctx context.Context, db *sql.DB, zone string, cloudflare CloudflareZone, token string) error {
	key, err := secretEncryptionKey(ctx, db, publicDNSZoneEncryptionKeyKey)
	if err != nil {
		return err
	}
	encrypted, err := encryptSecret(key, []byte(strings.TrimSpace(token)))
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, `
UPDATE public_dns_zones SET cloudflare_zone = ?, cloudflare_zone_id = ?, encrypted_token = ?, updated_at = ?
WHERE zone = ?
`, cloudflareZoneOrSelf(zone, cloudflare.Name), cloudflare.ID, encrypted, timeNow().UTC().Format(time.RFC3339), zone)
	if err != nil {
		return fmt.Errorf("set public DNS zone token: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return &PublicDNSZoneError{Zone: zone, Kind: "not-found"}
	}
	return nil
}

// RemovePublicDNSZone deletes a zone, refusing while any Project Domain is
// claimed under it.
func RemovePublicDNSZone(ctx context.Context, db *sql.DB, claims ProjectDomainClaimSource, zone string) error {
	if _, found, err := GetPublicDNSZone(ctx, db, zone); err != nil {
		return err
	} else if !found {
		return &PublicDNSZoneError{Zone: zone, Kind: "not-found"}
	}
	if err := checkPublicDNSZoneRemovable(ctx, claims, zone); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public_dns_zones WHERE zone = ?`, zone); err != nil {
		return fmt.Errorf("remove public DNS zone: %w", err)
	}
	return nil
}

func checkPublicDNSZoneRemovable(ctx context.Context, claims ProjectDomainClaimSource, zone string) error {
	if claims == nil {
		claims = noProjectDomainClaims{}
	}
	blocking, err := claims.ClaimsUnderZone(ctx, zone)
	if err != nil {
		return err
	}
	if len(blocking) > 0 {
		return &PublicDNSZoneError{Zone: zone, Kind: "claimed", Claims: blocking}
	}
	if source, ok := claims.(interface {
		HostnamesUnderZone(ctx context.Context, zone string) ([]MachineHostnameRef, error)
	}); ok {
		hostnames, err := source.HostnamesUnderZone(ctx, zone)
		if err != nil {
			return err
		}
		if len(hostnames) > 0 {
			return &PublicDNSZoneError{Zone: zone, Kind: "claimed", Hostnames: hostnames}
		}
	}
	return nil
}

// NormalizePublicDNSZone is the shared client/server normalization (§2.1).
func NormalizePublicDNSZone(value string) (string, error) {
	return domain.NormalizePublicDNSZone(value)
}

// CloudflareZone is a Cloudflare zone as resolved for a Public DNS Zone: the
// zone the token can see that equals or contains the requested name.
type CloudflareZone struct {
	ID   string
	Name string
}

// CloudflareZoneValidator proves a token can see and manage the Cloudflare
// zone that contains a Public DNS Zone, returning that zone. A token
// Cloudflare rejects, or one that sees no zone equal to or containing the
// requested name, yields a *PublicDNSZoneError of Kind "rejected"; any other
// error is a transport failure the caller should not treat as a rejection.
type CloudflareZoneValidator interface {
	ValidateZoneToken(ctx context.Context, zone, token string) (CloudflareZone, error)
}

// CloudflareZoneClient validates against the real API (or a test server via
// BaseURL): the zones the token can read (`GET /zones?per_page=50`, paged)
// are searched for the longest name equal to the requested zone or its parent
// on a label boundary; then `GET /zones/<id>/dns_records?per_page=1` against
// that zone proves DNS read.
type CloudflareZoneClient struct {
	BaseURL string
	HTTP    *http.Client
}

const (
	cloudflareAPIBaseURL   = "https://api.cloudflare.com/client/v4"
	cloudflareZonesPerPage = 50
	cloudflareZonesMaxPage = 100 // 5000 zones — a hard stop against a misbehaving server
)

func (c CloudflareZoneClient) ValidateZoneToken(ctx context.Context, zone, token string) (CloudflareZone, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return CloudflareZone{}, &PublicDNSZoneError{Zone: zone, Kind: "rejected", Other: "no token given"}
	}
	visible, err := c.listZones(ctx, zone, token)
	if err != nil {
		return CloudflareZone{}, err
	}
	resolved, err := containingCloudflareZone(zone, visible)
	if err != nil {
		return CloudflareZone{}, err
	}
	var records json.RawMessage
	if err := c.get(ctx, zone, token, "/zones/"+url.PathEscape(resolved.ID)+"/dns_records?per_page=1", &records, nil); err != nil {
		return CloudflareZone{}, err
	}
	return resolved, nil
}

// listZones pages through every zone the token can read.
func (c CloudflareZoneClient) listZones(ctx context.Context, zone, token string) ([]CloudflareZone, error) {
	var all []CloudflareZone
	for page := 1; page <= cloudflareZonesMaxPage; page++ {
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		var info cloudflareResultInfo
		path := fmt.Sprintf("/zones?per_page=%d&page=%d", cloudflareZonesPerPage, page)
		if err := c.get(ctx, zone, token, path, &zones, &info); err != nil {
			return nil, err
		}
		for _, z := range zones {
			all = append(all, CloudflareZone{ID: z.ID, Name: z.Name})
		}
		if len(zones) == 0 || info.TotalPages <= page {
			break
		}
	}
	return all, nil
}

// containingCloudflareZone picks, among the zones a token can see, the one
// whose name equals zone or is its parent on a label boundary — the longest
// such name. None is a rejection; two zones sharing the longest name is an
// ambiguity Cloudflare should never produce, reported as such.
func containingCloudflareZone(zone string, visible []CloudflareZone) (CloudflareZone, error) {
	var best []CloudflareZone
	for _, candidate := range visible {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate.Name)), ".")
		if name == "" || (name != zone && !strings.HasSuffix(zone, "."+name)) {
			continue
		}
		candidate.Name = name
		switch {
		case len(best) == 0 || len(name) > len(best[0].Name):
			best = []CloudflareZone{candidate}
		case len(name) == len(best[0].Name):
			best = append(best, candidate)
		}
	}
	switch len(best) {
	case 0:
		return CloudflareZone{}, &PublicDNSZoneError{Zone: zone, Kind: "rejected", Other: "the token cannot see a zone containing " + zone + " (check Zone > Zone > Read and the zone the token is scoped to)"}
	case 1:
		return best[0], nil
	default:
		return CloudflareZone{}, &PublicDNSZoneError{Zone: zone, Kind: "rejected", Other: fmt.Sprintf("the token sees %d zones named %s; expected exactly one", len(best), best[0].Name)}
	}
}

// cloudflareResultInfo is the paging block of a Cloudflare list envelope.
type cloudflareResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// get performs one authenticated Cloudflare v4 call. A non-success envelope
// (auth failure, missing permission) is a rejection carrying Cloudflare's own
// message; a transport or parse failure is returned as-is. info, when given,
// receives the envelope's result_info (paging) block.
func (c CloudflareZoneClient) get(ctx context.Context, zone, token, path string, out any, info *cloudflareResultInfo) error {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = cloudflareAPIBaseURL
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result     json.RawMessage       `json:"result"`
		ResultInfo *cloudflareResultInfo `json:"result_info"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("cloudflare GET %s: HTTP %d: %s", path, response.StatusCode, strings.TrimSpace(string(data)))
	}
	if !envelope.Success {
		messages := []string{}
		for _, e := range envelope.Errors {
			messages = append(messages, e.Message)
		}
		if len(messages) == 0 {
			messages = append(messages, fmt.Sprintf("HTTP %d", response.StatusCode))
		}
		return &PublicDNSZoneError{Zone: zone, Kind: "rejected", Other: strings.Join(messages, "; ")}
	}
	if info != nil && envelope.ResultInfo != nil {
		*info = *envelope.ResultInfo
	}
	if out != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}
