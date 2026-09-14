package authapp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// TailnetPublication is the single HTTPS site a Tenant Sidecar serves for a
// Machine. TargetPort is deliberately fixed at 443: a Machine's normal
// private HTTPS endpoint is the only upstream this feature exposes.
type TailnetPublication struct {
	Tenant     string
	Project    string
	Machine    string
	Hostname   string
	TargetPort int
	CertPEM    string
	KeyPEM     string
}

// TailnetPublisher is the infrastructure seam. The Auth App owns Cloudflare
// credentials and ACME; the implementation only installs a certificate and
// Caddy route on the Tenant Sidecar, returning its Tailscale IPv4 address.
type TailnetPublisher interface {
	Publish(context.Context, TailnetPublication) (tailnetIPv4 string, err error)
}

type TailnetPublicationRequest struct {
	Tenant   string `json:"tenant,omitempty"`
	Project  string `json:"project"`
	Machine  string `json:"machine"`
	Hostname string `json:"hostname"`
}

type TailnetPublicationResult struct {
	Hostname    string   `json:"hostname"`
	TargetPort  int      `json:"targetPort"`
	TailnetIPv4 string   `json:"tailnetIPv4"`
	Trace       []string `json:"trace,omitempty"`
}

func (h handler) tailnetPublicationsAPI(w http.ResponseWriter, r *http.Request) {
	verbose := r.Header.Get("X-Sandcastle-Verbose") == "1"
	trace := func(s string) []string {
		if verbose {
			return []string{s}
		}
		return nil
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.tailnetPublisher == nil || h.tailnetIssuer == nil {
		writeAPIError(w, http.StatusNotImplemented, fmt.Errorf("tailnet publishing is not available on this deployment"))
		return
	}
	u, err := h.requireBearerUser(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err)
		return
	}
	var q TailnetPublicationRequest
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
		return
	}
	tenantName, err := h.machineHostnameTenant(r.Context(), u, q.Tenant)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	hostname, err := NormalizeMachineHostname(q.Hostname)
	if err != nil || strings.TrimSpace(q.Project) == "" || strings.TrimSpace(q.Machine) == "" {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("invalid tailnet hostname, project, or machine"))
		return
	}
	zone, err := tailnetPublicationZone(r.Context(), h.db, hostname)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	if found, err := RouteHostnameRegistered(r.Context(), h.db, hostname); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	} else if found {
		writeAPIError(w, http.StatusConflict, fmt.Errorf("%q is already published as a Public Route", hostname))
		return
	}
	token, err := PublicDNSZoneToken(r.Context(), h.db, zone.Zone)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	if err := (cf{token: token, baseURL: h.cloudflareBaseURL}).tailnetPreflight(r.Context(), zone.CloudflareZoneID, hostname); err != nil {
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	issued, err := h.tailnetIssuer.Issue(r.Context(), zone.Zone, []string{hostname})
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, fmt.Errorf("issue tailnet certificate: %w", err))
		return
	}
	steps := trace("cloudflare api: DNS-01 certificate issued for " + hostname)
	ip, err := h.tailnetPublisher.Publish(r.Context(), TailnetPublication{Tenant: tenantName, Project: strings.TrimSpace(q.Project), Machine: strings.TrimSpace(q.Machine), Hostname: hostname, TargetPort: 443, CertPEM: issued.CertPEM, KeyPEM: issued.KeyPEM})
	if err != nil {
		log.Printf("auth-app tailnet publication %s: %v", hostname, err)
		writeAPIError(w, http.StatusBadGateway, fmt.Errorf("configure Tenant Sidecar: %w", err))
		return
	}
	if err := (cf{token: token, baseURL: h.cloudflareBaseURL}).tailnetA(r.Context(), zone.CloudflareZoneID, hostname, ip); err != nil {
		writeAPIError(w, http.StatusBadGateway, fmt.Errorf("set tailnet DNS: %w", err))
		return
	}
	if verbose {
		steps = append(steps, "tailscale api: Tenant Sidecar IPv4 "+ip, "cloudflare api: DNS-only A record set for "+hostname, "caddy api: Tenant Sidecar HTTPS route installed")
	}
	writeJSON(w, http.StatusOK, TailnetPublicationResult{Hostname: hostname, TargetPort: 443, TailnetIPv4: ip, Trace: steps})
}

func (c cf) tailnetPreflight(ctx context.Context, zoneID, hostname string) error {
	var records []struct {
		Type string `json:"type"`
	}
	if err := c.do(ctx, "GET", "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(hostname), nil, &records); err != nil {
		return err
	}
	for _, record := range records {
		if record.Type == "CNAME" {
			return fmt.Errorf("%q is already published through a Machine Tunnel", hostname)
		}
		return fmt.Errorf("%q is already published as a Tailnet service", hostname)
	}
	return nil
}

func tailnetPublicationZone(ctx context.Context, db *sql.DB, hostname string) (PublicDNSZone, error) {
	zones, err := ListPublicDNSZones(ctx, db)
	if err != nil {
		return PublicDNSZone{}, err
	}
	var match PublicDNSZone
	for _, zone := range zones {
		if hostname != zone.Zone && strings.HasSuffix(hostname, "."+zone.Zone) && len(zone.Zone) > len(match.Zone) {
			match = zone
		}
	}
	if match.Zone == "" {
		return PublicDNSZone{}, fmt.Errorf("no Public DNS Zone covers %s — ask your admin", hostname)
	}
	return match, nil
}

// tailnetA creates a DNS-only A record. A pre-existing identical record makes
// publish idempotent; every other record is a deliberate ownership conflict.
func (c cf) tailnetA(ctx context.Context, zoneID, hostname, ip string) error {
	var records []struct {
		Type    string `json:"type"`
		Content string `json:"content"`
		Proxied bool   `json:"proxied"`
	}
	if err := c.do(ctx, "GET", "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(hostname), nil, &records); err != nil {
		return err
	}
	for _, record := range records {
		if record.Type == "A" && strings.TrimSpace(record.Content) == strings.TrimSpace(ip) && !record.Proxied {
			return nil
		}
		return fmt.Errorf("%q already has a DNS record; remove it before publishing a Tailnet service", hostname)
	}
	return c.do(ctx, "POST", "/zones/"+zoneID+"/dns_records", map[string]any{"type": "A", "name": hostname, "content": ip, "ttl": 60, "proxied": false}, nil)
}

func (c DeviceClient) PublishTailnetService(ctx context.Context, q TailnetPublicationRequest) (TailnetPublicationResult, error) {
	b, _ := json.Marshal(q)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/tailnet-publications"), bytes.NewReader(b))
	if err != nil {
		return TailnetPublicationResult{}, err
	}
	r.Header.Set("Authorization", "Bearer "+c.AuthToken)
	if c.Verbose {
		r.Header.Set("X-Sandcastle-Verbose", "1")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := c.client().Do(r)
	if err != nil {
		return TailnetPublicationResult{}, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		return TailnetPublicationResult{}, fmt.Errorf("publish tailnet service: %s", strings.TrimSpace(string(payload)))
	}
	var result TailnetPublicationResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return TailnetPublicationResult{}, err
	}
	return result, nil
}
